// Package asset defines what modules report about a target's exposed
// surface: host names, IP addresses, network services and certificates.
//
// A finding says "something is wrong"; an asset says "this exists". The
// inventory is the list of what the customer exposes, with or without
// problems. Like findings, assets are facts observed by a module, never
// guesses.
package asset

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
)

// Kind is the type of an asset.
type Kind string

const (
	// KindHostname is a DNS name, equal to the target domain or under it,
	// that resolved. Names outside the target domain (a mail provider's MX
	// host, a CDN's name) are not the customer's assets and are refused.
	KindHostname Kind = "hostname"
	// KindIP is an address one of the target's names resolved to. It may
	// belong to a hosting provider or a CDN: it is where the domain points,
	// not a claim of ownership (see ownership.IPGate for that).
	KindIP Kind = "ip"
	// KindService is an open TCP port: value "ip:port/tcp", e.g.
	// "192.0.2.10:443/tcp" or "[2001:db8::1]:22/tcp".
	KindService Kind = "service"
	// KindCertificate is a TLS certificate served by the target, identified
	// by the lowercase hex SHA-256 of its DER encoding.
	KindCertificate Kind = "certificate"
)

// Valid reports whether k is one of the defined kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindHostname, KindIP, KindService, KindCertificate:
		return true
	}
	return false
}

// Limits on details (rule 7: values come from the target).
const (
	MaxDetails          = 16
	MaxDetailKeyBytes   = 64
	MaxDetailValueBytes = 512
)

// Asset is one element of a target's exposed surface.
//
// Kind and Value identify it: two modules reporting the same IP report the
// same asset. Details are descriptive (a certificate's subject and expiry,
// a service's expected name) and may change between scans.
type Asset struct {
	Kind    Kind
	Value   string
	Details map[string]string
}

// Key identifies an asset within a target.
func (a Asset) Key() string { return string(a.Kind) + " " + a.Value }

// Hostname, IP, Service and Certificate build assets in canonical form.

func Hostname(name string) Asset {
	return Asset{Kind: KindHostname, Value: strings.TrimSuffix(strings.ToLower(name), ".")}
}

func IP(ip netip.Addr) Asset {
	return Asset{Kind: KindIP, Value: ip.Unmap().String()}
}

func Service(ip netip.Addr, port uint16, details map[string]string) Asset {
	return Asset{Kind: KindService, Value: netip.AddrPortFrom(ip.Unmap(), port).String() + "/tcp", Details: details}
}

// Certificate takes the SHA-256 of the certificate's DER bytes.
func Certificate(sha256 [32]byte, details map[string]string) Asset {
	return Asset{Kind: KindCertificate, Value: fmt.Sprintf("%x", sha256), Details: details}
}

// Validate checks that a is well formed and belongs to target, the
// normalized domain being scanned. Values must be in canonical form (use
// the constructors above), so the same asset always has the same key.
func (a Asset) Validate(target string) error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch a.Kind {
	case KindHostname:
		name, err := dnsname.Normalize(a.Value)
		switch {
		case err != nil:
			fail("hostname: %w", err)
		case name != a.Value:
			fail("hostname %q: not in canonical form %q", a.Value, name)
		case name != target && !strings.HasSuffix(name, "."+target):
			fail("hostname %q: not %s or one of its subdomains", name, target)
		}
	case KindIP:
		ip, err := netip.ParseAddr(a.Value)
		switch {
		case err != nil:
			fail("ip: %w", err)
		case ip.Unmap().String() != a.Value || ip.Zone() != "":
			fail("ip %q: not in canonical form", a.Value)
		}
	case KindService:
		addr, ok := strings.CutSuffix(a.Value, "/tcp")
		ap, err := netip.ParseAddrPort(addr)
		switch {
		case !ok:
			fail("service %q: must end with /tcp", a.Value)
		case err != nil:
			fail("service: %w", err)
		case ap.Port() == 0 || ap.Addr().Zone() != "" ||
			netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String() != addr:
			fail("service %q: not in canonical form", a.Value)
		}
	case KindCertificate:
		if len(a.Value) != 64 || strings.Trim(a.Value, "0123456789abcdef") != "" {
			fail("certificate %q: must be a lowercase hex SHA-256", a.Value)
		}
	default:
		fail("kind: unknown value %q", a.Kind)
	}

	if len(a.Details) > MaxDetails {
		fail("details: %d entries, limit is %d", len(a.Details), MaxDetails)
	}
	for _, k := range slices.Sorted(maps.Keys(a.Details)) {
		v := a.Details[k]
		if k == "" || len(k) > MaxDetailKeyBytes || !utf8.ValidString(k) {
			fail("details: invalid key %q", k)
		}
		if len(v) > MaxDetailValueBytes || !utf8.ValidString(v) {
			fail("details[%s]: value must be valid UTF-8 of at most %d bytes", k, MaxDetailValueBytes)
		}
	}
	return errors.Join(errs...)
}

// TruncateDetail bounds a detail value to MaxDetailValueBytes without
// cutting a character in half. Modules call it on data from the target.
func TruncateDetail(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= MaxDetailValueBytes {
		return s
	}
	cut := MaxDetailValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Set collects assets during a run, merging duplicates: the same asset seen
// twice keeps one entry, with the details of both (later ones win). The
// zero value is ready to use. Not safe for concurrent use.
type Set struct {
	order []string
	byKey map[string]Asset
}

// Add records a.
func (s *Set) Add(a Asset) {
	if s.byKey == nil {
		s.byKey = make(map[string]Asset)
	}
	k := a.Key()
	prev, ok := s.byKey[k]
	if !ok {
		s.order = append(s.order, k)
		prev = Asset{Kind: a.Kind, Value: a.Value}
	}
	if len(a.Details) > 0 {
		merged := maps.Clone(prev.Details)
		if merged == nil {
			merged = make(map[string]string, len(a.Details))
		}
		maps.Copy(merged, a.Details)
		prev.Details = merged
	}
	s.byKey[k] = prev
}

// List returns the assets in the order they were first added.
func (s *Set) List() []Asset {
	out := make([]Asset, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.byKey[k])
	}
	return out
}
