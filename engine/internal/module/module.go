// Package module defines the contract every security check implements, and
// the rules that decide whether a module may run against a target.
//
// Adding a check means adding a package that implements Module; the engine
// never changes.
package module

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// Kind says whether a module only reads public data or sends probes.
type Kind string

const (
	// KindPassive modules use public, read-only data: DNS, certificates,
	// ordinary HTTP responses. They may run on unverified targets.
	KindPassive Kind = "passive"
	// KindActive modules send probes (port scans, application tests). They
	// run only on targets whose ownership has been verified.
	KindActive Kind = "active"
)

// Valid reports whether k is one of the defined kinds.
func (k Kind) Valid() bool { return k == KindPassive || k == KindActive }

// Info describes a module. ID is stable: it is stored in every finding and
// used to compute finding IDs, so it must never change once shipped.
type Info struct {
	ID   string // lowercase slug, e.g. "email"
	Name string // human-readable, e.g. "Email security"
	Kind Kind
}

// Target is what a customer asked us to scan.
type Target struct {
	Domain string
	// Verified is true once ownership has been proven through the
	// _orus-verify.<domain> TXT record.
	Verified bool
}

// Destination is one network endpoint a module is about to contact.
//
// For connections, IP is the exact address that will be contacted: the name
// is resolved first, the gate approves that IP (so IP exclusions work), and
// the connection goes to that IP. The name cannot point somewhere else between
// the check and the connection (DNS rebinding).
type Destination struct {
	Host string
	IP   netip.Addr // zero for name-only requests (e.g. DNS lookups)
	Port int        // 0 when not relevant (e.g. a DNS lookup through the resolver)
	Path string     // empty when not an HTTP request
}

// Gate must be called before every network request a module makes.
//
// It enforces customer exclusions (security rule 2) and then waits on the
// shared rate limiter (rule 3). A non-nil error means the request must not be
// sent. Combining both in one call means a module cannot apply one rule and
// forget the other.
type Gate interface {
	Allow(ctx context.Context, dest Destination) error
}

// Request carries everything a module needs for one run. Modules read nothing
// else: no global state, no environment variables.
type Request struct {
	Target Target
	// Config is the module-specific configuration; each module decodes it.
	Config json.RawMessage
	Gate   Gate
}

// Result is what a module observed in one run.
type Result struct {
	// Findings are the problems found, in the standard schema.
	Findings []finding.Finding
	// Assets are what the module saw exist (names that resolve, addresses,
	// open services, certificates), problem or not. They feed the asset
	// inventory. A module reports only what it actually observed: an asset
	// it did not report in a successful run is considered gone, as far as
	// this module knows.
	Assets []asset.Asset
}

// Module is one independent security check.
type Module interface {
	Info() Info
	// Run checks the target and returns what it observed, or an error. It
	// must respect ctx cancellation and deadline, and must never print or
	// log findings itself.
	Run(ctx context.Context, req Request) (Result, error)
}

var (
	// ErrNotVerified is returned when an active module would run on a target
	// whose ownership has not been verified.
	ErrNotVerified = errors.New("active module requires a verified target")
	// ErrInvalidKind is returned for a module that declares an unknown kind.
	ErrInvalidKind = errors.New("unknown module kind")
	// ErrExcluded must be wrapped by Gate implementations when a destination
	// matches a customer exclusion. Modules skip that destination and carry
	// on; any other gate error (rate limiter cancelled...) stops the run.
	ErrExcluded = errors.New("destination excluded by customer")
)

// CheckAllowed enforces security rule 1: no active scan without verified
// ownership. The engine must call it before every Run.
//
// It fails closed: a module with an unknown kind is refused, because we
// cannot tell whether it is safe.
func CheckAllowed(info Info, t Target) error {
	switch info.Kind {
	case KindPassive:
		return nil
	case KindActive:
		if !t.Verified {
			return fmt.Errorf("module %q on %q: %w", info.ID, t.Domain, ErrNotVerified)
		}
		return nil
	default:
		return fmt.Errorf("module %q: kind %q: %w", info.ID, info.Kind, ErrInvalidKind)
	}
}

// NormalizeDomain lowercases d, removes a trailing dot, and rejects anything
// that is not a plausible DNS name. The domain is customer input that ends up
// in DNS queries and connections, so modules check it rather than trust it.
// It is dnsname.Normalize, kept here because every module already uses it.
func NormalizeDomain(d string) (string, error) { return dnsname.Normalize(d) }
