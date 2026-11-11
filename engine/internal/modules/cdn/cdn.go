// Package cdn tells whether a domain's sites are served through a CDN or a
// web application firewall, for the dashboard's "Protections" column.
//
// It is passive: it resolves the domain and sends one ordinary HEAD request
// per site, like a browser checking a page, then reads the response headers.
// Two kinds of evidence, both facts:
//   - the address is in a CDN's published ranges (ranges.go);
//   - the response carries a header the CDN or WAF always adds (headers.go).
//
// It produces no findings: not using a CDN is not a vulnerability. It
// reports assets with a "cdn" detail (and "waf" when certain), which the
// risk function will use as a protection factor.
package cdn

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID.
const ID = "cdn"

// Detail keys set on assets. "none" means we looked and found no CDN: it
// is written explicitly so that a CDN removed later does not stay listed
// (asset details are merged across scans).
const (
	DetailCDN         = "cdn"
	DetailCDNEvidence = "cdn_evidence"
	DetailWAF         = "waf"
	None              = "none"
)

const (
	httpsPort = 443
	// maxIPsPerHost bounds the addresses checked per name.
	maxIPsPerHost = 4
	// requestTimeout bounds one request, from dial to the end of headers.
	requestTimeout = 10 * time.Second
	// maxHeaderBytes bounds what we read from the target (rule 7): headers
	// only, never the body.
	maxHeaderBytes = 32 << 10
	userAgent      = "OrusShield/1 (+security check of a site you registered)"
)

// Module is the CDN check.
type Module struct {
	dns  resolver.Resolver
	dial dialer.Dialer
}

// New returns the module. dns and dial are the underlying resolver and
// dialer; the module wraps both with the request's gate on every run.
func New(dns resolver.Resolver, dial dialer.Dialer) *Module {
	return &Module{dns: dns, dial: dial}
}

// Info implements module.Module. The module has no checks: it only
// describes the inventory.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "CDN and web protection", Kind: module.KindPassive}
}

// Run implements module.Module. It looks at the scan's names (the domain,
// www. and known subdomains: module.Target.ScanHosts). Names that do not resolve are skipped; DNS failures other than
// "not found", gate failures and cancellation stop the run.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("cdn: %w", err)
	}
	dns := resolver.Gated{Gate: req.Gate, Inner: m.dns}
	dial := dialer.Gated{Gate: req.Gate, Inner: m.dial}

	hosts := req.Target.ScanHosts(domain)
	var assets asset.Set
	for _, host := range hosts {
		addrs, err := dns.LookupIP(ctx, host)
		if errors.Is(err, resolver.ErrNotFound) {
			continue
		}
		if err != nil {
			return module.Result{}, fmt.Errorf("cdn: %w", err)
		}
		ips := unique(addrs, maxIPsPerHost)
		for _, ip := range ips {
			assets.Add(ipAsset(ip))
		}
		h, err := probeHost(ctx, dial, host, ips)
		if err != nil {
			return module.Result{}, fmt.Errorf("cdn: %w", err)
		}
		if h != nil {
			assets.Add(hostAsset(host, *h))
		}
	}
	return module.Result{Assets: assets.List()}, nil
}

// ipAsset says whether the address is in a CDN's published ranges.
func ipAsset(ip netip.Addr) asset.Asset {
	a := asset.IP(ip)
	provider, prefix, ok := providerOf(ip)
	if !ok {
		a.Details = map[string]string{DetailCDN: None}
		return a
	}
	a.Details = map[string]string{DetailCDN: provider, DetailCDNEvidence: "published range " + prefix.String()}
	return a
}

// hostAsset describes what the site's response headers reveal. It is only
// reported when a server answered: no answer tells nothing.
func hostAsset(host string, h http.Header) asset.Asset {
	a := asset.Hostname(host)
	sig, evidence, ok := detect(h)
	if !ok {
		a.Details = map[string]string{DetailCDN: None, DetailWAF: None}
		return a
	}
	a.Details = map[string]string{DetailCDN: sig.provider, DetailCDNEvidence: evidence, DetailWAF: None}
	if sig.waf {
		a.Details[DetailWAF] = sig.provider
	}
	return a
}

// probeHost sends one HEAD request to the first address that answers and
// returns its headers, or nil if none answered.
func probeHost(ctx context.Context, dial dialer.Gated, host string, ips []netip.Addr) (*http.Header, error) {
	for _, ip := range ips {
		h, err := head(ctx, dial, module.Destination{Host: host, IP: ip, Port: httpsPort, Path: "/"})
		switch {
		case err == nil:
			return &h, nil
		case errors.Is(err, module.ErrExcluded):
			continue // customer exclusion: skip this address
		case errors.Is(err, dialer.ErrGateRefused), errors.Is(err, dialer.ErrNoGate):
			return nil, err
		case ctx.Err() != nil:
			return nil, ctx.Err()
		}
		// Closed, timed out, not HTTP: try the next address.
	}
	return nil, nil
}

// head sends "HEAD /" over TLS and reads the response headers.
//
// The request is written by hand on a connection from the gated dialer,
// rather than with http.Client: the connection must go to the exact IP the
// gate approved, and nothing (redirects, keep-alive, proxies from the
// environment) may send a second request behind the gate's back.
func head(ctx context.Context, dial dialer.Gated, dest module.Destination) (http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	conn, err := dial.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tconn := tls.Client(conn, &tls.Config{
		ServerName: dest.Host,
		// Certificate problems are the tls module's job; here we only read
		// headers, and send nothing but a HEAD request.
		InsecureSkipVerify: true, //nolint:gosec // G402: deliberate, see comment above
		MinVersion:         tls.VersionTLS12,
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with %s: %w", dest.Host, err)
	}
	req := "HEAD / HTTP/1.1\r\nHost: " + dest.Host + "\r\nUser-Agent: " + userAgent +
		"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tconn, req); err != nil {
		return nil, fmt.Errorf("send request to %s: %w", dest.Host, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tconn, maxHeaderBytes)), &http.Request{Method: http.MethodHead})
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", dest.Host, err)
	}
	_ = resp.Body.Close() // HEAD: no body is read
	return resp.Header, nil
}

// unique removes duplicates (IPv4-mapped addresses count as IPv4) and keeps
// at most max addresses.
func unique(addrs []netip.Addr, max int) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || seen[a] || len(out) == max {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}
