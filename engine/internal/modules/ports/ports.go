// Package ports finds risky services exposed on a domain's servers: remote
// desktop, databases, file sharing, admin panels...
//
// It is an ACTIVE module: it opens TCP connections to the target's servers.
// It runs only on verified targets (security rule 1), and every connection
// goes through the gate it receives. For active modules that gate only lets
// connections through to IPs whose ownership is proven (ownership.IPGate),
// so this module cannot reach a hosting provider's or a CDN's servers.
//
// It is as little intrusive as possible: a TCP connection per port, then it
// reads what the service sends on its own (its banner) and closes. It never
// sends a request or a probe payload.
package ports

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "ports"

const (
	// maxIPs bounds how many addresses of the target are scanned.
	maxIPs = 4
	// concurrency is how many connection attempts may be in flight. The
	// gate's rate limiter still decides when each one starts; concurrency
	// only lets the timeouts of filtered ports overlap.
	concurrency = 10
	// defaultConnectTimeout bounds the TCP handshake only, not the wait for
	// the rate limiter (see connectTimeoutDialer).
	defaultConnectTimeout = 3 * time.Second
	// defaultBannerTimeout bounds how long we wait for a service to speak.
	defaultBannerTimeout = 2 * time.Second
	// maxBanner bounds what we read from the target (rule 7).
	maxBanner = 256
)

// ErrNoVerifiedIP means none of the target's addresses could be scanned,
// usually because none has verified ownership. The module then fails rather
// than report "no open port", which would be false.
var ErrNoVerifiedIP = errors.New("no address of the target could be scanned")

// Module is the ports check.
type Module struct {
	dns            resolver.Resolver
	dial           dialer.Dialer
	services       []service
	connectTimeout time.Duration
	bannerTimeout  time.Duration
}

// New returns the ports module. dns and dial are the underlying resolver and
// dialer; the module wraps both with the request's gate on every run.
func New(dns resolver.Resolver, dial dialer.Dialer) *Module {
	return &Module{
		dns:            dns,
		dial:           dial,
		services:       catalog,
		connectTimeout: defaultConnectTimeout,
		bannerTimeout:  defaultBannerTimeout,
	}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Exposed network services", Kind: module.KindActive}
}

// Run implements module.Module. It scans the addresses of the domain and of
// its www. subdomain. req.Config is ignored for now.
//
// Assets: each address actually scanned and its host name, and every open
// port of the catalog. Addresses the gate refused are not reported: we did
// not look at them.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("ports: %w", err)
	}
	dns := resolver.Gated{Gate: req.Gate, Inner: m.dns}
	dial := dialer.Gated{Gate: req.Gate, Inner: connectTimeoutDialer{m.dial, m.connectTimeout}}

	targets, err := m.addresses(ctx, dns, domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("ports: %w", err)
	}
	if len(targets) == 0 {
		return module.Result{}, nil // nothing resolves: no server to scan
	}

	var findings []finding.Finding
	var assets asset.Set
	scanned := 0
	for _, t := range targets {
		open, refused, err := m.scanIP(ctx, dial, t)
		if err != nil {
			return module.Result{}, fmt.Errorf("ports: %w", err)
		}
		if refused {
			continue // not ours to scan; the refusal is audited by the worker
		}
		scanned++
		assets.Add(asset.Hostname(t.host))
		assets.Add(asset.IP(t.ip))
		for _, o := range open {
			findings = append(findings, o.finding(domain, t))
			assets.Add(o.asset(t))
		}
	}
	if scanned == 0 {
		return module.Result{}, fmt.Errorf("ports: %w: none of %d addresses has verified ownership or all are excluded (see the audit log)",
			ErrNoVerifiedIP, len(targets))
	}
	return module.Result{Findings: findings, Assets: assets.List()}, nil
}

// asset describes the open port for the inventory. The banner is already
// sanitized and bounded by probe.
func (o openPort) asset(a address) asset.Asset {
	details := map[string]string{"expected": o.svc.name}
	if o.banner != "" {
		details["banner"] = asset.TruncateDetail(o.banner)
	}
	return asset.Service(a.ip, uint16(o.svc.port), details) //nolint:gosec // G115: catalog ports are constants in 1..65535
}

// address is one IP to scan and the host name it came from.
type address struct {
	host string
	ip   netip.Addr
}

// addresses resolves the domain and its www. subdomain, removes duplicates
// (both often point to the same server) and keeps at most maxIPs.
func (m *Module) addresses(ctx context.Context, dns resolver.Resolver, domain string) ([]address, error) {
	hosts := []string{domain}
	if !strings.HasPrefix(domain, "www.") {
		hosts = append(hosts, "www."+domain)
	}
	seen := make(map[netip.Addr]bool)
	var out []address
	for _, h := range hosts {
		ips, err := dns.LookupIP(ctx, h)
		if errors.Is(err, resolver.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !seen[ip] && len(out) < maxIPs {
				seen[ip] = true
				out = append(out, address{host: h, ip: ip})
			}
		}
	}
	return out, nil
}

// openPort is a port that accepted a connection.
type openPort struct {
	svc    service
	banner string
}

// errSkipped marks a destination the gate excluded.
var errSkipped = errors.New("skipped")

// scanIP tries every catalog port on one address. refused is true when the
// gate excluded every port, which happens when the IP itself is not
// verified or excluded.
func (m *Module) scanIP(ctx context.Context, dial dialer.Gated, a address) (open []openPort, refused bool, err error) {
	type result struct {
		svc    service
		open   bool
		banner string
		err    error
	}
	results := make(chan result, len(m.services))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, svc := range m.services {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{svc: svc, err: ctx.Err()}
				return
			}
			isOpen, banner, err := m.probe(ctx, dial, module.Destination{Host: a.host, IP: a.ip, Port: svc.port})
			results <- result{svc: svc, open: isOpen, banner: banner, err: err}
		})
	}
	wg.Wait()
	close(results)

	skipped := 0
	var firstErr error
	for r := range results {
		switch {
		case errors.Is(r.err, errSkipped):
			skipped++
		case r.err != nil:
			if firstErr == nil {
				firstErr = r.err
			}
		case r.open:
			open = append(open, openPort{svc: r.svc, banner: r.banner})
		}
	}
	if firstErr != nil {
		return nil, false, firstErr
	}
	sort.Slice(open, func(i, j int) bool { return open[i].svc.port < open[j].svc.port })
	return open, skipped == len(m.services), nil
}

// probe connects to one port and reads the banner, if any. A closed or
// filtered port is not an error: it returns open=false. Errors are reserved
// for "stop the scan" conditions (gate failure, cancellation).
func (m *Module) probe(ctx context.Context, dial dialer.Gated, dest module.Destination) (bool, string, error) {
	conn, err := dial.Dial(ctx, dest)
	if err != nil {
		switch {
		case errors.Is(err, module.ErrExcluded):
			return false, "", errSkipped
		case errors.Is(err, dialer.ErrGateRefused), errors.Is(err, dialer.ErrNoGate):
			return false, "", err
		case ctx.Err() != nil:
			return false, "", ctx.Err()
		}
		return false, "", nil // refused, filtered or unreachable: closed
	}
	defer func() { _ = conn.Close() }()

	// Many services (SSH, FTP, SMTP, MySQL...) greet first. We only listen;
	// silence is fine and simply means no banner.
	_ = conn.SetReadDeadline(time.Now().Add(m.bannerTimeout))
	buf := make([]byte, maxBanner)
	n, _ := conn.Read(buf)
	return true, sanitizeBanner(buf[:n]), nil
}

// sanitizeBanner keeps printable ASCII only. Banners come from the target
// and end up in reports and terminals: control characters (including
// terminal escape sequences) are replaced, never passed through (rule 7).
func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		case c == '\r' || c == '\n' || c == '\t':
			sb.WriteByte(' ')
		default:
			sb.WriteByte('.')
		}
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

// connectTimeoutDialer applies the connect timeout to the TCP handshake
// only. dialer.Gated waits for the rate limiter before calling it, so a
// port waiting its turn is never mistaken for a filtered one.
type connectTimeoutDialer struct {
	inner   dialer.Dialer
	timeout time.Duration
}

func (d connectTimeoutDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Once connected, the connection outlives this context (net.Dialer
	// semantics): only the handshake is bounded.
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.DialContext(ctx, network, address)
}

func (o openPort) finding(domain string, a address) finding.Finding {
	asset := netip.AddrPortFrom(a.ip, uint16(o.svc.port)) //nolint:gosec // G115: catalog ports are constants in 1..65535
	banner := o.banner
	if banner == "" {
		banner = "(none: the service waits for the client to speak first)"
	}
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, o.svc.family.checkID, domain, asset.String()),
		ModuleID:      ID,
		CheckID:       o.svc.family.checkID,
		Target:        domain,
		Asset:         asset.String(),
		Severity:      o.svc.sev(),
		Title:         fmt.Sprintf("%s reachable from the internet (port %d)", o.svc.name, o.svc.port),
		Description:   o.svc.family.why,
		Evidence: finding.TruncateEvidence(fmt.Sprintf("host: %s (%s)\nport: %d/tcp open\nexpected service: %s\nbanner: %s",
			a.host, a.ip, o.svc.port, o.svc.name, banner)),
		Remediation: o.svc.family.fix,
	}
}
