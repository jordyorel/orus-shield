// Package tlscheck checks the HTTPS endpoints of a domain: the certificate
// (expiry, hostname, trust, key strength) and the TLS versions accepted.
//
// It is passive: it performs ordinary TLS handshakes, like a browser opening
// the site, and sends no application data. The package is named tlscheck,
// not tls, to avoid clashing with crypto/tls; the module ID is "tls".
package tlscheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "tls"

// Check IDs. They are stable: reports use them to show localized text.
const (
	CheckHandshakeFailed      = "tls-handshake-failed"
	CheckLegacyVersion        = "tls-legacy-version"
	CheckCertExpired          = "tls-cert-expired"
	CheckCertExpiringSoon     = "tls-cert-expiring-soon"
	CheckCertNotYetValid      = "tls-cert-not-yet-valid"
	CheckCertHostnameMismatch = "tls-cert-hostname-mismatch"
	CheckCertUntrusted        = "tls-cert-untrusted"
	CheckCertWeakKey          = "tls-cert-weak-key"
)

const (
	httpsPort = 443
	// handshakeTimeout bounds one connection, from dial to end of handshake.
	handshakeTimeout = 10 * time.Second
)

// Module is the TLS check.
type Module struct {
	dns  resolver.Resolver
	dial dialer.Dialer
	// roots are the trusted CAs. nil means the system roots; tests set a
	// private test CA.
	roots *x509.CertPool
}

// New returns the TLS module. dns and dial are the underlying resolver and
// dialer (resolver.NewSystem(), dialer.NewSystem()); the module wraps both
// with the request's Gate on every run.
func New(dns resolver.Resolver, dial dialer.Dialer) *Module {
	return &Module{dns: dns, dial: dial}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "TLS and certificates", Kind: module.KindPassive, Checks: Checks}
}

// Checks is the module's catalog.
var Checks = []module.Check{
	{ID: CheckHandshakeFailed, Category: module.CategoryTLS, Severity: finding.SeverityMedium, Title: "HTTPS connections succeed"},
	{ID: CheckLegacyVersion, Category: module.CategoryTLS, Severity: finding.SeverityMedium, Title: "TLS 1.0 and 1.1 are refused"},
	{ID: CheckCertExpired, Category: module.CategoryTLS, Severity: finding.SeverityCritical, Title: "Certificate has not expired"},
	{ID: CheckCertExpiringSoon, Category: module.CategoryTLS, Severity: finding.SeverityMedium, Title: "Certificate is not about to expire"},
	{ID: CheckCertNotYetValid, Category: module.CategoryTLS, Severity: finding.SeverityHigh, Title: "Certificate is already valid"},
	{ID: CheckCertHostnameMismatch, Category: module.CategoryTLS, Severity: finding.SeverityHigh, Title: "Certificate matches the site name"},
	{ID: CheckCertUntrusted, Category: module.CategoryTLS, Severity: finding.SeverityHigh, Title: "Certificate is trusted by browsers"},
	{ID: CheckCertWeakKey, Category: module.CategoryTLS, Severity: finding.SeverityMedium, Title: "Certificate key is strong enough"},
}

// certChecks are evaluated on every completed handshake.
var certChecks = []string{
	CheckHandshakeFailed, CheckCertExpired, CheckCertExpiringSoon, CheckCertNotYetValid,
	CheckCertHostnameMismatch, CheckCertUntrusted, CheckCertWeakKey,
}

// Run implements module.Module. It checks the scan's names (the domain, www.
// and known subdomains: module.Target.ScanHosts) on port 443. req.Config is ignored for now.
//
// A host that does not resolve, or does not accept connections, produces no
// finding: we only report what we could observe. DNS failures other than
// "not found", gate failures and cancellation stop the run.
//
// Assets: each name that resolved, the addresses tested, port 443 on each
// address that accepted a connection, and each certificate served.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("tls: %w", err)
	}
	p := prober{
		dns:       resolver.Gated{Gate: req.Gate, Inner: m.dns},
		dial:      dialer.Gated{Gate: req.Gate, Inner: m.dial},
		roots:     m.roots,
		assets:    &asset.Set{},
		evaluated: &[]string{},
	}

	hosts := req.Target.ScanHosts(domain)

	var findings []finding.Finding
	for _, host := range hosts {
		issues, err := p.checkHost(ctx, host)
		if err != nil {
			return module.Result{}, fmt.Errorf("tls: %w", err)
		}
		for _, i := range issues {
			findings = append(findings, i.finding(domain))
		}
	}
	return module.Result{Findings: findings, Assets: p.assets.List(), Evaluated: *p.evaluated}, nil
}

// prober holds the gated network tools for one run, and collects the
// assets observed. Hosts and addresses are checked one at a time, so the set
// needs no lock.
type prober struct {
	dns    resolver.Gated
	dial   dialer.Gated
	roots  *x509.CertPool
	assets *asset.Set
	// evaluated lists the checks performed: certificate checks need a
	// completed handshake, so a domain with no HTTPS server has them all
	// not applicable rather than passed.
	evaluated *[]string
}

func (p prober) evaluate(ids ...string) { *p.evaluated = append(*p.evaluated, ids...) }

// maxIPsPerHost bounds how many addresses of one host we test. Each address
// costs two handshakes; 4 covers typical load balancers and CDN answers.
const maxIPsPerHost = 4

// checkHost tests every selected address of host and merges the results, so
// a problem on a single server (a node forgotten during renewal, an IPv6
// address pointing to an old vhost) is still reported.
func (p prober) checkHost(ctx context.Context, host string) ([]issue, error) {
	addrs, err := p.dns.LookupIP(ctx, host)
	if errors.Is(err, resolver.ErrNotFound) {
		return nil, nil
	}
	// Check err before using addrs: on error addrs is empty, and treating a
	// DNS timeout as "host does not exist" would hide the failure.
	if err != nil {
		return nil, err
	}
	ips := selectIPs(addrs, maxIPsPerHost)
	if len(ips) > 0 {
		p.assets.Add(asset.Hostname(host))
	}
	findingAsset := net.JoinHostPort(host, fmt.Sprint(httpsPort))

	var all []issue
	for _, ip := range ips {
		p.assets.Add(asset.IP(ip))
		issues, err := p.checkIP(ctx, module.Destination{Host: host, IP: ip, Port: httpsPort}, findingAsset)
		if err != nil {
			return nil, err
		}
		all = append(all, issues...)
	}
	return mergeIssues(all, ips), nil
}

// checkIP runs both probes against one address.
func (p prober) checkIP(ctx context.Context, dest module.Destination, findingAsset string) ([]issue, error) {
	issues, err := p.probe(ctx, dest, findingAsset)
	for i := range issues {
		issues[i].ip = dest.IP
	}
	return issues, err
}

func (p prober) probe(ctx context.Context, dest module.Destination, findingAsset string) ([]issue, error) {
	// 1. Normal handshake, offering every version up to TLS 1.3, to read the
	// certificate the way a browser would.
	state, err := p.handshake(ctx, dest, probeConfig(dest.Host, 0))
	if err != nil {
		if stop := stopError(ctx, err); stop != nil {
			return nil, stop
		}
		if isTLSFailure(err) {
			// The port is open, even though TLS failed.
			p.evaluate(CheckHandshakeFailed)
			p.assets.Add(asset.Service(dest.IP, httpsPort, map[string]string{"expected": "https"}))
			return []issue{handshakeFailed(findingAsset, dest, err)}, nil
		}
		return nil, nil // excluded, closed or silent: nothing to assert
	}
	p.observe(dest, state)
	p.evaluate(certChecks...)
	issues := certIssues(findingAsset, dest, state, p.roots, time.Now())

	// 2. Legacy handshake, offering only TLS 1.0 and 1.1. If the server
	// accepts it, it still supports deprecated versions.
	legacy, err := p.handshake(ctx, dest, probeConfig(dest.Host, tls.VersionTLS11))
	if err != nil {
		if stop := stopError(ctx, err); stop != nil {
			return nil, stop
		}
		if errors.Is(err, errHandshake) {
			p.evaluate(CheckLegacyVersion) // the server answered and refused: good
		}
		return issues, nil
	}
	p.evaluate(CheckLegacyVersion)
	return append(issues, legacyVersion(findingAsset, dest, legacy)), nil
}

// observe records the service and the certificate of a completed handshake.
func (p prober) observe(dest module.Destination, state tls.ConnectionState) {
	p.assets.Add(asset.Service(dest.IP, httpsPort, map[string]string{
		"expected": "https", "tls_version": tls.VersionName(state.Version),
	}))
	if len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	p.assets.Add(asset.Certificate(sha256.Sum256(leaf.Raw), map[string]string{
		// Certificate fields are chosen by whoever controls the server:
		// untrusted, so bounded (rule 7).
		"subject":   asset.TruncateDetail(leaf.Subject.CommonName),
		"issuer":    asset.TruncateDetail(leaf.Issuer.CommonName),
		"not_after": leaf.NotAfter.UTC().Format(time.RFC3339),
		"names":     asset.TruncateDetail(strings.Join(leaf.DNSNames, " ")),
	}))
}

// errHandshake marks errors that happened after the TCP connection was open.
var errHandshake = errors.New("tls handshake")

func (p prober) handshake(ctx context.Context, dest module.Destination, cfg *tls.Config) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := p.dial.Dial(ctx, dest)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }() // read-only probe: a close error changes nothing
	tconn := tls.Client(conn, cfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, fmt.Errorf("%w with %s: %w", errHandshake, dest.Host, err)
	}
	return tconn.ConnectionState(), nil
}

// probeConfig returns the client configuration for one probe. maxVersion 0
// means the highest version Go supports.
func probeConfig(host string, maxVersion uint16) *tls.Config {
	return &tls.Config{
		ServerName: host,
		// Certificate verification is skipped during the handshake on
		// purpose: we want to complete it with broken certificates so we can
		// describe what is wrong. certIssues verifies the chain afterwards.
		// No application data is ever sent on these connections.
		InsecureSkipVerify: true, //nolint:gosec // G402: deliberate, see comment above
		// Accept old versions and every cipher suite Go knows, so legacy
		// servers still complete the handshake and can be reported.
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   maxVersion,
		CipherSuites: allCipherSuites(),
	}
}

func allCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// stopError returns the error that must stop the whole run, or nil if the
// failure only concerns this host. Exclusions are expected and skip the
// host; any other gate refusal, or cancellation, stops the run.
func stopError(ctx context.Context, err error) error {
	if errors.Is(err, module.ErrExcluded) {
		return nil
	}
	if errors.Is(err, dialer.ErrGateRefused) || errors.Is(err, dialer.ErrNoGate) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return nil
}

// isTLSFailure reports whether err means "the server answered, but no valid
// TLS session could be set up" (alert, not TLS at all, no common version).
// Timeouts, resets and closed connections are not counted: they may be
// transient, and we never report what we did not observe.
func isTLSFailure(err error) bool {
	if !errors.Is(err, errHandshake) {
		return false // the TCP connection itself failed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return !errors.Is(err, io.EOF) &&
		!errors.Is(err, io.ErrUnexpectedEOF) &&
		!errors.Is(err, syscall.ECONNRESET) &&
		!errors.Is(err, context.DeadlineExceeded)
}

// issue is what a check detects; see the email module for the same pattern.
type issue struct {
	checkID     string
	asset       string
	severity    finding.Severity
	title       string
	description string
	evidence    string
	remediation []string
	references  []string
	ip          netip.Addr // address where it was observed; not part of the finding
}

func (i issue) finding(target string) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, i.checkID, target, i.asset),
		ModuleID:      ID,
		CheckID:       i.checkID,
		Target:        target,
		Asset:         i.asset,
		Severity:      i.severity,
		Title:         i.title,
		Description:   i.description,
		Evidence:      finding.TruncateEvidence(i.evidence),
		Remediation:   i.remediation,
		References:    i.references,
	}
}
