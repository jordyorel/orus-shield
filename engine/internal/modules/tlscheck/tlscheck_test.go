package tlscheck

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ---- Certificates -------------------------------------------------------

// testCA is a private certificate authority. Its pool replaces the system
// roots in the module, so certificates it signs count as trusted.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key := ecKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Orus Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, pool: pool}
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

type leafOpts struct {
	names      []string
	notBefore  time.Time
	notAfter   time.Time
	key        crypto.Signer // ECDSA P-256 when nil
	selfSigned bool
}

// leaf issues a server certificate. Zero fields get sensible defaults: valid
// for example.com and www.example.com, from an hour ago for 90 days.
func (ca testCA) leaf(t *testing.T, o leafOpts) tls.Certificate {
	t.Helper()
	if o.names == nil {
		o.names = []string{"example.com", "www.example.com"}
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if o.key == nil {
		o.key = ecKey(t)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: o.names[0]},
		DNSNames:     o.names,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := ca.cert, crypto.Signer(ca.key)
	if o.selfSigned {
		parent, signer = tmpl, o.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, o.key.Public(), signer)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: o.key}
}

// ---- Local servers ------------------------------------------------------

// serveTLS starts a TLS server on 127.0.0.1 and returns its address.
func serveTLS(t *testing.T, cert tls.Certificate, minVersion uint16) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minVersion}
	return serve(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.Handshake() // failures are what some tests expect
		_ = tc.Close()
	})
}

// servePlain starts a server that answers like plain HTTP, not TLS.
func servePlain(t *testing.T) string {
	t.Helper()
	return serve(t, func(c net.Conn) {
		buf := make([]byte, 1024)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_ = c.Close()
	})
}

func serve(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			wg.Add(1)
			go func() {
				defer wg.Done()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// ---- Fakes ----------------------------------------------------------------

// fakeDNS answers LookupIP from a map; unknown names are NXDOMAIN.
type fakeDNS struct {
	ips  map[string][]netip.Addr
	fail map[string]error
}

func (f *fakeDNS) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := f.fail[host]; err != nil {
		return nil, err
	}
	addrs, ok := f.ips[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
	}
	return addrs, nil
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
}

func (f *fakeDNS) LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error) {
	return nil, fmt.Errorf("lookup %s: %w", ip, resolver.ErrNotFound)
}

func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
}

// fakeDialer routes the addresses the module asks for (documentation IPs
// such as 192.0.2.10:443) to local test servers. Unrouted addresses are
// refused, like a closed port.
type fakeDialer struct {
	mu     sync.Mutex
	routes map[string]string
	dialed []string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, address)
	target, ok := f.routes[address]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// recordingGate records destinations and refuses some IPs.
type recordingGate struct {
	mu   sync.Mutex
	seen []module.Destination
	deny map[netip.Addr]error
	all  error // refuse everything with this error
}

func (g *recordingGate) Allow(ctx context.Context, dest module.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, dest)
	if g.all != nil {
		return g.all
	}
	return g.deny[dest.IP]
}

// ---- Test environment -----------------------------------------------------

var (
	apexIP = netip.MustParseAddr("192.0.2.10")
	wwwIP  = netip.MustParseAddr("192.0.2.11")
)

type env struct {
	ca   testCA
	dns  *fakeDNS
	dial *fakeDialer
	gate *recordingGate
}

// newEnv returns example.com resolving to apexIP, with no server yet.
// www.example.com does not resolve unless a test adds it.
func newEnv(t *testing.T) *env {
	return &env{
		ca:   newCA(t),
		dns:  &fakeDNS{ips: map[string][]netip.Addr{"example.com": {apexIP}}},
		dial: &fakeDialer{routes: map[string]string{}},
		gate: &recordingGate{},
	}
}

func (e *env) route(ip netip.Addr, serverAddr string) {
	e.dial.routes[netip.AddrPortFrom(ip, 443).String()] = serverAddr
}

func (e *env) run(ctx context.Context, domain string) ([]finding.Finding, error) {
	res, err := e.runAll(ctx, domain)
	return res.Findings, err
}

// runAll returns findings and assets.
func (e *env) runAll(ctx context.Context, domain string) (module.Result, error) {
	m := New(e.dns, e.dial)
	m.roots = e.ca.pool
	return m.Run(ctx, module.Request{
		Target: module.Target{Domain: domain},
		Gate:   e.gate,
	})
}

func checkIDs(findings []finding.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.CheckID)
	}
	slices.Sort(ids)
	return ids
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// ---- Tests ----------------------------------------------------------------

func TestInfo(t *testing.T) {
	info := New(&fakeDNS{}, &fakeDialer{}).Info()
	if info.ID != ID || info.Kind != module.KindPassive {
		t.Errorf("Info() = %+v, want ID %q and passive kind", info, ID)
	}
	if err := module.NewRegistry().Register(New(&fakeDNS{}, &fakeDialer{})); err != nil {
		t.Errorf("Register() = %v", err)
	}
}

func TestRunScenarios(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the weak key is what the test checks
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	now := time.Now()

	tests := []struct {
		name  string
		setup func(t *testing.T, e *env)
		want  []string
	}{
		{"valid certificate", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
		}, nil},
		{"expired", func(t *testing.T, e *env) {
			cert := e.ca.leaf(t, leafOpts{notBefore: now.Add(-days(100)), notAfter: now.Add(-days(1))})
			e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
		}, []string{CheckCertExpired}},
		{"expires in 3 days", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{notAfter: now.Add(days(3))}), tls.VersionTLS12))
		}, []string{CheckCertExpiringSoon}},
		{"expires in 60 days", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{notAfter: now.Add(days(60))}), tls.VersionTLS12))
		}, nil},
		{"not yet valid", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{notBefore: now.Add(days(1))}), tls.VersionTLS12))
		}, []string{CheckCertNotYetValid}},
		{"wrong hostname", func(t *testing.T, e *env) {
			cert := e.ca.leaf(t, leafOpts{names: []string{"other.example.net"}})
			e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
		}, []string{CheckCertHostnameMismatch}},
		{"self-signed", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{selfSigned: true}), tls.VersionTLS12))
		}, []string{CheckCertUntrusted}},
		{"rsa 1024 key", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{key: rsa1024}), tls.VersionTLS12))
		}, []string{CheckCertWeakKey}},
		{"accepts TLS 1.0", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS10))
		}, []string{CheckLegacyVersion}},
		{"not TLS on port 443", func(t *testing.T, e *env) {
			e.route(apexIP, servePlain(t))
		}, []string{CheckHandshakeFailed}},
		{"port 443 closed", func(t *testing.T, e *env) {}, nil},
		{"domain does not resolve", func(t *testing.T, e *env) {
			delete(e.dns.ips, "example.com")
		}, nil},
		{"IP excluded by customer", func(t *testing.T, e *env) {
			cert := e.ca.leaf(t, leafOpts{selfSigned: true})
			e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
			e.gate.deny = map[netip.Addr]error{apexIP: fmt.Errorf("rule 12: %w", module.ErrExcluded)}
		}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(t, e)
			findings, err := e.run(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := checkIDs(findings); !slices.Equal(got, tt.want) {
				t.Errorf("check IDs = %v, want %v", got, tt.want)
				for _, f := range findings {
					t.Logf("%s: %s", f.CheckID, f.Evidence)
				}
			}
		})
	}
}

func TestExpirySeverity(t *testing.T) {
	tests := []struct {
		left time.Duration
		want finding.Severity
	}{
		{days(3), finding.SeverityHigh},
		{days(20), finding.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.left.String(), func(t *testing.T) {
			e := newEnv(t)
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{notAfter: time.Now().Add(tt.left)}), tls.VersionTLS12))
			findings, err := e.run(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if len(findings) != 1 || findings[0].Severity != tt.want {
				t.Fatalf("findings = %v, want one %s finding", checkIDs(findings), tt.want)
			}
		})
	}
}

func TestExpiredIsCriticalWithEvidence(t *testing.T) {
	e := newEnv(t)
	cert := e.ca.leaf(t, leafOpts{notBefore: time.Now().Add(-days(100)), notAfter: time.Now().Add(-days(1))})
	e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", checkIDs(findings))
	}
	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if f.Asset != "example.com:443" {
		t.Errorf("asset = %q, want example.com:443", f.Asset)
	}
	for _, want := range []string{"192.0.2.10", "valid until", "sha256"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence does not mention %q:\n%s", want, f.Evidence)
		}
	}
}

func TestChecksWWWAsSeparateAsset(t *testing.T) {
	e := newEnv(t)
	e.dns.ips["www.example.com"] = []netip.Addr{wwwIP}
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	e.route(wwwIP, serveTLS(t, e.ca.leaf(t, leafOpts{selfSigned: true}), tls.VersionTLS12))

	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Asset != "www.example.com:443" || findings[0].CheckID != CheckCertUntrusted {
		t.Fatalf("findings = %+v, want one untrusted finding on www.example.com:443", findings)
	}
	if findings[0].Target != "example.com" {
		t.Errorf("target = %q, want example.com", findings[0].Target)
	}
}

func TestWWWTargetIsNotDoubled(t *testing.T) {
	e := newEnv(t)
	e.dns.ips["www.example.com"] = []netip.Addr{wwwIP}
	e.route(wwwIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	if _, err := e.run(context.Background(), "www.example.com"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, addr := range e.dial.dialed {
		if !strings.HasPrefix(addr, wwwIP.String()) {
			t.Errorf("dialed %s; for target www.example.com only %s should be contacted", addr, wwwIP)
		}
	}
}

func TestPrefersIPv4(t *testing.T) {
	e := newEnv(t)
	e.dns.ips["example.com"] = []netip.Addr{netip.MustParseAddr("2001:db8::10"), apexIP}
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	if _, err := e.run(context.Background(), "example.com"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(e.dial.dialed) == 0 || e.dial.dialed[0] != "192.0.2.10:443" {
		t.Errorf("dialed %v, want 192.0.2.10:443 first", e.dial.dialed)
	}
}

// Every connection must be approved by the gate with the exact IP and port.
func TestEveryConnectionGoesThroughGate(t *testing.T) {
	e := newEnv(t)
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS10))
	if _, err := e.run(context.Background(), "example.com"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var conns []module.Destination
	for _, d := range e.gate.seen {
		if d.IP.IsValid() {
			conns = append(conns, d)
		}
	}
	if len(conns) != len(e.dial.dialed) || len(conns) == 0 {
		t.Fatalf("gate approved %d connections, dialer opened %d", len(conns), len(e.dial.dialed))
	}
	for _, d := range conns {
		if d.IP != apexIP || d.Port != 443 || d.Host != "example.com" {
			t.Errorf("gate saw %+v, want example.com at %s:443", d, apexIP)
		}
	}
}

func TestRunErrors(t *testing.T) {
	errLimiter := errors.New("rate limiter stopped")
	timeout := &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name    string
		ctx     context.Context
		setup   func(e *env)
		wantErr error
	}{
		{"gate failure", context.Background(), func(e *env) { e.gate.all = errLimiter }, errLimiter},
		{"dns timeout", context.Background(), func(e *env) {
			e.dns.fail = map[string]error{"example.com": timeout}
		}, timeout},
		{"cancelled context", cancelled, func(e *env) {}, context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
			tt.setup(e)
			findings, err := e.run(tt.ctx, "example.com")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Run() error = %v, want %v", err, tt.wantErr)
			}
			if findings != nil {
				t.Errorf("Run() returned findings %v with an error", checkIDs(findings))
			}
		})
	}
}

func TestFindingsAreValid(t *testing.T) {
	e := newEnv(t)
	cert := e.ca.leaf(t, leafOpts{
		names:      []string{"other.example.net"},
		notBefore:  time.Now().Add(-days(100)),
		notAfter:   time.Now().Add(-days(1)),
		selfSigned: true,
	})
	e.route(apexIP, serveTLS(t, cert, tls.VersionTLS10))
	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("findings = %v, want several", checkIDs(findings))
	}
	now := time.Now()
	for _, f := range findings {
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", f.CheckID, err)
		}
	}
}

func TestSelectIPs(t *testing.T) {
	a := netip.MustParseAddr
	tests := []struct {
		name string
		in   []netip.Addr
		max  int
		want []netip.Addr
	}{
		{"empty", nil, 4, nil},
		{"one", []netip.Addr{a("192.0.2.1")}, 4, []netip.Addr{a("192.0.2.1")}},
		{"ipv4 first, then alternate",
			[]netip.Addr{a("2001:db8::1"), a("2001:db8::2"), a("192.0.2.1"), a("192.0.2.2")}, 4,
			[]netip.Addr{a("192.0.2.1"), a("2001:db8::1"), a("192.0.2.2"), a("2001:db8::2")}},
		{"cap keeps both families",
			[]netip.Addr{a("192.0.2.1"), a("192.0.2.2"), a("192.0.2.3"), a("192.0.2.4"), a("2001:db8::1")}, 4,
			[]netip.Addr{a("192.0.2.1"), a("2001:db8::1"), a("192.0.2.2"), a("192.0.2.3")}},
		{"duplicates and mapped addresses",
			[]netip.Addr{a("192.0.2.1"), a("::ffff:192.0.2.1"), a("192.0.2.1")}, 4,
			[]netip.Addr{a("192.0.2.1")}},
		{"only ipv6", []netip.Addr{a("2001:db8::1"), a("2001:db8::2")}, 4,
			[]netip.Addr{a("2001:db8::1"), a("2001:db8::2")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectIPs(tt.in, tt.max); !slices.Equal(got, tt.want) {
				t.Errorf("selectIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// One node of two still serves an expired certificate: the typical
// "forgotten server" after a renewal.
func TestOneServerOfTwoIsExpired(t *testing.T) {
	e := newEnv(t)
	second := netip.MustParseAddr("192.0.2.20")
	e.dns.ips["example.com"] = []netip.Addr{apexIP, second}
	expired := e.ca.leaf(t, leafOpts{notBefore: time.Now().Add(-days(100)), notAfter: time.Now().Add(-days(1))})
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	e.route(second, serveTLS(t, expired, tls.VersionTLS12))

	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].CheckID != CheckCertExpired {
		t.Fatalf("findings = %v, want one expired finding", checkIDs(findings))
	}
	f := findings[0]
	if f.Asset != "example.com:443" {
		t.Errorf("asset = %q, want example.com:443 (stable across IPs)", f.Asset)
	}
	if !strings.Contains(f.Evidence, "affected: 1 of 2 addresses tested (192.0.2.20)") {
		t.Errorf("evidence does not name the affected server:\n%s", f.Evidence)
	}
	if !strings.Contains(f.Description, "Only 1 of the 2 servers") {
		t.Errorf("description does not say the problem is partial: %q", f.Description)
	}
}

// IPv6 points to a different server with a self-signed certificate.
func TestIPv6Divergence(t *testing.T) {
	e := newEnv(t)
	v6 := netip.MustParseAddr("2001:db8::10")
	e.dns.ips["example.com"] = []netip.Addr{apexIP, v6}
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	e.route(v6, serveTLS(t, e.ca.leaf(t, leafOpts{selfSigned: true}), tls.VersionTLS12))

	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].CheckID != CheckCertUntrusted {
		t.Fatalf("findings = %v, want one untrusted finding", checkIDs(findings))
	}
	if !strings.Contains(findings[0].Evidence, "(2001:db8::10)") {
		t.Errorf("evidence does not name the IPv6 address:\n%s", findings[0].Evidence)
	}
}

// The same problem on every server is one finding, not one per server.
func TestSameProblemEverywhereIsOneFinding(t *testing.T) {
	e := newEnv(t)
	second := netip.MustParseAddr("192.0.2.20")
	e.dns.ips["example.com"] = []netip.Addr{apexIP, second}
	cert := e.ca.leaf(t, leafOpts{selfSigned: true})
	e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
	e.route(second, serveTLS(t, cert, tls.VersionTLS12))

	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want exactly one", checkIDs(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Evidence, "affected: 2 of 2") {
		t.Errorf("evidence = %q, want 2 of 2 affected", f.Evidence)
	}
	if strings.Contains(f.Description, "Only") {
		t.Errorf("description says partial although every server is affected: %q", f.Description)
	}
}

// The merged finding keeps the most severe occurrence.
func TestMergeKeepsWorstSeverity(t *testing.T) {
	e := newEnv(t)
	second := netip.MustParseAddr("192.0.2.20")
	e.dns.ips["example.com"] = []netip.Addr{apexIP, second}
	e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{notAfter: time.Now().Add(days(20))}), tls.VersionTLS12))
	e.route(second, serveTLS(t, e.ca.leaf(t, leafOpts{notAfter: time.Now().Add(days(3))}), tls.VersionTLS12))

	findings, err := e.run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != finding.SeverityHigh {
		t.Fatalf("findings = %+v, want one high-severity expiry finding", findings)
	}
}

func TestIPCapIsRespected(t *testing.T) {
	e := newEnv(t)
	var addrs []netip.Addr
	for i := 1; i <= 6; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		addrs = append(addrs, ip)
		e.route(ip, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
	}
	e.dns.ips["example.com"] = addrs
	if _, err := e.run(context.Background(), "example.com"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	distinct := make(map[string]bool)
	for _, d := range e.dial.dialed {
		distinct[d] = true
	}
	if len(distinct) != maxIPsPerHost {
		t.Errorf("connected to %d addresses %v, want %d", len(distinct), e.dial.dialed, maxIPsPerHost)
	}
}

func assetKeys(assets []asset.Asset) []string {
	keys := make([]string, 0, len(assets))
	for _, a := range assets {
		keys = append(keys, a.Key())
	}
	slices.Sort(keys)
	return keys
}

func TestAssets(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, e *env)
		want  []string // asset keys; certificates as "certificate *"
	}{
		{"valid certificate", func(t *testing.T, e *env) {
			e.route(apexIP, serveTLS(t, e.ca.leaf(t, leafOpts{}), tls.VersionTLS12))
		}, []string{"certificate *", "hostname example.com", "ip 192.0.2.10", "service 192.0.2.10:443/tcp"}},
		{"not TLS on port 443: the port is still open", func(t *testing.T, e *env) {
			e.route(apexIP, servePlain(t))
		}, []string{"hostname example.com", "ip 192.0.2.10", "service 192.0.2.10:443/tcp"}},
		{"port 443 closed: name and address only", func(t *testing.T, e *env) {},
			[]string{"hostname example.com", "ip 192.0.2.10"}},
		{"domain does not resolve: nothing", func(t *testing.T, e *env) {
			delete(e.dns.ips, "example.com")
		}, []string{}},
		{"www on its own address", func(t *testing.T, e *env) {
			e.dns.ips["www.example.com"] = []netip.Addr{wwwIP}
			e.route(wwwIP, servePlain(t))
		}, []string{"hostname example.com", "hostname www.example.com", "ip 192.0.2.10", "ip 192.0.2.11", "service 192.0.2.11:443/tcp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(t, e)
			res, err := e.runAll(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := assetKeys(res.Assets)
			for i, k := range got {
				if strings.HasPrefix(k, "certificate ") {
					got[i] = "certificate *"
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("assets = %v, want %v", got, tt.want)
			}
			for _, a := range res.Assets {
				if err := a.Validate("example.com"); err != nil {
					t.Errorf("invalid asset %+v: %v", a, err)
				}
			}
		})
	}
}

func TestCertificateAsset(t *testing.T) {
	e := newEnv(t)
	cert := e.ca.leaf(t, leafOpts{})
	e.route(apexIP, serveTLS(t, cert, tls.VersionTLS12))
	res, err := e.runAll(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(cert.Certificate[0]))
	for _, a := range res.Assets {
		if a.Kind != asset.KindCertificate {
			continue
		}
		if a.Value != want {
			t.Errorf("certificate value = %s, want the SHA-256 of the leaf %s", a.Value, want)
		}
		if a.Details["subject"] != "example.com" || a.Details["names"] != "example.com www.example.com" || a.Details["not_after"] == "" {
			t.Errorf("certificate details = %v", a.Details)
		}
		return
	}
	t.Errorf("no certificate asset in %v", assetKeys(res.Assets))
}
