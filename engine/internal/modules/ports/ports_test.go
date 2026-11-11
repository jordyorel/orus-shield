package ports

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ---- Fakes ----------------------------------------------------------------

// fakeDNS answers LookupIP from a map; everything else is NXDOMAIN.
type fakeDNS struct {
	ips  map[string][]netip.Addr
	ptr  map[netip.Addr][]string
	fail error
}

func (f *fakeDNS) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if a, ok := f.ips[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, resolver.ErrNotFound
}

func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}

func (f *fakeDNS) LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error) {
	if n, ok := f.ptr[ip]; ok {
		return n, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", ip, resolver.ErrNotFound)
}

// port behaviors for the fake dialer.
const blackHole = "\x00blackhole" // never answers (filtered port)

// fakeDialer simulates servers in memory. routes maps "ip:port" to the
// banner the service sends ("" = silent service, blackHole = filtered).
// Unrouted addresses are refused, like closed ports. No network is used.
type fakeDialer struct {
	mu     sync.Mutex
	routes map[string]string
	dialed []string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, address)
	banner, ok := f.routes[address]
	f.mu.Unlock()
	switch {
	case !ok:
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	case banner == blackHole:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	}
	client, server := net.Pipe()
	go func() {
		if banner != "" {
			_, _ = server.Write([]byte(banner))
		}
		_, _ = io.Copy(io.Discard, server) // until the client closes
		_ = server.Close()
	}()
	return client, nil
}

func (f *fakeDialer) addrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.dialed)
}

// fakeGate can exclude IPs or ports, fail, or be slow like a busy limiter.
type fakeGate struct {
	mu          sync.Mutex
	excludeIPs  map[netip.Addr]bool
	excludePort map[int]bool
	fail        error
	delay       time.Duration
	seen        []module.Destination
}

func (g *fakeGate) Allow(ctx context.Context, d module.Destination) error {
	g.mu.Lock()
	g.seen = append(g.seen, d)
	g.mu.Unlock()
	if g.fail != nil {
		return g.fail
	}
	if g.excludeIPs[d.IP] || g.excludePort[d.Port] {
		return fmt.Errorf("excluded: %w", module.ErrExcluded)
	}
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	return nil
}

var (
	ip1 = netip.MustParseAddr("192.0.2.10")
	ip2 = netip.MustParseAddr("192.0.2.20")
)

func route(ip netip.Addr, port int) string {
	return netip.AddrPortFrom(ip, uint16(port)).String() //nolint:gosec // G115: test ports are valid constants
}

// newTest returns a module with fast timeouts, example.com resolving to ip1,
// and an empty server map.
func newTest() (*Module, *fakeDNS, *fakeDialer, *fakeGate) {
	dns := &fakeDNS{ips: map[string][]netip.Addr{"example.com": {ip1}}}
	dial := &fakeDialer{routes: map[string]string{}}
	m := New(dns, dial)
	m.connectTimeout = 50 * time.Millisecond
	m.bannerTimeout = 50 * time.Millisecond
	return m, dns, dial, &fakeGate{}
}

func run(ctx context.Context, m *Module, g module.Gate) ([]finding.Finding, error) {
	res, err := runAll(ctx, m, g)
	return res.Findings, err
}

func runAll(ctx context.Context, m *Module, g module.Gate) (module.Result, error) {
	return m.Run(ctx, module.Request{Target: module.Target{Domain: "example.com", Verified: true}, Gate: g})
}

func checkIDs(fs []finding.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.CheckID)
	}
	slices.Sort(ids)
	return ids
}

// ---- Tests ----------------------------------------------------------------

func TestInfo(t *testing.T) {
	m, _, _, _ := newTest()
	if info := m.Info(); info.ID != ID || info.Kind != module.KindActive {
		t.Errorf("Info() = %+v, want ID %q and the active kind", info, ID)
	}
	if err := module.NewRegistry().Register(m); err != nil {
		t.Errorf("Register: %v", err)
	}
}

func TestCatalog(t *testing.T) {
	ports := make(map[int]bool)
	for _, s := range catalog {
		if ports[s.port] {
			t.Errorf("port %d listed twice", s.port)
		}
		ports[s.port] = true
		if s.port < 1 || s.port > 65535 || s.name == "" {
			t.Errorf("bad service %+v", s)
		}
		f := s.family
		if !s.sev().Valid() || f.why == "" || len(f.fix) == 0 || !strings.HasPrefix(f.checkID, "port-") {
			t.Errorf("port %d: incomplete family %+v", s.port, f)
		}
	}
	for _, expected := range []int{22, 3389, 445, 3306, 6379, 2375} {
		if !ports[expected] {
			t.Errorf("catalog misses port %d", expected)
		}
	}
	if ports[80] || ports[443] {
		t.Error("web ports 80/443 must not be reported as risky")
	}
}

func TestOpenPorts(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 22)] = "SSH-2.0-OpenSSH_9.6\r\n"
	dial.routes[route(ip1, 3389)] = "" // RDP waits for the client
	dial.routes[route(ip1, 6379)] = ""

	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"port-database-exposed", "port-remote-desktop-exposed", "port-ssh-exposed"}
	if got := checkIDs(findings); !slices.Equal(got, want) {
		t.Fatalf("check IDs = %v, want %v", got, want)
	}

	byPort := make(map[string]finding.Finding)
	for _, f := range findings {
		byPort[f.Asset] = f
	}
	sshF := byPort["192.0.2.10:22"]
	if sshF.Severity != finding.SeverityLow || !strings.Contains(sshF.Evidence, "banner: SSH-2.0-OpenSSH_9.6") {
		t.Errorf("ssh finding = %+v", sshF)
	}
	rdp := byPort["192.0.2.10:3389"]
	if rdp.Severity != finding.SeverityCritical || !strings.Contains(rdp.Evidence, "banner: (none") {
		t.Errorf("rdp finding = %+v", rdp)
	}
}

// A service that always greets first but stayed silent is reported as
// "not confirmed", at low severity: on a mobile network, a proxy answered
// every connection to port 21 and the module reported FTP on every server.
func TestSilentGreetingServiceIsNotConfirmed(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 21)] = ""                        // FTP always sends "220 ..."
	dial.routes[route(ip1, 3306)] = "J\x00\x00\x00\n8.0.36" // a real MySQL greeting
	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatal(err)
	}
	byPort := make(map[string]finding.Finding)
	for _, f := range findings {
		byPort[f.Asset] = f
	}
	ftp := byPort["192.0.2.10:21"]
	if ftp.Severity != finding.SeverityLow || ftp.Title != "Port 21 open, FTP not confirmed" ||
		!strings.Contains(ftp.Description, "firewall or proxy") || !strings.Contains(ftp.Remediation[0], "ss -ltnp") {
		t.Errorf("silent FTP = %+v", ftp)
	}
	if ftp.ID != finding.NewID(ID, fileSharing.checkID, "example.com", "192.0.2.10:21") {
		t.Error("the unconfirmed finding must keep the ID of the confirmed one")
	}
	if db := byPort["192.0.2.10:3306"]; db.Severity != finding.SeverityHigh || strings.Contains(db.Title, "not confirmed") {
		t.Errorf("MySQL that greeted = %+v", db)
	}
}

func TestNothingOpen(t *testing.T) {
	m, _, _, g := newTest()
	findings, err := run(context.Background(), m, g)
	if err != nil || len(findings) != 0 {
		t.Errorf("Run = %v, %v; want no findings and no error", checkIDs(findings), err)
	}
}

func TestNoAddress(t *testing.T) {
	m, dns, dial, g := newTest()
	dns.ips = nil
	findings, err := run(context.Background(), m, g)
	if err != nil || findings != nil || len(dial.addrs()) != 0 {
		t.Errorf("Run = %v, %v, %d dials; want nothing", findings, err, len(dial.addrs()))
	}
}

// Filtered ports never answer; their timeouts overlap, so a fully filtered
// server is scanned quickly instead of len(catalog) x timeout.
func TestFilteredPortsDoNotStall(t *testing.T) {
	m, _, dial, g := newTest()
	for _, s := range catalog {
		dial.routes[route(ip1, s.port)] = blackHole
	}
	start := time.Now()
	findings, err := run(context.Background(), m, g)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Run = %v, %v", checkIDs(findings), err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("filtered scan took %v; timeouts should overlap", elapsed)
	}
}

// Waiting for the rate limiter must not count against the connect timeout:
// otherwise open ports that wait their turn would look filtered.
func TestRateLimitWaitIsNotATimeout(t *testing.T) {
	m, _, dial, g := newTest()
	m.services = []service{{port: 3389, name: "RDP", family: remoteDesktop}}
	dial.routes[route(ip1, 3389)] = ""
	g.delay = 200 * time.Millisecond // 4x the connect timeout

	findings, err := run(context.Background(), m, g)
	if err != nil || len(findings) != 1 {
		t.Errorf("Run = %v, %v; want the open port despite the slow gate", checkIDs(findings), err)
	}
}

// An IP without verified ownership is not scanned. If it is the only one,
// the module fails instead of claiming "no open port".
func TestUnverifiedIP(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 3389)] = ""
	g.excludeIPs = map[netip.Addr]bool{ip1: true}

	_, err := run(context.Background(), m, g)
	if !errors.Is(err, ErrNoVerifiedIP) {
		t.Fatalf("Run = %v, want ErrNoVerifiedIP", err)
	}
	if n := len(dial.addrs()); n != 0 {
		t.Errorf("%d connections to an unverified IP", n)
	}
}

func TestOneOfTwoIPsUnverified(t *testing.T) {
	m, dns, dial, g := newTest()
	dns.ips["example.com"] = []netip.Addr{ip1, ip2}
	dial.routes[route(ip1, 3389)] = ""
	dial.routes[route(ip2, 3389)] = ""
	g.excludeIPs = map[netip.Addr]bool{ip1: true}

	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Asset != "192.0.2.20:3389" {
		t.Errorf("findings = %+v, want only the verified IP", findings)
	}
	for _, a := range dial.addrs() {
		if strings.HasPrefix(a, "192.0.2.10:") {
			t.Errorf("connected to unverified IP: %s", a)
		}
	}
}

// Customer port exclusions are respected.
func TestExcludedPort(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 22)] = "SSH-2.0-x"
	dial.routes[route(ip1, 3389)] = ""
	g.excludePort = map[int]bool{22: true}

	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := checkIDs(findings); !slices.Equal(got, []string{"port-remote-desktop-exposed"}) {
		t.Errorf("check IDs = %v", got)
	}
	if slices.Contains(dial.addrs(), route(ip1, 22)) {
		t.Error("connected to an excluded port")
	}
}

func TestEveryConnectionGoesThroughGate(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 22)] = "SSH-2.0-x"
	if _, err := run(context.Background(), m, g); err != nil {
		t.Fatal(err)
	}
	var conns int
	for _, d := range g.seen {
		if d.IP.IsValid() {
			conns++
			if d.Port == 0 || d.Host == "" {
				t.Errorf("gate saw an incomplete destination %+v", d)
			}
		}
	}
	if conns != len(dial.addrs()) || conns != len(catalog) {
		t.Errorf("gate approved %d connections, dialer saw %d, catalog has %d", conns, len(dial.addrs()), len(catalog))
	}
}

// The domain and www often share a server: each port is tried once per IP.
func TestAddressesAreDeduplicatedAndCapped(t *testing.T) {
	m, dns, dial, g := newTest()
	dns.ips["www.example.com"] = []netip.Addr{ip1}
	if _, err := run(context.Background(), m, g); err != nil {
		t.Fatal(err)
	}
	if n := len(dial.addrs()); n != len(catalog) {
		t.Errorf("%d connections for one shared IP, want %d", n, len(catalog))
	}

	m, dns, dial, g = newTest()
	m.services = m.services[:1]
	var many []netip.Addr
	for i := 1; i <= maxIPs+3; i++ {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	dns.ips["example.com"] = many
	if _, err := run(context.Background(), m, g); err != nil {
		t.Fatal(err)
	}
	if n := len(dial.addrs()); n != maxIPs {
		t.Errorf("scanned %d addresses, want at most %d", n, maxIPs)
	}
}

func TestRunErrors(t *testing.T) {
	limiter := errors.New("rate limiter stopped")
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name    string
		ctx     context.Context
		setup   func(dns *fakeDNS, g *fakeGate)
		wantErr error
	}{
		{"gate failure", context.Background(), func(_ *fakeDNS, g *fakeGate) { g.fail = limiter }, limiter},
		{"dns failure", context.Background(), func(d *fakeDNS, _ *fakeGate) { d.fail = timeout }, timeout},
		{"cancelled", cancelled, func(*fakeDNS, *fakeGate) {}, context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, dns, _, g := newTest()
			tt.setup(dns, g)
			findings, err := run(tt.ctx, m, g)
			if !errors.Is(err, tt.wantErr) || findings != nil {
				t.Errorf("Run = %v, %v; want %v", findings, err, tt.wantErr)
			}
		})
	}
}

func TestBannerIsBoundedAndSanitized(t *testing.T) {
	m, _, dial, g := newTest()
	m.services = []service{{port: 21, name: "FTP", family: fileSharing}}
	dial.routes[route(ip1, 21)] = "220 \x1b[31mEvil\x1b[0m FTP\r\n" + strings.Repeat("A", 2000)

	findings, err := run(context.Background(), m, g)
	if err != nil || len(findings) != 1 {
		t.Fatalf("Run = %v, %v", findings, err)
	}
	ev := findings[0].Evidence
	if strings.ContainsRune(ev, '\x1b') {
		t.Error("terminal escape sequence passed through to the evidence")
	}
	if !strings.Contains(ev, "220 .[31mEvil.[0m FTP") {
		t.Errorf("evidence = %q", ev)
	}
	if strings.Count(ev, "A") > maxBanner {
		t.Errorf("banner not bounded: %d bytes of payload kept", strings.Count(ev, "A"))
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct{ in, want string }{
		{"SSH-2.0-OpenSSH_9.6\r\n", "SSH-2.0-OpenSSH_9.6"},
		{"line one\nline two", "line one line two"},
		{"bell\x07null\x00", "bell.null."},
		{"\xff\xfe binary", ".. binary"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := sanitizeBanner([]byte(tt.in)); got != tt.want {
			t.Errorf("sanitizeBanner(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFindingsAreValid(t *testing.T) {
	m, _, dial, g := newTest()
	for _, s := range catalog {
		dial.routes[route(ip1, s.port)] = "hello"
	}
	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != len(catalog) {
		t.Fatalf("%d findings for %d open ports", len(findings), len(catalog))
	}
	now := time.Now()
	ids := make(map[string]bool)
	for _, f := range findings {
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("%s on %s: %v", f.CheckID, f.Asset, err)
		}
		if ids[f.ID] {
			t.Errorf("duplicate finding ID for %s", f.Asset)
		}
		ids[f.ID] = true
	}
}

// The whole rule 1 chain with the real components: the customer's own VPS
// (PTR under their domain) is scanned; their website on shared hosting
// (PTR owned by the provider) is not, although the domain is verified.
func TestOnlyOwnedServersAreScanned(t *testing.T) {
	m, dns, dial, _ := newTest()
	vps, shared := ip1, ip2
	dns.ips["example.com"] = []netip.Addr{shared}
	dns.ips["srv1.example.com"] = []netip.Addr{vps}
	dns.ips["host.provider.example"] = []netip.Addr{shared}
	dns.ptr = map[netip.Addr][]string{vps: {"srv1.example.com"}, shared: {"host.provider.example"}}
	// The scan reaches the VPS through its own name.
	dns.ips["www.example.com"] = []netip.Addr{shared, vps}
	dial.routes[route(vps, 3389)] = ""
	dial.routes[route(shared, 3389)] = ""

	var refused []netip.Addr
	verifier := ownership.New(nil, dns) // IPGate does not use the store
	g := verifier.IPGate(&fakeGate{}, "example.com", func(ip netip.Addr, reason string) {
		refused = append(refused, ip)
	})

	findings, err := run(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Asset != "192.0.2.10:3389" {
		t.Errorf("findings = %v, want only the customer's VPS", findings)
	}
	for _, a := range dial.addrs() {
		if strings.HasPrefix(a, shared.String()+":") {
			t.Fatalf("connected to the hosting provider's server: %s", a)
		}
	}
	if len(refused) != 1 || refused[0] != shared {
		t.Errorf("refused = %v, want the shared hosting IP once", refused)
	}
}

func TestAssets(t *testing.T) {
	m, dns, dial, g := newTest()
	dns.ips["example.com"] = []netip.Addr{ip1, ip2}
	dial.routes[route(ip1, 22)] = "SSH-2.0-OpenSSH_9.6\r\n"
	dial.routes[route(ip2, 3389)] = ""
	g.excludeIPs = map[netip.Addr]bool{ip2: true} // not verified: not scanned

	res, err := runAll(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var keys []string
	for _, a := range res.Assets {
		keys = append(keys, a.Key())
		if err := a.Validate("example.com"); err != nil {
			t.Errorf("invalid asset %+v: %v", a, err)
		}
	}
	slices.Sort(keys)
	want := []string{"hostname example.com", "ip 192.0.2.10", "service 192.0.2.10:22/tcp"}
	if !slices.Equal(keys, want) {
		t.Errorf("assets = %v, want %v (nothing about the address that was not scanned)", keys, want)
	}
	for _, a := range res.Assets {
		if a.Kind == asset.KindService && (a.Details["expected"] != "SSH" || a.Details["banner"] != "SSH-2.0-OpenSSH_9.6") {
			t.Errorf("service details = %v", a.Details)
		}
	}
}

func TestEvaluatedChecks(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 3389)] = ""
	g.excludePort = map[int]bool{22: true, 2222: true} // every port of the SSH family

	res, err := runAll(context.Background(), m, g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	outcomes, err := module.Evaluate(m.Info(), res)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range outcomes {
		want := module.CheckPassed
		switch o.ID {
		case "port-remote-desktop-exposed":
			want = module.CheckFailed
		case "port-ssh-exposed":
			want = module.CheckNotApplicable // excluded: never probed
		}
		if o.Status != want {
			t.Errorf("%s = %s, want %s", o.ID, o.Status, want)
		}
	}
}

func TestCatalogCoversEveryFamily(t *testing.T) {
	declared := map[string]bool{}
	for _, c := range Checks {
		declared[c.ID] = true
	}
	for _, svc := range catalog {
		if !declared[svc.family.checkID] {
			t.Errorf("port %d: family check %q is not in Checks", svc.port, svc.family.checkID)
		}
	}
	if err := module.NewRegistry().Register(New(&fakeDNS{}, &fakeDialer{})); err != nil {
		t.Fatalf("Register: %v", err)
	}
}
