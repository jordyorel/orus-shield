package vulns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// Shared fakes: a resolver that knows only the test names, and a gate that
// records what it approved. No real DNS, no third-party system (rule 6).

type fakeDNS struct{ hosts map[string]netip.Addr }

func (f fakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupAddr(context.Context, netip.Addr) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if ip, ok := f.hosts[host]; ok {
		return []netip.Addr{ip}, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}

type recordGate struct {
	mu   sync.Mutex
	seen []module.Destination
	deny func(module.Destination) error
}

func (g *recordGate) Allow(_ context.Context, d module.Destination) error {
	g.mu.Lock()
	g.seen = append(g.seen, d)
	g.mu.Unlock()
	if g.deny != nil {
		return g.deny(d)
	}
	return nil
}

// labDomain exists only in fakeDNS: if Nuclei tried to resolve or reach it
// by itself, around the proxy, it would fail.
const labDomain = "orus-lab.test"

// TestRealNuclei runs the pinned binary and templates against a local
// server, through the proxy. It needs ORUS_NUCLEI_BIN and
// ORUS_NUCLEI_TEMPLATES (the integration CI job and developers set them).
func TestRealNuclei(t *testing.T) {
	bin, templates := os.Getenv("ORUS_NUCLEI_BIN"), os.Getenv("ORUS_NUCLEI_TEMPLATES")
	if bin == "" || templates == "" {
		t.Skip("ORUS_NUCLEI_BIN and ORUS_NUCLEI_TEMPLATES not set")
	}
	// A few known templates, in the real layout, so the test takes
	// seconds, not an hour.
	dir := t.TempDir()
	for _, rel := range []string{
		"http/exposures/configs/git-config.yaml",
		"http/exposures/files/ds-store-file.yaml",
		"http/technologies/tech-detect.yaml",
	} {
		b, err := os.ReadFile(filepath.Join(templates, rel)) //nolint:gosec // G304: the developer's own templates directory (ORUS_NUCLEI_TEMPLATES)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil { //nolint:gosec // G703: dst is under t.TempDir(), rel is a constant above
			t.Fatal(err)
		}
	}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) { realNuclei(t, bin, dir, scheme) })
	}
}

func realNuclei(t *testing.T, bin, dir, scheme string) {
	var hits atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/.git/config":
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.invalid/x.git\n"))
		case "/.DS_Store":
			http.Error(w, "excluded, should never be asked", http.StatusTeapot)
		default:
			w.Header().Set("Server", "nginx/1.18.0")
			_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.1"></head><body>hi</body></html>`))
		}
	})
	srv := httptest.NewUnstartedServer(h)
	if scheme == "https" {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	g := &recordGate{deny: func(d module.Destination) error {
		if d.Path == "/.DS_Store" {
			return fmt.Errorf("path excluded: %w", module.ErrExcluded)
		}
		return nil
	}}
	m := New(fakeDNS{hosts: map[string]netip.Addr{labDomain: netip.MustParseAddr("127.0.0.1")}}, &net.Dialer{},
		Config{Binary: bin, Templates: dir})
	m.urls = func(host string) []string { return []string{scheme + "://" + host + ":" + u.Port()} }

	res, err := m.Run(context.Background(), module.Request{
		Target: module.Target{Domain: labDomain, Verified: true, Hosts: []string{}}, Gate: g,
	})
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range res.Findings {
		found = append(found, f.CheckID+" "+f.Asset)
	}
	want := CheckExposedData + " " + scheme + "://" + labDomain + ":" + u.Port() + "/.git/config#git-config"
	if len(res.Findings) != 1 || found[0] != want {
		t.Errorf("findings %v, want [%s]", found, want)
	}
	if len(res.Evaluated) != len(Checks) {
		t.Errorf("evaluated %v, want every check", res.Evaluated)
	}
	var techs string
	for _, a := range res.Assets {
		techs += a.Details["technologies"]
	}
	if !strings.Contains(strings.ToLower(techs), "nginx") {
		t.Errorf("assets %+v: nginx not detected", res.Assets)
	}

	// Every request the server got went through the gate: one approval
	// with an IP and a path per request, and nothing reached the excluded
	// path. The TCP probe before the run is the one approval without a path.
	approved, probes := 0, 0
	for _, d := range g.seen {
		switch {
		case !d.IP.IsValid():
		case d.Path == "":
			probes++
		case d.Path != "/.DS_Store":
			approved++
		}
	}
	if int64(approved) != hits.Load() || hits.Load() == 0 || probes != 1 {
		t.Errorf("server got %d requests, gate approved %d (and %d probes, want 1)", hits.Load(), approved, probes)
	}
	t.Logf("requests: %d, findings: %v, technologies: %s", hits.Load(), found, techs)
}
