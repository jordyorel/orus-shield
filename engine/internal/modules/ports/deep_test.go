package ports

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func TestIdentifyBanner(t *testing.T) {
	mysql := append([]byte{0x4a, 0, 0, 0, 0x0a}, []byte("8.0.36-0ubuntu0.24.04.1\x00\x08\x00\x00\x00")...)
	maria := append([]byte{0x5b, 0, 0, 0, 0x0a}, []byte("5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1\x00")...)
	tests := []struct {
		name string
		raw  []byte
		want identity
	}{
		{"openssh", []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"), identity{"SSH", "OpenSSH", "9.6p1"}},
		{"dropbear", []byte("SSH-2.0-dropbear_2022.83\r\n"), identity{"SSH", "dropbear", "2022.83"}},
		{"ssh without version", []byte("SSH-2.0-Go\r\n"), identity{"SSH", "Go", ""}},
		{"vsftpd", []byte("220 (vsFTPd 3.0.5)\r\n"), identity{"FTP", "vsFTPd", "3.0.5"}},
		{"proftpd", []byte("220 ProFTPD 1.3.8 Server (Debian) [::ffff:192.0.2.10]\r\n"), identity{"FTP", "ProFTPD", "1.3.8"}},
		{"postfix", []byte("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"), identity{"SMTP", "Postfix", ""}},
		{"exim", []byte("220 mx.example.com ESMTP Exim 4.96 Tue, 12 Nov 2026\r\n"), identity{"SMTP", "Exim", "4.96"}},
		{"dovecot", []byte("* OK [CAPABILITY IMAP4rev1] Dovecot (Ubuntu) ready.\r\n"), identity{"IMAP", "Dovecot", ""}},
		{"pop3", []byte("+OK POP3 ready\r\n"), identity{"POP3", "", ""}},
		{"vnc", []byte("RFB 003.008\n"), identity{"VNC", "", "003.008"}},
		{"mysql", mysql, identity{"MySQL", "MySQL", "8.0.36-0ubuntu0.24.04.1"}},
		{"mariadb", maria, identity{"MySQL", "MariaDB", "10.11.6"}},
		{"unknown", []byte("hello"), identity{}},
		{"binary noise", []byte{0, 1, 2, 3, 4, 5, 6}, identity{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identifyBanner(tt.raw, sanitizeBanner(tt.raw)); got != tt.want {
				t.Errorf("identifyBanner = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIdentifyHTTP(t *testing.T) {
	tests := []struct {
		head string
		want identity
	}{
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n", identity{"HTTP", "nginx", "1.24.0"}},
		{"HTTP/1.0 302 Found\r\nserver: Apache\r\nLocation: /x\r\n\r\n", identity{"HTTP", "Apache", ""}},
		{"HTTP/1.1 401 Unauthorized\r\nServer: Jetty(9.4.z-SNAPSHOT)\r\n\r\n", identity{"HTTP", "Jetty", ""}},
		{"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", identity{"HTTP", "", ""}},
		// Control characters from the target never reach reports (rule 7).
		{"HTTP/1.1 200 OK\r\nServer: evil\x1b[31m/1\r\n\r\n", identity{"HTTP", "evil.", ""}},
		{"SSH-2.0-OpenSSH_9.6\r\n", identity{}},
	}
	for _, tt := range tests {
		if got := identifyHTTP([]byte(tt.head)); got != tt.want {
			t.Errorf("identifyHTTP(%q) = %+v, want %+v", tt.head, got, tt.want)
		}
	}
}

func TestDeepServices(t *testing.T) {
	d := deepServices()
	if len(d) < 1000 {
		t.Errorf("deep scan covers %d ports, want more than 1 000", len(d))
	}
	seen := map[int]bool{}
	for _, s := range d {
		if seen[s.port] {
			t.Errorf("port %d listed twice", s.port)
		}
		seen[s.port] = true
		if s.port == 80 || s.port == 443 {
			t.Errorf("expected web port %d must not be reported", s.port)
		}
	}
	// The catalog keeps its families and advice.
	for _, s := range catalog {
		if !seen[s.port] {
			t.Errorf("catalog port %d missing from the deep scan", s.port)
		}
	}
}

func runDeep(ctx context.Context, m *Module, g module.Gate) (module.Result, error) {
	cfg, _ := json.Marshal(Config{Deep: true})
	return m.Run(ctx, module.Request{Target: module.Target{Domain: "example.com", Verified: true}, Gate: g, Config: cfg})
}

func TestDeepScanIdentifies(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 22)] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n"
	dial.routes[route(ip1, 8081)] = "" // silent: asked over HTTP
	dial.answers = map[string]string{route(ip1, 8081): "HTTP/1.1 200 OK\r\nServer: Jetty/9.4.51\r\n\r\n"}
	dial.routes[route(ip1, 7)] = "" // silent, not HTTP: open, unidentified

	res, err := runDeep(context.Background(), m, g)
	if err != nil {
		t.Fatal(err)
	}
	byPort := map[string]string{}
	for _, f := range res.Findings {
		byPort[f.Asset] = f.Title + " | " + f.Evidence
	}
	if got := byPort[route(ip1, 22)]; !strings.Contains(got, "identified: OpenSSH 9.6p1") {
		t.Errorf("ssh finding = %q", got)
	}
	if got := byPort[route(ip1, 8081)]; !strings.HasPrefix(got, "Jetty 9.4.51 reachable from the internet (port 8081)") {
		t.Errorf("http finding = %q", got)
	}
	if got := byPort[route(ip1, 7)]; !strings.HasPrefix(got, "Echo reachable") {
		t.Errorf("silent finding = %q", got)
	}
	// The HEAD request asked for headers only, with our Host.
	if r := dial.reqs(); len(r) == 0 || !strings.HasPrefix(r[0], "HEAD / HTTP/1.0\r\nHost: example.com\r\n") {
		t.Errorf("requests = %q", r)
	}
	// The identified software reaches the inventory.
	var svc asset.Asset
	for _, a := range res.Assets {
		if a.Kind == asset.KindService && strings.HasSuffix(a.Value, ":8081/tcp") {
			svc = a
		}
	}
	if svc.Details["product"] != "Jetty" || svc.Details["version"] != "9.4.51" || svc.Details["service"] != "HTTP" {
		t.Errorf("service details = %v", svc.Details)
	}
	if !slices.Contains(res.Evaluated, otherService.checkID) && !slices.ContainsFunc(res.Findings, func(f finding.Finding) bool { return f.CheckID == otherService.checkID }) {
		t.Error("deep scans evaluate the other-service check")
	}
}

func TestDeepScanHonoursPathExclusions(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 8081)] = ""
	dial.answers = map[string]string{route(ip1, 8081): "HTTP/1.1 200 OK\r\nServer: Jetty/9.4.51\r\n\r\n"}
	g.excludePath = map[string]bool{"/": true}
	if _, err := runDeep(context.Background(), m, g); err != nil {
		t.Fatal(err)
	}
	if r := dial.reqs(); len(r) != 0 {
		t.Errorf("an excluded path was requested: %q", r)
	}
}

func TestStandardScanSendsNothing(t *testing.T) {
	m, _, dial, g := newTest()
	dial.routes[route(ip1, 8080)] = ""
	dial.answers = map[string]string{route(ip1, 8080): "HTTP/1.1 200 OK\r\n\r\n"}
	res, err := runAll(context.Background(), m, g)
	if err != nil {
		t.Fatal(err)
	}
	if r := dial.reqs(); len(r) != 0 {
		t.Errorf("standard scan sent %q", r)
	}
	if n := len(dial.addrs()); n != len(catalog) {
		t.Errorf("standard scan dialed %d ports, want the %d of the catalog", n, len(catalog))
	}
	if slices.Contains(res.Evaluated, otherService.checkID) {
		t.Error("standard scans do not evaluate the other-service check")
	}
}
