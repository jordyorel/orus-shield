package mailer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server on 127.0.0.1 that records one message.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	from string
	rcpt []string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{addr: ln.Addr().String()}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); f.serve(c) }()
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line[len("RCPT TO:"):]))
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSendThroughSMTP(t *testing.T) {
	srv := newFakeSMTP(t)
	s := SMTP{Addr: srv.addr, From: "Orus Shield <no-reply@orus.example>"}
	link := SetupLink("https://app.orus.example/", "tok+en/=")
	err := s.Send(context.Background(), PasswordReset(French, "alice@example.com", link, time.Hour))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.from != "<no-reply@orus.example>" || len(srv.rcpt) != 1 || srv.rcpt[0] != "<alice@example.com>" {
		t.Errorf("envelope from %q to %v", srv.from, srv.rcpt)
	}
	msg, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != "Réinitialisation de votre mot de passe Orus Shield" {
		t.Errorf("subject = %q, %v", subject, err)
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" || msg.Header.Get("Message-Id") == "" {
		t.Errorf("headers = %v", msg.Header)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"valable 1 heure", "https://app.orus.example/setup-password#token=tok%2Ben%2F%3D", "ignorez cet email", "L'équipe Orus Shield"} {
		if !strings.Contains(text, want) {
			t.Errorf("body misses %q:\n%s", want, text)
		}
	}
}

func TestHeaderInjectionIsRefused(t *testing.T) {
	srv := newFakeSMTP(t)
	s := SMTP{Addr: srv.addr, From: "no-reply@orus.example"}
	for name, m := range map[string]Message{
		"newline in subject":   {To: "a@example.com", Subject: "Hi\r\nBcc: victim@example.com", Text: "x"},
		"newline in recipient": {To: "a@example.com\r\nBcc: victim@example.com", Subject: "Hi", Text: "x"},
		"not an address":       {To: "nobody", Subject: "Hi", Text: "x"},
		"empty body":           {To: "a@example.com", Subject: "Hi"},
	} {
		if err := s.Send(context.Background(), m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.rcpt) != 0 {
		t.Errorf("a refused message reached the server: %v", srv.rcpt)
	}
}

func TestValidate(t *testing.T) {
	for name, s := range map[string]SMTP{
		"no port":       {Addr: "smtp.example.com", From: "a@example.com"},
		"bad sender":    {Addr: "smtp.example.com:587", From: "nobody"},
		"sender inject": {Addr: "smtp.example.com:587", From: "a@example.com\r\nBcc: b@example.com"},
	} {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if err := (SMTP{Addr: "127.0.0.1:1025", From: "Orus <a@example.com>"}).Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
}

func TestIsLoopback(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "smtp.example.com": false, "192.0.2.1": false} {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v", host, got)
		}
	}
}

func TestFrenchDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Hour: "1 heure", 24 * time.Hour: "24 heures", 30 * time.Minute: "30 minutes"} {
		if got := frenchDuration(d); got != want {
			t.Errorf("frenchDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTemplatesNeutralizeOrganizationNames(t *testing.T) {
	m := Invitation(French, "a@example.com", "Evil\r\nBcc: x@example.com", "admin@example.com", false, "https://x/setup-password#token=t", 24*time.Hour)
	if strings.ContainsAny(m.Subject, "\r\n") || !strings.Contains(m.Subject, "Evil Bcc: x@example.com") {
		t.Errorf("subject = %q", m.Subject)
	}
	if !strings.Contains(m.Text, "valable 24 heures") || !strings.Contains(m.Text, "lecteur") {
		t.Errorf("text:\n%s", m.Text)
	}
	long := Invitation(French, "a@example.com", strings.Repeat("é", 300), "x@example.com", true, "l", time.Hour)
	if n := len([]rune(long.Subject)); n > 130 {
		t.Errorf("subject has %d characters", n)
	}
	if got := AddedToOrganization(French, "a@example.com", "", "x@example.com", true, "https://app/"); !strings.Contains(got.Text, "https://app/login") {
		t.Errorf("access email:\n%s", got.Text)
	}
}

func TestFirstScan(t *testing.T) {
	score := 72
	m := FirstScan(French, "a@example.com", "OrusLabs", "orushield.xyz",
		FirstScanFigures{Score: &score, Critical: 1, Medium: 3, Hostnames: 6}, TodayLink("https://app.example.com/", "org-1"), "offer")
	for _, want := range []string{"72/100", "1 critique, 3 moyens", "sous le domaine : 6", "https://app.example.com/orgs/org-1/aujourdhui", "« OrusLabs »"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, m.Text)
		}
	}
	if m.Subject != "Orus Shield : le premier scan de orushield.xyz est terminé" || m.To != "a@example.com" {
		t.Errorf("message = %+v", m)
	}
	// Nothing found, no score: said plainly.
	m = FirstScan(French, "a@example.com", "O", "example.com", FirstScanFigures{}, "l", "offer")
	if !strings.Contains(m.Text, "pas encore calculé") || !strings.Contains(m.Text, "aucun pour le moment") || strings.Contains(m.Text, "essai") {
		t.Errorf("empty summary:\n%s", m.Text)
	}
	// After the free audit: what it did not check, and the trial.
	m = FirstScan(French, "a@example.com", "O", "example.com", FirstScanFigures{IPs: 2, Free: true}, "l",
		OfferLink("https://app.example.com", "org-1"))
	for _, want := range []string{"ports ouverts de vos 2 serveurs", "14 jours", "https://app.example.com/orgs/org-1/offre"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("free audit summary lacks %q:\n%s", want, m.Text)
		}
	}
}

func TestParseLang(t *testing.T) {
	for in, want := range map[string]Lang{"en": English, "en-GB": English, " EN-us ": English, "fr": French, "fr-FR": French, "": French, "de": French, "eng": French} {
		if got := ParseLang(in); got != want {
			t.Errorf("ParseLang(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnglishTemplates checks that every template has its English text:
// English subject and body, English signature, no French left.
func TestEnglishTemplates(t *testing.T) {
	score := 72
	msgs := map[string]Message{
		"reset":       PasswordReset(English, "a@example.com", "link", time.Hour),
		"invitation":  Invitation(English, "a@example.com", "Acme", "admin@example.com", false, "link", 24*time.Hour),
		"access":      AddedToOrganization(English, "a@example.com", "Acme", "admin@example.com", true, "https://app/"),
		"signup":      ConfirmSignup(English, "a@example.com", "Acme", "link", time.Hour),
		"registered":  AlreadyRegistered(English, "a@example.com", "login", "forgot"),
		"findings":    NewFindings(English, "a@example.com", "Acme", "acme.example", []AlertItem{{Severity: "critical", Title: "Certificate has expired", Asset: "acme.example:443", Reopened: true, Link: "l"}}, 2, "list"),
		"threats":     EmergingThreats(English, "a@example.com", "Acme", "acme.example", []ThreatItem{{CVE: "CVE-2026-1", Name: "X RCE", Severity: "high", KEV: true, EPSS: 0.5, Products: []string{"nginx"}}}, 1, "scans"),
		"first scan":  FirstScan(English, "a@example.com", "Acme", "acme.example", FirstScanFigures{Score: &score, Critical: 1, IPs: 2, Free: true}, "today", "offer"),
		"trial nudge": TrialReminder(English, "a@example.com", "Acme", "acme.example", TrialNudge{Day: 10, Open: 3, High: 1, Top: "No DMARC record"}, "offer", "unsub"),
	}
	french := []string{"Bonjour", "L'équipe", "Vous recevez", "valable", "organisation «", " : "}
	for name, m := range msgs {
		if !strings.HasPrefix(m.Text, "Hello,") || !strings.Contains(m.Text, "The Orus Shield team") {
			t.Errorf("%s: not English:\n%s", name, m.Text)
		}
		for _, w := range french {
			if strings.Contains(m.Subject, w) || strings.Contains(m.Text, w) {
				t.Errorf("%s: French %q left in:\n%s\n%s", name, w, m.Subject, m.Text)
			}
		}
	}
	for name, want := range map[string]string{
		"reset":       "valid for 1 hour",
		"invitation":  "viewer (reads the results)",
		"findings":    "[Critical] Certificate has expired (back again",
		"threats":     "probability of exploitation within 30 days: 50%",
		"first scan":  "the open ports of your 2 servers",
		"trial nudge": "3 problems to fix, 1 of them urgent",
	} {
		if !strings.Contains(msgs[name].Text, want) {
			t.Errorf("%s lacks %q:\n%s", name, want, msgs[name].Text)
		}
	}
	if s := msgs["findings"].Subject; s != "Orus Shield: 1 critical vulnerability on acme.example" {
		t.Errorf("findings subject = %q", s)
	}
	if msgs["trial nudge"].Unsubscribe != "unsub" {
		t.Error("English reminder lost its unsubscribe link")
	}
}

func TestListUnsubscribeHeader(t *testing.T) {
	from, to := &mail.Address{Address: "no-reply@example.com"}, &mail.Address{Address: "a@example.com"}
	raw, err := build(from, to, Message{Subject: "s", Text: "t", Unsubscribe: "https://app.example.com/desinscription#token=x"}, time.Now())
	if err != nil || !strings.Contains(string(raw), "List-Unsubscribe: <https://app.example.com/desinscription#token=x>\r\n") {
		t.Errorf("header missing: %v\n%s", err, raw)
	}
	if _, err := build(from, to, Message{Subject: "s", Text: "t", Unsubscribe: "x>\r\nBcc: y"}, time.Now()); err == nil {
		t.Error("header injection through the unsubscribe link accepted")
	}
}
