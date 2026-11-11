// Package mailer sends the product's emails (password reset, invitations,
// alerts) over SMTP.
//
// It speaks plain SMTP with the standard library, so any provider works
// (Brevo, Mailjet, Amazon SES, Postmark...) and so does Mailpit, the local
// fake server of docker-compose: switching is configuration, not code.
//
// Messages are plain text in UTF-8. Every value that reaches a header is
// checked for line breaks: a newline in a subject or an address would let
// its author add headers or recipients (header injection).
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is one email to one recipient.
type Message struct {
	To      string // an address, "user@example.com"
	Subject string
	Text    string // plain text body, UTF-8
}

// Sender sends messages. The API holds one; tests use a fake.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// ErrInvalid wraps every message or configuration error.
var ErrInvalid = errors.New("invalid email")

// SMTP sends through an SMTP server.
//
// TLS: the connection is upgraded with STARTTLS whenever the server offers
// it, and must be, unless the server is on the loopback address (Mailpit in
// development). Credentials are never sent unencrypted to a remote server
// (smtp.PlainAuth refuses it too).
type SMTP struct {
	Addr     string // host:port, e.g. "smtp-relay.brevo.com:587" or "127.0.0.1:1025"
	Username string // empty: no authentication (Mailpit)
	Password string
	// From is the sender, e.g. "Orus Shield <no-reply@example.com>".
	From string
	// Timeout bounds one delivery; 30 seconds when zero.
	Timeout time.Duration
}

const defaultTimeout = 30 * time.Second

// Validate checks the configuration.
func (s SMTP) Validate() error {
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		return fmt.Errorf("%w: smtp address %q: %w", ErrInvalid, s.Addr, err)
	}
	if _, err := parseAddress(s.From); err != nil {
		return fmt.Errorf("%w: sender: %w", ErrInvalid, err)
	}
	return nil
}

// Send implements Sender.
func (s SMTP) Send(ctx context.Context, m Message) error {
	if err := s.Validate(); err != nil {
		return err
	}
	from, _ := parseAddress(s.From) // checked by Validate
	to, err := parseAddress(m.To)
	if err != nil {
		return fmt.Errorf("%w: recipient: %w", ErrInvalid, err)
	}
	data, err := build(from, to, m, time.Now())
	if err != nil {
		return err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("connect to smtp server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	host, _, _ := net.SplitHostPort(s.Addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	} else if !isLoopback(host) {
		return fmt.Errorf("smtp server %s does not offer STARTTLS: refusing to send unencrypted", host)
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp sender: %w", err)
	}
	if err := c.Rcpt(to.Address); err != nil {
		return fmt.Errorf("smtp recipient: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	return c.Quit()
}

// parseAddress accepts "user@example.com" or "Name <user@example.com>".
func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("line break in address")
	}
	return mail.ParseAddress(s)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// build returns the message in RFC 5322 format with CRLF line endings.
func build(from, to *mail.Address, m Message, now time.Time) ([]byte, error) {
	if strings.ContainsAny(m.Subject, "\r\n") {
		return nil, fmt.Errorf("%w: line break in subject", ErrInvalid)
	}
	if m.Subject == "" || m.Text == "" {
		return nil, fmt.Errorf("%w: subject and text required", ErrInvalid)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from.String())
	header("To", to.String())
	header("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", `text/plain; charset="utf-8"`)
	header("Content-Transfer-Encoding", "quoted-printable")
	// Tells mail servers this is automatic: no out-of-office replies.
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&crlfWriter{&b})
	if _, err := qp.Write([]byte(strings.ReplaceAll(m.Text, "\r\n", "\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// crlfWriter turns the "\n" of the encoded body into "\r\n", as SMTP wants.
type crlfWriter struct{ b *strings.Builder }

func (w *crlfWriter) Write(p []byte) (int, error) {
	w.b.WriteString(strings.ReplaceAll(strings.ReplaceAll(string(p), "\r\n", "\n"), "\n", "\r\n"))
	return len(p), nil
}
