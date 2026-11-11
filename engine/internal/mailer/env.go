package mailer

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// FromEnv reads the SMTP settings shared by the API and the worker:
//
//	ORUS_SMTP_ADDR      SMTP server host:port; unset: no email is sent
//	ORUS_SMTP_USERNAME  login, if the server needs one
//	ORUS_SMTP_PASSWORD  password
//	ORUS_MAIL_FROM      sender, e.g. "Orus Shield <no-reply@example.com>";
//	                    required with ORUS_SMTP_ADDR
//
// It returns nil when ORUS_SMTP_ADDR is unset (mail not configured).
func FromEnv(getenv func(string) string) (*SMTP, error) {
	addr := strings.TrimSpace(getenv("ORUS_SMTP_ADDR"))
	if addr == "" {
		return nil, nil
	}
	s := &SMTP{
		Addr: addr, Username: getenv("ORUS_SMTP_USERNAME"), Password: getenv("ORUS_SMTP_PASSWORD"),
		From: strings.TrimSpace(getenv("ORUS_MAIL_FROM")),
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("ORUS_SMTP_ADDR / ORUS_MAIL_FROM: %w", err)
	}
	return s, nil
}

// PublicURLFromEnv reads ORUS_PUBLIC_URL, the dashboard's address used in
// email links (default http://localhost:5173, the development server).
func PublicURLFromEnv(getenv func(string) string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(getenv("ORUS_PUBLIC_URL")), "/")
	if u == "" {
		return "http://localhost:5173", nil
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
		return "", errors.New("ORUS_PUBLIC_URL must be an http(s) URL, e.g. https://app.example.com")
	}
	return u, nil
}
