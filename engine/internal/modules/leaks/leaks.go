// Package leaks tells whether the email addresses of a customer's domain
// appear in known data breaches, through the XposedOrNot API (XON,
// https://xposedornot.com).
//
// It is passive and never contacts the target: it asks XON, per address,
// which breaches the address appears in. The addresses are the ones the
// worker passes (module.RunConfig.Emails): the organization's members on
// the domain and the addresses its admins declared, only for a verified
// domain. A breach a password was exposed in is a finding of
// "leak-password-exposed" (high when passwords were stored in clear or
// easy to crack); breaches of other data only, "leak-email-exposed".
//
// Only breach metadata is kept: the breach's name, year and the kinds of
// data exposed. XON never returns passwords. Its terms require attribution:
// the dashboard and the reports name XposedOrNot as the source.
package leaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// ID is the stable module ID.
const ID = "leaks"

// Check IDs.
const (
	CheckPassword = "leak-password-exposed"
	CheckEmail    = "leak-email-exposed"
)

const (
	// DefaultBaseURL is XON's public API.
	DefaultBaseURL = "https://api.xposedornot.com"
	// MaxAddresses bounds the addresses checked in one run: XON's free
	// tier allows 25 lookups an hour per endpoint.
	MaxAddresses = 20
	// pace spaces the lookups (XON: 2 requests a second at most).
	pace = 600 * time.Millisecond
	// requestTimeout bounds one lookup; maxBody what we read of an answer
	// (rule 7: a third party's answer is untrusted input too).
	requestTimeout = 15 * time.Second
	maxBody        = 1 << 20
	userAgent      = "OrusShield-Leaks/1"
	// maxBreachesShown bounds the breaches named in one finding.
	maxBreachesShown = 8
)

// Config is how the module reaches XON. The zero value uses the public API
// without a key (the free community tier).
type Config struct {
	BaseURL string // ORUS_XON_BASE_URL; empty: DefaultBaseURL
	APIKey  string // ORUS_XON_API_KEY, sent as x-api-key when set (paid tiers)
	// HTTP is the client to use; nil: a client with requestTimeout.
	HTTP *http.Client
	// Pace overrides the wait between lookups (tests); zero: pace.
	Pace time.Duration
}

// Module is the data leak check.
type Module struct{ cfg Config }

// New returns the module.
func New(cfg Config) *Module {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: requestTimeout}
	}
	if cfg.Pace == 0 {
		cfg.Pace = pace
	}
	return &Module{cfg: cfg}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{
		ID: ID, Name: "Data leaks", Kind: module.KindPassive, UsesEmails: true,
		Checks: []module.Check{
			{ID: CheckPassword, Category: module.CategoryLeaks, Severity: finding.SeverityHigh,
				Title: "No address of the domain in a breach that exposed passwords", TitleFR: "Aucune adresse du domaine dans une fuite de mots de passe"},
			{ID: CheckEmail, Category: module.CategoryLeaks, Severity: finding.SeverityLow,
				Title: "No address of the domain in a known data breach", TitleFR: "Aucune adresse du domaine dans une fuite de données connue"},
		},
	}
}

// ErrRateLimited is returned by lookup when XON refuses for now (HTTP 429).
var ErrRateLimited = errors.New("xposedornot rate limit reached")

// Breach is one breach an address appears in, as XON describes it.
type Breach struct {
	Name         string
	Domain       string
	Year         string
	Data         []string // kinds of data exposed: "Email addresses", "Passwords"...
	PasswordRisk string   // plaintext, easytocrack, hardtocrack, unknown
}

// exposesPasswords reports whether the breach exposed passwords.
func (b Breach) exposesPasswords() bool {
	for _, d := range b.Data {
		if strings.Contains(strings.ToLower(d), "password") {
			return true
		}
	}
	return false
}

// weakPasswords: stored in clear or easy to crack.
func (b Breach) weakPasswords() bool {
	r := strings.ToLower(b.PasswordRisk)
	return r == "plaintext" || r == "easytocrack"
}

// Run implements module.Module. It checks the addresses of the run's
// configuration that belong to the target's domain, at most MaxAddresses.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("leaks: %w", err)
	}
	var cfg module.RunConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			return module.Result{}, fmt.Errorf("leaks: config: %w", err)
		}
	}
	addrs := Addresses(cfg.Emails, domain)
	if len(addrs) == 0 {
		// Nothing to check: both checks are not applicable.
		return module.Result{}, nil
	}
	var res module.Result
	checked := 0
	for i, addr := range addrs {
		if i > 0 {
			select {
			case <-ctx.Done():
				return module.Result{}, ctx.Err()
			case <-time.After(m.cfg.Pace):
			}
		}
		breaches, err := m.lookup(ctx, addr)
		if errors.Is(err, ErrRateLimited) {
			// The rest keep their state: nothing was learned about them.
			res.Unreached = append(res.Unreached, addrs[i:]...)
			break
		}
		if err != nil {
			return module.Result{}, fmt.Errorf("leaks: %w", err)
		}
		checked++
		res.Findings = append(res.Findings, findingsFor(domain, addr, breaches)...)
	}
	if checked > 0 {
		res.Evaluated = []string{CheckPassword, CheckEmail}
	}
	return res, nil
}

// Addresses keeps the well-formed addresses on domain or under it,
// lowercased, without duplicates, at most MaxAddresses, in order.
func Addresses(list []string, domain string) []string {
	var out []string
	for _, a := range list {
		a = strings.ToLower(strings.TrimSpace(a))
		local, host, ok := strings.Cut(a, "@")
		if !ok || local == "" || strings.ContainsAny(local, " \t<>\"") || len(a) > 254 {
			continue
		}
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		if slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
		if len(out) == MaxAddresses {
			break
		}
	}
	return out
}

// xonAnswer is the part of XON's breach-analytics answer we use. Fields
// whose type varies (numbers or strings) are read leniently.
type xonAnswer struct {
	ExposedBreaches *struct {
		Details []struct {
			Breach       string          `json:"breach"`
			Domain       string          `json:"domain"`
			PasswordRisk string          `json:"password_risk"`
			XposedData   string          `json:"xposed_data"`
			XposedDate   json.RawMessage `json:"xposed_date"`
		} `json:"breaches_details"`
	} `json:"ExposedBreaches"`
}

// lookup asks XON which breaches addr appears in. No breach: nil, nil.
func (m *Module) lookup(ctx context.Context, addr string) ([]Breach, error) {
	u := m.cfg.BaseURL + "/v1/breach-analytics?email=" + url.QueryEscape(addr)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("User-Agent", userAgent)
	r.Header.Set("Accept", "application/json")
	if m.cfg.APIKey != "" {
		r.Header.Set("x-api-key", m.cfg.APIKey)
	}
	resp, err := m.cfg.HTTP.Do(r)
	if err != nil {
		return nil, fmt.Errorf("xposedornot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("xposedornot: read: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrRateLimited
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("xposedornot: status %d", resp.StatusCode)
	}
	var a xonAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, fmt.Errorf("xposedornot: decode: %w", err)
	}
	if a.ExposedBreaches == nil {
		return nil, nil
	}
	var out []Breach
	for _, d := range a.ExposedBreaches.Details {
		if strings.TrimSpace(d.Breach) == "" {
			continue
		}
		b := Breach{Name: clip(d.Breach, 80), Domain: clip(d.Domain, 120), PasswordRisk: clip(d.PasswordRisk, 20), Year: clip(rawText(d.XposedDate), 10)}
		for _, k := range strings.Split(d.XposedData, ";") {
			if k = strings.TrimSpace(k); k != "" {
				b.Data = append(b.Data, clip(k, 60))
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// rawText reads a JSON string or number as text.
func rawText(r json.RawMessage) string {
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(r, &n) == nil {
		return n.String()
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// findingsFor turns an address's breaches into at most two findings: one
// for the breaches that exposed passwords, one for the others.
func findingsFor(domain, addr string, breaches []Breach) []finding.Finding {
	var withPw, others []Breach
	for _, b := range breaches {
		if b.exposesPasswords() {
			withPw = append(withPw, b)
		} else {
			others = append(others, b)
		}
	}
	var out []finding.Finding
	if len(withPw) > 0 {
		sev := finding.SeverityMedium
		for _, b := range withPw {
			if b.weakPasswords() {
				sev = finding.SeverityHigh
			}
		}
		out = append(out, build(domain, addr, CheckPassword, sev, withPw,
			fmt.Sprintf("%s appears in %d data breach(es) that exposed passwords", addr, len(withPw)),
			fmt.Sprintf("%s figure dans %d fuite(s) de données qui ont exposé des mots de passe", addr, len(withPw)),
			"Attackers try leaked passwords on other services (credential stuffing). If this password, or a close one, is still used anywhere, especially for email, VPN or banking, that account can be taken over.",
			"Les attaquants essaient les mots de passe fuités sur d’autres services. Si ce mot de passe, ou un mot de passe proche, sert encore quelque part, en particulier pour la messagerie, le VPN ou la banque, ce compte peut être pris.",
			[]string{
				"Change this account's password now, and every account where the same or a similar password was used.",
				"Turn on two-factor authentication for the mailbox and for critical tools.",
				"Use a password manager so that each service has its own password.",
			},
			[]string{
				"Changez tout de suite le mot de passe de ce compte, et celui de chaque compte qui utilisait le même ou un mot de passe proche.",
				"Activez la double authentification sur la messagerie et sur les outils critiques.",
				"Utilisez un gestionnaire de mots de passe pour avoir un mot de passe différent par service.",
			}))
	}
	if len(others) > 0 {
		out = append(out, build(domain, addr, CheckEmail, finding.SeverityLow, others,
			fmt.Sprintf("%s appears in %d known data breach(es)", addr, len(others)),
			fmt.Sprintf("%s figure dans %d fuite(s) de données connue(s)", addr, len(others)),
			"The address and other personal data are in circulation. Expect targeted phishing that uses these details to look credible.",
			"L’adresse et d’autres données personnelles circulent. Attendez-vous à de l’hameçonnage ciblé qui s’appuie sur ces informations pour paraître crédible.",
			[]string{
				"Warn the person concerned: messages quoting these details may be phishing.",
				"Check that two-factor authentication protects the mailbox.",
			},
			[]string{
				"Prévenez la personne concernée : des messages citant ces informations peuvent être de l’hameçonnage.",
				"Vérifiez que la double authentification protège la messagerie.",
			}))
	}
	return out
}

func build(domain, addr, check string, sev finding.Severity, breaches []Breach, title, titleFR, desc, descFR string, steps, stepsFR []string) finding.Finding {
	var ev strings.Builder
	ev.WriteString("Source: XposedOrNot (xposedornot.com)\n")
	for i, b := range breaches {
		if i == maxBreachesShown {
			fmt.Fprintf(&ev, "and %d more\n", len(breaches)-i)
			break
		}
		fmt.Fprintf(&ev, "%s", b.Name)
		if b.Year != "" {
			fmt.Fprintf(&ev, " (%s)", b.Year)
		}
		if len(b.Data) > 0 {
			fmt.Fprintf(&ev, ": %s", strings.Join(b.Data, ", "))
		}
		if b.PasswordRisk != "" && b.exposesPasswords() {
			fmt.Fprintf(&ev, " [passwords: %s]", b.PasswordRisk)
		}
		ev.WriteString("\n")
	}
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, check, domain, addr),
		ModuleID:      ID,
		CheckID:       check,
		Target:        domain,
		Asset:         addr,
		Severity:      sev,
		Title:         title,
		Description:   desc,
		Evidence:      finding.TruncateEvidence(ev.String()),
		Remediation:   steps,
		References:    []string{"https://xposedornot.com"},
		Translations:  map[string]finding.Text{"fr": {Title: titleFR, Description: descFR, Remediation: stepsFR}},
	}
}
