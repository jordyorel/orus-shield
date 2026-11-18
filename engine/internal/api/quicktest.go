package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/modules/email"
	"github.com/jordyorel/orus-shield/engine/internal/modules/tlscheck"
	"github.com/jordyorel/orus-shield/engine/internal/modules/web"
	"github.com/jordyorel/orus-shield/engine/internal/quicktest"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// The public domain test of the home page (package quicktest), without an
// account. Its limits, so it cannot be turned against a domain or against
// us:
const (
	// quickCache: a domain tested within this window gets the same
	// result, without reaching it again.
	quickCache = time.Hour
	// quickPerIP: tests one address may ask per hour, cached ones included.
	quickPerIP = 10
	// quickPerHour: tests actually run per hour, by everyone.
	quickPerHour = 300
	// quickSlots: tests running at the same time in this process.
	quickSlots = 4
	// quickUnlockWindow: how long after a test its full report may be
	// asked for.
	quickUnlockWindow = 24 * time.Hour
	// leadsPerIP and leadsPerEmail bound the reports emailed per hour, so
	// the form cannot be used to flood someone's mailbox.
	leadsPerIP    = 10
	leadsPerEmail = 3
)

// quickRunner runs the real passive modules: email, TLS, web.
func quickRunner(dns resolver.Resolver) func(ctx context.Context, domain string) (quicktest.Report, error) {
	mods := []module.Module{email.New(dns), tlscheck.New(dns, dialer.NewSystem()), web.New(dns, dialer.NewSystem())}
	return func(ctx context.Context, domain string) (quicktest.Report, error) {
		return quicktest.Run(ctx, mods, domain, time.Now())
	}
}

type quickRequest struct {
	Domain string `json:"domain"`
}

// quickProblem is a failed check of a test: what anyone may see without
// leaving an email (public facts, as other public testers show).
type quickProblem struct {
	CheckID  string   `json:"check_id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	TitleFR  string   `json:"title_fr"`
	Hosts    []string `json:"hosts"`
	// Details: the explanation and steps, in English and French, only in
	// the answer to an email (unlock).
	Details *quickDetails `json:"details,omitempty"`
}

type quickDetails struct {
	Description   string   `json:"description"`
	Remediation   []string `json:"remediation"`
	DescriptionFR string   `json:"description_fr"`
	RemediationFR []string `json:"remediation_fr"`
}

type quickResponse struct {
	ID        string            `json:"id"`
	Domain    string            `json:"domain"`
	Score     *int              `json:"score"`
	At        time.Time         `json:"at"`
	Checks    []quicktest.Check `json:"checks"`
	Problems  []quickProblem    `json:"problems"`
	Unreached []string          `json:"unreached"`
}

// problemsOf groups a report's findings by check, most severe first: the
// same check failing on the name and its www is one problem.
func problemsOf(rep quicktest.Report, details bool) []quickProblem {
	by := map[string]*quickProblem{}
	var order []string
	for _, f := range rep.Findings {
		// Info findings describe, they do not warn (they weigh nothing in
		// the score): not problems, as on the dashboard.
		if f.Severity == finding.SeverityInfo {
			continue
		}
		p := by[f.CheckID]
		if p == nil {
			fr := f.Localized("fr")
			p = &quickProblem{CheckID: f.CheckID, Severity: string(f.Severity), Title: f.Title, TitleFR: fr.Title, Hosts: []string{}}
			if details {
				p.Details = &quickDetails{Description: f.Description, Remediation: nonNil(f.Remediation), DescriptionFR: fr.Description, RemediationFR: nonNil(fr.Remediation)}
			}
			by[f.CheckID] = p
			order = append(order, f.CheckID)
		}
		if f.Severity.Rank() > finding.Severity(p.Severity).Rank() {
			p.Severity = string(f.Severity)
		}
		if h := hostOfAsset(f.Asset); h != "" && !slices.Contains(p.Hosts, h) {
			p.Hosts = append(p.Hosts, h)
		}
	}
	out := make([]quickProblem, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return finding.Severity(out[i].Severity).Rank() > finding.Severity(out[j].Severity).Rank()
	})
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// hostOfAsset is the name a finding's asset is about: a URL's host, the
// name of "name:443", and the domain of "_dmarc.example.com" or
// "s1._domainkey.example.com".
func hostOfAsset(a string) string {
	a, _, _ = strings.Cut(a, "#")
	if u, err := url.Parse(a); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	if _, after, ok := strings.Cut(a, "._domainkey."); ok {
		return after
	}
	return strings.TrimPrefix(a, "_dmarc.")
}

// quickTest answers POST /api/v1/quicktest: the public test of a domain.
// 200 with the score and the failed checks (no explanations); 400 for a
// name that is not a public domain; 429 over the address's limit; 503
// when too many tests run; 422 when nothing could be checked.
func (s *Server) quickTest(w http.ResponseWriter, r *http.Request) {
	var req quickRequest
	if !decode(w, r, &req) {
		return
	}
	domain, err := quicktest.NormalizeDomain(req.Domain)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_domain", "enter a public domain name, such as example.com")
		return
	}
	ip := account.ClientFrom(r).IP
	now := s.cfg.Now()
	counts, err := s.public.QuickTestCounts(r.Context(), ip, now.Add(-time.Hour))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if counts.ByIP >= quickPerIP {
		writeErrorCode(w, http.StatusTooManyRequests, "rate_limited", "too many tests from this address, try again in an hour")
		return
	}
	raw, cached, err := s.public.CachedQuickTest(r.Context(), domain, now.Add(-quickCache))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !cached {
		if counts.Run >= quickPerHour {
			writeErrorCode(w, http.StatusServiceUnavailable, "busy", "too many tests right now, try again in a few minutes")
			return
		}
		select {
		case s.quickSlots <- struct{}{}:
		default:
			writeErrorCode(w, http.StatusServiceUnavailable, "busy", "too many tests right now, try again in a minute")
			return
		}
		rep, err := s.cfg.QuickTest(r.Context(), domain)
		<-s.quickSlots
		if errors.Is(err, quicktest.ErrInvalidDomain) {
			writeErrorCode(w, http.StatusBadRequest, "invalid_domain", "enter a public domain name, such as example.com")
			return
		}
		if err != nil {
			s.log.Info("quick test found nothing to check", "err", err)
			writeErrorCode(w, http.StatusUnprocessableEntity, "unreachable", "nothing could be checked on this domain: does it exist?")
			return
		}
		if raw, err = json.Marshal(rep); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	id, err := s.public.RecordQuickTest(r.Context(), domain, ip, raw, cached, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var rep quicktest.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, quickResponse{ID: id, Domain: rep.Domain, Score: rep.Score, At: rep.At,
		Checks: rep.Checks, Problems: problemsOf(rep, false), Unreached: rep.Unreached})
}

type unlockRequest struct {
	Email string `json:"email"`
	// Marketing: the visitor also agrees to receive our messages
	// (optional; the report is sent either way).
	Marketing bool `json:"marketing"`
}

// unlockQuickTest answers POST /api/v1/quicktest/{id}/unlock: the visitor
// leaves an email, gets the explanations and steps of every problem, and
// the report by email. 404 for an unknown or old test, 400 for a bad
// address, 429 over the limits.
func (s *Server) unlockQuickTest(w http.ResponseWriter, r *http.Request) {
	var req unlockRequest
	if !decode(w, r, &req) {
		return
	}
	to, err := store.NormalizeEmail(req.Email)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_email", "enter a valid email address")
		return
	}
	c := account.ClientFrom(r)
	now := s.cfg.Now()
	domain, raw, err := s.public.QuickTest(r.Context(), r.PathValue("id"), now.Add(-quickUnlockWindow))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown or expired test")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	byIP, byEmail, err := s.public.LeadCounts(r.Context(), c.IP, to, now.Add(-time.Hour))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if byIP >= leadsPerIP || byEmail >= leadsPerEmail {
		writeErrorCode(w, http.StatusTooManyRequests, "rate_limited", "too many reports asked, try again in an hour")
		return
	}
	var rep quicktest.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.public.AddLead(r.Context(), store.Lead{TestID: r.PathValue("id"), Email: to, Domain: domain, Lang: c.Lang, Marketing: req.Marketing, IP: c.IP}); err != nil {
		s.internalError(w, r, err)
		return
	}
	problems := problemsOf(rep, true)
	s.sendQuickReport(r.Context(), mailer.ParseLang(c.Lang), to, rep, problems)
	writeJSON(w, http.StatusOK, map[string]any{"problems": problems, "emailed": s.cfg.Mailer != nil})
}

// sendQuickReport emails the report in the background; a failure is
// logged without the address.
func (s *Server) sendQuickReport(ctx context.Context, lang mailer.Lang, to string, rep quicktest.Report, problems []quickProblem) {
	if s.cfg.Mailer == nil {
		s.log.Warn("email not sent: mail is not configured (ORUS_SMTP_ADDR)", "kind", "quick_test")
		return
	}
	items := make([]mailer.QuickItem, 0, len(problems))
	for _, p := range problems {
		it := mailer.QuickItem{Severity: p.Severity, Title: p.Title, Steps: p.Details.Remediation}
		if lang == mailer.French {
			it.Title, it.Steps = p.TitleFR, p.Details.RemediationFR
		}
		items = append(items, it)
	}
	m := mailer.QuickTestReport(lang, to, rep.Domain, rep.Score, items, mailer.SignupDomainLink(s.cfg.PublicURL, rep.Domain))
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.cfg.Mailer.Send(ctx, m); err != nil {
			s.log.Error("email delivery failed", "kind", "quick_test", "err", err)
		}
	}()
}
