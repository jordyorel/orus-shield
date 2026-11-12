package zap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// Logging in with a form is done here, not by ZAP: ZAP's per-user requests
// do not carry the upstream proxy's credential, and gateproxy requires it
// (that is what keeps other local programs off it). So we log in through
// gateproxy ourselves, every request checked by the gate, and hand ZAP the
// session as a Cookie header (applyAuth). A session that expires during a
// long scan is not renewed.

const (
	loginTimeout = 30 * time.Second
	maxLoginPage = 1 << 20
)

var (
	reForm     = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	reInput    = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	reAttr     = regexp.MustCompile(`(?is)([a-z][a-z0-9_-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	reNoScript = regexp.MustCompile(`(?is)<script\b.*?</script>`)
)

func attrs(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range reAttr.FindAllStringSubmatch(tag, -1) {
		v := m[3] + m[4] + m[5]
		out[strings.ToLower(m[1])] = html.UnescapeString(v)
	}
	return out
}

// loginForm finds the form with a password field: where it posts and its
// hidden fields (a CSRF token, for instance).
func loginForm(page string) (action string, hidden url.Values, ok bool) {
	page = reNoScript.ReplaceAllString(page, "")
	for _, f := range reForm.FindAllStringSubmatch(page, 20) {
		hasPassword := false
		hidden = url.Values{}
		for _, in := range reInput.FindAllStringSubmatch(f[2], 100) {
			a := attrs(in[1])
			switch strings.ToLower(a["type"]) {
			case "password":
				hasPassword = true
			case "hidden":
				if a["name"] != "" {
					hidden.Set(a["name"], a["value"])
				}
			}
		}
		if hasPassword {
			return attrs(f[1])["action"], hidden, true
		}
	}
	return "", nil, false
}

// ErrLoginFailed means the test account could not log in.
var ErrLoginFailed = errors.New("test account login failed")

// formLogin logs in through the proxy and returns the Cookie header of the
// session. Every URL stays in the domain (the form's action included).
func formLogin(ctx context.Context, proxyURL, domain string, auth *module.ScanAuth) (string, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout:   loginTimeout,
		Jar:       jar,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: insecureThroughProxy()},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || !inScope(req.URL.String(), domain) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	get := func(u string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxLoginPage))
		return string(b), err
	}

	page, err := get(auth.LoginURL)
	if err != nil {
		return "", fmt.Errorf("%w: load the login page: %w", ErrLoginFailed, err)
	}
	action, form, ok := loginForm(page)
	if !ok {
		return "", fmt.Errorf("%w: no form with a password field at %s", ErrLoginFailed, auth.LoginURL)
	}
	base, _ := url.Parse(auth.LoginURL)
	target := base
	if action != "" {
		if target, err = base.Parse(action); err != nil {
			return "", fmt.Errorf("%w: form action: %w", ErrLoginFailed, err)
		}
	}
	if !inScope(target.String(), domain) {
		return "", fmt.Errorf("%w: the form posts outside %s", ErrLoginFailed, domain)
	}
	uf, pf := auth.UsernameField, auth.PasswordField
	if uf == "" {
		uf = "username"
	}
	if pf == "" {
		pf = "password"
	}
	form.Set(uf, auth.Username)
	form.Set(pf, auth.Secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: send the form: %w", ErrLoginFailed, err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxLoginPage))
	_ = resp.Body.Close()
	// Still a login form, or an error status: the login did not work.
	if _, _, again := loginForm(string(body)); again || resp.StatusCode >= 400 {
		return "", fmt.Errorf("%w: the site answered %d with the login form again: check the username, the password and the field names", ErrLoginFailed, resp.StatusCode)
	}
	var parts []string
	for _, c := range jar.Cookies(base) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%w: no session cookie after the login", ErrLoginFailed)
	}
	return strings.Join(parts, "; "), nil
}

// insecureThroughProxy accepts gateproxy's throwaway certificate: gateproxy
// terminates TLS to see each request's path, and opens its own TLS
// connection to the target (see package gateproxy).
func insecureThroughProxy() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // G402: the peer is our local gateproxy, see above
}

// sessionAuth turns a form test account into the session it opens (a
// Cookie header); other accounts are returned as they are.
func sessionAuth(ctx context.Context, proxyURL, domain string, auth *module.ScanAuth) (*module.ScanAuth, error) {
	if auth == nil || auth.Kind != "form" {
		return auth, nil
	}
	cookie, err := formLogin(ctx, proxyURL, domain, auth)
	if err != nil {
		return nil, err
	}
	return &module.ScanAuth{Kind: "header", HeaderName: "Cookie", Secret: cookie}, nil
}
