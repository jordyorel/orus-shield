package m365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Limits on what we read from Microsoft (rule 7: a provider's answer is
// untrusted input too).
const (
	maxBody  = 8 << 20 // one page of a Graph answer
	maxPages = 20      // pages followed for one collection
)

var (
	// ErrThrottled: Microsoft asked us to slow down (HTTP 429). The run
	// stops; findings keep their state until the next scan.
	ErrThrottled = errors.New("microsoft graph throttled the requests")
	// errForbidden: the permission is not granted, or the tenant's licence
	// does not include the data (sign-in activity needs Entra ID P1). The
	// checks that need it are not applicable.
	errForbidden = errors.New("forbidden")
	// errNotFound: e.g. a user without a mailbox.
	errNotFound = errors.New("not found")
)

// graph is one tenant's Graph client, with its access token.
type graph struct {
	http  *http.Client
	base  string // e.g. https://graph.microsoft.com/v1.0, no trailing slash
	token string
	roles []string // the permissions the token carries
	pace  time.Duration
	calls int
}

// token gets an app-only access token for tenant with the client
// credentials grant: our app's ID and secret, in the tenant whose admin
// consented. Nothing of the customer's is needed.
func fetchToken(ctx context.Context, hc *http.Client, loginURL, tenant, clientID, secret string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	u := loginURL + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("token: read: %w", err)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(body, &t)
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		// The error code only (e.g. invalid_client, or unauthorized_client
		// when the consent was withdrawn): the description may echo input.
		return "", fmt.Errorf("token: status %d %s", resp.StatusCode, clip(t.Error, 60))
	}
	return t.AccessToken, nil
}

// get reads one Graph resource into out. path is relative to base
// ("/organization?..."), or a nextLink, which must point back to base:
// a link elsewhere would send our token to another host.
func (g *graph) get(ctx context.Context, path string, out any) error {
	u := path
	if strings.HasPrefix(path, "/") {
		u = g.base + path
	} else if !strings.HasPrefix(path, g.base+"/") {
		return fmt.Errorf("graph: refusing link outside %s", g.base)
	}
	if g.calls > 0 && g.pace > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(g.pace):
		}
	}
	g.calls++
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("graph: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("graph: read: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return ErrThrottled
	case http.StatusForbidden, http.StatusUnauthorized:
		return errForbidden
	case http.StatusNotFound:
		return errNotFound
	default:
		return fmt.Errorf("graph: status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("graph: decode: %w", err)
	}
	return nil
}

// page is a Graph collection page.
type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// list reads a collection, following its pages, up to limit items.
// truncated is true when items were left out.
func list[T any](ctx context.Context, g *graph, path string, limit int) (items []T, truncated bool, err error) {
	for i := 0; path != "" && i < maxPages; i++ {
		var p page[T]
		if err := g.get(ctx, path, &p); err != nil {
			return nil, false, err
		}
		for _, v := range p.Value {
			if len(items) == limit {
				return items, true, nil
			}
			items = append(items, v)
		}
		path = p.NextLink
	}
	return items, path != "", nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
