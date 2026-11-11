package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultCrtshURL is the public crt.sh search endpoint.
const DefaultCrtshURL = "https://crt.sh/"

const (
	// crtshTimeout bounds one query. crt.sh is slow for large domains and
	// sometimes does not answer at all: two attempts and the pause between
	// them stay under the worker's module timeout (2 minutes).
	crtshTimeout    = 45 * time.Second
	crtshRetryAfter = 5 * time.Second
	// maxCrtshBytes bounds the response we read (rule 7: the service is a
	// third party; a domain with many certificates returns megabytes).
	maxCrtshBytes = 16 << 20
	// maxCrtshNames bounds the names we keep from it.
	maxCrtshNames = 5000
)

// Crtsh reads Certificate Transparency through crt.sh's JSON interface.
//
// The query goes to crt.sh, not to the customer: it reveals to crt.sh's
// operator which domain we look at (the data itself is public). It is not
// sent through the scan's gate, whose exclusions and rate are about the
// customer's servers.
type Crtsh struct {
	BaseURL string       // DefaultCrtshURL when empty
	Client  *http.Client // a client with crtshTimeout when nil
	// RetryAfter is the pause before the second attempt (tests shorten it).
	RetryAfter time.Duration
}

// crtshEntry is one certificate in crt.sh's answer. name_value holds the
// certificate's names separated by newlines.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// Names implements CTSource. It asks for every certificate of the domain
// and its subdomains ("%.example.com"), expired ones included: an old
// certificate still points at a name worth checking. crt.sh is often
// overloaded: a failed query is tried once more after a short pause.
func (c Crtsh) Names(ctx context.Context, domain string) ([]string, error) {
	names, err := c.query(ctx, domain)
	if err == nil || ctx.Err() != nil {
		return names, err
	}
	select {
	case <-ctx.Done():
		return nil, err
	case <-time.After(c.retryAfter()):
	}
	return c.query(ctx, domain)
}

func (c Crtsh) retryAfter() time.Duration {
	if c.RetryAfter > 0 {
		return c.RetryAfter
	}
	return crtshRetryAfter
}

func (c Crtsh) query(ctx context.Context, domain string) ([]string, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultCrtshURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: crtshTimeout}
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("crt.sh url: %w", err)
	}
	u.RawQuery = url.Values{"q": {"%." + domain}, "output": {"json"}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OrusShield/1 (+attack surface discovery)")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query crt.sh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query crt.sh: status %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, maxCrtshBytes+1)
	var entries []crtshEntry
	// An answer over the limit is cut, so it fails to decode: refused.
	if err := json.NewDecoder(body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode crt.sh answer (limit %d MB): %w", maxCrtshBytes>>20, err)
	}

	seen := make(map[string]bool)
	var names []string
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			names = append(names, n)
			if len(names) == maxCrtshNames {
				return names, nil
			}
		}
	}
	return names, nil
}
