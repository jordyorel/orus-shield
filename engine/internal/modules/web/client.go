package web

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// client sends the module's requests through the gate.
//
// Requests are written by hand on a connection from the gated dialer rather
// than with http.Client: each connection must go to the exact IP the gate
// approved, for the exact path it approved, and nothing (automatic
// redirects, keep-alive, proxies from the environment) may send a request
// behind the gate's back. Redirects are followed here, one gated request
// per hop.
type client struct {
	dns  resolver.Gated
	dial dialer.Gated
}

// response is what we keep of one HTTP response: never the body.
type response struct {
	url     *url.URL // what was requested: scheme, host, path
	ip      netip.Addr
	status  int
	header  http.Header
	cookies []*http.Cookie
	// location is the resolved redirect target, nil when the response is
	// not a redirect or its Location header is unusable.
	location *url.URL
}

func (r *response) redirect() bool { return r.status >= 300 && r.status < 400 }

// lookup returns at most maxIPsPerHost distinct addresses of host, or none
// when the name does not exist.
func (c client) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := c.dns.LookupIP(ctx, host)
	if errors.Is(err, resolver.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || seen[a] || len(out) == maxIPsPerHost {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// fetchPage requests "/" on host and follows redirects that stay on the same
// host and scheme (for example "/" to "/fr/"), at most maxRedirects times.
// It returns every response in order, or nil when the port did not answer.
// A redirect to another host is not followed: that host is checked on its
// own (www.) or is not the customer's.
func (c client) fetchPage(ctx context.Context, host string, ips []netip.Addr, port int) ([]*response, error) {
	var chain []*response
	path := "/"
	for range maxRedirects + 1 {
		r, err := c.fetch(ctx, host, ips, port, path)
		if err != nil || r == nil {
			return chain, err
		}
		chain = append(chain, r)
		next := r.location
		if !r.redirect() || next == nil || next.Scheme != r.url.Scheme ||
			!strings.EqualFold(next.Hostname(), host) || !defaultPort(next) {
			break
		}
		path = next.RequestURI()
	}
	return chain, nil
}

// defaultPort reports whether u uses its scheme's default port.
func defaultPort(u *url.URL) bool {
	switch u.Port() {
	case "":
		return true
	case "80":
		return u.Scheme == "http"
	case "443":
		return u.Scheme == "https"
	}
	return false
}

// fetch sends "GET path" to the first address of host that answers.
// It returns nil when none did (closed, silent, excluded, not HTTP).
func (c client) fetch(ctx context.Context, host string, ips []netip.Addr, port int, path string) (*response, error) {
	for _, ip := range ips {
		r, err := c.get(ctx, host, ip, port, path)
		if err == nil {
			return r, nil
		}
		if stop := stopError(ctx, err); stop != nil {
			return nil, stop
		}
	}
	return nil, nil
}

// get sends one request and reads the status line and headers.
func (c client) get(ctx context.Context, host string, ip netip.Addr, port int, requestURI string) (*response, error) {
	scheme := "http"
	if port == httpsPort {
		scheme = "https"
	}
	u, err := url.Parse(scheme + "://" + host + requestURI)
	if err != nil {
		return nil, fmt.Errorf("request url: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	// The gate sees the path, so path exclusions apply to every hop.
	conn, err := c.dial.Dial(ctx, module.Destination{Host: host, IP: ip, Port: port, Path: u.Path})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }() // read-only request: a close error changes nothing
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	rw := io.ReadWriter(conn)
	if scheme == "https" {
		tconn := tls.Client(conn, &tls.Config{
			ServerName: host,
			// Certificate problems are the tls module's job; here we only
			// read headers, and send nothing but a GET request.
			InsecureSkipVerify: true, //nolint:gosec // G402: deliberate, see comment above
			MinVersion:         tls.VersionTLS12,
		})
		if err := tconn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake with %s: %w", host, err)
		}
		rw = tconn
	}

	req := "GET " + u.RequestURI() + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + userAgent +
		"\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(rw, req); err != nil {
		return nil, fmt.Errorf("send request to %s: %w", host, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(rw, maxHeaderBytes)), &http.Request{Method: http.MethodGet, URL: u})
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", host, err)
	}
	_ = resp.Body.Close() // the body is never read

	r := &response{url: u, ip: ip, status: resp.StatusCode, header: resp.Header, cookies: resp.Cookies()}
	if r.redirect() {
		r.location = resolveLocation(u, resp.Header.Get("Location"))
	}
	return r, nil
}

// maxLocation bounds the redirect targets we accept.
const maxLocation = 2048

// resolveLocation parses a Location header (untrusted, rule 7) against the
// URL that returned it. Unusable values give nil: the redirect is then not
// followed nor judged.
func resolveLocation(base *url.URL, loc string) *url.URL {
	if loc == "" || len(loc) > maxLocation {
		return nil
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	next := base.ResolveReference(ref)
	if (next.Scheme != "http" && next.Scheme != "https") || next.Hostname() == "" || next.User != nil {
		return nil
	}
	return next
}
