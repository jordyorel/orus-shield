// Package gateproxy is a local HTTP proxy that puts an external scanner
// (Nuclei) under the same security rules as our own modules.
//
// An external program opens its own connections: left alone, it would ignore
// customer exclusions, the rate limiter and per-IP ownership (security rules
// 1 to 3). Instead it is started with this proxy as its only route out. The
// proxy:
//
//   - listens on 127.0.0.1 only and requires a random per-scan credential, so
//     no other local process can use it;
//   - accepts only names equal to or under the scan's domain;
//   - resolves names itself through the gated resolver, and connects through
//     the gated dialer: one gate call per request, carrying the request's
//     path, so IP, port, path and host exclusions, the rate limit and the
//     IPGate apply to every single request;
//   - terminates the scanner's TLS (CONNECT) with a throwaway certificate so
//     it can see the path of HTTPS requests; the scanner does not verify
//     certificates, and the connection to the target is TLS again;
//   - opens a new connection per request (no reuse behind the gate's back)
//     and bounds request and response sizes (rule 7).
//
// A refused request gets a 403 with the X-Orus-Refused header: the scanner
// sees a dead end, never the target. A target that does not answer gets
// its connection closed, as it would without the proxy.
package gateproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

const (
	// maxRequestHeader and maxRequestBody bound what the scanner sends us.
	maxRequestHeader = 64 << 10
	maxRequestBody   = 1 << 20
	// maxResponseHeader and maxResponseBody bound what we read from the
	// target and relay (rule 7). Longer bodies are cut: detection templates
	// match on the start of a page.
	maxResponseHeader = 64 << 10
	maxResponseBody   = 2 << 20
	// requestTimeout bounds one upstream exchange, dial to last byte.
	requestTimeout = 15 * time.Second
	// idleTimeout closes a scanner connection that sends nothing.
	idleTimeout = 60 * time.Second
	// maxIPsPerHost bounds the addresses tried per name.
	maxIPsPerHost = 4
	// RefusedHeader marks the proxy's own refusals.
	RefusedHeader = "X-Orus-Refused"
)

// Config is what one proxy needs. It serves one scan of one target.
type Config struct {
	// Domain is the normalized target domain: only it and names under it
	// are reachable.
	Domain string
	// Gate is the scan's gate; for an active module, the IPGate.
	Gate module.Gate
	// DNS and Dial are the underlying resolver and dialer; the proxy wraps
	// both with Gate.
	DNS  resolver.Resolver
	Dial dialer.Dialer
}

// Stats counts what went through the proxy.
type Stats struct {
	Requests int64 // requests received from the scanner
	Answered int64 // requests the target answered
	Refused  int64 // requests refused (scope, exclusions, unverified IPs)
}

// Proxy is a running proxy. Close it when the scanner has exited.
type Proxy struct {
	cfg      Config
	dns      resolver.Gated
	dial     dialer.Gated
	ln       net.Listener
	user     string
	pass     string
	tlsConf  *tls.Config
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	requests atomic.Int64
	answered atomic.Int64
	refused  atomic.Int64

	mu    sync.Mutex
	ips   map[string][]netip.Addr // resolved names, for the proxy's lifetime
	hosts map[string]*hostCount   // per name: answered and refused requests
	err   error                   // first fatal gate error (cancelled scan, rate limiter)
	conns map[net.Conn]bool
}

// Start listens on a random port of 127.0.0.1 and serves until Close or
// until ctx ends.
func Start(ctx context.Context, cfg Config) (*Proxy, error) {
	domain, err := dnsname.Normalize(cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("gateproxy: %w", err)
	}
	if cfg.Gate == nil || cfg.DNS == nil || cfg.Dial == nil {
		return nil, errors.New("gateproxy: gate, resolver and dialer are required")
	}
	cfg.Domain = domain
	cert, err := throwawayCert()
	if err != nil {
		return nil, fmt.Errorf("gateproxy: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("gateproxy: listen: %w", err)
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &Proxy{
		cfg:  cfg,
		dns:  resolver.Gated{Gate: cfg.Gate, Inner: cfg.DNS},
		dial: dialer.Gated{Gate: cfg.Gate, Inner: cfg.Dial},
		ln:   ln,
		user: "orus",
		pass: randomToken(),
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"}, // no HTTP/2 inside the tunnel
		},
		ctx:    pctx,
		cancel: cancel,
		ips:    map[string][]netip.Addr{},
		hosts:  map[string]*hostCount{},
		conns:  map[net.Conn]bool{},
	}
	p.wg.Add(1)
	go p.serve()
	go func() {
		<-pctx.Done()
		_ = p.ln.Close()
		p.closeConns()
	}()
	return p, nil
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

// URL is the proxy address with its credential, for the scanner's proxy
// setting. It is a secret for the scan's duration: pass it in a file, not
// on a command line other local users could read.
func (p *Proxy) URL() string {
	return (&url.URL{Scheme: "http", User: url.UserPassword(p.user, p.pass), Host: p.ln.Addr().String()}).String()
}

// Stats returns the counters so far.
func (p *Proxy) Stats() Stats {
	return Stats{Requests: p.requests.Load(), Answered: p.answered.Load(), Refused: p.refused.Load()}
}

type hostCount struct{ answered, refused int }

func (p *Proxy) count(host string, answered bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.hosts[host]
	if c == nil {
		c = &hostCount{}
		p.hosts[host] = c
	}
	if answered {
		c.answered++
	} else {
		c.refused++
	}
}

// Unreached returns the names the scanner asked for that the gate never let
// through (excluded, or every address unverified): nothing was learned
// about them, so their findings must keep their state.
func (p *Proxy) Unreached() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for h, c := range p.hosts {
		if c.refused > 0 && c.answered == 0 {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out
}

// Err returns the first error that should stop the scan (cancelled scan,
// rate limiter failure), or nil. Refusals for exclusions are not errors.
func (p *Proxy) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close stops the proxy and waits for its connections to end.
func (p *Proxy) Close() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		if !p.track(conn) {
			_ = conn.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(conn)
			p.handleConn(conn)
		}()
	}
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return false
	}
	p.conns[c] = true
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *Proxy) closeConns() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		_ = c.Close()
	}
}

func (p *Proxy) fatal(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
}

// budget is a reader whose byte allowance is reset before each request, so
// one request cannot make us buffer without bound.
type budget struct {
	r io.Reader
	n int64
}

func (b *budget) Read(buf []byte) (int, error) {
	if b.n <= 0 {
		return 0, errors.New("request too large")
	}
	if int64(len(buf)) > b.n {
		buf = buf[:b.n]
	}
	n, err := b.r.Read(buf)
	b.n -= int64(n)
	return n, err
}

// handleConn serves one scanner connection: plain proxy requests
// (absolute-form URLs) or one CONNECT tunnel.
func (p *Proxy) handleConn(conn net.Conn) {
	lim := &budget{r: conn}
	br := bufio.NewReader(lim)
	for {
		lim.n = maxRequestHeader + maxRequestBody
		_ = conn.SetDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if !p.authorized(req) {
			_ = writeStatus(conn, req, http.StatusProxyAuthRequired, "proxy authentication required",
				http.Header{"Proxy-Authenticate": {`Basic realm="orus"`}})
			return
		}
		if req.Method == http.MethodConnect {
			p.tunnel(conn, br, req)
			return
		}
		if req.URL.Scheme != "http" || req.URL.Host == "" {
			_ = writeStatus(conn, req, http.StatusBadRequest, "absolute http:// URL expected", nil)
			return
		}
		if !p.exchange(conn, req, "http", req.URL.Host) || req.Close {
			return
		}
	}
}

func (p *Proxy) authorized(req *http.Request) bool {
	h := req.Header.Get("Proxy-Authorization")
	raw, ok := strings.CutPrefix(h, "Basic ")
	if !ok {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	want := p.user + ":" + p.pass
	return subtle.ConstantTimeCompare(dec, []byte(want)) == 1
}

// tunnel answers a CONNECT, terminates the scanner's TLS and serves the
// requests inside as https:// requests to the CONNECT authority.
func (p *Proxy) tunnel(conn net.Conn, br *bufio.Reader, connect *http.Request) {
	authority := connect.Host
	if _, _, ok := p.inScope(authority, 443); !ok {
		p.refused.Add(1)
		_ = writeStatus(conn, connect, http.StatusForbidden, "outside the scan's domain", http.Header{RefusedHeader: {"scope"}})
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	// Bytes the scanner sent right after CONNECT (start of the TLS
	// handshake) may already sit in br.
	inner := tls.Server(&prefixConn{Conn: conn, r: br}, p.tlsConf)
	_ = inner.SetDeadline(time.Now().Add(idleTimeout))
	if err := inner.HandshakeContext(p.ctx); err != nil {
		return
	}
	lim := &budget{r: inner}
	tbr := bufio.NewReader(lim)
	for {
		lim.n = maxRequestHeader + maxRequestBody
		_ = inner.SetDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		if !p.exchange(inner, req, "https", authority) || req.Close {
			return
		}
	}
}

// prefixConn reads first what a bufio.Reader already buffered.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// inScope parses an authority ("host" or "host:port") and accepts it only
// for the scan's domain or a name under it.
func (p *Proxy) inScope(authority string, defaultPort int) (host string, port int, ok bool) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		host, portStr = authority, strconv.Itoa(defaultPort)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	n, err := dnsname.Normalize(host)
	if err != nil || (n != p.cfg.Domain && !strings.HasSuffix(n, "."+p.cfg.Domain)) {
		return "", 0, false
	}
	return n, port, true
}

// exchange forwards one request and writes the answer to the scanner. It
// returns false when the scanner connection should be closed.
func (p *Proxy) exchange(w io.Writer, req *http.Request, scheme, authority string) bool {
	p.requests.Add(1)
	defaultPort := 80
	if scheme == "https" {
		defaultPort = 443
	}
	host, port, ok := p.inScope(authority, defaultPort)
	if !ok {
		p.refused.Add(1)
		return writeStatus(w, req, http.StatusForbidden, "outside the scan's domain", http.Header{RefusedHeader: {"scope"}}) == nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody+1))
	if err != nil || len(body) > maxRequestBody {
		_ = writeStatus(w, req, http.StatusRequestEntityTooLarge, "request body too large", nil)
		return false
	}

	resp, err := p.forward(req, scheme, host, port, body)
	if err != nil {
		var refusal *refusalError
		if errors.As(err, &refusal) {
			p.refused.Add(1)
			if refusal.kind == "excluded" {
				p.count(host, false)
			}
			return writeStatus(w, req, http.StatusForbidden, refusal.reason, http.Header{RefusedHeader: {refusal.kind}}) == nil
		}
		// The target did not answer: close the scanner's connection, as
		// the target would have. Nuclei counts that as a host error and
		// gives up on a dead site after a few, instead of spending
		// thousands of rate-limit slots on it.
		return false
	}
	defer func() { _ = resp.Body.Close() }() // an in-memory body: nothing to release, but explicit
	p.answered.Add(1)
	p.count(host, true)
	resp.Close = req.Close
	return resp.Write(w) == nil
}

// refusalError is a request we did not send.
type refusalError struct{ kind, reason string }

func (e *refusalError) Error() string { return e.reason }

// forward sends one request to host:port through the gate and returns the
// bounded response.
func (p *Proxy) forward(req *http.Request, scheme, host string, port int, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(p.ctx, requestTimeout)
	defer cancel()

	ips, err := p.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	excluded := 0
	for _, ip := range ips {
		c, err := p.dial.Dial(ctx, module.Destination{Host: host, IP: ip, Port: port, Path: req.URL.Path})
		if err == nil {
			conn = c
			break
		}
		if errors.Is(err, module.ErrExcluded) {
			excluded++
			continue
		}
		if errors.Is(err, dialer.ErrGateRefused) {
			// Not an exclusion: the rate limiter gave up waiting, because the
			// scan ended (fatal) or this request ran out of time.
			if p.ctx.Err() != nil {
				p.fatal(err)
			}
			return nil, &refusalError{"busy", "rate limit wait interrupted"}
		}
		// Connection refused or timed out: try the next address.
	}
	if conn == nil {
		if excluded > 0 && excluded == len(ips) {
			return nil, &refusalError{"excluded", "excluded or unverified destination"}
		}
		return nil, errors.New("no address answered")
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	rw := io.ReadWriter(conn)
	if scheme == "https" {
		tconn := tls.Client(conn, &tls.Config{
			ServerName: host,
			// Certificates are the tls module's job; the scanner checks
			// applications, it must reach them even with a bad certificate.
			InsecureSkipVerify: true, //nolint:gosec // G402: deliberate, see comment above
			MinVersion:         tls.VersionTLS10,
		})
		if err := tconn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake with %s: %w", host, err)
		}
		rw = tconn
	}

	out := outgoing(req, body)
	if err := out.Write(rw); err != nil {
		return nil, fmt.Errorf("send request to %s: %w", host, err)
	}
	br := bufio.NewReader(io.LimitReader(rw, maxResponseHeader+maxResponseBody))
	resp, err := http.ReadResponse(br, out)
	for err == nil && resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
		resp, err = http.ReadResponse(br, out) // skip 1xx interim answers
	}
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", host, err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		return nil, &refusalError{"protocol", "protocol upgrades are not relayed"}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody)) // a cut body is still relayed
	_ = resp.Body.Close()
	clean := &http.Response{
		Status: resp.Status, StatusCode: resp.StatusCode,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: resp.Header.Clone(), Body: io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)), Request: req,
	}
	removeHopHeaders(clean.Header)
	clean.Header.Del("Content-Length")
	return clean, nil
}

// lookup resolves host once per proxy (each lookup costs a rate-limit slot).
func (p *Proxy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	p.mu.Lock()
	ips, ok := p.ips[host]
	p.mu.Unlock()
	if ok {
		return ips, nil
	}
	addrs, err := p.dns.LookupIP(ctx, host)
	switch {
	case errors.Is(err, resolver.ErrNotFound):
		addrs = nil
	case errors.Is(err, module.ErrExcluded):
		return nil, &refusalError{"excluded", "excluded name"}
	case err != nil && p.ctx.Err() != nil:
		p.fatal(err)
		return nil, &refusalError{"stopped", "scan stopped"}
	case err != nil:
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && !seen[a] && len(ips) < maxIPsPerHost {
			seen[a] = true
			ips = append(ips, a)
		}
	}
	p.mu.Lock()
	p.ips[host] = ips
	p.mu.Unlock()
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", host)
	}
	return ips, nil
}

// hopHeaders are meaningful for one connection only (RFC 9110 7.6.1), plus
// the proxy credential, which must never reach the target.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

// outgoing is the request sent to the target: origin-form URL, the
// scanner's headers without hop-by-hop ones, one request per connection.
func outgoing(req *http.Request, body []byte) *http.Request {
	h := req.Header.Clone()
	removeHopHeaders(h)
	u := &url.URL{Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	if u.Path == "" {
		u.Path = "/"
	}
	out := &http.Request{
		Method: req.Method, URL: u, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, Host: req.Host, Close: true, ContentLength: int64(len(body)),
	}
	if len(body) > 0 {
		out.Body = io.NopCloser(bytes.NewReader(body))
	}
	return out
}

// writeStatus writes the proxy's own short answer.
func writeStatus(w io.Writer, req *http.Request, code int, msg string, h http.Header) error {
	if h == nil {
		h = http.Header{}
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	body := "orus shield proxy: " + msg + "\n"
	resp := &http.Response{
		StatusCode: code, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: h,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}
	return resp.Write(w)
}
