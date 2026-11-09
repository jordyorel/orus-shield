package cdn

import (
	"net/http"
	"strings"
)

// signature recognizes a CDN or WAF from response headers. Each one is a
// header the provider documents or always adds; matching it is evidence,
// not a heuristic score.
type signature struct {
	provider string
	// waf is true for products whose purpose is filtering attacks (a web
	// application firewall). A CDN may also offer a WAF, but its headers do
	// not tell whether it is enabled, so we never claim it.
	waf   bool
	match func(h http.Header) (evidence string, ok bool)
}

// has matches when the header is present.
func has(name string) func(http.Header) (string, bool) {
	return func(h http.Header) (string, bool) {
		if h.Get(name) != "" {
			return "header " + strings.ToLower(name), true
		}
		return "", false
	}
}

// contains matches when the header's value contains want (case-insensitive).
func contains(name, want string) func(http.Header) (string, bool) {
	return func(h http.Header) (string, bool) {
		for _, v := range h.Values(name) {
			if strings.Contains(strings.ToLower(v), want) {
				return "header " + strings.ToLower(name) + " contains " + want, true
			}
		}
		return "", false
	}
}

func anyOf(fns ...func(http.Header) (string, bool)) func(http.Header) (string, bool) {
	return func(h http.Header) (string, bool) {
		for _, fn := range fns {
			if ev, ok := fn(h); ok {
				return ev, true
			}
		}
		return "", false
	}
}

// signatures are tried in order. WAF products come first: Sucuri and
// Imperva sit in front of the site and may forward headers of a CDN behind
// them.
var signatures = []signature{
	{provider: "sucuri", waf: true, match: anyOf(has("X-Sucuri-Id"), contains("Server", "sucuri"))},
	{provider: "imperva", waf: true, match: anyOf(has("X-Iinfo"), contains("X-Cdn", "imperva"), contains("X-Cdn", "incapsula"))},
	{provider: "cloudflare", match: anyOf(has("Cf-Ray"), contains("Server", "cloudflare"))},
	{provider: "cloudfront", match: anyOf(has("X-Amz-Cf-Id"), contains("Via", "cloudfront"))},
	{provider: "fastly", match: anyOf(has("X-Fastly-Request-Id"), has("Fastly-Debug-Digest"))},
	{provider: "akamai", match: anyOf(contains("Server", "akamaighost"), has("X-Akamai-Transformed"))},
	{provider: "azure-front-door", match: has("X-Azure-Ref")},
	{provider: "vercel", match: has("X-Vercel-Id")},
	{provider: "netlify", match: has("X-Nf-Request-Id")},
}

// detect returns the first signature matching h.
func detect(h http.Header) (sig signature, evidence string, ok bool) {
	for _, s := range signatures {
		if ev, ok := s.match(h); ok {
			return s, ev, true
		}
	}
	return signature{}, "", false
}
