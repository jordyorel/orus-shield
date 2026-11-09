package cdn

import "net/netip"

// Published address ranges of CDNs. An address in one of them is served by
// that CDN: a fact, not a guess, as long as the list is current.
//
// Retrieved on 2026-11-09 from the providers' official lists:
//   - Cloudflare: https://www.cloudflare.com/ips-v4 and /ips-v6
//   - Fastly: https://api.fastly.com/public-ip-list
//
// They change rarely but they do change: refresh them by hand until a
// periodic job does it (like the planned KEV ingestion). Other CDNs
// (CloudFront, Akamai, Azure) publish very long or frequently changing
// lists; they are recognized by their response headers instead.
var publishedRanges = map[string][]string{
	"cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	},
	"fastly": {
		"23.235.32.0/20", "43.249.72.0/22", "90.98.0.0/17", "90.98.128.0/18",
		"103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
		"140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
		"157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20",
		"167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
		"199.232.0.0/16",
		"2a04:4e40::/32", "2a04:4e42::/31", "2a04:4e44::/32",
	},
}

// rangeEntry is one parsed prefix and the CDN it belongs to.
type rangeEntry struct {
	prefix   netip.Prefix
	provider string
}

// ranges is publishedRanges parsed once. A malformed entry is a programming
// error caught by the tests, so parsing panics rather than silently
// shrinking the list.
var ranges = func() []rangeEntry {
	var out []rangeEntry
	for provider, list := range publishedRanges {
		for _, s := range list {
			out = append(out, rangeEntry{prefix: netip.MustParsePrefix(s), provider: provider})
		}
	}
	return out
}()

// providerOf returns the CDN whose published ranges contain ip, and the
// matching range, or ok false.
func providerOf(ip netip.Addr) (provider string, prefix netip.Prefix, ok bool) {
	ip = ip.Unmap()
	for _, r := range ranges {
		if r.prefix.Contains(ip) {
			return r.provider, r.prefix, true
		}
	}
	return "", netip.Prefix{}, false
}
