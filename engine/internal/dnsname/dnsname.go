// Package dnsname validates and normalizes DNS names. It has no
// dependencies inside the engine, so every package can use it (module and
// asset both do, and asset cannot import module: module imports asset).
package dnsname

import (
	"errors"
	"fmt"
	"strings"
)

// Normalize lowercases d, removes a trailing dot, and rejects anything
// that is not a plausible DNS name. The domain is customer input that ends up
// in DNS queries and connections, so modules check it rather than trust it.
func Normalize(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" {
		return "", errors.New("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain %q: longer than 253 characters", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("domain %q: invalid label %q", d, label)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("domain %q: invalid character %q", d, r)
			}
		}
	}
	return d, nil
}
