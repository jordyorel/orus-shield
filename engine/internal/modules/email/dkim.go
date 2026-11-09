package email

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

const (
	refDKIM        = "RFC 6376"
	refDKIMKeySize = "RFC 8301"
)

// dkimSelectors are common selector names. DKIM keys live at
// <selector>._domainkey.<domain>, and the selector is chosen freely by each
// mail provider. Passively, we can only try well-known names, so "not found"
// never proves that DKIM is absent.
var dkimSelectors = []string{
	"default", "dkim", "google", "k1", "k2", "mail", "s1", "s2", "selector1", "selector2",
}

// maxDKIMKeyChars bounds the base64 key we decode. A 4096-bit RSA key is
// about 740 characters; anything far larger is not a real key (rule 7).
const maxDKIMKeyChars = 4096

func checkDKIM(ctx context.Context, dns resolver.Resolver, domain string, receivesMail bool, ev *evaluated) ([]issue, error) {
	var issues []issue
	keysFound := 0
	for _, selector := range dkimSelectors {
		name := selector + "._domainkey." + domain
		txt, err := lookupTXT(ctx, dns, name)
		if err != nil {
			return nil, err
		}
		for _, record := range txt {
			tags := tagMap(parseTags(record))
			key, ok := tags["p"]
			if !ok {
				continue // not a DKIM key record
			}
			// Long keys are often split with spaces; base64 ignores none.
			key = strings.Join(strings.Fields(key), "")
			if key == "" {
				continue // revoked key (RFC 6376 §3.6.1)
			}
			keysFound++
			if i, ok := dkimKeyIssue(name, record, tags["k"], key); ok {
				issues = append(issues, i)
			}
		}
	}

	// Key checks need a key; "not found" is only meaningful for a domain
	// that receives mail (it is only reported then).
	if keysFound > 0 {
		ev.add(CheckDKIMInvalidKey, CheckDKIMWeakKey, CheckDKIMShortKey)
	}
	if receivesMail {
		ev.add(CheckDKIMNotFound)
	}
	if keysFound == 0 && receivesMail {
		issues = append(issues, issue{
			checkID:  CheckDKIMNotFound,
			asset:    "_domainkey." + domain,
			severity: finding.SeverityInfo,
			title:    "No DKIM key found under common selectors",
			description: fmt.Sprintf("We looked for DKIM keys under %d common selectors and found none. "+
				"Selectors are chosen freely, so your mail may still be signed with a selector we did not try. "+
				"If it is not, receivers cannot verify that your mail was not altered or forged.", len(dkimSelectors)),
			evidence: "selectors tried: " + strings.Join(dkimSelectors, ", "),
			remediation: []string{
				"Check in your mail provider's settings that DKIM signing is enabled.",
				"Publish the DKIM key the provider gives you as a TXT record at <selector>._domainkey." + domain + ".",
			},
			references: []string{refDKIM},
		})
	}
	return issues, nil
}

// dkimKeyIssue checks one published key. keyType is the k= tag (RSA when
// empty); key is the base64 p= value without whitespace.
func dkimKeyIssue(asset, record, keyType, key string) (issue, bool) {
	invalid := issue{
		checkID:     CheckDKIMInvalidKey,
		asset:       asset,
		severity:    finding.SeverityMedium,
		title:       "Unreadable DKIM key",
		description: "The DKIM record publishes a key that cannot be decoded. Receivers cannot verify signatures made with it, so signed mail is treated as unsigned.",
		evidence:    record,
		remediation: []string{"Copy the DKIM record again from your mail provider, without truncating the key."},
		references:  []string{refDKIM},
	}
	if len(key) > maxDKIMKeyChars {
		return invalid, true
	}
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return invalid, true
	}

	switch strings.ToLower(keyType) {
	case "ed25519": // RFC 8463: the raw 32-byte public key
		if len(der) != ed25519.PublicKeySize {
			return invalid, true
		}
		return issue{}, false
	case "", "rsa":
		// Handled below.
	default:
		return invalid, true
	}

	// RFC 6376 specifies a SubjectPublicKeyInfo (PKIX) key, but some
	// providers publish a bare PKCS #1 key, which receivers also accept.
	var pub *rsa.PublicKey
	if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return invalid, true
		}
		pub = rsaKey
	} else if pub, err = x509.ParsePKCS1PublicKey(der); err != nil {
		return invalid, true
	}

	bits := pub.N.BitLen()
	evidence := fmt.Sprintf("%s\nRSA key size: %d bits", record, bits)
	switch {
	case bits < 1024:
		return issue{
			checkID:     CheckDKIMWeakKey,
			asset:       asset,
			severity:    finding.SeverityHigh,
			title:       "DKIM key is too weak",
			description: fmt.Sprintf("The DKIM key is only %d bits. Keys this short can be factored, letting an attacker sign forged mail as you, and receivers must ignore signatures made with them.", bits),
			evidence:    evidence,
			remediation: []string{"Generate a new 2048-bit DKIM key in your mail provider and publish it, then remove the old one."},
			references:  []string{refDKIMKeySize},
		}, true
	case bits < 2048:
		return issue{
			checkID:     CheckDKIMShortKey,
			asset:       asset,
			severity:    finding.SeverityLow,
			title:       "DKIM key is shorter than recommended",
			description: fmt.Sprintf("The DKIM key is %d bits. It is still accepted, but 2048 bits is the recommended minimum.", bits),
			evidence:    evidence,
			remediation: []string{"Rotate to a 2048-bit DKIM key when convenient."},
			references:  []string{refDKIMKeySize},
		}, true
	default:
		return issue{}, false
	}
}
