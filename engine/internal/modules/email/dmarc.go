package email

import (
	"context"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

const refDMARC = "RFC 7489"

// parseDMARC returns the tags of record if it is a DMARC record, that is if
// its first tag is v=DMARC1 (RFC 7489 §6.3). Other TXT records published at
// _dmarc.<domain> must be ignored.
func parseDMARC(record string) (map[string]string, bool) {
	tags := parseTags(record)
	if len(tags) == 0 || tags[0].name != "v" || !strings.EqualFold(tags[0].value, "DMARC1") {
		return nil, false
	}
	return tagMap(tags), true
}

func checkDMARC(ctx context.Context, dns resolver.Resolver, domain string, receivesMail bool, ev *evaluated) ([]issue, error) {
	asset := "_dmarc." + domain
	txt, err := lookupTXT(ctx, dns, asset)
	if err != nil {
		return nil, err
	}
	ev.add(CheckDMARCMissing)
	var records []string
	var tags map[string]string
	for _, rec := range txt {
		if t, ok := parseDMARC(rec); ok {
			records = append(records, rec)
			tags = t
		}
	}

	// As for SPF, each step is evaluated only if the previous one passed.
	if len(records) > 0 {
		ev.add(CheckDMARCMultiple)
	}
	switch len(records) {
	case 0:
		return []issue{dmarcMissing(asset, receivesMail)}, nil
	case 1:
		// Analyzed below.
	default:
		return []issue{{
			checkID:     CheckDMARCMultiple,
			asset:       asset,
			severity:    finding.SeverityHigh,
			title:       "Several DMARC records",
			description: "More than one DMARC record is published. Receivers then apply no DMARC policy at all.",
			evidence:    strings.Join(records, "\n"),
			remediation: []string{"Keep a single DMARC record at " + asset + "."},
			references:  []string{refDMARC},
		}}, nil
	}

	record := records[0]
	policy := strings.ToLower(tags["p"])
	ev.add(CheckDMARCInvalid)
	switch policy {
	case "none", "quarantine", "reject":
	default:
		return []issue{{
			checkID:     CheckDMARCInvalid,
			asset:       asset,
			severity:    finding.SeverityHigh,
			title:       "Invalid DMARC record",
			description: "The DMARC record has a missing or unknown policy (p=). Without a valid policy, receivers do not apply DMARC.",
			evidence:    record,
			remediation: []string{"Set p=none, p=quarantine or p=reject in the DMARC record."},
			references:  []string{refDMARC},
		}}, nil
	}

	var issues []issue
	ev.add(CheckDMARCPolicyNone, CheckDMARCNoReporting)
	if policy == "none" {
		issues = append(issues, issue{
			checkID:     CheckDMARCPolicyNone,
			asset:       asset,
			severity:    finding.SeverityMedium,
			title:       "DMARC policy does not block spoofing",
			description: "The DMARC policy is p=none: receivers only report failures and still deliver spoofed mail. This is a monitoring stage, not protection.",
			evidence:    record,
			remediation: []string{
				"Read the DMARC reports to confirm all legitimate mail passes SPF or DKIM.",
				"Move to p=quarantine, then p=reject.",
			},
			references: []string{refDMARC},
		})
	} else {
		// Partial enforcement and subdomain policy only matter once the
		// policy enforces something.
		ev.add(CheckDMARCPartialEnforcement, CheckDMARCSubdomainNone)
		if pct, err := strconv.Atoi(tags["pct"]); err == nil && pct < 100 {
			issues = append(issues, issue{
				checkID:     CheckDMARCPartialEnforcement,
				asset:       asset,
				severity:    finding.SeverityLow,
				title:       "DMARC policy applies to only part of the mail",
				description: "The pct= tag limits the policy to a percentage of failing mail; the rest is delivered as if there were no policy.",
				evidence:    record,
				remediation: []string{"Raise pct to 100, or remove the pct tag (100 is the default)."},
				references:  []string{refDMARC},
			})
		}
		if strings.EqualFold(tags["sp"], "none") {
			issues = append(issues, issue{
				checkID:     CheckDMARCSubdomainNone,
				asset:       asset,
				severity:    finding.SeverityLow,
				title:       "Subdomains are not protected by DMARC",
				description: "The sp=none tag disables the policy for subdomains, so mail can still be spoofed from any subdomain (for example billing." + domain + ").",
				evidence:    record,
				remediation: []string{"Remove sp=none so subdomains inherit the main policy, or set sp=reject."},
				references:  []string{refDMARC},
			})
		}
	}
	if tags["rua"] == "" {
		i := issue{
			checkID:     CheckDMARCNoReporting,
			asset:       asset,
			severity:    finding.SeverityLow,
			title:       "DMARC reports are not collected",
			description: "The DMARC record has no rua= address, so you receive no reports about who sends mail in your name, legitimately or not.",
			evidence:    record,
			remediation: []string{"Add rua=mailto:<address> to receive aggregate reports."},
			references:  []string{refDMARC},
		}
		// Without mail, reports only tell who tried to spoof the domain;
		// the policy already blocks them. Useful to know, not a problem to
		// fix: reporting it as one would teach customers to ignore reports.
		if !receivesMail {
			i.severity = finding.SeverityInfo
			i.description = "The domain handles no mail and its DMARC policy already blocks spoofed messages. Adding a rua= address would also tell you who tries to send mail in its name."
			i.remediation = []string{"Optional: add rua=mailto:<address> to receive reports about spoofing attempts."}
		}
		issues = append(issues, i)
	}
	return issues, nil
}

func dmarcMissing(asset string, receivesMail bool) issue {
	i := issue{
		checkID:     CheckDMARCMissing,
		asset:       asset,
		severity:    finding.SeverityHigh,
		title:       "No DMARC record",
		description: "The domain publishes no DMARC policy. Receivers have no instruction to reject mail that fails SPF and DKIM, so the domain can be used for phishing.",
		references:  []string{refDMARC},
	}
	if receivesMail {
		i.remediation = []string{
			"Publish \"v=DMARC1; p=none; rua=mailto:<address>\" at " + asset + " to start collecting reports.",
			"After checking the reports, move to p=quarantine, then p=reject.",
		}
	} else {
		i.remediation = []string{
			"If the domain never sends mail, publish \"v=DMARC1; p=reject\" at " + asset + ".",
		}
	}
	return i
}
