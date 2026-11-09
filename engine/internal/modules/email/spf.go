package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// spfLookupLimit is the maximum number of DNS-querying terms an SPF
// evaluation may use (RFC 7208 section 4.6.4). Beyond it, receivers return
// "permerror" and SPF fails entirely.
const spfLookupLimit = 10

const refSPF = "RFC 7208"

// spfRecord is what we need from a parsed SPF record.
type spfRecord struct {
	all      string   // qualifier of the "all" mechanism: "+", "-", "~", "?"; empty if absent
	redirect string   // target of the redirect= modifier, if any
	includes []string // targets of include: mechanisms
	lookups  int      // DNS-querying terms in this record alone
	unknown  []string // terms we do not recognize (syntax errors)
}

// targets returns the domains whose SPF records this record pulls in.
// redirect= is ignored when an "all" mechanism is present (RFC 7208 §6.1).
func (r spfRecord) targets() []string {
	if r.all == "" && r.redirect != "" {
		return append(r.includes[:len(r.includes):len(r.includes)], r.redirect)
	}
	return r.includes
}

// isSPF reports whether a TXT record is an SPF record: its first term is
// "v=spf1", case-insensitive.
func isSPF(record string) bool {
	fields := strings.Fields(record)
	return len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1")
}

// parseSPF parses a record for which isSPF is true.
func parseSPF(record string) spfRecord {
	var r spfRecord
	terms := strings.Fields(strings.ToLower(record))
	for _, term := range terms[1:] { // terms[0] is "v=spf1"
		// A modifier is "name=value" where name has no ':' or '/'.
		// Unknown modifiers are legal and ignored (RFC 7208 §6).
		if name, value, ok := strings.Cut(term, "="); ok && !strings.ContainsAny(name, ":/") {
			if name == "redirect" {
				r.redirect = value
			}
			continue
		}

		qualifier := "+"
		if strings.ContainsRune("+-~?", rune(term[0])) {
			qualifier, term = term[:1], term[1:]
		}
		name, arg, _ := strings.Cut(term, ":")
		name, _, _ = strings.Cut(name, "/") // "a/24", "mx/24"

		switch name {
		case "all":
			if r.all == "" {
				r.all = qualifier
			}
		case "include":
			if arg == "" {
				r.unknown = append(r.unknown, term)
				continue
			}
			r.lookups++
			r.includes = append(r.includes, arg)
		case "a", "mx", "ptr", "exists":
			r.lookups++
		case "ip4", "ip6":
			// No DNS query.
		default:
			r.unknown = append(r.unknown, term)
		}
	}
	if r.all == "" && r.redirect != "" {
		r.lookups++
	}
	return r
}

func checkSPF(ctx context.Context, dns resolver.Resolver, domain string, receivesMail bool, ev *evaluated) ([]issue, error) {
	txt, err := lookupTXT(ctx, dns, domain)
	if err != nil {
		return nil, err
	}
	ev.add(CheckSPFMissing)
	var records []string
	for _, rec := range txt {
		if isSPF(rec) {
			records = append(records, rec)
		}
	}

	// Each step below is evaluated only if the previous one passed: a
	// record that is missing, duplicated or unparseable has no policy to
	// analyze, so the later checks are not applicable.
	if len(records) > 0 {
		ev.add(CheckSPFMultiple)
	}
	switch len(records) {
	case 0:
		return []issue{spfMissing(domain, receivesMail)}, nil
	case 1:
		// Analyzed below.
	default:
		return []issue{{
			checkID:     CheckSPFMultiple,
			asset:       domain,
			severity:    finding.SeverityHigh,
			title:       "Several SPF records",
			description: "The domain publishes more than one SPF record. Receivers treat this as a permanent error and ignore SPF entirely, so the domain is not protected.",
			evidence:    strings.Join(records, "\n"),
			remediation: []string{"Merge all SPF records into a single TXT record starting with v=spf1."},
			references:  []string{refSPF},
		}}, nil
	}

	record := records[0]
	parsed := parseSPF(record)
	ev.add(CheckSPFInvalid)
	if len(parsed.unknown) > 0 {
		// Receivers reject the whole record; analyzing it further would
		// describe a policy that is never applied.
		return []issue{{
			checkID:     CheckSPFInvalid,
			asset:       domain,
			severity:    finding.SeverityHigh,
			title:       "Invalid SPF record",
			description: "The SPF record contains terms receivers do not understand. They treat this as a permanent error and ignore SPF entirely.",
			evidence:    fmt.Sprintf("%s\nunrecognized: %s", record, strings.Join(parsed.unknown, " ")),
			remediation: []string{"Fix or remove the unrecognized terms; check the record with an SPF validator before publishing."},
			references:  []string{refSPF},
		}}, nil
	}

	var issues []issue
	// With a redirect and no "all", the redirected record decides: the
	// "all" checks say nothing about this one.
	if parsed.all != "" || parsed.redirect == "" {
		ev.add(CheckSPFPassAll, CheckSPFNeutralAll, CheckSPFSoftfailAll, CheckSPFNoAll)
	}
	if i, ok := spfAllIssue(domain, record, parsed); ok {
		issues = append(issues, i)
	}

	lookups, err := countSPFLookups(ctx, dns, parsed)
	if err != nil {
		return nil, err
	}
	ev.add(CheckSPFTooManyLookups)
	if lookups > spfLookupLimit {
		issues = append(issues, issue{
			checkID:     CheckSPFTooManyLookups,
			asset:       domain,
			severity:    finding.SeverityHigh,
			title:       "SPF record needs too many DNS lookups",
			description: fmt.Sprintf("Evaluating the SPF record requires more than %d DNS lookups, counting nested includes. Receivers stop at %d and treat SPF as a permanent error, so legitimate mail may be rejected and spoofing is not blocked.", spfLookupLimit, spfLookupLimit),
			evidence:    fmt.Sprintf("%s\nlookups counted: more than %d", record, spfLookupLimit),
			remediation: []string{
				"Remove includes for services you no longer use.",
				"Replace includes of your own servers with ip4:/ip6: ranges, which need no lookup.",
			},
			references: []string{refSPF},
		})
	}
	return issues, nil
}

func spfMissing(domain string, receivesMail bool) issue {
	i := issue{
		checkID:     CheckSPFMissing,
		asset:       domain,
		title:       "No SPF record",
		description: "The domain publishes no SPF record, so receivers cannot tell which servers are allowed to send mail for it. Anyone can send mail that appears to come from this domain.",
		references:  []string{refSPF},
	}
	if receivesMail {
		i.severity = finding.SeverityHigh
		i.remediation = []string{
			"List every service that sends mail for the domain (mail provider, newsletter, invoicing...).",
			"Publish one TXT record such as \"v=spf1 include:<provider> -all\", using the include each provider documents.",
		}
	} else {
		// No MX: probably no mail at all. Still spoofable, so still a finding.
		i.severity = finding.SeverityMedium
		i.remediation = []string{
			"If the domain never sends mail, publish \"v=spf1 -all\" to declare that no server may send for it.",
		}
	}
	return i
}

// spfAllIssue reports a weak or missing "all" mechanism, which decides what
// happens to mail from servers the record does not list.
func spfAllIssue(domain, record string, r spfRecord) (issue, bool) {
	i := issue{asset: domain, evidence: record, references: []string{refSPF}}
	switch r.all {
	case "+":
		i.checkID = CheckSPFPassAll
		i.severity = finding.SeverityCritical
		i.title = "SPF allows every server to send mail"
		i.description = "The SPF record ends with \"+all\" (or a bare \"all\"), which authorizes every server on the internet to send mail for the domain. It is worse than having no SPF record, because spoofed mail now passes SPF."
		i.remediation = []string{"Replace \"+all\" with \"-all\" after listing your legitimate senders."}
	case "?":
		i.checkID = CheckSPFNeutralAll
		i.severity = finding.SeverityMedium
		i.title = "SPF does not reject unknown senders"
		i.description = "The SPF record ends with \"?all\" (neutral): mail from unlisted servers is neither accepted nor rejected, so SPF gives almost no protection."
		i.remediation = []string{"Replace \"?all\" with \"-all\" (or \"~all\" during a transition)."}
	case "~":
		i.checkID = CheckSPFSoftfailAll
		i.severity = finding.SeverityLow
		i.title = "SPF only soft-fails unknown senders"
		i.description = "The SPF record ends with \"~all\" (softfail): mail from unlisted servers is marked as suspicious but usually still delivered. This is acceptable when DMARC is enforced, but \"-all\" is stricter."
		i.remediation = []string{"Once all legitimate senders are listed, replace \"~all\" with \"-all\"."}
	case "":
		if r.redirect != "" {
			return issue{}, false // the redirected record decides
		}
		i.checkID = CheckSPFNoAll
		i.severity = finding.SeverityMedium
		i.title = "SPF record has no default rule"
		i.description = "The SPF record has no \"all\" mechanism. Mail from unlisted servers gets a neutral result, so SPF gives almost no protection."
		i.remediation = []string{"End the SPF record with \"-all\"."}
	default: // "-": strict, nothing to report
		return issue{}, false
	}
	return i, true
}

// countSPFLookups counts DNS-querying terms, following include: and
// redirect= into the records they point to.
//
// It stops fetching as soon as the count exceeds the limit. Every fetched
// target was already counted in its parent, so at most spfLookupLimit+1
// records are fetched, even for include loops: a hostile record cannot make
// us send unbounded queries.
func countSPFLookups(ctx context.Context, dns resolver.Resolver, root spfRecord) (int, error) {
	total := 0
	var walk func(r spfRecord) error
	walk = func(r spfRecord) error {
		total += r.lookups
		for _, target := range r.targets() {
			if total > spfLookupLimit {
				return nil
			}
			// Macros like %{d} depend on the sender at evaluation time; we
			// cannot expand them statically. Already counted, not followed.
			if strings.Contains(target, "%") {
				continue
			}
			txt, err := lookupTXT(ctx, dns, target)
			if err != nil {
				return err
			}
			var child []string
			for _, rec := range txt {
				if isSPF(rec) {
					child = append(child, rec)
				}
			}
			if len(child) != 1 {
				continue // missing or ambiguous: nothing more to count
			}
			if err := walk(parseSPF(child[0])); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(root)
	return total, err
}
