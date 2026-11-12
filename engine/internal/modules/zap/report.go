package zap

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// report is the part of ZAP's "traditional-json" report we read.
type report struct {
	Site []struct {
		Alerts []alert `json:"alerts"`
	} `json:"site"`
}

type alert struct {
	PluginID  string     `json:"pluginid"`
	Name      string     `json:"name"`
	Alert     string     `json:"alert"`
	RiskCode  string     `json:"riskcode"` // 0 info, 1 low, 2 medium, 3 high
	Desc      string     `json:"desc"`
	Solution  string     `json:"solution"`
	Reference string     `json:"reference"`
	CWE       string     `json:"cweid"`
	Instances []instance `json:"instances"`
}

type instance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Attack   string `json:"attack"`
	Evidence string `json:"evidence"`
}

// readReport reads the report, bounded (rule 7).
func readReport(path string) (report, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the run's own work directory
	if err != nil {
		return report{}, fmt.Errorf("read report: %w", err)
	}
	defer func() { _ = f.Close() }()
	var r report
	dec := json.NewDecoder(io.LimitReader(f, maxReport))
	if err := dec.Decode(&r); err != nil {
		return report{}, fmt.Errorf("read report: %w", err)
	}
	return r, nil
}

// classes map CWE identifiers to the checks.
var classes = map[string]string{
	// injections
	"77": CheckInjection, "78": CheckInjection, "89": CheckInjection, "90": CheckInjection,
	"94": CheckInjection, "95": CheckInjection, "96": CheckInjection, "97": CheckInjection,
	"611": CheckInjection, "643": CheckInjection, "652": CheckInjection, "917": CheckInjection,
	"943": CheckInjection, "1336": CheckInjection,
	// cross-site scripting
	"79": CheckXSS, "80": CheckXSS,
	// files
	"22": CheckFiles, "23": CheckFiles, "35": CheckFiles, "73": CheckFiles, "98": CheckFiles,
	// request forgery
	"601": CheckForgery, "918": CheckForgery,
}

// classify returns the check of an alert, "" for alerts we do not report:
// low and informational ones (hygiene, the web module's), and medium ones
// outside the known classes.
func classify(a alert) (check string, sev finding.Severity) {
	risk, _ := strconv.Atoi(a.RiskCode)
	if risk < 2 {
		return "", ""
	}
	check = classes[strings.TrimSpace(a.CWE)]
	switch {
	case check == "" && risk >= 3:
		check = CheckOther
	case check == "":
		return "", ""
	}
	sev = finding.SeverityMedium
	if risk >= 3 {
		sev = finding.SeverityHigh
		if check == CheckInjection {
			sev = finding.SeverityCritical
		}
	}
	return check, sev
}

const (
	maxText     = 2000
	maxSnippet  = 300
	maxInstance = 5
	maxFindings = 200
)

var reTags = regexp.MustCompile(`<[^>]*>`)

// plain turns ZAP's HTML text into bounded plain text.
func plain(s string, max int) string {
	s = reTags.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	return truncate(s, max)
}

// clean keeps printable text from the target (rule 7), bounded.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return truncate(b.String(), max)
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

var reURL = regexp.MustCompile(`https?://[^\s<>"']+`)

// convert turns the report into the zap module's findings.
func convert(domain string, r report) module.Result {
	return convertWith(ID, classify, domain, r)
}

// convertWith turns the report into findings of moduleID, classified by
// classify: one per alert and page (URL without its query), with up to
// maxInstance proofs.
func convertWith(moduleID string, classify func(alert) (string, finding.Severity), domain string, r report) module.Result {
	type key struct{ check, asset string }
	byKey := map[key]*finding.Finding{}
	var order []key
	for _, site := range r.Site {
		for _, a := range site.Alerts {
			check, sev := classify(a)
			if check == "" {
				continue
			}
			name := a.Name
			if name == "" {
				name = a.Alert
			}
			for _, in := range a.Instances {
				u, err := url.Parse(in.URI)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
					continue
				}
				host, err := dnsname.Normalize(u.Hostname())
				if err != nil || (host != domain && !strings.HasSuffix(host, "."+domain)) {
					continue // out of scope: never reported, whatever ZAP says
				}
				page := u.Scheme + "://" + u.Host + u.EscapedPath()
				assetValue := clean(page, 500) + "#zap-" + clean(a.PluginID, 12)
				k := key{check, assetValue}
				f, ok := byKey[k]
				if !ok {
					if len(order) >= maxFindings {
						continue
					}
					var refs []string
					if cwe := strings.TrimSpace(a.CWE); cwe != "" && cwe != "0" && cwe != "-1" {
						refs = append(refs, "CWE-"+clean(cwe, 8))
					}
					for _, ref := range reURL.FindAllString(a.Reference, 5) {
						refs = append(refs, clean(ref, 300))
					}
					f = &finding.Finding{
						SchemaVersion: finding.SchemaVersion,
						ID:            finding.NewID(moduleID, check, domain, assetValue),
						ModuleID:      moduleID,
						CheckID:       check,
						Target:        domain,
						Asset:         assetValue,
						Severity:      sev,
						Title:         clean(name, 200) + " (" + clean(u.Host+u.EscapedPath(), 120) + ")",
						Description:   plain(a.Desc, maxText),
						Remediation:   nonEmpty(plain(a.Solution, maxText)),
						References:    refs,
					}
					byKey[k] = f
					order = append(order, k)
				}
				if strings.Count(f.Evidence, "request: ") < maxInstance {
					var ev strings.Builder
					fmt.Fprintf(&ev, "request: %s %s\n", clean(in.Method, 10), clean(in.URI, 500))
					if in.Param != "" {
						fmt.Fprintf(&ev, "parameter: %s\n", clean(in.Param, 100))
					}
					if in.Attack != "" {
						fmt.Fprintf(&ev, "payload: %s\n", clean(in.Attack, maxSnippet))
					}
					if in.Evidence != "" {
						fmt.Fprintf(&ev, "evidence: %s\n", clean(in.Evidence, maxSnippet))
					}
					f.Evidence = finding.TruncateEvidence(f.Evidence + ev.String())
				}
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].asset < order[j].asset })
	var res module.Result
	for _, k := range order {
		res.Findings = append(res.Findings, *byKey[k])
	}
	return res
}

func nonEmpty(s string) []string {
	if s == "" {
		return []string{"Fix the flaw in the application code, then run the scan again."}
	}
	return []string{s}
}
