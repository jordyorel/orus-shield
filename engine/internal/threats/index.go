// Package threats turns new vulnerability detections into rescans of the
// customers they may affect ("emerging threats").
//
// When the operator installs a newer nuclei-templates release, it brings
// templates for CVEs published since the last one. The worker indexes the
// critical and high CVE templates (Index), records the ones it has never
// seen (store), and matches each new one against the technologies the vulns
// module detected on every verified domain (Match): a WordPress plugin CVE
// concerns the domains where WordPress was seen. Each match queues a vulns
// rescan and an email to the organization's admins. The rescan, not the
// match, decides whether the customer is vulnerable: a match is "your stack
// may be concerned", never a finding (rule 8: facts come from scanners).
package threats

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Template is one CVE detection template.
type Template struct {
	ID       string // template ID, e.g. "CVE-2026-103956"
	CVE      string
	Name     string
	Severity string   // "critical" or "high"
	Products []string // product tags: what the template is about
	KEV      bool     // in CISA's Known Exploited Vulnerabilities catalog
	EPSS     float64  // probability of exploitation in the next 30 days (FIRST), 0 when unknown
	New      bool     // listed in the release's .new-additions
}

const (
	// cvesDir holds the CVE templates in nuclei-templates.
	cvesDir = "http/cves"
	// maxTemplateBytes bounds what we read of one template: the header
	// we need is at the top.
	maxTemplateBytes = 64 << 10
	// maxTemplates bounds the index (nuclei-templates has about 4500).
	maxTemplates = 50000
)

// genericTags are template tags that name a kind of flaw or a source, not a
// product: they must never make a template match a customer.
var genericTags = map[string]bool{
	"cve": true, "kev": true, "vkev": true, "vuln": true, "rce": true, "sqli": true, "xss": true,
	"lfi": true, "rfi": true, "ssrf": true, "xxe": true, "ssti": true, "redirect": true, "traversal": true,
	"auth-bypass": true, "unauth": true, "intrusive": true, "oast": true, "default-login": true,
	"packetstorm": true, "edb": true, "wpscan": true, "huntr": true, "hackerone": true, "seclists": true,
	"injection": true, "disclosure": true, "exposure": true, "config": true, "misconfig": true,
	"file-upload": true, "fileupload": true, "upload": true, "deserialization": true, "passive": true,
	"panel": true, "login": true, "takeover": true, "cnvd": true, "mcp": true, "ai": true, "time-based-sqli": true,
	"blind": true, "unauthenticated": true, "authenticated": true, "authenticated-bypass": true, "idor": true,
	"plugin": true, "wp-plugin": true, "wp-theme": true,
	"path-traversal": true, "authorization": true, "privesc": true, "fileread": true, "file-read": true,
	"oob": true, "code-injection": true, "php-filter-chain": true, "cloud": true, "devops": true,
	"api": true, "cms": true, "http": true, "web": true, "info-leak": true, "info": true, "lfr": true,
}

// Index reads the critical and high CVE templates of a nuclei-templates
// directory. The directory is pinned and installed by the operator, but it is
// still read with bounds: a corrupt file is skipped, never fatal.
func Index(dir string) ([]Template, error) {
	newPaths, err := newAdditions(filepath.Join(dir, ".new-additions"))
	if err != nil {
		return nil, err
	}
	var out []Template
	root := filepath.Join(dir, cvesDir)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if len(out) == maxTemplates {
			return fmt.Errorf("more than %d templates", maxTemplates)
		}
		t, ok, err := readTemplate(path)
		if err != nil || !ok {
			return nil //nolint:nilerr // an unreadable template is skipped, see Index
		}
		rel, _ := filepath.Rel(dir, path)
		t.New = newPaths[filepath.ToSlash(rel)]
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("index templates in %s: %w", root, err)
	}
	slices.SortFunc(out, func(a, b Template) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// newAdditions reads the release's list of added template paths.
func newAdditions(path string) (map[string]bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: inside the operator's templates directory
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for sc.Scan() {
		if p := strings.TrimSpace(sc.Text()); p != "" {
			out[p] = true
		}
	}
	return out, sc.Err()
}

// readTemplate reads the fields we need from a template's header with a
// line scan: the format is regular ("key: value" under "info:" and its
// "classification:" and "metadata:" blocks), and a YAML library would be a
// dependency for five fields. ok is false for templates we do not index.
func readTemplate(path string) (Template, bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: inside the operator's templates directory
	if err != nil {
		return Template{}, false, err
	}
	defer func() { _ = f.Close() }()

	var t Template
	var tags []string
	var product string
	sc := bufio.NewScanner(io.LimitReader(f, maxTemplateBytes))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "http:") || strings.HasPrefix(line, "requests:") {
			break // end of the header
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		indented := strings.HasPrefix(line, " ")
		switch {
		case !indented && key == "id":
			t.ID = value
		case indented && key == "name" && t.Name == "":
			t.Name = value
		case indented && key == "severity":
			t.Severity = strings.ToLower(value)
		case indented && key == "cve-id" && t.CVE == "":
			t.CVE = strings.ToUpper(value)
		case indented && key == "epss-score":
			_, _ = fmt.Sscanf(value, "%g", &t.EPSS)
		case indented && key == "product":
			product = value
		case indented && key == "tags":
			tags = strings.Split(value, ",")
		}
	}
	if err := sc.Err(); err != nil {
		return Template{}, false, err
	}
	if t.ID == "" || (t.Severity != "critical" && t.Severity != "high") {
		return Template{}, false, nil
	}
	if t.CVE == "" && strings.HasPrefix(strings.ToUpper(t.ID), "CVE-") {
		t.CVE = strings.ToUpper(t.ID)
	}
	seen := map[string]bool{}
	products := strings.Split(strings.Trim(product, "[]"), ",")
	for _, tag := range append(tags, products...) {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "kev" {
			t.KEV = true
		}
		if tag == "" || genericTags[tag] || strings.HasPrefix(tag, "cve2") || seen[tag] {
			continue
		}
		seen[tag] = true
		t.Products = append(t.Products, tag)
	}
	if t.EPSS < 0 || t.EPSS > 1 {
		t.EPSS = 0
	}
	return t, len(t.Products) > 0, nil
}

// TechKeys turns a hostname's "technologies" detail ("nginx 1.18.0,
// WordPress 6.1") into lowercase product keys ("nginx", "wordpress").
func TechKeys(detail string) []string {
	var out []string
	for _, item := range strings.Split(detail, ",") {
		fields := strings.Fields(strings.ToLower(item))
		if len(fields) == 0 {
			continue
		}
		k := fields[0]
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// aliases maps technology names as detected to the product tags templates
// use, when they differ.
var aliases = map[string][]string{
	"wordpress":     {"wordpress", "wp"},
	"apache":        {"apache", "httpd"},
	"microsoft-iis": {"iis"},
}

// Match returns the products of techs (keys, see TechKeys) that template
// t is about; none means t does not concern that host.
func Match(t Template, techs []string) []string {
	var out []string
	for _, tech := range techs {
		names := aliases[tech]
		if names == nil {
			names = []string{tech}
		}
		for _, n := range names {
			if slices.Contains(t.Products, n) && !slices.Contains(out, tech) {
				out = append(out, tech)
			}
		}
	}
	return out
}
