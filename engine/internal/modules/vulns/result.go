package vulns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// result is one line of Nuclei's JSONL output: only the fields we use.
// Everything in it is untrusted: the template text is pinned, but matched
// URLs and extracted values come from the target (rule 7).
type result struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		Severity       string  `json:"severity"`
		Tags           strList `json:"tags"`
		Reference      strList `json:"reference"`
		Remediation    string  `json:"remediation"`
		Classification struct {
			CVE       strList `json:"cve-id"`
			CWE       strList `json:"cwe-id"`
			CVSSScore float64 `json:"cvss-score"`
			EPSSScore float64 `json:"epss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type        string  `json:"type"`
	MatchedAt   string  `json:"matched-at"`
	MatcherName string  `json:"matcher-name"`
	Extracted   strList `json:"extracted-results"`
	IP          string  `json:"ip"`
}

// strList accepts a JSON string, a list of strings, or null: Nuclei writes
// some fields either way depending on the template.
type strList []string

func (s *strList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one != "" {
			*s = strList{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// parser reads Nuclei's stdout line by line, with bounds. It is an
// io.Writer so the runner can stream into it.
type parser struct {
	domain  string
	buf     []byte
	results []result
	err     error
}

const maxLine = 256 << 10

func (p *parser) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := slices.Index(p.buf, '\n')
		if i < 0 {
			break
		}
		p.line(p.buf[:i])
		p.buf = p.buf[i+1:]
	}
	if len(p.buf) > maxLine {
		p.fail(errors.New("output line too long"))
		p.buf = nil
	}
	return len(b), nil
}

// Flush handles a last line without a newline.
func (p *parser) Flush() {
	if len(p.buf) > 0 {
		p.line(p.buf)
		p.buf = nil
	}
}

func (p *parser) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

func (p *parser) line(b []byte) {
	if len(strings.TrimSpace(string(b))) == 0 || p.err != nil {
		return
	}
	if len(p.results) == maxResults {
		p.fail(fmt.Errorf("more than %d results", maxResults))
		return
	}
	var r result
	if err := json.Unmarshal(b, &r); err != nil {
		p.fail(fmt.Errorf("invalid JSON line: %w", err))
		return
	}
	p.results = append(p.results, r)
}

var _ io.Writer = (*parser)(nil)

// hasTag reports whether the template has one of tags.
func (r result) hasTag(tags ...string) bool {
	for _, t := range r.Info.Tags {
		if slices.Contains(tags, strings.ToLower(strings.TrimSpace(t))) {
			return true
		}
	}
	return false
}

// tech is a technology seen on a host.
type tech struct{ key, label string }

// technology recognizes a detection-only result ("this host runs nginx"):
// info severity, tagged tech. It is an asset detail, not a problem.
func (r result) technology(domain string) (tech, string, bool) {
	if !strings.EqualFold(r.Info.Severity, "info") || !r.hasTag("tech") || r.hasTag("panel") {
		return tech{}, "", false
	}
	host := hostOf(r.MatchedAt)
	if !inDomain(host, domain) {
		return tech{}, "", false
	}
	name := r.MatcherName
	if name == "" {
		name = strings.TrimSuffix(r.TemplateID, "-detect")
	}
	key := slug(name)
	if key == "" {
		return tech{}, "", false
	}
	label := clean(name, 60)
	if len(r.Extracted) > 0 {
		label += " " + clean(r.Extracted[0], 40) // usually the version
	}
	return tech{key: key, label: label}, host, true
}

// checkOf picks our check for a template, from its classification and tags.
func (r result) checkOf() string {
	switch {
	case len(r.Info.Classification.CVE) > 0 || r.hasTag("cve"):
		return CheckKnownCVE
	case r.hasTag("takeover"):
		return CheckTakeover
	case r.hasTag("eol"):
		return CheckOutdatedOrEOL
	case r.hasTag("panel", "login"):
		return CheckExposedPanel
	case r.hasTag("exposure", "backup", "logs", "disclosure", "leak", "files", "config"):
		return CheckExposedData
	default:
		return CheckMisconfig
	}
}

var severities = map[string]finding.Severity{
	"critical": finding.SeverityCritical, "high": finding.SeverityHigh, "medium": finding.SeverityMedium,
	"low": finding.SeverityLow, "info": finding.SeverityInfo,
}

// finding converts a result. ok is false for results we do not report:
// outside the domain, unknown severity, or informational ones other than
// exposed panels (detections are technologies, not problems).
func (r result) finding(domain string) (finding.Finding, bool) {
	sev, known := severities[strings.ToLower(r.Info.Severity)]
	if !known || slug(r.TemplateID) == "" {
		return finding.Finding{}, false
	}
	u, err := url.Parse(strings.TrimSpace(r.MatchedAt))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !inDomain(hostOf(r.MatchedAt), domain) {
		return finding.Finding{}, false
	}
	check := r.checkOf()
	if sev == finding.SeverityInfo {
		if check != CheckExposedPanel {
			return finding.Finding{}, false
		}
		sev = finding.SeverityLow
	}
	// The asset is the matched URL without its query (payloads vary), with
	// the template in the fragment: two templates can match the same URL,
	// and the fragment is never sent anywhere.
	where := url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host), Path: u.Path, RawPath: u.RawPath}
	assetValue := clean(where.String(), 400) + "#" + slug(r.TemplateID)

	title := clean(r.Info.Name, 200)
	cves := cleanList(r.Info.Classification.CVE, 10, 30)
	if len(cves) > 0 && !strings.Contains(strings.ToUpper(title), strings.ToUpper(cves[0])) {
		title = cves[0] + ": " + title
	}
	if title == "" {
		title = "Nuclei template " + slug(r.TemplateID) + " matched"
	}
	desc := clean(r.Info.Description, 2000)
	if desc == "" {
		desc = "The detection template " + slug(r.TemplateID) + " matched this address."
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "template: %s\nmatched at: %s\n", slug(r.TemplateID), clean(r.MatchedAt, 500))
	if r.MatcherName != "" {
		fmt.Fprintf(&ev, "matcher: %s\n", clean(r.MatcherName, 100))
	}
	if r.IP != "" {
		fmt.Fprintf(&ev, "ip: %s\n", clean(r.IP, 45))
	}
	if r.Info.Classification.CVSSScore > 0 {
		fmt.Fprintf(&ev, "cvss: %.1f\n", r.Info.Classification.CVSSScore)
	}
	if e := r.Info.Classification.EPSSScore; e > 0 && e <= 1 {
		// FIRST's EPSS: probability of exploitation in the next 30 days.
		fmt.Fprintf(&ev, "epss: %.4f\n", e)
	}
	kev := r.hasTag("kev")
	if kev {
		ev.WriteString("known exploited: yes (CISA KEV catalog)\n")
	}
	for _, x := range cleanList(r.Extracted, 5, 200) {
		fmt.Fprintf(&ev, "extracted: %s\n", x)
	}

	refs := append(cves, cleanList(r.Info.Classification.CWE, 5, 20)...)
	if kev {
		refs = append(refs, kevCatalog)
	}
	for _, ref := range cleanList(r.Info.Reference, 8, 300) {
		if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
			refs = append(refs, ref)
		}
	}

	remediation := defaultRemediation[check]
	remediationFR := defaultRemediationFR[check]
	if s := clean(r.Info.Remediation, 1000); s != "" {
		remediation = append([]string{s}, remediation...)
		remediationFR = append([]string{"Recommandation de l’éditeur du modèle (en anglais) : " + s}, remediationFR...)
	}
	// The template's name and description are the tool's, in English, and
	// there are thousands: the French text names the kind of problem,
	// explains it, and quotes the technical detail as such.
	kind := kindsFR[check]
	fr := finding.Text{
		Title:       kind.label + " : " + title,
		Description: kind.why + " Détail technique (en anglais) : " + desc,
		Remediation: remediationFR,
	}

	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, check, domain, assetValue),
		ModuleID:      ID,
		CheckID:       check,
		Target:        domain,
		Asset:         assetValue,
		Severity:      sev,
		Title:         title,
		Description:   desc,
		Evidence:      finding.TruncateEvidence(ev.String()),
		Remediation:   remediation,
		References:    refs,
		Translations:  map[string]finding.Text{"fr": fr},
	}, true
}

// kevCatalog is CISA's Known Exploited Vulnerabilities catalog: a CVE in it
// is being exploited by attackers now.
const kevCatalog = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

var defaultRemediation = map[string][]string{
	CheckKnownCVE: {
		"Update the affected software to a version that fixes this vulnerability (see the references).",
		"If you cannot update at once, restrict access to it (firewall, VPN) and apply the vendor's workaround.",
		"Check the server's logs for signs that the vulnerability was already exploited.",
	},
	CheckExposedData: {
		"Remove the file from the web server, or deny access to it in the server configuration.",
		"If it contains passwords, keys or tokens, consider them compromised and change them.",
	},
	CheckTakeover: {
		"Delete the DNS record that points to the unused service, or claim the resource it points to again.",
	},
	CheckMisconfig: {
		"Fix the configuration described above; the references explain the safe setting.",
	},
	CheckExposedPanel: {
		"Make the administration interface reachable only from your network or through a VPN.",
		"If it must stay public, require strong passwords and two-factor authentication.",
	},
	CheckOutdatedOrEOL: {
		"Upgrade to a version that still receives security updates.",
	},
}

// kindFR names and explains a kind of problem in French.
type kindFR struct{ label, why string }

var kindsFR = map[string]kindFR{
	CheckKnownCVE: {"Vulnérabilité connue",
		"Une vulnérabilité publiée et répertoriée affecte un logiciel détecté à cette adresse. Les attaquants recherchent activement ce type de faille, car les moyens de l’exploiter sont souvent publics."},
	CheckExposedData: {"Fichier ou donnée exposés",
		"Un fichier qui ne devrait pas être public (sauvegarde, configuration, journal, données) est accessible depuis internet. Il peut révéler des mots de passe, des clés ou des informations sur vos clients."},
	CheckTakeover: {"Sous-domaine exposé à une prise de contrôle",
		"Un enregistrement DNS pointe vers un service tiers qui n’est plus réservé à votre nom : quelqu’un pourrait le réclamer et publier son propre contenu sur votre sous-domaine, par exemple une fausse page de connexion."},
	CheckMisconfig: {"Erreur de configuration",
		"Une erreur de configuration a été détectée à cette adresse. Elle peut affaiblir la sécurité du site ou révéler des informations utiles à un attaquant."},
	CheckExposedPanel: {"Interface d’administration exposée",
		"Une page de connexion ou un panneau d’administration est accessible depuis internet. Ces pages subissent des tentatives de connexion automatisées en permanence."},
	CheckOutdatedOrEOL: {"Logiciel obsolète ou en fin de vie",
		"Un logiciel détecté à cette adresse n’est plus maintenu ou n’est plus à jour : ses failles connues ne seront plus corrigées."},
}

var defaultRemediationFR = map[string][]string{
	CheckKnownCVE: {
		"Mettez à jour le logiciel concerné vers une version qui corrige cette vulnérabilité (voir les références).",
		"Si la mise à jour n’est pas possible tout de suite, restreignez l’accès (pare-feu, VPN) et appliquez le contournement indiqué par l’éditeur.",
		"Vérifiez dans les journaux du serveur que la vulnérabilité n’a pas déjà été exploitée.",
	},
	CheckExposedData: {
		"Supprimez le fichier du serveur web, ou interdisez son accès dans la configuration du serveur.",
		"S’il contient des mots de passe, des clés ou des jetons, considérez-les comme compromis et changez-les.",
	},
	CheckTakeover: {
		"Supprimez l’enregistrement DNS qui pointe vers le service inutilisé, ou réservez de nouveau la ressource vers laquelle il pointe.",
	},
	CheckMisconfig: {
		"Corrigez la configuration décrite ci-dessus ; les références indiquent le réglage sûr.",
	},
	CheckExposedPanel: {
		"Rendez l’interface d’administration accessible uniquement depuis votre réseau ou par un VPN.",
		"Si elle doit rester publique, exigez des mots de passe robustes et la double authentification.",
	},
	CheckOutdatedOrEOL: {
		"Passez à une version qui reçoit encore des mises à jour de sécurité.",
	},
}

// hostOf returns the lowercased host name of a URL or "host:port", or "".
func hostOf(v string) string {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	if i := strings.LastIndexByte(v, ':'); i > 0 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

func inDomain(host, domain string) bool {
	n, err := dnsname.Normalize(host)
	return err == nil && (n == domain || strings.HasSuffix(n, "."+domain))
}

// clean makes untrusted text one bounded line: control characters become
// spaces, runs of spaces collapse.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(out); len(r) > max {
		out = string(r[:max]) + "…"
	}
	return out
}

func cleanList(in []string, maxItems, maxLen int) []string {
	var out []string
	for _, s := range in {
		if c := clean(s, maxLen); c != "" && len(out) < maxItems && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// slug keeps a-z, 0-9 and "-" (template IDs, technology names), bounded.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == '_' || r == ' ' || r == '.':
			b.WriteRune('-')
		}
		if b.Len() >= 80 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}
