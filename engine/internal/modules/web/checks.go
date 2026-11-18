package web

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

const (
	refHSTS      = "RFC 6797"
	refCSP       = "W3C Content Security Policy Level 3"
	refFrame     = "RFC 7034"
	refCookies   = "RFC 6265"
	refOWASPHdrs = "https://owasp.org/www-project-secure-headers/"
	refFetch     = "https://fetch.spec.whatwg.org/#x-content-type-options-header"

	// minHSTSAge is the shortest HSTS lifetime we accept: 180 days, the
	// minimum many guides recommend (the HSTS preload list asks for a year).
	minHSTSAge = 180 * 24 * 60 * 60
)

// analyzeHTTP judges the plain-HTTP chain of host: visitors who type the
// address without https:// must end up on HTTPS. evaluated is false when the
// responses do not allow a verdict (an error page, or a redirect to another
// site or to http:// on another name, which is checked on its own).
func analyzeHTTP(domain, host string, chain []*response, httpsWorks bool) (_ *issue, evaluated bool) {
	last := chain[len(chain)-1]
	switch {
	case last.redirect():
		next := last.location
		if next == nil {
			return nil, false
		}
		if next.Scheme == "https" {
			return nil, true // sent to HTTPS: good, wherever it goes
		}
		return nil, false // http:// elsewhere: that name is judged on its own
	case last.status < 200 || last.status >= 300:
		return nil, false // an error page serves no content to protect
	}

	i := issue{
		checkID:    CheckHTTPNotRedirected,
		asset:      net.JoinHostPort(host, strconv.Itoa(httpPort)),
		severity:   finding.SeverityMedium,
		evidence:   chainEvidence(chain),
		references: []string{refHSTS, refOWASPHdrs},
	}
	if httpsWorks {
		i.title = "Website does not redirect HTTP to HTTPS"
		i.description = fmt.Sprintf("http://%s/ serves the site without encryption instead of sending visitors to the HTTPS version. "+
			"Anyone on the same network (public Wi-Fi, a compromised router) can read or change what these visitors see and send, "+
			"including passwords typed into forms.", host)
		i.remediation = []string{
			"Make the web server answer every http:// request with a permanent redirect (301) to the same address in https://.",
			"nginx: in the port 80 server block, use `return 301 https://$host$request_uri;`. Apache: `Redirect permanent / https://" + host + "/`. Most hosting panels have a \"Force HTTPS\" option.",
			"Then enable HSTS so browsers stop trying http:// at all.",
		}
		i.fr = finding.Text{
			Title: "Le site ne redirige pas HTTP vers HTTPS",
			Description: fmt.Sprintf("http://%s/ sert le site sans chiffrement au lieu d’envoyer les visiteurs vers la version HTTPS. "+
				"Toute personne sur le même réseau (Wi-Fi public, routeur compromis) peut lire ou modifier ce que ces visiteurs voient et envoient, "+
				"y compris les mots de passe saisis dans les formulaires.", host),
			Remediation: []string{
				"Faites répondre le serveur web à chaque requête http:// par une redirection permanente (301) vers la même adresse en https://.",
				"nginx : dans le bloc server du port 80, utilisez `return 301 https://$host$request_uri;`. Apache : `Redirect permanent / https://" + host + "/`. La plupart des panneaux d’hébergement proposent une option « Forcer HTTPS ».",
				"Activez ensuite HSTS pour que les navigateurs n’essaient plus du tout http://.",
			},
		}
		return &i, true
	}
	i.severity = finding.SeverityHigh
	i.title = "Website is only available without encryption"
	i.description = fmt.Sprintf("http://%s/ serves the site and no working HTTPS version was found. "+
		"Everything visitors see and send, including passwords typed into forms, travels in clear text and can be read or changed on the way.", host)
	i.remediation = []string{
		"Get a free certificate (Let's Encrypt, or the SSL option of your hosting panel) for " + host + ".",
		"Enable HTTPS on the web server, then redirect every http:// request to https://.",
	}
	i.fr = finding.Text{
		Title: "Le site n’est accessible que sans chiffrement",
		Description: fmt.Sprintf("http://%s/ sert le site et aucune version HTTPS fonctionnelle n’a été trouvée. "+
			"Tout ce que les visiteurs voient et envoient, y compris les mots de passe saisis dans les formulaires, circule en clair et peut être lu ou modifié en chemin.", host),
		Remediation: []string{
			"Obtenez un certificat gratuit (Let’s Encrypt, ou l’option SSL de votre panneau d’hébergement) pour " + host + ".",
			"Activez HTTPS sur le serveur web, puis redirigez chaque requête http:// vers https://.",
		},
	}
	return &i, true
}

// analyzeHTTPS judges the HTTPS chain of host. HSTS and cookies are read on
// every response (a redirect must carry HSTS too); the content headers only
// on the page finally served, not on a redirect to another name.
func analyzeHTTPS(host string, chain []*response) hostResult {
	var r hostResult
	asset := net.JoinHostPort(host, strconv.Itoa(httpsPort))
	first, last := chain[0], chain[len(chain)-1]

	if i := checkHSTS(asset, first); i != nil {
		r.add(*i)
	}
	r.evaluate(CheckHSTSMissing)

	if i := checkCookies(asset, chain); i != nil {
		r.add(*i)
	}
	r.evaluate(CheckCookieNotSecure)

	if last.redirect() {
		return r // no page here: the headers below protect page content
	}
	r.evaluate(CheckCSPMissing, CheckFramingAllowed, CheckNosniffMissing)
	h := last.header
	evidence := chainEvidence(chain)

	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		r.add(issue{
			checkID: CheckCSPMissing, asset: asset, severity: finding.SeverityLow,
			title: "No Content Security Policy",
			description: "The site does not tell browsers which sources of scripts, styles and frames are legitimate. " +
				"If an attacker manages to inject a script into a page (a comment field, a vulnerable plugin), nothing stops the browser from running it.",
			evidence: evidence,
			remediation: []string{
				"Add a Content-Security-Policy header. Start in report-only mode (Content-Security-Policy-Report-Only) to see what would break.",
				"A reasonable first policy: `default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'`, then allow the external sources the site really uses.",
			},
			references: []string{refCSP, refOWASPHdrs},
			fr: finding.Text{
				Title: "Aucune politique de sécurité du contenu (CSP)",
				Description: "Le site n’indique pas aux navigateurs quelles sources de scripts, de styles et de cadres sont légitimes. " +
					"Si un attaquant parvient à injecter un script dans une page (un champ de commentaire, une extension vulnérable), rien n’empêche le navigateur de l’exécuter.",
				Remediation: []string{
					"Ajoutez un en-tête Content-Security-Policy. Commencez en mode observation (Content-Security-Policy-Report-Only) pour voir ce qui serait bloqué.",
					"Une première politique raisonnable : `default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'`, puis autorisez les sources externes que le site utilise réellement.",
				},
			},
		})
	}

	if !framingProtected(h.Get("X-Frame-Options"), csp) {
		r.add(issue{
			checkID: CheckFramingAllowed, asset: asset, severity: finding.SeverityLow,
			title: "Pages can be embedded by other sites (clickjacking)",
			description: "Any website can show these pages inside an invisible frame and trick visitors into clicking buttons on them " +
				"(confirming an action, changing a setting) while they think they are clicking something else.",
			evidence: evidence,
			remediation: []string{
				"Add the header `X-Frame-Options: SAMEORIGIN` (or DENY if the site never frames its own pages).",
				"With a Content Security Policy, `frame-ancestors 'self'` does the same for modern browsers.",
			},
			references: []string{refFrame, refOWASPHdrs},
			fr: finding.Text{
				Title: "D’autres sites peuvent intégrer vos pages (clickjacking)",
				Description: "N’importe quel site peut afficher ces pages dans un cadre invisible et amener les visiteurs à cliquer sur leurs boutons " +
					"(confirmer une action, modifier un réglage) en croyant cliquer sur autre chose.",
				Remediation: []string{
					"Ajoutez l’en-tête `X-Frame-Options: SAMEORIGIN` (ou DENY si le site n’intègre jamais ses propres pages).",
					"Avec une politique de sécurité du contenu, `frame-ancestors 'self'` produit le même effet dans les navigateurs modernes.",
				},
			},
		})
	}

	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		r.add(issue{
			checkID: CheckNosniffMissing, asset: asset, severity: finding.SeverityLow,
			title: "Browsers may guess content types (missing nosniff)",
			description: "Without `X-Content-Type-Options: nosniff`, a browser may treat an uploaded text or image file as a script or a web page, " +
				"which can turn a file upload feature into a way to attack visitors.",
			evidence:    evidence,
			remediation: []string{"Add the header `X-Content-Type-Options: nosniff` to every response."},
			references:  []string{refFetch, refOWASPHdrs},
			fr: finding.Text{
				Title: "Les navigateurs peuvent deviner le type des contenus (nosniff absent)",
				Description: "Sans `X-Content-Type-Options: nosniff`, un navigateur peut traiter un fichier texte ou une image téléversés comme un script ou une page web, " +
					"ce qui peut transformer une fonction d’envoi de fichiers en moyen d’attaquer les visiteurs.",
				Remediation: []string{"Ajoutez l’en-tête `X-Content-Type-Options: nosniff` à chaque réponse."},
			},
		})
	}
	return r
}

// checkHSTS reads Strict-Transport-Security on the first HTTPS response.
func checkHSTS(asset string, first *response) *issue {
	value := first.header.Get("Strict-Transport-Security")
	age, ok := hstsMaxAge(value)
	if ok && age >= minHSTSAge {
		return nil
	}
	i := &issue{
		checkID: CheckHSTSMissing, asset: asset, severity: finding.SeverityMedium,
		evidence: chainEvidence([]*response{first}),
		remediation: []string{
			"Add the header `Strict-Transport-Security: max-age=31536000` (one year) to HTTPS responses, once every page works in HTTPS.",
			"Add `includeSubDomains` only when every subdomain has HTTPS.",
		},
		references: []string{refHSTS, refOWASPHdrs},
		fr: finding.Text{Remediation: []string{
			"Ajoutez l’en-tête `Strict-Transport-Security: max-age=31536000` (un an) aux réponses HTTPS, une fois que toutes les pages fonctionnent en HTTPS.",
			"N’ajoutez `includeSubDomains` que si tous les sous-domaines disposent de HTTPS.",
		}},
	}
	if value == "" || !ok {
		i.title = "HSTS is not enabled"
		i.description = "The site does not tell browsers to always use HTTPS. A visitor who types the address or follows an old http:// link " +
			"makes a first unencrypted request, which an attacker on the same network can intercept to keep them on a fake, unencrypted version (SSL stripping)."
		i.fr.Title = "HSTS n’est pas activé"
		i.fr.Description = "Le site n’indique pas aux navigateurs d’utiliser toujours HTTPS. Un visiteur qui tape l’adresse ou suit un ancien lien http:// " +
			"envoie une première requête non chiffrée, qu’un attaquant sur le même réseau peut intercepter pour le maintenir sur une fausse version non chiffrée (SSL stripping)."
		return i
	}
	i.title = "HSTS lifetime is too short"
	i.description = fmt.Sprintf("Browsers are told to remember HTTPS for %s only. After that, visitors are exposed again to a first unencrypted request. "+
		"Use at least 180 days, ideally one year.", humanDuration(age))
	i.fr.Title = "La durée HSTS est trop courte"
	i.fr.Description = fmt.Sprintf("Les navigateurs ne retiennent l’usage de HTTPS que pendant %s. Ensuite, les visiteurs sont de nouveau exposés à une première requête non chiffrée. "+
		"Utilisez au moins 180 jours, idéalement un an.", humanDurationFR(age))
	return i
}

// hstsMaxAge parses the max-age directive. ok is false when the header is
// missing or has no valid max-age.
func hstsMaxAge(v string) (age int64, ok bool) {
	for _, d := range strings.Split(v, ";") {
		name, val, found := strings.Cut(strings.TrimSpace(d), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(val), `"`), 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func humanDurationFR(seconds int64) string {
	n := func(v int64, unit string) string { return fmt.Sprintf("%d %s%s", v, unit, finding.Plural(int(v), "s")) }
	switch {
	case seconds >= 86400:
		return n(seconds/86400, "jour")
	case seconds >= 3600:
		return n(seconds/3600, "heure")
	default:
		return n(seconds, "seconde")
	}
}

func humanDuration(seconds int64) string {
	switch {
	case seconds >= 86400:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 3600:
		return fmt.Sprintf("%d hours", seconds/3600)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}

// framingProtected reports whether X-Frame-Options or the CSP
// frame-ancestors directive stops other sites from framing the page.
func framingProtected(xfo, csp string) bool {
	switch strings.ToUpper(strings.TrimSpace(xfo)) {
	case "DENY", "SAMEORIGIN":
		return true
	}
	for _, d := range strings.Split(csp, ";") {
		fields := strings.Fields(d)
		if len(fields) > 1 && strings.EqualFold(fields[0], "frame-ancestors") && fields[1] != "*" {
			return true
		}
	}
	return false
}

// maxCookieNames bounds how many cookie names the evidence lists.
const maxCookieNames = 10

// checkCookies reports cookies set over HTTPS without the Secure flag.
func checkCookies(asset string, chain []*response) *issue {
	var names []string
	seen := make(map[string]bool)
	for _, r := range chain {
		for _, c := range r.cookies {
			name := sanitize(c.Name, 64)
			if c.Secure || seen[name] {
				continue
			}
			seen[name] = true
			if len(names) < maxCookieNames {
				names = append(names, name)
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return &issue{
		checkID: CheckCookieNotSecure, asset: asset, severity: finding.SeverityLow,
		title: "Cookies can be sent without encryption",
		description: fmt.Sprintf("The site sets %d cookie(s) without the Secure flag. The browser will also send them over plain http://, "+
			"where they can be read on the network. If one of them is a session cookie, reading it is enough to take over the visitor's account.", len(seen)),
		evidence: fmt.Sprintf("cookies without Secure: %s\n\n%s", strings.Join(names, ", "), chainEvidence(chain)),
		remediation: []string{
			"Set the Secure flag on every cookie the site creates (in the application, framework or CMS settings).",
			"Also set HttpOnly on session cookies, and SameSite=Lax or Strict.",
		},
		references: []string{refCookies, refOWASPHdrs},
		fr: finding.Text{
			Title: "Des cookies peuvent circuler sans chiffrement",
			Description: fmt.Sprintf("Le site crée %d cookie%s sans l’attribut Secure. Le navigateur les enverra aussi en http:// simple, "+
				"où ils peuvent être lus sur le réseau. S’il s’agit d’un cookie de session, le lire suffit pour prendre le contrôle du compte du visiteur.", len(seen), finding.Plural(len(seen), "s")),
			Remediation: []string{
				"Activez l’attribut Secure sur chaque cookie créé par le site (dans les réglages de l’application, du framework ou du CMS).",
				"Activez aussi HttpOnly sur les cookies de session, ainsi que SameSite=Lax ou Strict.",
			},
		},
	}
}

// versionHeaders are the headers in which servers and frameworks announce
// themselves.
var versionHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"}

// versionPattern matches a product followed by a version number:
// "nginx/1.24.0", "PHP/8.1.2", "Apache/2.4.58", or a bare "4.0.30319".
var versionPattern = regexp.MustCompile(`(^|[A-Za-z][A-Za-z0-9._-]*[/ ])v?\d+(\.\d+)+`)

// analyzeVersions looks for software versions in the headers of every
// response read on host. The finding is per host: the same server
// configuration usually answers on both ports.
func analyzeVersions(host string, chains ...[]*response) hostResult {
	var r hostResult
	var seen []string
	have := make(map[string]bool)
	read := false
	for _, chain := range chains {
		for _, resp := range chain {
			read = true
			for _, name := range versionHeaders {
				for _, v := range resp.header.Values(name) {
					v = sanitize(v, 120)
					if !versionPattern.MatchString(v) {
						continue
					}
					line := strings.ToLower(name) + ": " + v
					if !have[line] {
						have[line] = true
						seen = append(seen, line)
					}
				}
			}
		}
	}
	if !read {
		return r
	}
	r.evaluate(CheckVersionDisclosed)
	if len(seen) == 0 {
		return r
	}
	r.add(issue{
		checkID: CheckVersionDisclosed, asset: host, severity: finding.SeverityLow,
		title: "Server reveals its software versions",
		description: "The response headers announce which software and which exact versions run the site. " +
			"Attackers use this to pick known vulnerabilities for those versions without having to probe. Hiding it does not fix anything by itself, " +
			"but it removes a free hint, and an old version number is a reminder to update.",
		evidence: strings.Join(seen, "\n"),
		remediation: []string{
			"nginx: `server_tokens off;`. Apache: `ServerTokens Prod` and `ServerSignature Off`. PHP: `expose_php = Off` in php.ini.",
			"Remove X-Powered-By and X-AspNet-Version headers in the framework settings.",
			"Keep the software itself up to date: hiding a version does not patch it.",
		},
		references: []string{refOWASPHdrs},
		fr: finding.Text{
			Title: "Le serveur révèle les versions de ses logiciels",
			Description: "Les en-têtes de réponse indiquent quels logiciels font fonctionner le site, et en quelle version exacte. " +
				"Les attaquants s’en servent pour choisir des vulnérabilités connues de ces versions sans avoir à sonder. Masquer ces informations ne corrige rien en soi, " +
				"mais retire un indice gratuit, et un numéro de version ancien rappelle qu’il faut mettre à jour.",
			Remediation: []string{
				"nginx : `server_tokens off;`. Apache : `ServerTokens Prod` et `ServerSignature Off`. PHP : `expose_php = Off` dans php.ini.",
				"Supprimez les en-têtes X-Powered-By et X-AspNet-Version dans les réglages du framework.",
				"Gardez les logiciels eux-mêmes à jour : masquer une version ne la corrige pas.",
			},
		},
	})
	return r
}

// evidenceHeaders are the headers shown in evidence, when present.
var evidenceHeaders = []string{
	"Location", "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Server", "X-Powered-By",
}

// chainEvidence describes each request and the relevant headers of its
// response. Values come from the target: sanitized and bounded.
func chainEvidence(chain []*response) string {
	var b strings.Builder
	for n, r := range chain {
		if n > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "GET %s (%s)\n%d %s\n", r.url, r.ip, r.status, http.StatusText(r.status))
		for _, name := range evidenceHeaders {
			for _, v := range r.header.Values(name) {
				fmt.Fprintf(&b, "%s: %s\n", strings.ToLower(name), sanitize(v, 300))
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// sanitize keeps printable ASCII only and bounds the length. Header values
// come from the target and end up in reports and terminals (rule 7).
func sanitize(s string, maxLen int) string {
	var sb strings.Builder
	for i := 0; i < len(s) && sb.Len() < maxLen; i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
