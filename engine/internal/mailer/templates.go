package mailer

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// signature ends every email.
const signature = `
--
L'équipe Orus Shield
Orus Shield ne vous demandera jamais votre mot de passe ni un code de
connexion par email ou par téléphone.`

// SetupLink is the dashboard page where a one-time token sets a password.
// The token goes in the fragment (#token=...): browsers never send the
// fragment to a server, so it stays out of access logs and Referer headers.
func SetupLink(publicURL, token string) string {
	return strings.TrimRight(publicURL, "/") + "/setup-password#token=" + url.QueryEscape(token)
}

// PasswordReset is the email sent after "Mot de passe oublié".
func PasswordReset(to, link string, valid time.Duration) Message {
	return Message{
		To:      to,
		Subject: "Réinitialisation de votre mot de passe Orus Shield",
		Text: fmt.Sprintf(`Bonjour,

Une réinitialisation du mot de passe de votre compte Orus Shield a été
demandée. Pour choisir un nouveau mot de passe, ouvrez ce lien
(valable %s, utilisable une seule fois) :

%s

Si vous n'êtes pas à l'origine de cette demande, ignorez cet email :
votre mot de passe actuel reste valable et personne n'a accès à votre
compte. La double authentification reste active si vous l'utilisez.
%s
`, frenchDuration(valid), link, signature),
	}
}

// frenchDuration writes "1 heure", "24 heures", "30 minutes".
func frenchDuration(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		h := int(d / time.Hour)
		if h == 1 {
			return "1 heure"
		}
		return fmt.Sprintf("%d heures", h)
	}
	return fmt.Sprintf("%d minutes", int(d/time.Minute))
}

// oneLine makes text chosen by a customer (an organization name) safe for
// a subject and a single line: control characters become spaces, and the
// length is bounded.
func oneLine(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
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

func roleText(admin bool) string {
	if admin {
		return "administrateur (gestion des domaines, des scans et de l'équipe)"
	}
	return "lecteur (consultation des résultats)"
}

// Invitation is the email to a new member: a link to activate the account.
func Invitation(to, org, inviter string, admin bool, link string, valid time.Duration) Message {
	org = oneLine(org, 80)
	if org == "" {
		org = "votre organisation"
	}
	return Message{
		To:      to,
		Subject: "Invitation à rejoindre " + org + " sur Orus Shield",
		Text: fmt.Sprintf(`Bonjour,

%s vous invite à rejoindre « %s » sur Orus Shield, la plateforme qui
surveille la sécurité des domaines et des serveurs exposés sur internet.
Votre rôle : %s.

Pour activer votre compte et choisir votre mot de passe, ouvrez ce lien
(valable %s, utilisable une seule fois) :

%s

Si vous ne connaissez pas cette personne ou n'attendiez pas cette
invitation, ignorez cet email : aucun compte ne sera activé sans vous.
%s
`, oneLine(inviter, 254), org, roleText(admin), frenchDuration(valid), link, signature),
	}
}

// AddedToOrganization tells an existing user they were given access to an
// organization: nothing to activate, they sign in as usual.
func AddedToOrganization(to, org, inviter string, admin bool, publicURL string) Message {
	org = oneLine(org, 80)
	if org == "" {
		org = "une organisation"
	}
	return Message{
		To:      to,
		Subject: "Vous avez accès à " + org + " sur Orus Shield",
		Text: fmt.Sprintf(`Bonjour,

%s vous a donné accès à « %s » sur Orus Shield.
Votre rôle : %s.

Connectez-vous avec votre compte habituel :

%s

Si vous n'attendiez pas cet accès, prévenez la personne qui vous l'a
donné, ou ignorez cet email.
%s
`, oneLine(inviter, 254), org, roleText(admin), strings.TrimRight(publicURL, "/")+"/login", signature),
	}
}

// AlertItem is one finding listed in an alert.
type AlertItem struct {
	Severity string // "critical", "high"...
	Title    string // the module's English title (finding texts stay English)
	Asset    string
	Reopened bool
	Link     string // the finding in the dashboard
}

var severityFR = map[string]string{"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible", "info": "Info"}

// NewFindings is the alert sent after a scan that opened or reopened
// critical or high findings.
func NewFindings(to, org, domain string, items []AlertItem, total int, listLink string) Message {
	domain = oneLine(domain, 253)
	var critical int
	for _, it := range items {
		if it.Severity == "critical" {
			critical++
		}
	}
	subject := fmt.Sprintf("Orus Shield : %d nouvelle%s vulnérabilité%s sur %s", total, plural(total), plural(total), domain)
	if critical > 0 {
		subject = fmt.Sprintf("Orus Shield : %d vulnérabilité%s critique%s sur %s", critical, plural(critical), plural(critical), domain)
	}

	var b strings.Builder
	for _, it := range items {
		label := severityFR[it.Severity]
		if label == "" {
			label = oneLine(it.Severity, 20)
		}
		back := ""
		if it.Reopened {
			back = " (de retour : elle avait été corrigée)"
		}
		fmt.Fprintf(&b, "- [%s] %s%s\n  %s\n  %s\n", label, oneLine(it.Title, 200), back, oneLine(it.Asset, 253), it.Link)
	}
	more := ""
	if total > len(items) {
		more = fmt.Sprintf("\n... et %d autre%s.\n", total-len(items), plural(total-len(items)))
	}
	org = oneLine(org, 80)
	return Message{
		To:      to,
		Subject: subject,
		Text: fmt.Sprintf(`Bonjour,

Le dernier scan de %s (organisation « %s ») a trouvé %d vulnérabilité%s
critique%s ou élevée%s nouvelle%s ou revenue%s :

%s%s
Chaque lien ouvre l'explication et les étapes de correction. Toutes les
vulnérabilités ouvertes :

%s

Vous recevez cet email parce que vous êtes administrateur de « %s ».
Seules les vulnérabilités critiques et élevées déclenchent une alerte.
%s
`, domain, org, total, plural(total), plural(total), plural(total), plural(total), plural(total), b.String(), more, listLink, org, signature),
	}
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}

// FindingsLink is the dashboard's vulnerabilities page, optionally on one
// finding.
func FindingsLink(publicURL, orgID, findingID string) string {
	// The path is the dashboard's French route for the vulnerabilities screen (nav.tsx).
	u := strings.TrimRight(publicURL, "/") + "/orgs/" + url.PathEscape(orgID) + "/vulnerabilites" //nolint:misspell // French route name, not a typo
	if findingID != "" {
		u += "?id=" + url.QueryEscape(findingID)
	}
	return u
}

// ConfirmSignup is the email that confirms a signup: the link creates the
// account and the organization.
func ConfirmSignup(to, org, link string, valid time.Duration) Message {
	org = oneLine(org, 80)
	return Message{
		To:      to,
		Subject: "Confirmez la création de votre compte Orus Shield",
		Text: fmt.Sprintf(`Bonjour,

Pour créer votre compte Orus Shield et l'organisation « %s », confirmez
votre adresse en ouvrant ce lien, puis choisissez votre mot de passe
(valable %s, utilisable une seule fois) :

%s

Rien n'est créé tant que vous n'avez pas ouvert ce lien. Si vous n'êtes pas
à l'origine de cette demande, ignorez cet email.
%s
`, org, frenchDuration(valid), link, signature),
	}
}

// AlreadyRegistered answers a signup for an address that has an account:
// the form gives the same answer either way, the email tells the owner.
func AlreadyRegistered(to, loginURL, forgotURL string) Message {
	return Message{
		To:      to,
		Subject: "Vous avez déjà un compte Orus Shield",
		Text: fmt.Sprintf(`Bonjour,

Quelqu'un (vous, probablement) a demandé à créer un compte Orus Shield
avec cette adresse. Vous en avez déjà un : connectez-vous ici

%s

Mot de passe oublié ? Choisissez-en un nouveau ici :

%s

Si vous n'êtes pas à l'origine de cette demande, ignorez cet email :
rien n'a changé sur votre compte.
%s
`, loginURL, forgotURL, signature),
	}
}

// ThreatItem is one emerging threat listed in an alert.
type ThreatItem struct {
	CVE      string // may be empty
	Name     string // the template's English name
	Severity string // "critical" or "high"
	KEV      bool   // exploited in the wild (CISA KEV)
	EPSS     float64
	Products []string // the detected technologies it concerns
}

// EmergingThreats tells admins that newly published vulnerabilities may
// concern their domain and that a check was started. It never says the
// domain is vulnerable: the rescan decides, and a new_findings alert
// follows if it is.
func EmergingThreats(to, org, domain string, items []ThreatItem, total int, scansLink string) Message {
	domain = oneLine(domain, 253)
	org = oneLine(org, 80)
	subject := fmt.Sprintf("Orus Shield : %d nouvelle%s faille%s pouvant concerner %s, vérification en cours",
		total, plural(total), plural(total), domain)
	var b strings.Builder
	for _, it := range items {
		label := severityFR[it.Severity]
		if label == "" {
			label = oneLine(it.Severity, 20)
		}
		id := oneLine(it.CVE, 40)
		if id != "" {
			id += " : "
		}
		fmt.Fprintf(&b, "- [%s] %s%s\n", label, id, oneLine(it.Name, 200))
		var notes []string
		if len(it.Products) > 0 {
			var p []string
			for _, x := range it.Products {
				p = append(p, oneLine(x, 40))
			}
			notes = append(notes, "concerne : "+strings.Join(p, ", "))
		}
		if it.KEV {
			notes = append(notes, "déjà exploitée par des attaquants (catalogue CISA KEV)")
		}
		if it.EPSS >= 0.01 {
			notes = append(notes, fmt.Sprintf("probabilité d'exploitation sous 30 jours : %.0f %%", it.EPSS*100))
		}
		if len(notes) > 0 {
			fmt.Fprintf(&b, "  %s\n", strings.Join(notes, " ; "))
		}
	}
	more := ""
	if total > len(items) {
		more = fmt.Sprintf("\n... et %d autre%s.\n", total-len(items), plural(total-len(items)))
	}
	return Message{
		To:      to,
		Subject: subject,
		Text: fmt.Sprintf(`Bonjour,

De nouvelles failles de sécurité viennent d'être publiées pour des
logiciels que nous avons détectés sur %s (organisation « %s ») :

%s%s
Cela ne veut pas dire que vous êtes vulnérable : la version que vous
utilisez est peut-être déjà corrigée. Nous avons lancé une vérification
de vos serveurs. Si elle confirme une faille, vous recevrez une alerte
avec les étapes de correction. Suivre la vérification :

%s

Vous recevez cet email parce que vous êtes administrateur de « %s ».
%s
`, domain, org, b.String(), more, scansLink, org, signature),
	}
}

// ScansLink is the dashboard's scans page of an organization.
func ScansLink(publicURL, orgID string) string {
	return strings.TrimRight(publicURL, "/") + "/orgs/" + url.PathEscape(orgID) + "/scans"
}
