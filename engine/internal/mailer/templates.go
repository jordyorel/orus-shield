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
