package mailer

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TrialEndingFigures are what a trial brought, for the email sent before
// it ends. Problems are counted in lines, as the dashboard shows them.
type TrialEndingFigures struct {
	Plan    string // plan ID: "sme", "pro", "enterprise"
	EndsAt  time.Time
	Scans   int // scans finished during the trial
	Fixed   int // problem lines fixed during the trial
	Open    int // problem lines still open
	Urgent  int // critical and high ones among them
	Domains int // verified domains
}

// TrialEnding is our email before a paid trial ends. Paddle, the merchant
// of record, sends the legal reminder of the charge; this one says what the
// trial found and fixed, what continues, and how to cancel before the date.
// It is a service email about the customer's own subscription: no
// unsubscribe link, and it never states an amount (Paddle's email does,
// with the taxes of the customer's country).
func TrialEnding(lang Lang, to, org string, f TrialEndingFigures, todayLink, billingLink string) Message {
	org = oneLine(org, 80)
	if lang == English {
		return trialEndingEN(to, org, f, todayLink, billingLink)
	}
	date := frenchDate(f.EndsAt)
	name := planName(French, f.Plan)

	fixed := "aucun pour l'instant"
	if f.Fixed > 0 {
		fixed = fmt.Sprintf("%d", f.Fixed)
	}
	open := "aucun"
	if f.Open > 0 {
		open = fmt.Sprintf("%d", f.Open)
		if f.Urgent > 0 {
			open += fmt.Sprintf(", dont %d urgent%s", f.Urgent, plural(f.Urgent))
		}
	}
	next := "Votre plan d'action est à jour dans votre tableau de bord :"
	if f.Open > 0 {
		next = `Il vous reste quelques jours pour en corriger d'autres : chaque correction
est revérifiée et votre score remonte. Votre plan d'action, du plus
urgent au moins urgent :`
	}
	return Message{
		To:      to,
		Subject: fmt.Sprintf("Orus Shield : votre essai %s se termine le %s", name, date),
		Text: fmt.Sprintf(`Bonjour,

L'essai de l'offre %s de « %s » se termine le %s.
Ce qu'il a donné jusqu'ici :

- Scans effectués : %d
- Problèmes corrigés : %s
- Problèmes encore ouverts : %s
- Domaines surveillés : %d

%s

%s

Après le %s, votre abonnement continue sans rien à faire : scans
planifiés, alertes, vérification de vos corrections. Paddle, notre
prestataire de paiement, vous envoie de son côté le détail du
prélèvement.

Si vous ne souhaitez pas continuer, annulez avant le %s depuis
Réglages > Abonnement > « Factures et paiement » : rien ne sera prélevé,
et vos résultats restent consultables.

%s

Vous recevez cet email parce que vous êtes administrateur de « %s ».
%s
`, name, org, date, f.Scans, fixed, open, f.Domains, next, todayLink, date, date, billingLink, org, signature),
	}
}

func trialEndingEN(to, org string, f TrialEndingFigures, todayLink, billingLink string) Message {
	date := englishDate(f.EndsAt)
	name := planName(English, f.Plan)

	fixed := "none yet"
	if f.Fixed > 0 {
		fixed = fmt.Sprintf("%d", f.Fixed)
	}
	open := "none"
	if f.Open > 0 {
		open = fmt.Sprintf("%d", f.Open)
		if f.Urgent > 0 {
			open += fmt.Sprintf(", %d of them urgent", f.Urgent)
		}
	}
	next := "Your action plan is up to date in your dashboard:"
	if f.Open > 0 {
		next = `You still have a few days to fix more: every fix is verified and your
score goes back up. Your action plan, from most to least urgent:`
	}
	return Message{
		To:      to,
		Subject: fmt.Sprintf("Orus Shield: your %s trial ends on %s", name, date),
		Text: fmt.Sprintf(`Hello,

The %s trial of "%s" ends on %s.
What it has brought so far:

- Scans run: %d
- Problems fixed: %s
- Problems still open: %s
- Domains monitored: %d

%s

%s

After %s, your subscription continues with nothing to do: scheduled
scans, alerts, verification of your fixes. Paddle, our payment provider,
sends you the details of the charge separately.

If you do not want to continue, cancel before %s from Settings >
Subscription > "Invoices and payment": nothing will be charged, and your
results stay readable.

%s

You receive this email because you are an administrator of "%s".
%s
`, name, org, date, f.Scans, fixed, open, f.Domains, next, todayLink, date, date, billingLink, org, signatureEN),
	}
}

// BillingLink is the dashboard's Réglages > Abonnement section, where
// "Factures et paiement" opens Paddle's customer portal (cancellation).
func BillingLink(publicURL, orgID string) string {
	return strings.TrimRight(publicURL, "/") + "/orgs/" + url.PathEscape(orgID) + "/reglages?s=abonnement"
}

// planName is an offer's name as the site shows it in each language.
func planName(lang Lang, id string) string {
	fr := map[string]string{"discovery": "Gratuit", "sme": "Essentiel", "pro": "Pro", "enterprise": "Sur devis"}
	en := map[string]string{"discovery": "Free", "sme": "Essential", "pro": "Pro", "enterprise": "Custom"}
	names := fr
	if lang == English {
		names = en
	}
	if n, ok := names[id]; ok {
		return n
	}
	return "Orus Shield"
}

var frenchMonths = [...]string{"janvier", "février", "mars", "avril", "mai", "juin",
	"juillet", "août", "septembre", "octobre", "novembre", "décembre"}

// frenchDate writes "2 décembre 2026" (UTC, like the rest of our emails).
func frenchDate(t time.Time) string {
	t = t.UTC()
	day := fmt.Sprintf("%d", t.Day())
	if t.Day() == 1 {
		day = "1er"
	}
	return fmt.Sprintf("%s %s %d", day, frenchMonths[t.Month()-1], t.Year())
}

// englishDate writes "December 2, 2026" (UTC).
func englishDate(t time.Time) string {
	return t.UTC().Format("January 2, 2006")
}
