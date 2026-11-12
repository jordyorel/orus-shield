package report

import (
	"fmt"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// strings is the report's own wording in one language.
type strs struct {
	executiveTitle, technicalTitle     string
	preparedFor, generated, page       string
	confidential                       string
	summary, score, noScore            string
	scoreHelp                          string
	change                             func(delta, days int) string
	openProblems, noOpen               string
	fixedInPeriod                      func(n, days int, meanHours *float64) string
	topActions, topActionsHelp         string
	noActions                          string
	domains, domain, status, lastScan  string
	verified, notVerified, never       string
	openCol, scoreCol                  string
	details, detailsHelp               string
	asset, firstSeen, evidence, fix    string
	references, accepted, acceptedHelp string
	more                               func(n int) string
	inventory, inventoryHelp           string
	kinds                              map[string]string
	noAssets                           string
	scope                              string
	sev                                map[finding.Severity]string
	date                               func(time.Time) string
}

var frMonths = []string{"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"}

var texts = map[Lang]strs{
	French: {
		executiveTitle: "Rapport de sécurité pour la direction",
		technicalTitle: "Rapport de sécurité technique",
		preparedFor:    "Préparé pour",
		generated:      "Établi le",
		page:           "Page %d sur %d",
		confidential:   "Confidentiel : ce document décrit des faiblesses de sécurité. Ne le diffusez qu’aux personnes chargées de les corriger.", //nolint:misspell // French text
		summary:        "Synthèse",
		score:          "Score de sécurité",
		noScore:        "Pas encore de score : lancez un premier scan.",
		scoreHelp:      "Part des vérifications réussies, pondérée par leur gravité. 100 signifie qu’aucune vérification n’a échoué.",
		change: func(delta, days int) string {
			switch {
			case delta > 0:
				return fmt.Sprintf("En hausse de %d points sur %d jours.", delta, days)
			case delta < 0:
				return fmt.Sprintf("En baisse de %d points sur %d jours.", -delta, days)
			}
			return fmt.Sprintf("Stable sur %d jours.", days)
		},
		openProblems: "Problèmes à corriger",
		noOpen:       "Aucun problème ouvert : rien à corriger pour le moment.",
		fixedInPeriod: func(n, days int, mean *float64) string {
			if n == 0 {
				return fmt.Sprintf("Aucun problème corrigé ces %d derniers jours.", days)
			}
			s := fmt.Sprintf("%d problème%s corrigé%s ces %d derniers jours", n, pl(n), pl(n), days)
			if mean != nil {
				s += ", en " + frDuration(*mean) + " en moyenne"
			}
			return s + "."
		},
		topActions:     "Les actions prioritaires",
		topActionsHelp: "Les problèmes les plus graves, à confier en premier à votre équipe ou à votre prestataire.",
		noActions:      "Aucune action urgente.",
		domains:        "Vos domaines",
		domain:         "Domaine",
		status:         "Propriété",
		lastScan:       "Dernier scan",
		verified:       "Vérifiée",
		notVerified:    "Non vérifiée",
		never:          "Jamais",
		openCol:        "Problèmes",
		scoreCol:       "Score",
		details:        "Détail des problèmes",
		detailsHelp:    "Chaque problème avec sa preuve technique et les étapes de correction. Les textes techniques sont en anglais.",
		asset:          "Élément concerné",
		firstSeen:      "Détecté le",
		evidence:       "Preuve",
		fix:            "Correction",
		references:     "Références",
		accepted:       "Risques acceptés",
		acceptedHelp:   "Problèmes que votre organisation a choisi d’accepter. Ils ne comptent plus dans les priorités.",
		more: func(n int) string {
			return fmt.Sprintf("… et %d autre%s problème%s, à voir dans le tableau de bord.", n, pl(n), pl(n))
		},
		inventory:     "Inventaire des actifs exposés",
		inventoryHelp: "Ce que nos scans ont observé sur internet pour vos domaines.",
		kinds:         map[string]string{"hostname": "Noms", "ip": "Adresses IP", "service": "Services ouverts", "certificate": "Certificats"}, //nolint:misspell // French text
		noAssets:      "Aucun actif observé pour le moment.",
		scope:         "Ce rapport couvre les vérifications externes d’Orus Shield : ce qui est visible depuis internet. Il ne remplace pas un audit complet.",
		sev:           map[finding.Severity]string{finding.SeverityCritical: "Critique", finding.SeverityHigh: "Élevée", finding.SeverityMedium: "Moyenne", finding.SeverityLow: "Faible", finding.SeverityInfo: "Info"},
		date: func(t time.Time) string {
			return fmt.Sprintf("%d %s %d", t.Day(), frMonths[t.Month()-1], t.Year())
		},
	},
	English: {
		executiveTitle: "Security report for management",
		technicalTitle: "Technical security report",
		preparedFor:    "Prepared for",
		generated:      "Issued on",
		page:           "Page %d of %d",
		confidential:   "Confidential: this document describes security weaknesses. Share it only with the people in charge of fixing them.",
		summary:        "Summary",
		score:          "Security score",
		noScore:        "No score yet: run a first scan.",
		scoreHelp:      "Share of passed checks, weighted by severity. 100 means no check failed.",
		change: func(delta, days int) string {
			switch {
			case delta > 0:
				return fmt.Sprintf("Up %d points over %d days.", delta, days)
			case delta < 0:
				return fmt.Sprintf("Down %d points over %d days.", -delta, days)
			}
			return fmt.Sprintf("Stable over %d days.", days)
		},
		openProblems: "Problems to fix",
		noOpen:       "No open problem: nothing to fix for now.",
		fixedInPeriod: func(n, days int, mean *float64) string {
			if n == 0 {
				return fmt.Sprintf("No problem fixed in the last %d days.", days)
			}
			s := fmt.Sprintf("%d problem%s fixed in the last %d days", n, pl(n), days)
			if mean != nil {
				s += ", in " + enDuration(*mean) + " on average"
			}
			return s + "."
		},
		topActions:     "Priority actions",
		topActionsHelp: "The most serious problems, to hand first to your team or your provider.",
		noActions:      "No urgent action.",
		domains:        "Your domains",
		domain:         "Domain",
		status:         "Ownership",
		lastScan:       "Last scan",
		verified:       "Verified",
		notVerified:    "Not verified",
		never:          "Never",
		openCol:        "Problems",
		scoreCol:       "Score",
		details:        "Problems in detail",
		detailsHelp:    "Each problem with its technical evidence and the steps to fix it.",
		asset:          "Affected item",
		firstSeen:      "Detected on",
		evidence:       "Evidence",
		fix:            "How to fix",
		references:     "References",
		accepted:       "Accepted risks",
		acceptedHelp:   "Problems your organization chose to accept. They no longer count in priorities.",
		more:           func(n int) string { return fmt.Sprintf("... and %d more problem%s, in the dashboard.", n, pl(n)) },
		inventory:      "Exposed asset inventory",
		inventoryHelp:  "What our scans observed on the internet for your domains.",
		kinds:          map[string]string{"hostname": "Names", "ip": "IP addresses", "service": "Open services", "certificate": "Certificates"},
		noAssets:       "No asset observed yet.",
		scope:          "This report covers Orus Shield's external checks: what is visible from the internet. It does not replace a full audit.",
		sev:            map[finding.Severity]string{finding.SeverityCritical: "Critical", finding.SeverityHigh: "High", finding.SeverityMedium: "Medium", finding.SeverityLow: "Low", finding.SeverityInfo: "Info"},
		date:           func(t time.Time) string { return t.Format("2 January 2006") },
	},
}

func pl(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}

func frDuration(hours float64) string {
	if hours < 48 {
		h := int(hours + 0.5)
		return fmt.Sprintf("%d heure%s", h, pl(h))
	}
	d := int(hours/24 + 0.5)
	return fmt.Sprintf("%d jour%s", d, pl(d))
}

func enDuration(hours float64) string {
	if hours < 48 {
		h := int(hours + 0.5)
		return fmt.Sprintf("%d hour%s", h, pl(h))
	}
	d := int(hours/24 + 0.5)
	return fmt.Sprintf("%d day%s", d, pl(d))
}

// title returns the report's title.
func (s strs) title(k Kind) string {
	if k == Executive {
		return s.executiveTitle
	}
	return s.technicalTitle
}
