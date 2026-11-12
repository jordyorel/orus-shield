// Package report renders an organization's security report as PDF, in
// French or English, in two versions:
//
//   - Executive: for management, two pages or so, no jargon: the score and
//     its trend, open problems by severity, the five actions that matter
//     most, and where each domain stands.
//   - Technical: the executive summary, then every open finding with its
//     evidence, remediation steps and references, accepted risks, and the
//     asset inventory.
//
// Every figure comes from stored scan data (Data), assembled by the caller:
// the report computes nothing that the engine did not measure, and invents
// nothing (rule 8). Finding texts are the modules' English (decided
// 2026-11-10); the report's own wording follows the chosen language.
package report

import (
	"cmp"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// Kind is the version of the report.
type Kind string

const (
	Executive Kind = "executive"
	Technical Kind = "technical"
)

// Lang is the report's language.
type Lang string

const (
	French  Lang = "fr"
	English Lang = "en"
)

// ErrInvalid is returned for an unknown kind or language.
var ErrInvalid = errors.New("invalid report options")

// Data is everything a report shows, read from the store by the caller.
type Data struct {
	OrgName     string
	GeneratedAt time.Time
	// Score pools every domain's checks (posture.Series), nil when nothing
	// was evaluated; ScoreChange is over PeriodDays, nil when unknown.
	Score       *int
	ScoreChange *int
	PeriodDays  int
	// Fixed findings in the period, and their mean time to fix.
	Fixed        int
	MeanFixHours *float64
	Targets      []Target
}

// Target is one domain.
type Target struct {
	Domain     string
	Verified   bool
	LastScanAt *time.Time
	Score      *int
	Findings   []finding.Finding // open and accepted ones; fixed ones are left out
	Assets     []asset.Asset     // current ones
}

// Options chooses the version and the language.
type Options struct {
	Kind Kind
	Lang Lang
}

// Validate checks the options.
func (o Options) Validate() error {
	if (o.Kind != Executive && o.Kind != Technical) || (o.Lang != French && o.Lang != English) {
		return ErrInvalid
	}
	return nil
}

// maxTechnicalFindings bounds the findings detailed in one technical
// report; the rest are counted.
const maxTechnicalFindings = 300

// Write renders the report as PDF.
func Write(w io.Writer, d Data, o Options) error {
	if err := o.Validate(); err != nil {
		return err
	}
	t := texts[o.Lang]
	r := newRenderer(t, o, d)
	r.cover()
	r.summary()
	if o.Kind == Technical {
		r.details()
		r.inventory()
	}
	return r.finish(w)
}

// openFindings returns the open findings of every domain, most severe first,
// then the oldest first (the longest exposed).
func openFindings(d Data) []domainFinding {
	var out []domainFinding
	for _, t := range d.Targets {
		for _, f := range t.Findings {
			if f.Status == finding.StatusOpen {
				out = append(out, domainFinding{t.Domain, f})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b domainFinding) int {
		return cmp.Or(cmp.Compare(b.f.Severity.Rank(), a.f.Severity.Rank()), a.f.FirstSeen.Compare(b.f.FirstSeen),
			cmp.Compare(a.domain, b.domain), cmp.Compare(a.f.ID, b.f.ID))
	})
	return out
}

type domainFinding struct {
	domain string
	f      finding.Finding
}

var severities = []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo}
