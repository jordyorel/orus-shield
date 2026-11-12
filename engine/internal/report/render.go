package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/pdf"
)

// Colors and measures, from the dashboard's mockups.
var (
	ink     = pdf.Hex("#0E1116")
	muted   = pdf.Hex("#5B6570")
	rule    = pdf.Hex("#D5DAE1")
	brand   = pdf.Hex("#0C5DA5")
	surface = pdf.Hex("#EEF1F4")
	white   = pdf.Hex("#FFFFFF")

	sevColor = map[finding.Severity]pdf.Color{
		finding.SeverityCritical: pdf.Hex("#B42318"),
		finding.SeverityHigh:     pdf.Hex("#C4320A"),
		finding.SeverityMedium:   pdf.Hex("#B54708"),
		finding.SeverityLow:      pdf.Hex("#175CD3"),
		finding.SeverityInfo:     pdf.Hex("#5B6570"),
	}
)

const (
	margin  = 50.0
	width   = pdf.PageWidth - 2*margin
	bottom  = pdf.PageHeight - 60 // last baseline before the footer
	body    = 10.0
	leading = 1.4 // line height, in font sizes
)

// renderer lays content out from top to bottom, opening pages as needed.
type renderer struct {
	t    strs
	o    Options
	d    Data
	doc  *pdf.Document
	page *pdf.Page
	y    float64 // top of the next line
}

func newRenderer(t strs, o Options, d Data) *renderer {
	return &renderer{t: t, o: o, d: d, doc: pdf.New(t.title(o.Kind)+" - "+d.OrgName, string(o.Lang))}
}

func (r *renderer) newPage() {
	r.page = r.doc.AddPage()
	r.y = margin
}

// need opens a new page unless h points fit on this one.
func (r *renderer) need(h float64) {
	if r.page == nil || r.y+h > bottom {
		r.newPage()
	}
}

// para writes wrapped text at indent x.
func (r *renderer) para(x float64, f pdf.Font, size float64, c pdf.Color, s string) {
	for _, line := range pdf.Wrap(f, size, width-x, s) {
		r.need(size * leading)
		r.page.Text(margin+x, r.y+size, f, size, c, line)
		r.y += size * leading
	}
}

func (r *renderer) gap(h float64) { r.y += h }

// heading starts a section; it moves to a new page rather than leave a
// heading alone at the bottom of one.
func (r *renderer) heading(s string) {
	r.need(80)
	r.gap(8)
	r.page.Text(margin, r.y+16, pdf.HelveticaBold, 16, ink, s)
	r.y += 24
	r.page.Line(margin, r.y, margin+width, r.y, 0.75, rule)
	r.gap(10)
}

func (r *renderer) subheading(s string) {
	r.need(50)
	r.gap(4)
	r.para(0, pdf.HelveticaBold, 12, ink, s)
	r.gap(2)
}

// chip draws a severity label at (x, top) and returns its width.
func (r *renderer) chip(x, top float64, sev finding.Severity) float64 {
	label := r.t.sev[sev]
	w := pdf.Width(pdf.HelveticaBold, 8, label) + 10
	r.page.Rect(x, top, w, 13, sevColor[sev])
	r.page.Text(x+5, top+9.5, pdf.HelveticaBold, 8, white, label)
	return w
}

func (r *renderer) cover() {
	r.newPage()
	r.page.Rect(0, 0, pdf.PageWidth, 6, brand)
	r.page.Text(margin, margin+14, pdf.HelveticaBold, 12, brand, "Orus Shield")
	r.y = margin + 60
	r.para(0, pdf.HelveticaBold, 24, ink, r.t.title(r.o.Kind))
	r.gap(6)
	r.para(0, pdf.Helvetica, 12, muted, r.t.preparedFor+" : "+r.d.OrgName)
	r.para(0, pdf.Helvetica, 12, muted, r.t.generated+" "+r.t.date(r.d.GeneratedAt))
	r.gap(12)
	r.para(0, pdf.Helvetica, 9, muted, r.t.confidential)
	r.gap(14)
}

func (r *renderer) summary() {
	r.heading(r.t.summary)

	// The score, big, with what it means.
	r.need(70)
	top := r.y
	r.page.Rect(margin, top, 120, 62, surface)
	if r.d.Score != nil {
		s := strconv.Itoa(*r.d.Score)
		r.page.Text(margin+14, top+40, pdf.HelveticaBold, 30, brand, s)
		r.page.Text(margin+16+pdf.Width(pdf.HelveticaBold, 30, s), top+40, pdf.Helvetica, 12, muted, "/ 100")
	} else {
		r.page.Text(margin+14, top+40, pdf.HelveticaBold, 30, muted, "-")
	}
	r.page.Text(margin+14, top+55, pdf.Helvetica, 8, muted, r.t.score)
	saved := r.y
	r.y = top
	text := r.t.scoreHelp
	if r.d.Score == nil {
		text = r.t.noScore
	} else if r.d.ScoreChange != nil {
		text = r.t.change(*r.d.ScoreChange, r.d.PeriodDays) + " " + text
	}
	for _, line := range pdf.Wrap(pdf.Helvetica, body, width-140, text) {
		r.page.Text(margin+140, r.y+body, pdf.Helvetica, body, ink, line)
		r.y += body * leading
	}
	r.y = max(saved+66, r.y+4)

	// Open problems by severity.
	open := openFindings(r.d)
	counts := map[finding.Severity]int{}
	for _, df := range open {
		counts[df.f.Severity]++
	}
	r.subheading(r.t.openProblems)
	if len(open) == 0 {
		r.para(0, pdf.Helvetica, body, ink, r.t.noOpen)
	} else {
		r.need(24)
		x := margin
		for _, sev := range severities {
			if counts[sev] == 0 {
				continue
			}
			x += r.chip(x, r.y, sev) + 4
			n := strconv.Itoa(counts[sev])
			r.page.Text(x, r.y+10, pdf.HelveticaBold, 11, ink, n)
			x += pdf.Width(pdf.HelveticaBold, 11, n) + 14
		}
		r.y += 20
	}
	r.para(0, pdf.Helvetica, body, muted, r.t.fixedInPeriod(r.d.Fixed, r.d.PeriodDays, r.d.MeanFixHours))

	// The top five.
	r.subheading(r.t.topActions)
	r.para(0, pdf.Helvetica, 9, muted, r.t.topActionsHelp)
	r.gap(4)
	urgent := 0
	for _, df := range open {
		if urgent == 5 {
			break
		}
		if df.f.Severity.Rank() < finding.SeverityMedium.Rank() {
			break
		}
		urgent++
		r.item(urgent, df)
	}
	if urgent == 0 {
		r.para(0, pdf.Helvetica, body, ink, r.t.noActions)
	}

	r.domainsTable()
	r.gap(6)
	r.para(0, pdf.Helvetica, 8, muted, r.t.scope)
}

// item is one priority: number, severity, title, then where and the first
// remediation step.
func (r *renderer) item(n int, df domainFinding) {
	r.need(48)
	top := r.y
	r.page.Text(margin, top+10, pdf.HelveticaBold, 11, brand, strconv.Itoa(n)+".")
	w := r.chip(margin+18, top, df.f.Severity)
	lines := pdf.Wrap(pdf.HelveticaBold, body, width-26-w, df.f.Title)
	for i, l := range lines {
		r.page.Text(margin+24+w, top+10+float64(i)*body*leading, pdf.HelveticaBold, body, ink, l)
	}
	r.y = top + float64(max(len(lines), 1))*body*leading + 2
	r.para(18, pdf.Helvetica, 9, muted, df.domain+" · "+df.f.Asset)
	if len(df.f.Remediation) > 0 {
		r.para(18, pdf.Helvetica, 9, ink, df.f.Remediation[0])
	}
	r.gap(6)
}

func (r *renderer) domainsTable() {
	r.subheading(r.t.domains)
	cols := []float64{0, 190, 280, 380, 450} // domain, ownership, last scan, problems, score
	header := []string{r.t.domain, r.t.status, r.t.lastScan, r.t.openCol, r.t.scoreCol}
	r.need(20)
	for i, h := range header {
		r.page.Text(margin+cols[i], r.y+9, pdf.HelveticaBold, 8, muted, strings.ToUpper(h))
	}
	r.y += 14
	for _, t := range r.d.Targets {
		r.need(18)
		r.page.Line(margin, r.y, margin+width, r.y, 0.5, rule)
		base := r.y + 12
		r.page.Text(margin, base, pdf.Helvetica, 9, ink, clip(t.Domain, pdf.Helvetica, 9, cols[1]-8))
		own := r.t.notVerified
		if t.Verified {
			own = r.t.verified
		}
		r.page.Text(margin+cols[1], base, pdf.Helvetica, 9, ink, own)
		last := r.t.never
		if t.LastScanAt != nil {
			last = r.t.date(*t.LastScanAt)
		}
		r.page.Text(margin+cols[2], base, pdf.Helvetica, 9, ink, last)
		n := 0
		for _, f := range t.Findings {
			if f.Status == finding.StatusOpen {
				n++
			}
		}
		r.page.Text(margin+cols[3], base, pdf.Helvetica, 9, ink, strconv.Itoa(n))
		score := "-"
		if t.Score != nil {
			score = strconv.Itoa(*t.Score)
		}
		r.page.Text(margin+cols[4], base, pdf.HelveticaBold, 9, ink, score)
		r.y += 18
	}
}

// clip shortens s to fit w.
func clip(s string, f pdf.Font, size, w float64) string {
	if pdf.Width(f, size, s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && pdf.Width(f, size, string(r)+"…") > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// details lists every open finding, then the accepted risks.
func (r *renderer) details() {
	r.heading(r.t.details)
	r.para(0, pdf.Helvetica, 9, muted, r.t.detailsHelp)
	r.gap(6)
	open := openFindings(r.d)
	for i, df := range open {
		if i == maxTechnicalFindings {
			r.para(0, pdf.Helvetica, body, muted, r.t.more(len(open)-i))
			break
		}
		r.finding(df)
	}

	var accepted []domainFinding
	for _, t := range r.d.Targets {
		for _, f := range t.Findings {
			if f.Status == finding.StatusAcceptedRisk {
				accepted = append(accepted, domainFinding{t.Domain, f})
			}
		}
	}
	if len(accepted) > 0 {
		r.subheading(r.t.accepted)
		r.para(0, pdf.Helvetica, 9, muted, r.t.acceptedHelp)
		for _, df := range accepted {
			r.need(16)
			w := r.chip(margin, r.y, df.f.Severity)
			r.page.Text(margin+w+6, r.y+10, pdf.Helvetica, 9, ink, clip(df.f.Title+" · "+df.domain, pdf.Helvetica, 9, width-w-6))
			r.y += 17
		}
	}
}

func (r *renderer) finding(df domainFinding) {
	f := df.f
	r.need(90)
	r.page.Line(margin, r.y, margin+width, r.y, 0.5, rule)
	r.gap(8)
	top := r.y
	w := r.chip(margin, top, f.Severity)
	lines := pdf.Wrap(pdf.HelveticaBold, 11, width-w-8, f.Title)
	for i, l := range lines {
		r.page.Text(margin+w+8, top+10+float64(i)*11*leading, pdf.HelveticaBold, 11, ink, l)
	}
	r.y = top + float64(max(len(lines), 1))*11*leading + 2
	r.para(0, pdf.Helvetica, 9, muted, fmt.Sprintf("%s : %s · %s · %s %s", r.t.asset, df.domain, f.Asset, r.t.firstSeen, r.t.date(f.FirstSeen)))
	r.gap(2)
	r.para(0, pdf.Helvetica, body, ink, f.Description)
	if strings.TrimSpace(f.Evidence) != "" {
		r.gap(3)
		r.para(0, pdf.HelveticaBold, 9, ink, r.t.evidence)
		for _, line := range strings.Split(strings.TrimSpace(f.Evidence), "\n") {
			r.para(8, pdf.Helvetica, 8, muted, line)
		}
	}
	if len(f.Remediation) > 0 {
		r.gap(3)
		r.para(0, pdf.HelveticaBold, 9, ink, r.t.fix)
		for i, step := range f.Remediation {
			r.para(8, pdf.Helvetica, 9, ink, fmt.Sprintf("%d. %s", i+1, step))
		}
	}
	if len(f.References) > 0 {
		r.gap(3)
		r.para(0, pdf.HelveticaBold, 9, ink, r.t.references)
		r.para(8, pdf.Helvetica, 8, muted, strings.Join(f.References, " · "))
	}
	r.gap(8)
}

// inventory lists the current assets by kind, per domain.
func (r *renderer) inventory() {
	r.heading(r.t.inventory)
	r.para(0, pdf.Helvetica, 9, muted, r.t.inventoryHelp)
	any := false
	for _, t := range r.d.Targets {
		if len(t.Assets) == 0 {
			continue
		}
		any = true
		r.subheading(t.Domain)
		for _, kind := range []asset.Kind{asset.KindHostname, asset.KindIP, asset.KindService, asset.KindCertificate} {
			var values []string
			for _, a := range t.Assets {
				if a.Kind != kind {
					continue
				}
				v := a.Value
				if tech := a.Details["technologies"]; tech != "" {
					v += " (" + tech + ")"
				}
				if exp := a.Details["expected"]; exp != "" && kind == asset.KindService {
					v += " (" + exp + ")"
				}
				values = append(values, v)
			}
			if len(values) == 0 {
				continue
			}
			slices.Sort(values)
			r.para(0, pdf.HelveticaBold, 9, ink, fmt.Sprintf("%s (%d)", r.t.kinds[string(kind)], len(values)))
			for _, v := range values {
				r.para(8, pdf.Helvetica, 8, muted, v)
			}
			r.gap(3)
		}
	}
	if !any {
		r.para(0, pdf.Helvetica, body, ink, r.t.noAssets)
	}
}

// finish draws the footers, now that the page count is known, and writes.
func (r *renderer) finish(w io.Writer) error {
	n := r.doc.Pages()
	for i := range n {
		p := r.doc.Page(i)
		p.Line(margin, pdf.PageHeight-45, margin+width, pdf.PageHeight-45, 0.5, rule)
		p.Text(margin, pdf.PageHeight-32, pdf.Helvetica, 8, muted, clip("Orus Shield · "+r.d.OrgName, pdf.Helvetica, 8, width-80))
		label := fmt.Sprintf(r.t.page, i+1, n)
		p.Text(margin+width-pdf.Width(pdf.Helvetica, 8, label), pdf.PageHeight-32, pdf.Helvetica, 8, muted, label)
	}
	return r.doc.Write(w, r.d.GeneratedAt)
}
