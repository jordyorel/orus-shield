package api

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
	"github.com/jordyorel/orus-shield/engine/internal/report"
)

// reportPeriodDays is the period of the report's trend and remediation
// figures, like the overview's default.
const reportPeriodDays = 30

// report answers GET /orgs/{org}/report?kind=executive|technical&lang=fr|en
// with a PDF built from the organization's stored data, generated on
// demand (nothing is kept). Viewers may download it: it shows what the
// dashboard shows them already.
func (s *Server) report(w http.ResponseWriter, r *http.Request, req orgRequest) {
	q := r.URL.Query()
	o := report.Options{Kind: report.Kind(q.Get("kind")), Lang: report.Lang(q.Get("lang"))}
	if o.Kind == "" {
		o.Kind = report.Executive
	}
	if o.Lang == "" {
		o.Lang = report.French
	}
	if err := o.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "kind must be executive or technical, lang fr or en")
		return
	}

	d, err := s.reportData(r, req)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var buf bytes.Buffer
	if err := report.Write(&buf, d, o); err != nil {
		s.internalError(w, r, err)
		return
	}
	name := fmt.Sprintf("orus-shield-%s-%s-%s.pdf", o.Kind, o.Lang, d.GeneratedAt.Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store") // security findings: never in a shared cache
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// reportData reads what the report shows, the same way the overview does.
func (s *Server) reportData(r *http.Request, req orgRequest) (report.Data, error) {
	ctx := r.Context()
	now := s.cfg.Now()
	period := reportPeriodDays * 24 * time.Hour
	since := now.Add(-period)
	d := report.Data{GeneratedAt: now, PeriodDays: reportPeriodDays}
	name, err := req.org.Name(ctx)
	if err != nil {
		return d, err
	}
	d.OrgName = name

	points, err := req.org.PosturePoints(ctx, since)
	if err != nil {
		return d, err
	}
	series := posture.Series(points, []time.Time{since, now})
	d.Score = series[len(series)-1]
	if delta, ok := posture.Change(series); ok {
		d.ScoreChange = &delta
	}
	rem, err := req.org.Remediation(ctx, since, now.Add(time.Second))
	if err != nil {
		return d, err
	}
	d.Fixed = rem.Fixed
	if rem.Fixed > 0 {
		h := rem.Mean.Hours()
		d.MeanFixHours = &h
	}

	sums, err := req.org.Overview(ctx)
	if err != nil {
		return d, err
	}
	for _, t := range sums {
		fs, err := req.org.ListFindings(ctx, t.ID)
		if err != nil {
			return d, err
		}
		var kept []finding.Finding
		for _, f := range fs {
			if f.Status != finding.StatusFixed {
				kept = append(kept, f)
			}
		}
		stored, err := req.org.ListAssets(ctx, t.ID, false)
		if err != nil {
			return d, err
		}
		assets := make([]asset.Asset, 0, len(stored))
		for _, a := range stored {
			assets = append(assets, asset.Asset{Kind: a.Kind, Value: a.Value, Details: a.Details})
		}
		d.Targets = append(d.Targets, report.Target{Domain: t.Domain, Verified: t.Verified, LastScanAt: t.LastScanAt,
			Score: t.PostureScore, Findings: kept, Assets: assets})
	}
	return d, nil
}
