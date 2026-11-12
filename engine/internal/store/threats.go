package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// ActorThreats is who requested a rescan triggered by an emerging threat,
// in scans and in the audit log (rule 4).
const ActorThreats = "threats"

// NotifyEmergingThreat is the kind of notification sent when new threats
// may concern a target and a rescan was queued.
const NotifyEmergingThreat = "emerging_threat"

// threatModules is what a threat rescan runs: the known-vulnerability scan.
var threatModules = []string{"vulns"}

// maxThreatsPerAlert bounds the threats listed in one email.
const maxThreatsPerAlert = 20

// ThreatTemplate is a critical or high CVE detection template (package
// threats indexes them).
type ThreatTemplate struct {
	ID       string
	CVE      string
	Name     string
	Severity string // "critical" or "high"
	Products []string
	KEV      bool
	EPSS     float64
	// New: listed as added by its release. Only used on the first sync,
	// which is the baseline.
	New bool
}

// SyncThreatTemplates records the templates not seen before and returns
// how many were added. On the first sync (empty table), only templates
// marked New are emerging: the rest is the baseline, or every customer
// would be alerted about four thousand old CVEs. Afterwards, every template
// not seen before is emerging.
func (s *Store) SyncThreatTemplates(ctx context.Context, templates []ThreatTemplate, now time.Time) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("sync threat templates: %w", err)
	}
	defer tx.Rollback(ctx)
	// Two workers starting together: one syncs, the other waits and then
	// finds everything there.
	if _, err := tx.Exec(ctx, "LOCK TABLE threat_templates IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return 0, fmt.Errorf("sync threat templates: %w", err)
	}
	var baseline bool
	if err := tx.QueryRow(ctx, "SELECT NOT EXISTS (SELECT 1 FROM threat_templates)").Scan(&baseline); err != nil {
		return 0, fmt.Errorf("sync threat templates: %w", err)
	}
	added := 0
	for _, t := range templates {
		emerging := !baseline || t.New
		tag, err := tx.Exec(ctx, `
			INSERT INTO threat_templates (id, cve, name, severity, products, kev, epss, emerging, first_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO NOTHING`,
			truncateRunes(t.ID, 200), truncateRunes(t.CVE, 40), truncateRunes(t.Name, 500), t.Severity,
			t.Products, t.KEV, t.EPSS, emerging, now)
		if err != nil {
			return 0, fmt.Errorf("sync threat template %s: %w", t.ID, err)
		}
		added += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("sync threat templates: %w", err)
	}
	return added, nil
}

// PendingThreats returns the emerging templates not matched yet, oldest
// first, at most limit.
func (s *Store) PendingThreats(ctx context.Context, limit int) ([]ThreatTemplate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cve, name, severity, products, kev, epss FROM threat_templates
		WHERE emerging AND processed_at IS NULL
		ORDER BY first_seen, id
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("pending threats: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ThreatTemplate, error) {
		var t ThreatTemplate
		err := r.Scan(&t.ID, &t.CVE, &t.Name, &t.Severity, &t.Products, &t.KEV, &t.EPSS)
		return t, err
	})
	if err != nil {
		return nil, fmt.Errorf("pending threats: %w", err)
	}
	return out, nil
}

// TargetTechnologies is what the vulns module detected on one verified
// target: the "technologies" detail of each of its current hostnames.
type TargetTechnologies struct {
	TargetID     string
	Technologies []string // one detail string per hostname, e.g. "nginx 1.18.0, WordPress 6.1"
}

// VerifiedTargetTechnologies lists, across organizations, the verified
// targets with detected technologies. Threat rescans run the active vulns
// module: an unverified target could not run it anyway.
func (s *Store) VerifiedTargetTechnologies(ctx context.Context) ([]TargetTechnologies, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.target_id::text, array_agg(a.details->>'technologies' ORDER BY a.value)
		FROM assets a JOIN targets t ON t.id = a.target_id
		WHERE a.kind = 'hostname' AND a.gone_at IS NULL AND a.details ? 'technologies'
		  AND t.verified_at IS NOT NULL
		GROUP BY a.target_id
		ORDER BY a.target_id`)
	if err != nil {
		return nil, fmt.Errorf("target technologies: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (TargetTechnologies, error) {
		var t TargetTechnologies
		err := r.Scan(&t.TargetID, &t.Technologies)
		return t, err
	})
	if err != nil {
		return nil, fmt.Errorf("target technologies: %w", err)
	}
	return out, nil
}

// ThreatMatch says that a template may concern a target, because of the
// products listed.
type ThreatMatch struct {
	TemplateID string
	TargetID   string
	Products   []string
}

// EmergingThreat is one threat listed in an alert.
type EmergingThreat struct {
	TemplateID string   `json:"template_id"`
	CVE        string   `json:"cve"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	KEV        bool     `json:"kev"`
	EPSS       float64  `json:"epss"`
	Products   []string `json:"products"`
}

// EmergingThreatAlert is the payload of an emerging_threat notification.
type EmergingThreatAlert struct {
	OrgID   string           `json:"org_id"`
	OrgName string           `json:"org_name"`
	Domain  string           `json:"domain"`
	ScanID  string           `json:"scan_id"`
	Threats []EmergingThreat `json:"threats"` // most severe first, at most maxThreatsPerAlert
	Total   int              `json:"total"`
}

// RecordThreats stores the matches of the given templates, queues one
// vulns rescan per matched target (or reuses a vulns scan already waiting
// in the queue) with its audit entry, queues one email per activated admin
// listing the target's new threats, and marks the templates processed, all
// in one transaction: a crash leaves the templates pending, and a retry
// cannot rescan twice (UNIQUE (target_id, template_id)). It returns the
// number of rescans queued.
func (s *Store) RecordThreats(ctx context.Context, templateIDs []string, matches []ThreatMatch, now time.Time) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("record threats: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock the templates; another worker that got here first has processed
	// them, and its matches stand.
	rows, err := tx.Query(ctx, `
		SELECT id, cve, name, severity, kev, epss FROM threat_templates
		WHERE id = ANY($1) AND processed_at IS NULL
		FOR UPDATE SKIP LOCKED`, templateIDs)
	if err != nil {
		return 0, fmt.Errorf("record threats: %w", err)
	}
	templates := map[string]EmergingThreat{}
	for rows.Next() {
		var t EmergingThreat
		if err := rows.Scan(&t.TemplateID, &t.CVE, &t.Name, &t.Severity, &t.KEV, &t.EPSS); err != nil {
			rows.Close()
			return 0, fmt.Errorf("record threats: %w", err)
		}
		templates[t.TemplateID] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("record threats: %w", err)
	}

	// Group by target: one rescan and one email per target.
	byTarget := map[string][]ThreatMatch{}
	var order []string
	for _, m := range matches {
		if _, ok := templates[m.TemplateID]; !ok || !isUUID(m.TargetID) {
			continue
		}
		if _, seen := byTarget[m.TargetID]; !seen {
			order = append(order, m.TargetID)
		}
		byTarget[m.TargetID] = append(byTarget[m.TargetID], m)
	}

	rescans := 0
	for _, targetID := range order {
		queued, err := recordTargetThreats(ctx, tx, targetID, byTarget[targetID], templates, now)
		if err != nil {
			return 0, err
		}
		if queued {
			rescans++
		}
	}

	ids := make([]string, 0, len(templates))
	for id := range templates {
		ids = append(ids, id)
	}
	if _, err := tx.Exec(ctx, `UPDATE threat_templates SET processed_at = $2 WHERE id = ANY($1)`, ids, now); err != nil {
		return 0, fmt.Errorf("record threats: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("record threats: %w", err)
	}
	return rescans, nil
}

// recordTargetThreats handles one target's matches. queued is false when
// no new match was recorded (all seen before) or the target is gone.
func recordTargetThreats(ctx context.Context, tx pgx.Tx, targetID string, matches []ThreatMatch,
	templates map[string]EmergingThreat, now time.Time) (queued bool, err error) {
	var orgID, domain, orgName string
	err = tx.QueryRow(ctx, `
		SELECT t.org_id::text, t.domain, o.name FROM targets t JOIN organizations o ON o.id = t.org_id
		WHERE t.id = $1 AND t.verified_at IS NOT NULL`, targetID).Scan(&orgID, &domain, &orgName)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // deleted or unverified since the match was computed
	}
	if err != nil {
		return false, fmt.Errorf("record threats for target %s: %w", targetID, err)
	}

	var fresh []ThreatMatch
	for _, m := range matches {
		tag, err := tx.Exec(ctx, `
			INSERT INTO threat_matches (org_id, target_id, template_id, products, created_at)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (target_id, template_id) DO NOTHING`,
			orgID, targetID, m.TemplateID, m.Products, now)
		if err != nil {
			return false, fmt.Errorf("record threat %s for target %s: %w", m.TemplateID, targetID, err)
		}
		if tag.RowsAffected() == 1 {
			fresh = append(fresh, m)
		}
	}
	if len(fresh) == 0 {
		return false, nil
	}

	// A vulns scan already waiting will load the new templates when it
	// starts: reuse it rather than queue another one.
	var scanID string
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM scans
		WHERE target_id = $1 AND status = 'queued' AND modules @> $2
		ORDER BY created_at LIMIT 1`, targetID, threatModules).Scan(&scanID)
	reused := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			INSERT INTO scans (org_id, target_id, modules, requested_by) VALUES ($1, $2, $3, $4)
			RETURNING id::text`, orgID, targetID, threatModules, ActorThreats).Scan(&scanID)
	}
	if err != nil {
		return false, fmt.Errorf("rescan target %s: %w", targetID, err)
	}

	alert := EmergingThreatAlert{OrgID: orgID, OrgName: orgName, Domain: domain, ScanID: scanID, Total: len(fresh)}
	cves := make([]string, 0, len(fresh))
	for _, m := range fresh {
		t := templates[m.TemplateID]
		t.Products = m.Products
		alert.Threats = append(alert.Threats, t)
		cves = append(cves, cmp.Or(t.CVE, t.TemplateID))
	}
	if _, err := tx.Exec(ctx, `UPDATE threat_matches SET scan_id = $3 WHERE target_id = $1 AND template_id = ANY($2)`,
		targetID, templateIDsOf(fresh), scanID); err != nil {
		return false, fmt.Errorf("rescan target %s: %w", targetID, err)
	}
	if !reused {
		if err := appendAudit(ctx, tx, AuditEntry{
			OrgID: orgID, Actor: ActorThreats, Action: ActionScanRequested, Target: domain,
			Details: map[string]any{"scan_id": scanID, "modules": threatModules, "threats": cves},
		}); err != nil {
			return false, err
		}
	}

	slices.SortStableFunc(alert.Threats, func(a, b EmergingThreat) int {
		return cmp.Or(cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)), cmp.Compare(b.EPSS, a.EPSS))
	})
	if len(alert.Threats) > maxThreatsPerAlert {
		alert.Threats = alert.Threats[:maxThreatsPerAlert]
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return false, fmt.Errorf("threat alert: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO notifications (org_id, target_id, scan_id, kind, recipient, payload)
		SELECT $1, $2, $3, $4, u.email, $5
		FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.role = $6 AND u.password_hash IS NOT NULL AND u.disabled_at IS NULL`,
		orgID, targetID, scanID, NotifyEmergingThreat, data, RoleAdmin); err != nil {
		return false, fmt.Errorf("threat alert: %w", err)
	}
	return !reused, nil
}

func templateIDsOf(ms []ThreatMatch) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.TemplateID
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 2
	case "high":
		return 1
	}
	return 0
}

// ThreatView is one emerging threat as the dashboard shows it.
type ThreatView struct {
	TemplateID string
	CVE        string
	Name       string
	Severity   string
	KEV        bool
	EPSS       float64
	TargetID   string
	Domain     string
	Products   []string
	ScanID     string // "" when unknown
	ScanStatus string // the rescan's status: queued, running, done, failed
	At         time.Time
}

// ListThreats returns the organization's emerging threats, most recent
// first, at most limit.
func (o *Org) ListThreats(ctx context.Context, limit int) ([]ThreatView, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list threats: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT m.template_id, tt.cve, tt.name, tt.severity, tt.kev, tt.epss, m.target_id::text, t.domain,
		       m.products, coalesce(m.scan_id::text, ''), coalesce(s.status, ''), m.created_at
		FROM threat_matches m
		JOIN threat_templates tt ON tt.id = m.template_id
		JOIN targets t ON t.id = m.target_id
		LEFT JOIN scans s ON s.id = m.scan_id
		WHERE m.org_id = $1
		ORDER BY m.created_at DESC, tt.severity, m.template_id
		LIMIT $2`, o.orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("list threats: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ThreatView, error) {
		var v ThreatView
		err := r.Scan(&v.TemplateID, &v.CVE, &v.Name, &v.Severity, &v.KEV, &v.EPSS, &v.TargetID, &v.Domain,
			&v.Products, &v.ScanID, &v.ScanStatus, &v.At)
		return v, err
	})
	if err != nil {
		return nil, fmt.Errorf("list threats: %w", err)
	}
	return out, tx.Commit(ctx)
}
