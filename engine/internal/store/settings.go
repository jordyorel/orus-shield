package store

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ActionSettingsChanged is the audit action of a change in Réglages.
const ActionSettingsChanged = "org.settings_changed"

// Alert levels: the lowest severity that sends an alert email.
const (
	AlertCritical = "critical"
	AlertHigh     = "high"
	AlertAll      = "all"
)

// Scan profiles.
const (
	ProfileQuick    = "quick"
	ProfileStandard = "standard"
)

// OrgSettings are the organization-wide choices of Réglages (table
// org_settings). Frequency is empty while no schedule was chosen.
type OrgSettings struct {
	AlertLevel      string
	EmailAlerts     bool
	Profile         string
	DisabledModules []string
	Frequency       string // daily, weekly, monthly, or ""
	Weekday         int    // 0 is Sunday
	Hour            int
	TimeZone        string
	RatePerSec      int // 0: the worker's default
}

// DefaultOrgSettings are the settings of an organization without a row.
func DefaultOrgSettings() OrgSettings {
	return OrgSettings{AlertLevel: AlertHigh, EmailAlerts: true, Profile: ProfileStandard,
		DisabledModules: []string{}, Weekday: 6, Hour: 2, TimeZone: "UTC"}
}

const orgSettingsColumns = `alert_level, email_alerts, profile, disabled_modules,
	coalesce(frequency, ''), weekday, hour, timezone, rate_per_sec`

func scanOrgSettings(row pgx.Row) (OrgSettings, error) {
	var s OrgSettings
	err := row.Scan(&s.AlertLevel, &s.EmailAlerts, &s.Profile, &s.DisabledModules,
		&s.Frequency, &s.Weekday, &s.Hour, &s.TimeZone, &s.RatePerSec)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultOrgSettings(), nil
	}
	return s, err
}

// Settings returns the organization's settings, the defaults without a row.
func (o *Org) Settings(ctx context.Context) (OrgSettings, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return OrgSettings{}, fmt.Errorf("settings: %w", err)
	}
	defer tx.Rollback(ctx)
	s, err := scanOrgSettings(tx.QueryRow(ctx, "SELECT "+orgSettingsColumns+" FROM org_settings WHERE org_id = $1", o.orgID))
	if err != nil {
		return OrgSettings{}, fmt.Errorf("settings: %w", err)
	}
	return s, tx.Commit(ctx)
}

// SaveSettings stores the settings (already validated by the caller) and
// records the change in the audit log.
func (o *Org) SaveSettings(ctx context.Context, s OrgSettings, actor string) error {
	if s.DisabledModules == nil {
		s.DisabledModules = []string{}
	}
	slices.Sort(s.DisabledModules)
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	defer tx.Rollback(ctx)
	var freq *string
	if s.Frequency != "" {
		freq = &s.Frequency
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO org_settings (org_id, alert_level, email_alerts, profile, disabled_modules,
			frequency, weekday, hour, timezone, rate_per_sec)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id) DO UPDATE SET alert_level = $2, email_alerts = $3, profile = $4,
			disabled_modules = $5, frequency = $6, weekday = $7, hour = $8, timezone = $9,
			rate_per_sec = $10, updated_at = now()`,
		o.orgID, s.AlertLevel, s.EmailAlerts, s.Profile, s.DisabledModules,
		freq, s.Weekday, s.Hour, s.TimeZone, s.RatePerSec)
	if err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionSettingsChanged, Target: "organization",
		Details: map[string]any{"alert_level": s.AlertLevel, "email_alerts": s.EmailAlerts, "profile": s.Profile,
			"disabled_modules": s.DisabledModules, "frequency": s.Frequency, "weekday": s.Weekday,
			"hour": s.Hour, "timezone": s.TimeZone, "rate_per_sec": s.RatePerSec},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// alertSettings reads, inside a transaction of the worker (no row-level
// security: it runs as the schema owner), what alerts an organization wants.
func alertSettings(ctx context.Context, tx pgx.Tx, orgID string) (level string, email bool, err error) {
	err = tx.QueryRow(ctx, "SELECT alert_level, email_alerts FROM org_settings WHERE org_id = $1", orgID).Scan(&level, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		d := DefaultOrgSettings()
		return d.AlertLevel, d.EmailAlerts, nil
	}
	return level, email, err
}
