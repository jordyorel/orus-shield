package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	// ProfileDeep needs a consent on record (DeepConsentAt).
	ProfileDeep = "deep"
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
	// DeepConsentAt and DeepConsentBy record who confirmed being allowed
	// to have the servers tested deeply, and when. Kept when the profile
	// changes back, so the history stays.
	DeepConsentAt *time.Time
	DeepConsentBy string
}

// DefaultOrgSettings are the settings of an organization without a row.
func DefaultOrgSettings() OrgSettings {
	return OrgSettings{AlertLevel: AlertHigh, EmailAlerts: true, Profile: ProfileStandard,
		DisabledModules: []string{}, Weekday: 6, Hour: 2, TimeZone: "UTC"}
}

const orgSettingsColumns = `alert_level, email_alerts, profile, disabled_modules,
	coalesce(frequency, ''), weekday, hour, timezone, rate_per_sec, deep_consent_at, coalesce(deep_consent_by, '')`

func scanOrgSettings(row pgx.Row) (OrgSettings, error) {
	var s OrgSettings
	err := row.Scan(&s.AlertLevel, &s.EmailAlerts, &s.Profile, &s.DisabledModules,
		&s.Frequency, &s.Weekday, &s.Hour, &s.TimeZone, &s.RatePerSec, &s.DeepConsentAt, &s.DeepConsentBy)
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
// records the change in the audit log. consent records, now and by actor,
// the deep profile's consent; without it the stored consent is kept.
func (o *Org) SaveSettings(ctx context.Context, s OrgSettings, consent bool, actor string) error {
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
	// The consent travels in the inserted row itself: PostgreSQL checks
	// org_settings_deep_needs_consent on that row before ON CONFLICT turns
	// it into an update, so it must already hold the consent on record.
	_, err = tx.Exec(ctx, `
		INSERT INTO org_settings (org_id, alert_level, email_alerts, profile, disabled_modules,
			frequency, weekday, hour, timezone, rate_per_sec, deep_consent_at, deep_consent_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			CASE WHEN $11 THEN now() ELSE (SELECT deep_consent_at FROM org_settings WHERE org_id = $1) END,
			CASE WHEN $11 THEN $12 ELSE (SELECT deep_consent_by FROM org_settings WHERE org_id = $1) END)
		ON CONFLICT (org_id) DO UPDATE SET alert_level = $2, email_alerts = $3, profile = $4,
			disabled_modules = $5, frequency = $6, weekday = $7, hour = $8, timezone = $9,
			rate_per_sec = $10, updated_at = now(),
			deep_consent_at = EXCLUDED.deep_consent_at, deep_consent_by = EXCLUDED.deep_consent_by`,
		o.orgID, s.AlertLevel, s.EmailAlerts, s.Profile, s.DisabledModules,
		freq, s.Weekday, s.Hour, s.TimeZone, s.RatePerSec, consent, actor)
	if err != nil {
		if isCheckViolation(err, "org_settings_deep_needs_consent") {
			return ErrNoDeepConsent
		}
		return fmt.Errorf("save settings: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionSettingsChanged, Target: "organization",
		Details: map[string]any{"alert_level": s.AlertLevel, "email_alerts": s.EmailAlerts, "profile": s.Profile,
			"disabled_modules": s.DisabledModules, "frequency": s.Frequency, "weekday": s.Weekday,
			"hour": s.Hour, "timezone": s.TimeZone, "rate_per_sec": s.RatePerSec, "deep_consent": consent},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ErrNoDeepConsent: the deep profile was chosen without a consent on record.
var ErrNoDeepConsent = errors.New("the deep profile needs the customer's consent")

// ScanProfileOf returns the scan profile of an organization for the worker
// (schema owner, no row-level security): deep only with a consent on
// record, standard without settings.
func (s *Store) ScanProfileOf(ctx context.Context, orgID string) (string, error) {
	if !isUUID(orgID) {
		return "", fmt.Errorf("scan profile of %s: %w", orgID, ErrNotFound)
	}
	var profile string
	err := s.pool.QueryRow(ctx, `
		SELECT CASE WHEN profile = 'deep' AND deep_consent_at IS NULL THEN 'standard' ELSE profile END
		FROM org_settings WHERE org_id = $1`, orgID).Scan(&profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProfileStandard, nil
	}
	if err != nil {
		return "", fmt.Errorf("scan profile of %s: %w", orgID, err)
	}
	return profile, nil
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

// isCheckViolation reports whether err is PostgreSQL's check_violation of
// the named constraint.
func isCheckViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == constraint
}
