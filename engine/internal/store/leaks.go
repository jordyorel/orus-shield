package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions of the addresses declared for leak monitoring.
const (
	ActionLeakAddressAdded   = "leak_address.added"
	ActionLeakAddressRemoved = "leak_address.removed"
)

// MaxLeakAddresses bounds the addresses declared on one domain (the leaks
// module checks at most 20 a run, members included).
const MaxLeakAddresses = 15

// ErrTooManyLeakAddresses: the domain already has MaxLeakAddresses.
var ErrTooManyLeakAddresses = errors.New("too many addresses declared on this domain")

// LeakAddress is an address declared on a domain for leak monitoring.
type LeakAddress struct {
	ID        string
	TargetID  string
	Email     string
	CreatedAt time.Time
	CreatedBy string
}

func scanLeakAddress(row pgx.CollectableRow) (LeakAddress, error) {
	var a LeakAddress
	err := row.Scan(&a.ID, &a.TargetID, &a.Email, &a.CreatedAt, &a.CreatedBy)
	return a, err
}

const leakAddressColumns = "id::text, target_id::text, email, created_at, created_by"

// LeakAddresses lists the addresses declared on a target.
func (o *Org) LeakAddresses(ctx context.Context, targetID string) ([]LeakAddress, error) {
	if !isUUID(targetID) {
		return nil, ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("leak addresses: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+leakAddressColumns+" FROM leak_addresses WHERE target_id = $1 ORDER BY email", targetID)
	if err != nil {
		return nil, fmt.Errorf("leak addresses: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanLeakAddress)
	if err != nil {
		return nil, fmt.Errorf("leak addresses: %w", err)
	}
	return out, tx.Commit(ctx)
}

// AddLeakAddress declares an address on a target. The caller checks that
// it is on the target's domain; the email is stored lowercased.
func (o *Org) AddLeakAddress(ctx context.Context, targetID, email, actor string) (LeakAddress, error) {
	if !isUUID(targetID) {
		return LeakAddress{}, ErrNotFound
	}
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := o.begin(ctx)
	if err != nil {
		return LeakAddress{}, fmt.Errorf("add leak address: %w", err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM leak_addresses WHERE target_id = $1", targetID).Scan(&n); err != nil {
		return LeakAddress{}, fmt.Errorf("add leak address: %w", err)
	}
	if n >= MaxLeakAddresses {
		return LeakAddress{}, ErrTooManyLeakAddresses
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO leak_addresses (org_id, target_id, email, created_by)
		VALUES ($1, $2, $3, $4) RETURNING `+leakAddressColumns, o.orgID, targetID, email, actor)
	if err != nil {
		return LeakAddress{}, fmt.Errorf("add leak address: %w", err)
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanLeakAddress)
	if err != nil {
		if isUniqueViolation(err) {
			return LeakAddress{}, ErrExists
		}
		return LeakAddress{}, fmt.Errorf("add leak address: %w", foreignKeyNotFound(err))
	}
	var domain string
	if err := tx.QueryRow(ctx, "SELECT domain FROM targets WHERE id = $1", targetID).Scan(&domain); err != nil {
		return LeakAddress{}, fmt.Errorf("add leak address: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionLeakAddressAdded, Target: domain,
		Details: map[string]any{"address_id": a.ID, "email": a.Email},
	}); err != nil {
		return LeakAddress{}, err
	}
	return a, tx.Commit(ctx)
}

// RemoveLeakAddress removes a declared address.
func (o *Org) RemoveLeakAddress(ctx context.Context, targetID, id, actor string) error {
	if !isUUID(targetID) || !isUUID(id) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("remove leak address: %w", err)
	}
	defer tx.Rollback(ctx)
	var email, domain string
	err = tx.QueryRow(ctx, `
		DELETE FROM leak_addresses a USING targets t
		WHERE t.id = a.target_id AND a.org_id = $1 AND a.target_id = $2 AND a.id = $3
		RETURNING a.email, t.domain`, o.orgID, targetID, id).Scan(&email, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("remove leak address: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionLeakAddressRemoved, Target: domain,
		Details: map[string]any{"address_id": id, "email": email},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// LeakEmails returns the addresses the leaks module checks on a target, for
// the worker (no row-level security): the organization's members whose
// address is on the domain or under it, then the declared addresses.
func (s *Store) LeakEmails(ctx context.Context, targetID string) ([]string, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.email FROM targets t
		JOIN memberships m ON m.org_id = t.org_id
		JOIN users u ON u.id = m.user_id
		WHERE t.id = $1 AND (u.email LIKE '%@' || t.domain OR u.email LIKE '%.' || t.domain)
		UNION
		SELECT a.email FROM leak_addresses a WHERE a.target_id = $1
		ORDER BY 1`, targetID)
	if err != nil {
		return nil, fmt.Errorf("leak emails: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("leak emails: %w", err)
	}
	return out, nil
}
