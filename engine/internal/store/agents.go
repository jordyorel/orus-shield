package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Audit actions of agents.
const (
	ActionAgentCreated  = "agent.created"
	ActionAgentEnrolled = "agent.enrolled"
	ActionAgentRevoked  = "agent.revoked"
	ActionAgentCode     = "agent.enrolment_code"
)

// EnrolTTL is how long an enrolment code stays valid.
const EnrolTTL = 24 * time.Hour

// ErrRevoked is an agent that was revoked, or a token that matches none.
var ErrRevoked = errors.New("unknown or revoked agent")

// Agent is an agent as the dashboard sees it.
type Agent struct {
	ID              string
	TargetID        string
	Domain          string // its internal network's target name
	Name            string
	Ranges          []string
	EnrollExpiresAt *time.Time // a code is pending until then
	EnrolledAt      *time.Time
	LastSeenAt      *time.Time
	Hostname        string
	OS              string
	Version         string
	RevokedAt       *time.Time
	CreatedAt       time.Time
	CreatedBy       string
}

const agentColumns = `a.id::text, a.target_id::text, t.domain, a.name, a.ranges, a.enroll_expires_at, a.enrolled_at, a.last_seen_at,
	coalesce(a.hostname, ''), coalesce(a.os, ''), coalesce(a.version, ''), a.revoked_at, a.created_at, a.created_by`

func scanAgent(row pgx.CollectableRow) (Agent, error) {
	var a Agent
	err := row.Scan(&a.ID, &a.TargetID, &a.Domain, &a.Name, &a.Ranges, &a.EnrollExpiresAt, &a.EnrolledAt, &a.LastSeenAt,
		&a.Hostname, &a.OS, &a.Version, &a.RevokedAt, &a.CreatedAt, &a.CreatedBy)
	return a, err
}

// newCode returns a one-time code and its hash.
func newCode() (string, []byte, error) {
	return newToken()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateAgent creates an agent and its internal network (a verified,
// internal target), and returns the one-time enrolment code. ranges are
// already validated (private CIDRs).
func (o *Org) CreateAgent(ctx context.Context, name string, ranges []string, actor string) (Agent, string, error) {
	code, hash, err := newCode()
	if err != nil {
		return Agent{}, "", err
	}
	suffix, err := randomHex(6)
	if err != nil {
		return Agent{}, "", err
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Agent{}, "", fmt.Errorf("create agent: %w", err)
	}
	defer tx.Rollback(ctx)
	var targetID, domain string
	err = tx.QueryRow(ctx, `
		INSERT INTO targets (org_id, domain, verified_at, internal) VALUES ($1, $2, now(), true)
		RETURNING id::text, domain`, o.orgID, "agent-"+suffix+".internal").Scan(&targetID, &domain)
	if err != nil {
		return Agent{}, "", fmt.Errorf("create agent: internal network: %w", err)
	}
	// RETURNING only the columns the API's role may read (not the hashes).
	var agentID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO agents (org_id, target_id, name, ranges, enroll_hash, enroll_expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), $7) RETURNING id::text`,
		o.orgID, targetID, name, ranges, hash, EnrolTTL.Seconds(), actor).Scan(&agentID); err != nil {
		return Agent{}, "", fmt.Errorf("create agent: %w", err)
	}
	rows, err := tx.Query(ctx, "SELECT "+agentColumns+" FROM agents a JOIN targets t ON t.id = a.target_id WHERE a.id = $1", agentID)
	if err != nil {
		return Agent{}, "", fmt.Errorf("create agent: %w", err)
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAgent)
	if err != nil {
		return Agent{}, "", fmt.Errorf("create agent: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionAgentCreated, Target: domain,
		Details: map[string]any{"agent_id": a.ID, "name": name, "ranges": ranges},
	}); err != nil {
		return Agent{}, "", err
	}
	return a, code, tx.Commit(ctx)
}

// ListAgents returns the organization's agents, newest first.
func (o *Org) ListAgents(ctx context.Context) ([]Agent, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+agentColumns+" FROM agents a JOIN targets t ON t.id = a.target_id WHERE a.org_id = $1 ORDER BY a.created_at DESC", o.orgID)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanAgent)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	return out, tx.Commit(ctx)
}

// RevokeAgent stops an agent: its token stops working at once. Its internal
// network and results stay. Unknown is ErrNotFound.
func (o *Org) RevokeAgent(ctx context.Context, agentID, actor string) error {
	return o.agentChange(ctx, agentID, actor, ActionAgentRevoked,
		"UPDATE agents a SET revoked_at = coalesce(revoked_at, now()), enroll_hash = NULL, enroll_expires_at = NULL")
}

// NewEnrolmentCode issues a new one-time code for an agent not revoked
// (to install it again); the previous code stops working.
func (o *Org) NewEnrolmentCode(ctx context.Context, agentID, actor string) (string, error) {
	code, hash, err := newCode()
	if err != nil {
		return "", err
	}
	err = o.agentChange(ctx, agentID, actor, ActionAgentCode,
		"UPDATE agents a SET enroll_hash = $3, enroll_expires_at = now() + make_interval(secs => $4)", hash, EnrolTTL.Seconds())
	return code, err
}

func (o *Org) agentChange(ctx context.Context, agentID, actor, action, update string, args ...any) error {
	if !isUUID(agentID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	defer tx.Rollback(ctx)
	var domain string
	// update is a constant of this file; values are parameters.
	q := update + ` FROM targets t WHERE t.id = a.target_id AND a.org_id = $1 AND a.id = $2 AND a.revoked_at IS NULL RETURNING t.domain`
	err = tx.QueryRow(ctx, q, append([]any{o.orgID, agentID}, args...)...).Scan(&domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: action, Target: domain,
		Details: map[string]any{"agent_id": agentID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- The agents' side (API, role orus_agent) -------------------------------

const agentRole = "orus_agent"

// Agents is the store handle of the API's agent endpoints: it reaches
// agents, their internal networks and their scans, nothing else.
type Agents struct{ pool *pgxpool.Pool }

// Agents returns the agent endpoints' handle.
func (s *Store) Agents() *Agents { return &Agents{pool: s.pool} }

func (g *Agents) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// agentRole is a constant: no injection possible.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+agentRole); err != nil {
		return fmt.Errorf("switch to role %s: %w", agentRole, err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AgentInfo is an authenticated agent.
type AgentInfo struct {
	ID       string
	OrgID    string
	TargetID string
	Ranges   []string
}

// Enrol exchanges a one-time code for the agent's token, and records the
// machine it runs on.
func (g *Agents) Enrol(ctx context.Context, code, hostname, os, version string) (AgentInfo, string, error) {
	token, hash, err := newToken()
	if err != nil {
		return AgentInfo{}, "", err
	}
	var a AgentInfo
	err = g.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE agents SET token_hash = $2, enroll_hash = NULL, enroll_expires_at = NULL, enrolled_at = now(),
				last_seen_at = now(), hostname = $3, os = $4, version = $5
			WHERE enroll_hash = $1 AND enroll_expires_at > now() AND revoked_at IS NULL
			RETURNING id::text, org_id::text, target_id::text, ranges`,
			tokenHash(code), hash, truncateRunes(hostname, 255), truncateRunes(os, 50), truncateRunes(version, 50)).
			Scan(&a.ID, &a.OrgID, &a.TargetID, &a.Ranges)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		return appendAudit(ctx, tx, AuditEntry{OrgID: a.OrgID, Actor: "agent:" + a.ID, Action: ActionAgentEnrolled, Target: "agent",
			Details: map[string]any{"agent_id": a.ID, "hostname": hostname, "os": os, "version": version}})
	})
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return AgentInfo{}, "", err
		}
		return AgentInfo{}, "", fmt.Errorf("enrol agent: %w", err)
	}
	return a, token, nil
}

// Authenticate returns the agent of token and records that it was seen.
func (g *Agents) Authenticate(ctx context.Context, token, version string) (AgentInfo, error) {
	var a AgentInfo
	err := g.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE agents SET last_seen_at = now(), version = coalesce(nullif($2, ''), version)
			WHERE token_hash = $1 AND revoked_at IS NULL
			RETURNING id::text, org_id::text, target_id::text, ranges`, tokenHash(token), truncateRunes(version, 50)).
			Scan(&a.ID, &a.OrgID, &a.TargetID, &a.Ranges)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevoked
		}
		return err
	})
	if err != nil && !errors.Is(err, ErrRevoked) {
		return AgentInfo{}, fmt.Errorf("authenticate agent: %w", err)
	}
	return a, err
}

// AgentJob is a scan of an agent's internal network.
type AgentJob struct {
	Scan       Scan
	Exclusions json.RawMessage
	RatePerSec float64
}

// ClaimScan gives the agent the oldest scan of its internal network that
// is queued, or running with an expired lease (the agent crashed).
func (g *Agents) ClaimScan(ctx context.Context, a AgentInfo, lease time.Duration, maxAttempts int) (AgentJob, bool, error) {
	var job AgentJob
	ok := false
	err := g.inTx(ctx, func(tx pgx.Tx) error {
		sc, err := scanScan(tx.QueryRow(ctx, `
			WITH s AS (
				UPDATE scans SET status = 'running', attempts = attempts + 1,
					locked_until = now() + make_interval(secs => $2), started_at = coalesce(started_at, now())
				WHERE id = (
					SELECT id FROM scans WHERE target_id = $1
					  AND (status = 'queued' OR (status = 'running' AND locked_until < now() AND attempts < $3))
					ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
				)
				RETURNING *
			)
			SELECT `+scanColumns+` FROM s JOIN targets t ON t.id = s.target_id`, a.TargetID, lease.Seconds(), maxAttempts))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT exclusions, rate_per_sec FROM targets WHERE id = $1", a.TargetID).Scan(&job.Exclusions, &job.RatePerSec); err != nil {
			return err
		}
		job.Scan, ok = sc, true
		return appendAudit(ctx, tx, AuditEntry{OrgID: a.OrgID, Actor: "agent:" + a.ID, Action: ActionScanStarted, Target: sc.Domain,
			Details: map[string]any{"scan_id": sc.ID, "modules": sc.Modules, "attempt": sc.Attempt}})
	})
	if err != nil {
		return AgentJob{}, false, fmt.Errorf("agent claim: %w", err)
	}
	return job, ok, nil
}

// ExtendLease keeps an agent's running scan claimed.
func (g *Agents) ExtendLease(ctx context.Context, a AgentInfo, scanID string, attempt int, lease time.Duration) error {
	if !isUUID(scanID) {
		return ErrLeaseLost
	}
	return g.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE scans SET locked_until = now() + make_interval(secs => $4)
			WHERE id = $1 AND target_id = $2 AND attempts = $3 AND status = 'running'`, scanID, a.TargetID, attempt, lease.Seconds())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrLeaseLost
		}
		return nil
	})
}

// SubmitResult stores what an agent sent for its running scan, for the
// worker to validate and record. A scan that is not the agent's, not
// running, or of another attempt is ErrLeaseLost.
func (g *Agents) SubmitResult(ctx context.Context, a AgentInfo, scanID string, attempt int, payload json.RawMessage) error {
	if !isUUID(scanID) {
		return ErrLeaseLost
	}
	return g.inTx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scans WHERE id = $1 AND target_id = $2 AND attempts = $3 AND status = 'running'`,
			scanID, a.TargetID, attempt).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrLeaseLost
		}
		// The role cannot read agent_results: a second submission for the
		// same attempt is a unique violation, taken as done (savepoint, so
		// the transaction survives it).
		if _, err := tx.Exec(ctx, "SAVEPOINT submit"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO agent_results (org_id, agent_id, scan_id, attempt, payload) VALUES ($1, $2, $3, $4, $5)`,
			a.OrgID, a.ID, scanID, attempt, payload)
		if isUniqueViolation(err) {
			_, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT submit")
		}
		return err
	})
}

// ---- The worker's side ------------------------------------------------------

// AgentResult is an agent's submission waiting for the worker.
type AgentResult struct {
	ID      string
	AgentID string
	Ranges  []string
	Scan    Scan
	Payload json.RawMessage
}

// ClaimAgentResult takes the oldest unprocessed submission and marks it
// processed: a worker that crashes before recording it loses it, the scan's
// lease then expires and the agent scans again.
func (s *Store) ClaimAgentResult(ctx context.Context) (AgentResult, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AgentResult{}, false, fmt.Errorf("claim agent result: %w", err)
	}
	defer tx.Rollback(ctx)
	var r AgentResult
	var scanID string
	err = tx.QueryRow(ctx, `
		UPDATE agent_results SET processed_at = now()
		WHERE id = (SELECT id FROM agent_results WHERE processed_at IS NULL ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id::text, agent_id::text, scan_id::text, payload`).Scan(&r.ID, &r.AgentID, &scanID, &r.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentResult{}, false, nil
	}
	if err != nil {
		return AgentResult{}, false, fmt.Errorf("claim agent result: %w", err)
	}
	if err := tx.QueryRow(ctx, "SELECT ranges FROM agents WHERE id = $1", r.AgentID).Scan(&r.Ranges); err != nil {
		return AgentResult{}, false, fmt.Errorf("claim agent result: %w", err)
	}
	if r.Scan, err = scanScan(tx.QueryRow(ctx, "SELECT "+scanColumns+" FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = $1", scanID)); err != nil {
		return AgentResult{}, false, fmt.Errorf("claim agent result: %w", err)
	}
	return r, true, tx.Commit(ctx)
}
