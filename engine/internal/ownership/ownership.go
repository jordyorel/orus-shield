// Package ownership proves that a customer controls a domain before active
// modules may scan it (security rule 1).
//
// The customer publishes a random token we give them:
//
//	_orus-verify.<domain>  TXT  "orus-verify=<token>"
//
// Only someone who controls the domain's DNS can do that. The record must
// stay published: before active scans, workers check it again, and remove
// the verified status if it is gone (the domain may have changed hands).
//
// Known limit (see CLAUDE.md, rule 1): this proves control of the DNS, not
// ownership of the IPs the domain points to.
package ownership

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

const (
	// RecordLabel is the DNS label under which the token is published.
	RecordLabel = "_orus-verify"
	valuePrefix = "orus-verify="

	// TokenTTL is how long a customer has to publish a new token.
	TokenTTL = 7 * 24 * time.Hour
	// RecheckInterval is how old a successful check may be before an
	// active scan checks the record again.
	RecheckInterval = 24 * time.Hour
)

var (
	// ErrRecordMissing means the expected TXT record was not found.
	ErrRecordMissing = errors.New("verification record not found")
	// ErrNoToken means no token was issued yet, or it expired.
	ErrNoToken = errors.New("no valid verification token: request one first")
)

// RecordName returns the DNS name holding the token for domain.
func RecordName(domain string) string { return RecordLabel + "." + domain }

// RecordValue returns the TXT value to publish for token.
func RecordValue(token string) string { return valuePrefix + token }

// NewToken returns a random token: 26 base32 characters, 128 bits from
// crypto/rand. Unguessable, so nobody can verify a domain with a token they
// did not receive. Lowercase because it is typed into DNS panels.
func NewToken() string {
	return strings.ToLower(rand.Text())
}

// Store is the part of store.Store this package uses.
type Store interface {
	GetTarget(ctx context.Context, id string) (store.Target, error)
	IssueVerificationToken(ctx context.Context, targetID, token string, expiresAt time.Time, actor string) error
	MarkVerified(ctx context.Context, targetID, token, actor string) error
	TouchVerification(ctx context.Context, targetID string) error
	RevokeVerification(ctx context.Context, targetID, actor, reason string, retryWindow time.Duration) error
	AppendAudit(ctx context.Context, e store.AuditEntry) error
}

// Verifier issues tokens, verifies targets and re-checks them.
type Verifier struct {
	st  Store
	dns resolver.Resolver // underlying resolver; always used through a gate
	now func() time.Time
}

// New returns a Verifier. dns is the raw resolver (resolver.NewSystem());
// every lookup goes through the target's gate.
func New(st Store, dns resolver.Resolver) *Verifier {
	return &Verifier{st: st, dns: dns, now: time.Now}
}

// Instructions is what the customer must publish.
type Instructions struct {
	Domain      string
	RecordName  string
	RecordValue string
	ExpiresAt   *time.Time // nil once verified
	Verified    bool
}

// Instructions returns the record to publish for a target, issuing a token
// if there is no valid one. Calling it again returns the same token until it
// expires, so the instructions do not change under the customer's feet.
func (v *Verifier) Instructions(ctx context.Context, targetID, actor string) (Instructions, error) {
	t, err := v.st.GetTarget(ctx, targetID)
	if err != nil {
		return Instructions{}, err
	}
	if t.Verified() || v.tokenValid(t) {
		return instructions(t, t.VerifyToken, t.VerifyTokenExpiresAt), nil
	}
	token := NewToken()
	expires := v.now().Add(TokenTTL)
	if err := v.st.IssueVerificationToken(ctx, t.ID, token, expires, actor); err != nil {
		return Instructions{}, err
	}
	return instructions(t, token, &expires), nil
}

func instructions(t store.Target, token string, expires *time.Time) Instructions {
	return Instructions{
		Domain:      t.Domain,
		RecordName:  RecordName(t.Domain),
		RecordValue: RecordValue(token),
		ExpiresAt:   expires,
		Verified:    t.Verified(),
	}
}

func (v *Verifier) tokenValid(t store.Target) bool {
	return t.VerifyToken != "" && t.VerifyTokenExpiresAt != nil && v.now().Before(*t.VerifyTokenExpiresAt)
}

// Verify looks for the target's record and marks the target verified if it
// is there. Verifying an already verified target is a no-op. Failed
// attempts are recorded in the audit log.
func (v *Verifier) Verify(ctx context.Context, targetID, actor string) error {
	t, err := v.st.GetTarget(ctx, targetID)
	if err != nil {
		return err
	}
	if t.Verified() {
		return nil
	}
	if !v.tokenValid(t) {
		return fmt.Errorf("verify %s: %w", t.Domain, ErrNoToken)
	}
	g, err := gate.FromTarget(t.Exclusions, t.RatePerSec)
	if err != nil {
		return fmt.Errorf("verify %s: %w", t.Domain, err)
	}
	found, err := recordPresent(ctx, resolver.Gated{Gate: g, Inner: v.dns}, t.Domain, t.VerifyToken)
	if err != nil {
		return fmt.Errorf("verify %s: %w", t.Domain, err)
	}
	if !found {
		if err := v.st.AppendAudit(ctx, store.AuditEntry{
			OrgID: t.OrgID, Actor: actor, Action: store.ActionVerificationFailed, Target: t.Domain,
			Details: map[string]any{"reason": "record not found"},
		}); err != nil {
			return err
		}
		return fmt.Errorf("verify %s: %w: expected %s TXT %q (DNS changes can take a few minutes to appear)",
			t.Domain, ErrRecordMissing, RecordName(t.Domain), RecordValue(t.VerifyToken))
	}
	return v.st.MarkVerified(ctx, t.ID, t.VerifyToken, actor)
}

// Recheck tells whether t may be actively scanned now. A recent successful
// check is trusted; otherwise the record is looked up again through g.
//
//   - record present: the check time is updated, true;
//   - record gone: the verified status is revoked (and audited), false;
//   - lookup failed: error. The caller must treat the target as not
//     verified for this scan, without revoking: a DNS outage is not proof
//     that the customer lost the domain.
func (v *Verifier) Recheck(ctx context.Context, t store.Target, g module.Gate, actor string) (bool, error) {
	if !t.Verified() {
		return false, nil
	}
	if t.VerifyCheckedAt != nil && v.now().Sub(*t.VerifyCheckedAt) < RecheckInterval {
		return true, nil
	}
	found, err := recordPresent(ctx, resolver.Gated{Gate: g, Inner: v.dns}, t.Domain, t.VerifyToken)
	if err != nil {
		return false, fmt.Errorf("recheck ownership of %s: %w", t.Domain, err)
	}
	if !found {
		reason := fmt.Sprintf("%s TXT record no longer found", RecordName(t.Domain))
		if err := v.st.RevokeVerification(ctx, t.ID, actor, reason, TokenTTL); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := v.st.TouchVerification(ctx, t.ID); err != nil {
		return false, err
	}
	return true, nil
}

// recordPresent reports whether one TXT record at the verification name is
// exactly the expected value. Other records there are ignored.
func recordPresent(ctx context.Context, dns resolver.Resolver, domain, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	records, err := dns.LookupTXT(ctx, RecordName(domain))
	if errors.Is(err, resolver.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want := RecordValue(token)
	for _, r := range records {
		if strings.TrimSpace(r) == want {
			return true, nil
		}
	}
	return false, nil
}
