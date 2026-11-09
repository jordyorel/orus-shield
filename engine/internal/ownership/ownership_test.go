package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// ---- Fakes ----------------------------------------------------------------

// fakeStore keeps one target and mimics the store's verification rules.
type fakeStore struct {
	target  store.Target
	audit   []string
	revoked string
	touched int
}

func (f *fakeStore) GetTarget(ctx context.Context, id string) (store.Target, error) {
	if id != f.target.ID {
		return store.Target{}, store.ErrNotFound
	}
	return f.target, nil
}

func (f *fakeStore) IssueVerificationToken(ctx context.Context, targetID, token string, expiresAt time.Time, actor string) error {
	if f.target.Verified() {
		return store.ErrAlreadyVerified
	}
	f.target.VerifyToken, f.target.VerifyTokenExpiresAt = token, &expiresAt
	f.audit = append(f.audit, actor+" "+store.ActionVerifyTokenIssued)
	return nil
}

func (f *fakeStore) MarkVerified(ctx context.Context, targetID, token, actor string) error {
	if token != f.target.VerifyToken {
		return store.ErrTokenMismatch
	}
	now := time.Now()
	f.target.VerifiedAt, f.target.VerifyCheckedAt, f.target.VerifyTokenExpiresAt = &now, &now, nil
	f.audit = append(f.audit, actor+" "+store.ActionVerified)
	return nil
}

func (f *fakeStore) TouchVerification(ctx context.Context, targetID string) error {
	f.touched++
	return nil
}

func (f *fakeStore) RevokeVerification(ctx context.Context, targetID, actor, reason string, retryWindow time.Duration) error {
	f.target.VerifiedAt = nil
	f.revoked = reason
	f.audit = append(f.audit, actor+" "+store.ActionVerificationRevoked)
	return nil
}

func (f *fakeStore) AppendAudit(ctx context.Context, e store.AuditEntry) error {
	f.audit = append(f.audit, e.Actor+" "+e.Action)
	return nil
}

// fakeDNS answers TXT lookups from a map; other names are NXDOMAIN.
type fakeDNS struct {
	txt   map[string][]string
	err   error // returned for every lookup when set
	calls []string
}

func (d *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	d.calls = append(d.calls, name)
	if d.err != nil {
		return nil, d.err
	}
	if r, ok := d.txt[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
}

func (d *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}

func (d *fakeDNS) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, resolver.ErrNotFound
}

type allowAll struct{ calls int }

func (g *allowAll) Allow(ctx context.Context, dest module.Destination) error {
	g.calls++
	return nil
}

func mustInstructions(t *testing.T, v *Verifier) Instructions {
	t.Helper()
	in, err := v.Instructions(context.Background(), "t1", "x")
	if err != nil {
		t.Fatalf("Instructions: %v", err)
	}
	return in
}

func newVerifier() (*Verifier, *fakeStore, *fakeDNS) {
	st := &fakeStore{target: store.Target{
		ID: "t1", Domain: "example.com", RatePerSec: 50, Exclusions: json.RawMessage("{}"),
	}}
	dns := &fakeDNS{txt: map[string][]string{}}
	return New(st, dns), st, dns
}

func publish(dns *fakeDNS, in Instructions) {
	dns.txt[in.RecordName] = []string{"some other record", in.RecordValue}
}

// ---- Tests ----------------------------------------------------------------

func TestNewToken(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		tok := NewToken()
		if len(tok) != 26 || tok != strings.ToLower(tok) {
			t.Fatalf("token %q: want 26 lowercase characters", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestVerifyFlow(t *testing.T) {
	v, st, dns := newVerifier()
	ctx := context.Background()

	in, err := v.Instructions(ctx, "t1", "cli:jordy")
	if err != nil {
		t.Fatalf("Instructions: %v", err)
	}
	if in.RecordName != "_orus-verify.example.com" || !strings.HasPrefix(in.RecordValue, "orus-verify=") || in.ExpiresAt == nil {
		t.Fatalf("instructions = %+v", in)
	}
	// Asking again gives the same token.
	again, err := v.Instructions(ctx, "t1", "cli:jordy")
	if err != nil || again.RecordValue != in.RecordValue {
		t.Errorf("second Instructions = %+v, %v; want the same record", again, err)
	}

	// Not published yet: refused, and the attempt is audited.
	err = v.Verify(ctx, "t1", "cli:jordy")
	if !errors.Is(err, ErrRecordMissing) || !strings.Contains(err.Error(), in.RecordValue) {
		t.Fatalf("Verify before publishing = %v, want ErrRecordMissing with the expected record", err)
	}
	if st.target.Verified() {
		t.Fatal("target verified without the record")
	}

	publish(dns, in)
	if err := v.Verify(ctx, "t1", "cli:jordy"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !st.target.Verified() {
		t.Fatal("target not verified after publishing the record")
	}
	// Idempotent.
	if err := v.Verify(ctx, "t1", "cli:jordy"); err != nil {
		t.Errorf("Verify on a verified target = %v", err)
	}

	want := []string{
		"cli:jordy " + store.ActionVerifyTokenIssued,
		"cli:jordy " + store.ActionVerificationFailed,
		"cli:jordy " + store.ActionVerified,
	}
	if strings.Join(st.audit, "|") != strings.Join(want, "|") {
		t.Errorf("audit = %v, want %v", st.audit, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("no token", func(t *testing.T) {
		v, _, _ := newVerifier()
		if err := v.Verify(ctx, "t1", "x"); !errors.Is(err, ErrNoToken) {
			t.Errorf("Verify = %v, want ErrNoToken", err)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		v, st, dns := newVerifier()
		in := mustInstructions(t, v)
		publish(dns, in)
		past := time.Now().Add(-time.Minute)
		st.target.VerifyTokenExpiresAt = &past
		if err := v.Verify(ctx, "t1", "x"); !errors.Is(err, ErrNoToken) {
			t.Errorf("Verify = %v, want ErrNoToken", err)
		}
	})
	t.Run("another token published", func(t *testing.T) {
		v, st, dns := newVerifier()
		in := mustInstructions(t, v)
		dns.txt[in.RecordName] = []string{RecordValue("someone-elses-token")}
		if err := v.Verify(ctx, "t1", "x"); !errors.Is(err, ErrRecordMissing) || st.target.Verified() {
			t.Errorf("Verify = %v, verified %v; want ErrRecordMissing", err, st.target.Verified())
		}
	})
	t.Run("token at the apex instead of _orus-verify", func(t *testing.T) {
		v, _, dns := newVerifier()
		in := mustInstructions(t, v)
		dns.txt["example.com"] = []string{in.RecordValue}
		if err := v.Verify(ctx, "t1", "x"); !errors.Is(err, ErrRecordMissing) {
			t.Errorf("Verify = %v, want ErrRecordMissing", err)
		}
	})
	t.Run("dns failure is an error, not a refusal", func(t *testing.T) {
		v, st, dns := newVerifier()
		mustInstructions(t, v)
		dns.err = &net.DNSError{Err: "server misbehaving"}
		err := v.Verify(ctx, "t1", "x")
		if err == nil || errors.Is(err, ErrRecordMissing) {
			t.Errorf("Verify = %v, want the DNS error", err)
		}
		if st.target.Verified() {
			t.Error("verified despite DNS failure")
		}
	})
	t.Run("excluded verification name", func(t *testing.T) {
		v, st, _ := newVerifier()
		mustInstructions(t, v)
		st.target.Exclusions = json.RawMessage(`{"hosts": ["_orus-verify.example.com"]}`)
		if err := v.Verify(ctx, "t1", "x"); !errors.Is(err, module.ErrExcluded) {
			t.Errorf("Verify = %v, want ErrExcluded", err)
		}
	})
}

func TestInstructionsForVerifiedTarget(t *testing.T) {
	v, st, dns := newVerifier()
	ctx := context.Background()
	in, _ := v.Instructions(ctx, "t1", "x")
	publish(dns, in)
	if err := v.Verify(ctx, "t1", "x"); err != nil {
		t.Fatal(err)
	}
	got, err := v.Instructions(ctx, "t1", "x")
	if err != nil {
		t.Fatalf("Instructions = %v", err)
	}
	// The published record must stay valid: same value, no new token.
	if !got.Verified || got.RecordValue != in.RecordValue {
		t.Errorf("instructions after verification = %+v, want verified with the same record", got)
	}
	if strings.Count(strings.Join(st.audit, "|"), store.ActionVerifyTokenIssued) != 1 {
		t.Errorf("a second token was issued: %v", st.audit)
	}
}

func TestRecheck(t *testing.T) {
	ctx := context.Background()
	verified := func(t *testing.T, checkedAgo time.Duration) (*Verifier, *fakeStore, *fakeDNS) {
		t.Helper()
		v, st, dns := newVerifier()
		in := mustInstructions(t, v)
		publish(dns, in)
		if err := v.Verify(ctx, "t1", "x"); err != nil {
			t.Fatal(err)
		}
		checked := time.Now().Add(-checkedAgo)
		st.target.VerifyCheckedAt = &checked
		dns.calls = nil
		return v, st, dns
	}

	t.Run("unverified target", func(t *testing.T) {
		v, st, _ := newVerifier()
		ok, err := v.Recheck(ctx, st.target, &allowAll{}, "worker:a")
		if ok || err != nil {
			t.Errorf("Recheck = %v, %v; want false", ok, err)
		}
	})
	t.Run("recent check is trusted without lookup", func(t *testing.T) {
		v, st, dns := verified(t, time.Hour)
		ok, err := v.Recheck(ctx, st.target, &allowAll{}, "worker:a")
		if !ok || err != nil || len(dns.calls) != 0 {
			t.Errorf("Recheck = %v, %v, %d lookups; want true without lookup", ok, err, len(dns.calls))
		}
	})
	t.Run("old check, record still there", func(t *testing.T) {
		v, st, dns := verified(t, 2*RecheckInterval)
		g := &allowAll{}
		ok, err := v.Recheck(ctx, st.target, g, "worker:a")
		if !ok || err != nil || st.touched != 1 {
			t.Errorf("Recheck = %v, %v, touched %d; want true and touched", ok, err, st.touched)
		}
		if g.calls != len(dns.calls) || g.calls == 0 {
			t.Errorf("gate saw %d requests for %d lookups", g.calls, len(dns.calls))
		}
	})
	t.Run("old check, record removed", func(t *testing.T) {
		v, st, dns := verified(t, 2*RecheckInterval)
		dns.txt = map[string][]string{}
		ok, err := v.Recheck(ctx, st.target, &allowAll{}, "worker:a")
		if ok || err != nil {
			t.Fatalf("Recheck = %v, %v; want false", ok, err)
		}
		if st.target.Verified() || !strings.Contains(st.revoked, "_orus-verify.example.com") {
			t.Errorf("verification not revoked: %+v, reason %q", st.target, st.revoked)
		}
		if st.audit[len(st.audit)-1] != "worker:a "+store.ActionVerificationRevoked {
			t.Errorf("audit = %v, want a revocation by the worker", st.audit)
		}
	})
	t.Run("dns failure: not verified now, not revoked", func(t *testing.T) {
		v, st, dns := verified(t, 2*RecheckInterval)
		dns.err = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		ok, err := v.Recheck(ctx, st.target, &allowAll{}, "worker:a")
		if ok || err == nil {
			t.Errorf("Recheck = %v, %v; want false with an error", ok, err)
		}
		if !st.target.Verified() || st.revoked != "" {
			t.Error("a DNS failure revoked the verification")
		}
	})
}
