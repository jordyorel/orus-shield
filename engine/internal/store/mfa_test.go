package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// enrolled returns a user with confirmed MFA, the session used to enrol and
// the recovery codes.
func enrolled(t *testing.T, s *Store, email string) (User, string, []string) {
	t.Helper()
	ctx := context.Background()
	auth := s.Auth()
	u := newUser(t, s, email)
	session, err := auth.CreateSession(ctx, u.ID, "192.0.2.1", "t", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.BeginMFASetup(ctx, u.ID, []byte("sealed secret, opaque to the store")); err != nil {
		t.Fatal(err)
	}
	codes, err := auth.EnableMFA(ctx, u.ID, 100, session, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	return u, session, codes
}

func TestMFAEnrolment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	u := newUser(t, s, "alice@example.com")

	if _, err := auth.MFA(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("MFA before setup = %v, want ErrNotFound", err)
	}
	current, _ := auth.CreateSession(ctx, u.ID, "192.0.2.1", "t", time.Now().Add(time.Hour))
	other, _ := auth.CreateSession(ctx, u.ID, "192.0.2.9", "t", time.Now().Add(time.Hour))

	// Setup can be restarted until confirmed.
	if err := auth.BeginMFASetup(ctx, u.ID, []byte("first secret sealed...........")); err != nil {
		t.Fatal(err)
	}
	if err := auth.BeginMFASetup(ctx, u.ID, []byte("second secret sealed..........")); err != nil {
		t.Fatalf("restarting setup: %v", err)
	}
	m, err := auth.MFA(ctx, u.ID)
	if err != nil || m.Enabled || !strings.HasPrefix(string(m.Sealed), "second") {
		t.Fatalf("pending MFA = %+v, %v", m, err)
	}
	if sess, _ := auth.SessionUser(ctx, current, time.Hour); sess.MFAEnabled || sess.MFA {
		t.Errorf("unconfirmed setup counts as MFA: %+v", sess)
	}

	codes, err := auth.EnableMFA(ctx, u.ID, 100, current, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 19 || seen[c] {
			t.Errorf("recovery code %q: bad shape or duplicate", c)
		}
		seen[c] = true
	}
	if len(codes) != RecoveryCodeCount {
		t.Errorf("%d recovery codes, want %d", len(codes), RecoveryCodeCount)
	}
	sess, err := auth.SessionUser(ctx, current, time.Hour)
	if err != nil || !sess.MFA || !sess.MFAEnabled {
		t.Errorf("enrolling session = %+v, %v; want MFA", sess, err)
	}
	if _, err := auth.SessionUser(ctx, other, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("other session after enrolment = %v, want closed", err)
	}
	if got, _ := auth.UserByEmail(ctx, u.Email); !got.MFAEnabled {
		t.Error("UserByEmail does not report MFA")
	}

	// Enabled: no new setup, no second confirmation.
	if err := auth.BeginMFASetup(ctx, u.ID, []byte("third secret sealed...........")); !errors.Is(err, ErrExists) {
		t.Errorf("setup over an enabled factor = %v, want ErrExists", err)
	}
	if _, err := auth.EnableMFA(ctx, u.ID, 200, current, "192.0.2.1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second EnableMFA = %v, want ErrNotFound", err)
	}
	var stored int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM recovery_codes WHERE code_hash = $1", []byte(codes[0])).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("recovery code stored in clear: %d, %v", stored, err)
	}
}

func TestTOTPStepsAreUsedOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	u, _, _ := enrolled(t, s, "alice@example.com") // confirmed at step 100

	for _, tt := range []struct {
		step int64
		want bool
	}{
		{100, false}, // the confirmation code, replayed
		{99, false},  // older
		{101, true},
		{101, false}, // replayed
		{103, true},
		{102, false}, // older than the last accepted
	} {
		if ok, err := auth.UseTOTPStep(ctx, u.ID, tt.step); err != nil || ok != tt.want {
			t.Errorf("UseTOTPStep(%d) = %v, %v; want %v", tt.step, ok, err, tt.want)
		}
	}
	// A user without MFA has no step to use.
	plain := newUser(t, s, "bob@example.com")
	if ok, _ := auth.UseTOTPStep(ctx, plain.ID, 500); ok {
		t.Error("UseTOTPStep accepted for a user without MFA")
	}
}

func TestRecoveryCodes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	alice, _, codes := enrolled(t, s, "alice@example.com")
	bob, _, bobCodes := enrolled(t, s, "bob@example.com")

	typed := strings.ToLower(strings.ReplaceAll(codes[0], "-", " ")) // as a user may type it
	if ok, err := auth.UseRecoveryCode(ctx, alice.ID, typed); err != nil || !ok {
		t.Fatalf("UseRecoveryCode = %v, %v", ok, err)
	}
	for name, tt := range map[string]struct{ user, code string }{
		"used twice":         {alice.ID, codes[0]},
		"another user's":     {alice.ID, bobCodes[0]},
		"unknown":            {alice.ID, "AAAA-AAAA-AAAA-AAAA"},
		"wrong length":       {alice.ID, "AAAA"},
		"not a uuid user id": {"x", codes[1]},
	} {
		if ok, err := auth.UseRecoveryCode(ctx, tt.user, tt.code); err != nil || ok {
			t.Errorf("%s: UseRecoveryCode = %v, %v; want false", name, ok, err)
		}
	}
	if ok, _ := auth.UseRecoveryCode(ctx, bob.ID, bobCodes[0]); !ok {
		t.Error("bob's own code refused")
	}
}

func TestMFAChallenge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	alice, _, _ := enrolled(t, s, "alice@example.com")
	bob, _, _ := enrolled(t, s, "bob@example.com")

	ch, err := auth.CreateMFAChallenge(ctx, alice.ID, "192.0.2.1", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if u, err := auth.MFAChallengeUser(ctx, ch); err != nil || u.ID != alice.ID || u.Email != alice.Email {
		t.Fatalf("MFAChallengeUser = %+v, %v", u, err)
	}
	// A challenge names its user: it cannot open bob's session.
	if _, err := auth.CompleteMFALogin(ctx, ch, bob.ID, "192.0.2.1", "t", time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("challenge for another user = %v, want ErrInvalidToken", err)
	}
	session, err := auth.CompleteMFALogin(ctx, ch, alice.ID, "192.0.2.1", "t", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sess, err := auth.SessionUser(ctx, session, time.Hour); err != nil || !sess.MFA {
		t.Errorf("MFA login session = %+v, %v; want MFA", sess, err)
	}
	if _, err := auth.CompleteMFALogin(ctx, ch, alice.ID, "192.0.2.1", "t", time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("challenge reused = %v, want ErrInvalidToken", err)
	}
	if _, err := auth.MFAChallengeUser(ctx, ch); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("consumed challenge = %v, want ErrInvalidToken", err)
	}

	expired, _ := auth.CreateMFAChallenge(ctx, alice.ID, "192.0.2.1", time.Now().Add(-time.Second))
	for name, tok := range map[string]string{"expired": expired, "unknown": "nope", "empty": ""} {
		if _, err := auth.MFAChallengeUser(ctx, tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s challenge = %v, want ErrInvalidToken", name, err)
		}
	}
	if _, err := auth.CompleteMFALogin(ctx, expired, alice.ID, "192.0.2.1", "t", time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired challenge completed = %v, want ErrInvalidToken", err)
	}
}

func TestDisableAndResetMFA(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	u, session, codes := enrolled(t, s, "alice@example.com")
	other, _ := auth.CreateSession(ctx, u.ID, "192.0.2.9", "t", time.Now().Add(time.Hour))
	pending, _ := auth.CreateMFAChallenge(ctx, u.ID, "192.0.2.1", time.Now().Add(time.Minute))

	if err := auth.DisableMFA(ctx, u.ID, session, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	sess, err := auth.SessionUser(ctx, session, time.Hour)
	if err != nil || sess.MFA || sess.MFAEnabled {
		t.Errorf("session after disabling = %+v, %v; want open without MFA", sess, err)
	}
	if _, err := auth.SessionUser(ctx, other, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("other session after disabling = %v, want closed", err)
	}
	if _, err := auth.MFAChallengeUser(ctx, pending); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("pending challenge after disabling = %v, want gone", err)
	}
	if ok, _ := auth.UseRecoveryCode(ctx, u.ID, codes[1]); ok {
		t.Error("recovery code still works after disabling")
	}

	// An operator's reset, for a lost phone: everything goes, sessions too.
	v, vSession, _ := enrolled(t, s, "victor@example.com")
	if err := s.ResetMFA(ctx, v.ID, "cli:jordy"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.MFA(ctx, v.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("MFA after reset = %v, want ErrNotFound", err)
	}
	if _, err := auth.SessionUser(ctx, vSession, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("session after reset = %v, want closed", err)
	}
	var actions []string
	rows, _ := s.pool.Query(ctx, "SELECT action FROM auth_log WHERE email = $1 ORDER BY id", v.Email)
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	if strings.Join(actions, ",") != AuthMFAEnabled+","+AuthMFAReset {
		t.Errorf("auth log = %v", actions)
	}
	if err := s.ResetMFA(ctx, "0190a000-0000-7000-8000-000000000000", "cli:jordy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("reset of an unknown user = %v, want ErrNotFound", err)
	}
}
