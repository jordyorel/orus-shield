package store

import (
	"context"
	"errors"
	"testing"
)

func TestTargetCredentials(t *testing.T) {
	l := newLifecycle(t)
	s, ctx := l.s, context.Background()
	if c, err := l.org.Credential(ctx, l.target.ID); err != nil || c != nil {
		t.Fatalf("none yet: %+v, %v", c, err)
	}
	c := Credential{TargetID: l.target.ID, Kind: CredentialForm, LoginURL: "https://example.com/login", Username: "test@example.com", PasswordField: "pass"}
	if err := l.org.SetCredential(ctx, c, []byte("sealed-1"), "jordy"); err != nil {
		t.Fatal(err)
	}
	got, err := l.org.Credential(ctx, l.target.ID)
	if err != nil || got == nil || got.Kind != CredentialForm || got.Username != "test@example.com" || got.PasswordField != "pass" || got.CreatedBy != "jordy" {
		t.Fatalf("credential = %+v, %v", got, err)
	}
	// The API's role cannot read the sealed secret back.
	tx, err := l.org.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	if err := tx.QueryRow(ctx, "SELECT sealed_secret FROM target_credentials WHERE target_id = $1", l.target.ID).Scan(&b); err == nil {
		t.Error("orus_app read the sealed secret")
	}
	_ = tx.Rollback(ctx)
	// Replaced, then read by the worker with its secret.
	c = Credential{TargetID: l.target.ID, Kind: CredentialHeader, HeaderName: "Authorization"}
	if err := l.org.SetCredential(ctx, c, []byte("sealed-2"), "jordy"); err != nil {
		t.Fatal(err)
	}
	wc, sealed, err := s.TargetCredential(ctx, l.target.ID)
	if err != nil || wc == nil || wc.Kind != CredentialHeader || wc.HeaderName != "Authorization" || wc.LoginURL != "" || string(sealed) != "sealed-2" {
		t.Errorf("worker credential = %+v %q, %v", wc, sealed, err)
	}
	// Audited without the secret.
	entries, err := l.org.AuditLog(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	sets := 0
	for _, e := range entries {
		if e.Action == ActionCredentialSet {
			sets++
		}
	}
	if sets != 2 {
		t.Errorf("%d credential.set entries, want 2", sets)
	}
	if err := l.org.DeleteCredential(ctx, l.target.ID, "jordy"); err != nil {
		t.Fatal(err)
	}
	if err := l.org.DeleteCredential(ctx, l.target.ID, "jordy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete again = %v, want ErrNotFound", err)
	}
	if wc, _, err := s.TargetCredential(ctx, l.target.ID); err != nil || wc != nil {
		t.Errorf("after delete = %+v, %v", wc, err)
	}
}
