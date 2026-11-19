package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/seal"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type fakeStore struct {
	due      []store.WebhookDelivery
	outcomes []store.DeliveryOutcome
	allowed  bool
}

func (f *fakeStore) ClaimWebhookDeliveries(context.Context, time.Time, time.Duration, int) ([]store.WebhookDelivery, error) {
	out := f.due
	f.due = nil
	return out, nil
}
func (f *fakeStore) FinishWebhookDelivery(_ context.Context, _ store.WebhookDelivery, o store.DeliveryOutcome, _ time.Time) error {
	f.outcomes = append(f.outcomes, o)
	return nil
}
func (f *fakeStore) WebhooksAllowed(context.Context, string, time.Time) (bool, error) {
	return f.allowed, nil
}

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// setup returns a deliverer trusting srv (a local TLS server: tests never
// reach third parties), and a sealed secret for url.
func setup(t *testing.T, srv *httptest.Server, st *fakeStore) (*Deliverer, []byte, []byte) {
	t.Helper()
	raw := make([]byte, seal.KeyLen)
	_, _ = rand.Read(raw)
	key, err := seal.NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("whsec_test")
	sealed, err := key.Seal(secret, store.WebhookSealOwner("org-1", srv.URL+"/hook"))
	if err != nil {
		t.Fatal(err)
	}
	d := New(st, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.now = func() time.Time { return now }
	d.client = SafeClient(func(netip.Addr) bool { return true })
	d.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	return d, secret, sealed
}

func delivery(url string, sealed []byte, attempts int) store.WebhookDelivery {
	return store.WebhookDelivery{ID: "d1", OrgID: "org-1", WebhookID: "w1", EventType: "finding.opened",
		Payload: []byte(`{"type":"finding.opened"}`), Attempts: attempts, CreatedAt: now.Add(-time.Minute), URL: url, SecretSealed: sealed}
}

func TestSign(t *testing.T) {
	// Recomputed independently: HMAC-SHA256 of "<unix time>.<body>".
	mac := hmac.New(sha256.New, []byte("s"))
	mac.Write([]byte("1700000000.{}"))
	want := "t=1700000000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if got := Sign([]byte("s"), []byte(`{}`), time.Unix(1700000000, 0)); got != want {
		t.Errorf("Sign = %q, want %q", got, want)
	}
	if Sign([]byte("s"), []byte(`{}`), time.Unix(1700000000, 0)) == Sign([]byte("other"), []byte(`{}`), time.Unix(1700000000, 0)) {
		t.Error("the secret does not change the signature")
	}
}

func TestDelivers(t *testing.T) {
	var gotSig, gotEvent string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotEvent = r.Header.Get("Orus-Signature"), r.Header.Get("Orus-Event")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	st := &fakeStore{allowed: true}
	d, secret, sealed := setup(t, srv, st)
	st.due = []store.WebhookDelivery{delivery(srv.URL+"/hook", sealed, 1)}
	if n, err := d.RunOnce(context.Background()); err != nil || n != 1 || !st.outcomes[0].Delivered || st.outcomes[0].Status != 204 {
		t.Fatalf("RunOnce = %d, %v, %+v", n, err, st.outcomes)
	}
	// The receiver can check the signature with its secret.
	if gotEvent != "finding.opened" || gotSig != Sign(secret, gotBody, now) {
		t.Errorf("event %q signature %q", gotEvent, gotSig)
	}
}

func TestRetriesThenAbandons(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://example.com/", http.StatusFound) // never followed
	}))
	defer srv.Close()
	st := &fakeStore{allowed: true}
	d, _, sealed := setup(t, srv, st)
	st.due = []store.WebhookDelivery{delivery(srv.URL+"/hook", sealed, 1)}
	_, _ = d.RunOnce(context.Background())
	o := st.outcomes[0]
	if o.Delivered || o.Status != http.StatusFound || o.RetryAt == nil || !o.RetryAt.Equal(now.Add(time.Minute)) {
		t.Errorf("first failure = %+v", o)
	}
	st.due = []store.WebhookDelivery{delivery(srv.URL+"/hook", sealed, len(retryDelays)+1)}
	_, _ = d.RunOnce(context.Background())
	if o := st.outcomes[1]; o.Delivered || o.RetryAt != nil {
		t.Errorf("last attempt = %+v, want abandoned", o)
	}
}

func TestRefusesPrivateAddressesAndLapsedOffers(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	st := &fakeStore{allowed: true}
	d, _, sealed := setup(t, srv, st)
	// The real client: 127.0.0.1 is not public.
	d.client = SafeClient(nil)
	st.due = []store.WebhookDelivery{delivery(srv.URL+"/hook", sealed, 1)}
	_, _ = d.RunOnce(context.Background())
	if hit || st.outcomes[0].Delivered || !strings.Contains(st.outcomes[0].Error, "public") {
		t.Errorf("loopback delivered: hit %v, %+v", hit, st.outcomes[0])
	}
	st.allowed = false
	st.due = []store.WebhookDelivery{delivery(srv.URL+"/hook", sealed, 1)}
	_, _ = d.RunOnce(context.Background())
	if o := st.outcomes[1]; o.Delivered || o.RetryAt != nil {
		t.Errorf("lapsed offer = %+v, want dropped", o)
	}
}
