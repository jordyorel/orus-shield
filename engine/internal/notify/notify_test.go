package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type fakeStore struct {
	mu        sync.Mutex
	due       []store.Notification
	sent      []string
	retried   map[string]time.Time
	abandoned map[string]string
}

func (f *fakeStore) ClaimNotifications(_ context.Context, _ time.Time, _ time.Duration, limit int) ([]store.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.due
	if len(out) > limit {
		out = out[:limit]
	}
	f.due = f.due[len(out):]
	return out, nil
}
func (f *fakeStore) MarkNotificationSent(_ context.Context, id string, _ time.Time) error {
	f.sent = append(f.sent, id)
	return nil
}
func (f *fakeStore) RetryNotification(_ context.Context, id, _ string, at time.Time) error {
	f.retried[id] = at
	return nil
}
func (f *fakeStore) AbandonNotification(_ context.Context, id, reason string, _ time.Time) error {
	f.abandoned[id] = reason
	return nil
}

type fakeMail struct {
	sent []mailer.Message
	fail error
}

func (m *fakeMail) Send(_ context.Context, msg mailer.Message) error {
	if m.fail != nil {
		return m.fail
	}
	m.sent = append(m.sent, msg)
	return nil
}

var now = time.Date(2026, 11, 12, 2, 5, 0, 0, time.UTC)

func alert(t *testing.T, id string, attempts int, created time.Time) store.Notification {
	t.Helper()
	payload, err := json.Marshal(store.NewFindingsAlert{
		OrgID: "org-1", OrgName: "Acme", Domain: "acme.example", ScanID: "s1", Total: 3,
		Findings: []store.AlertFinding{
			{ID: "f1", Title: "Certificate has expired", Asset: "acme.example:443", Severity: finding.SeverityCritical},
			{ID: "f2", Title: "No DMARC record", Asset: "_dmarc.acme.example", Severity: finding.SeverityHigh, Reopened: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store.Notification{ID: id, OrgID: "org-1", Kind: store.NotifyNewFindings, Recipient: "admin@acme.example",
		Payload: payload, CreatedAt: created, Attempts: attempts}
}

func newNotifier(st *fakeStore, m *fakeMail) *Notifier {
	n := New(st, m, "https://app.example", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.now = func() time.Time { return now }
	return n
}

func TestDeliversAlerts(t *testing.T) {
	st := &fakeStore{due: []store.Notification{alert(t, "n1", 1, now.Add(-time.Minute))}, retried: map[string]time.Time{}, abandoned: map[string]string{}}
	m := &fakeMail{}
	sent, err := newNotifier(st, m).RunOnce(context.Background())
	if err != nil || sent != 1 || len(st.sent) != 1 || len(m.sent) != 1 {
		t.Fatalf("sent %d, err %v, store %v", sent, err, st.sent)
	}
	msg := m.sent[0]
	if msg.To != "admin@acme.example" || msg.Subject != "Orus Shield : 1 vulnérabilité critique sur acme.example" {
		t.Errorf("to %q subject %q", msg.To, msg.Subject)
	}
	for _, want := range []string{
		"[Critique] Certificate has expired", "[Élevée] No DMARC record (de retour",
		"https://app.example/orgs/org-1/vulnerabilites?id=f1", "... et 1 autre.",
		"https://app.example/orgs/org-1/vulnerabilites\n", "administrateur de « Acme »",
	} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("body misses %q:\n%s", want, msg.Text)
		}
	}
}

func TestFailuresAreRetriedThenAbandoned(t *testing.T) {
	st := &fakeStore{retried: map[string]time.Time{}, abandoned: map[string]string{}}
	st.due = []store.Notification{
		alert(t, "first", 1, now.Add(-time.Minute)),
		alert(t, "last", len(retryDelays)+1, now.Add(-time.Hour)),
		alert(t, "old", 1, now.Add(-25*time.Hour)),
		{ID: "junk", Kind: store.NotifyNewFindings, Payload: []byte("{"), CreatedAt: now, Attempts: 1},
	}
	if _, err := newNotifier(st, &fakeMail{fail: errors.New("connection refused")}).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if at, ok := st.retried["first"]; !ok || !at.Equal(now.Add(retryDelays[0])) {
		t.Errorf("first failure: retry at %v, want %v", at, now.Add(retryDelays[0]))
	}
	if !strings.HasPrefix(st.abandoned["last"], "gave up") {
		t.Errorf("after the last attempt: %q, want abandoned", st.abandoned["last"])
	}
	if st.abandoned["old"] != "too old to send" {
		t.Errorf("a day-old alert: %q, want dropped", st.abandoned["old"])
	}
	if _, ok := st.abandoned["junk"]; !ok {
		t.Error("unreadable payload not abandoned")
	}
	if len(st.sent) != 0 {
		t.Errorf("sent = %v", st.sent)
	}
}
