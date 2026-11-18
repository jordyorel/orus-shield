package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The public test's handle runs as orus_public: this proves its grants are
// enough, and the counts, cache, retention and leads work.
func TestPublicQuickTests(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p := s.Public()
	now := time.Now().UTC().Truncate(time.Microsecond)
	hourAgo := now.Add(-time.Hour)

	old, err := p.RecordQuickTest(ctx, "old.example", "192.0.2.9", []byte(`{"n":0}`), false, now.Add(-QuickTestRetention-time.Hour))
	if err != nil {
		t.Fatalf("record old: %v", err)
	}
	id, err := p.RecordQuickTest(ctx, "example.com", "192.0.2.1", []byte(`{"n":1}`), false, now)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	// The newer insert purged the result past its retention.
	if _, _, err := p.QuickTest(ctx, old, now.Add(-365*24*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("old result kept: %v", err)
	}
	if _, err := p.RecordQuickTest(ctx, "example.com", "192.0.2.1", []byte(`{"n":1}`), true, now); err != nil {
		t.Fatalf("record cached: %v", err)
	}

	c, err := p.QuickTestCounts(ctx, "192.0.2.1", hourAgo)
	if err != nil || c.ByIP != 2 || c.Run != 1 {
		t.Errorf("counts = %+v, %v; want 2 by IP, 1 run", c, err)
	}
	res, ok, err := p.CachedQuickTest(ctx, "example.com", hourAgo)
	if err != nil || !ok || string(res) != `{"n": 1}` {
		t.Errorf("cached = %s, %v, %v", res, ok, err)
	}
	if _, ok, _ := p.CachedQuickTest(ctx, "example.com", now.Add(time.Minute)); ok {
		t.Error("a result older than the cache window was reused")
	}
	if d, _, err := p.QuickTest(ctx, id, hourAgo); err != nil || d != "example.com" {
		t.Errorf("test = %q, %v", d, err)
	}
	if _, _, err := p.QuickTest(ctx, "not-a-uuid", hourAgo); !errors.Is(err, ErrNotFound) {
		t.Errorf("bad id: %v", err)
	}

	if err := p.AddLead(ctx, Lead{TestID: id, Email: " Boss@Example.com ", Domain: "example.com", Lang: "en", Marketing: true, IP: "192.0.2.1"}); err != nil {
		t.Fatalf("add lead: %v", err)
	}
	if err := p.AddLead(ctx, Lead{TestID: id, Email: "nope", Domain: "example.com", IP: "192.0.2.1"}); err == nil {
		t.Error("invalid email recorded")
	}
	byIP, byEmail, err := p.LeadCounts(ctx, "192.0.2.1", "boss@example.com", hourAgo)
	if err != nil || byIP != 1 || byEmail != 1 {
		t.Errorf("lead counts = %d, %d, %v", byIP, byEmail, err)
	}

	f, err := s.Funnel(ctx, hourAgo)
	if err != nil || f.Tests != 2 || f.Domains != 1 || f.Leads != 1 || f.Marketing != 1 {
		t.Errorf("funnel = %+v, %v", f, err)
	}
}
