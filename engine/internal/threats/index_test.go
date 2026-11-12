package threats

import (
	"slices"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func TestIndex(t *testing.T) {
	ts, err := Index("testdata/templates")
	if err != nil {
		t.Fatal(err)
	}
	// 0002 is medium, 0003 names no product: not indexed.
	if len(ts) != 2 || ts[0].ID != "CVE-2020-0004" || ts[1].ID != "CVE-2026-0001" {
		t.Fatalf("index = %+v", ts)
	}
	avada := ts[1]
	if avada.CVE != "CVE-2026-0001" || avada.Name != "Avada Builder < 3.11 - Unauthenticated RCE" || avada.Severity != "critical" ||
		!avada.KEV || avada.EPSS != 0.42 || !avada.New || !slices.Equal(avada.Products, []string{"wordpress", "avada"}) {
		t.Errorf("avada = %+v", avada)
	}
	atl := ts[0]
	if atl.New || atl.KEV || atl.CVE != "CVE-2020-0004" || !slices.Equal(atl.Products, []string{"atlassian", "jira", "confluence"}) {
		t.Errorf("atlassian = %+v", atl)
	}
	if _, err := Index("testdata/nope"); err == nil {
		t.Error("missing directory: nil error")
	}
}

func TestTechKeysAndMatch(t *testing.T) {
	keys := TechKeys("nginx 1.18.0, WordPress 6.1,  , nginx")
	if !slices.Equal(keys, []string{"nginx", "wordpress"}) {
		t.Fatalf("keys = %v", keys)
	}
	wp := Template{Products: []string{"wp", "elementor"}}
	if got := Match(wp, keys); !slices.Equal(got, []string{"wordpress"}) {
		t.Errorf("wordpress alias: %v", got)
	}
	if got := Match(Template{Products: []string{"drupal"}}, keys); got != nil {
		t.Errorf("drupal matched %v", got)
	}
}

func TestMatchAll(t *testing.T) {
	pending := []store.ThreatTemplate{
		{ID: "a", Products: []string{"wordpress"}},
		{ID: "b", Products: []string{"jira"}},
	}
	targets := []store.TargetTechnologies{
		{TargetID: "t1", Technologies: []string{"WordPress 6.1, PHP 8.1", "nginx"}},
		{TargetID: "t2", Technologies: []string{"jira 9"}},
		{TargetID: "t3", Technologies: []string{"drupal"}},
	}
	ids, matches := matchAll(pending, targets)
	if !slices.Equal(ids, []string{"a", "b"}) || len(matches) != 2 ||
		matches[0].TemplateID != "a" || matches[0].TargetID != "t1" ||
		matches[1].TargetID != "t2" || !slices.Equal(matches[0].Products, []string{"wordpress"}) {
		t.Errorf("ids %v, matches %+v", ids, matches)
	}
}
