package all

import (
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

func TestRegistry(t *testing.T) {
	reg, err := Registry(resolver.NewSystem(), Options{})
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	for _, id := range []string{"email", "tls", "ports", "cdn", "web", "discovery", "vulns", "zap", "api"} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("module %q is missing", id)
		}
	}
}
