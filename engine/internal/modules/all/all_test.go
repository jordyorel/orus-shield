package all

import "testing"

func TestRegistry(t *testing.T) {
	reg, err := Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	for _, id := range []string{"email", "tls", "ports"} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("module %q is missing", id)
		}
	}
}
