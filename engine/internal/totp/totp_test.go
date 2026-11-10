package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column: 8-digit codes for the ASCII secret
// "12345678901234567890".
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	tests := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tt := range tests {
		step := Step(time.Unix(tt.unix, 0))
		if got := Code(secret, step, 8); got != tt.want {
			t.Errorf("Code(T=%d) = %s, want %s", tt.unix, got, tt.want)
		}
		// Six digits are the last six of the eight.
		if got := Code(secret, step, 6); got != tt.want[2:] {
			t.Errorf("Code(T=%d, 6) = %s, want %s", tt.unix, got, tt.want[2:])
		}
	}
}

func TestVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	cur := Step(now)
	code := func(step int64) string { return Code(secret, step, Digits) }

	tests := []struct {
		name     string
		code     string
		lastStep int64
		wantOK   bool
		wantStep int64
	}{
		{"current step", code(cur), 0, true, cur},
		{"previous step (clock drift)", code(cur - 1), 0, true, cur - 1},
		{"next step (clock drift)", code(cur + 1), 0, true, cur + 1},
		{"two steps old", code(cur - 2), 0, false, 0},
		{"two steps ahead", code(cur + 2), 0, false, 0},
		{"replayed: step already used", code(cur), cur, false, 0},
		{"older than the last used", code(cur - 1), cur, false, 0},
		{"after the last used", code(cur + 1), cur, true, cur + 1},
		{"wrong length", code(cur)[:5], 0, false, 0},
		{"not digits", "abcdef", 0, false, 0},
	}
	for _, tt := range tests {
		step, ok := Verify(secret, tt.code, now, tt.lastStep)
		if ok != tt.wantOK || step != tt.wantStep {
			t.Errorf("%s: Verify = %d, %v; want %d, %v", tt.name, step, ok, tt.wantStep, tt.wantOK)
		}
	}
}

func TestSecretsDiffer(t *testing.T) {
	a, _ := NewSecret()
	b, _ := NewSecret()
	if len(a) != SecretLen || string(a) == string(b) {
		t.Errorf("secrets %x and %x", a, b)
	}
}

func TestURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	got := URI(secret, "Orus Shield", "alice@example.com")
	want := "otpauth://totp/Orus%20Shield:alice@example.com?algorithm=SHA1&digits=6&issuer=Orus%20Shield&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got != want {
		t.Errorf("URI =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(Encode(secret), "=") {
		t.Error("secret has base32 padding, which some apps reject")
	}
}
