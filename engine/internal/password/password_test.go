package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash = %q, want PHC argon2id with OWASP parameters", h)
	}
	if ok, err := Verify("correct horse battery staple", h); err != nil || !ok {
		t.Errorf("Verify(right) = %v, %v", ok, err)
	}
	if ok, err := Verify("correct horse battery stapler", h); err != nil || ok {
		t.Errorf("Verify(wrong) = %v, %v", ok, err)
	}
	h2, _ := Hash("correct horse battery staple")
	if h == h2 {
		t.Error("two hashes of the same password are equal: the salt is not random")
	}
}

func TestVerifyRejectsMalformedAndAbusiveHashes(t *testing.T) {
	good, _ := Hash("correct horse battery staple")
	parts := strings.Split(good, "$")
	for name, h := range map[string]string{
		"empty":          "",
		"bcrypt":         "$2a$10$abcdefghijklmnopqrstuv",
		"wrong version":  strings.Replace(good, "v=19", "v=16", 1),
		"huge memory":    strings.Replace(good, "m=19456", "m=4194304", 1), // 4 GiB
		"huge passes":    strings.Replace(good, "t=2", "t=1000", 1),
		"bad salt":       "$argon2id$v=19$" + parts[3] + "$!!!$" + parts[5],
		"short key":      "$argon2id$v=19$" + parts[3] + "$" + parts[4] + "$AAAA",
		"missing fields": "$argon2id$v=19$m=19456,t=2,p=1",
	} {
		if _, err := Verify("x", h); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Verify = %v, want ErrMalformed", name, err)
		}
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		pw   string
		want error
	}{
		{"short", ErrTooShort},
		{"élévation12", ErrTooShort}, // 11 characters, more bytes
		{"twelve chars", nil},
		{strings.Repeat("a", MaxBytes+1), ErrTooLong},
	}
	for _, tt := range tests {
		if err := Check(tt.pw); !errors.Is(err, tt.want) {
			t.Errorf("Check(%q) = %v, want %v", tt.pw, err, tt.want)
		}
	}
	if ok, _ := Verify(strings.Repeat("a", MaxBytes+1), dummy); ok {
		t.Error("an oversized password matched")
	}
}

func TestVerifyDummyNeverMatches(t *testing.T) {
	VerifyDummy("anything at all") // must not panic
	if ok, err := Verify("anything", dummy); ok || err != nil {
		t.Errorf("dummy hash: %v, %v", ok, err)
	}
}
