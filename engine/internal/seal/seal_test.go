package seal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func newKey(t *testing.T) *Key {
	t.Helper()
	b := make([]byte, KeyLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k, err := NewKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen(t *testing.T) {
	k := newKey(t)
	secret := []byte("12345678901234567890")
	a, err := k.Seal(secret, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := k.Seal(secret, "user-1")
	if bytes.Equal(a, b) {
		t.Error("two seals of the same value are equal: the nonce is not random")
	}
	if bytes.Contains(a, secret) {
		t.Error("sealed value contains the plaintext")
	}
	got, err := k.Open(a, "user-1")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}

	tampered := bytes.Clone(a)
	tampered[len(tampered)-1] ^= 1
	badVersion := bytes.Clone(a)
	badVersion[0] = 2
	tests := map[string]struct {
		key    *Key
		sealed []byte
		owner  string
	}{
		"another owner":   {k, a, "user-2"},
		"another key":     {newKey(t), a, "user-1"},
		"modified":        {k, tampered, "user-1"},
		"unknown version": {k, badVersion, "user-1"},
		"truncated":       {k, a[:10], "user-1"},
		"empty":           {k, nil, "user-1"},
	}
	for name, tt := range tests {
		if _, err := tt.key.Open(tt.sealed, tt.owner); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Open = %v, want ErrOpen", name, err)
		}
	}
}

func TestNewKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewKey(make([]byte, n)); err == nil {
			t.Errorf("NewKey(%d bytes) = nil error", n)
		}
	}
}
