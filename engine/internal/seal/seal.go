// Package seal encrypts small secrets stored in the database (TOTP
// secrets) with AES-256-GCM, under a key that lives outside the database
// (ORUS_MFA_KEY, security rule 5).
//
// Unlike a password, a TOTP secret cannot be hashed: the server needs it
// to compute the expected code. Encrypting it means a dump of the database
// alone does not let anyone generate a user's codes.
//
// Each value is bound to its owner through GCM's additional data (the user
// ID): a sealed secret copied onto another user's row does not open.
//
// Layout: version (1 byte) | nonce (12 bytes) | ciphertext and tag. The
// version byte leaves room for key rotation.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyLen is the key size: AES-256.
const KeyLen = 32

const version byte = 1

// ErrOpen means a sealed value is malformed, was sealed under another key
// or for another owner, or was modified.
var ErrOpen = errors.New("cannot open sealed value")

// Key seals and opens values. It is safe for concurrent use.
type Key struct {
	aead cipher.AEAD
}

// NewKey returns a Key from KeyLen random bytes.
func NewKey(key []byte) (*Key, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("seal key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}
	return &Key{aead: aead}, nil
}

// Seal encrypts plaintext for owner. A fresh random nonce is used every
// time: with 96-bit random nonces, the collision risk stays negligible far
// beyond the number of values we will ever seal under one key.
func (k *Key) Seal(plaintext []byte, owner string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+k.aead.Overhead())
	out = append(out, version)
	out = append(out, nonce...)
	return k.aead.Seal(out, nonce, plaintext, []byte(owner)), nil
}

// Open decrypts a value sealed for owner.
func (k *Key) Open(sealed []byte, owner string) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < 1+n+k.aead.Overhead() || sealed[0] != version {
		return nil, ErrOpen
	}
	plain, err := k.aead.Open(nil, sealed[1:1+n], sealed[1+n:], []byte(owner))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}
