// Package password hashes and verifies user passwords with argon2id.
//
// Why argon2id and a dependency: the standard library offers PBKDF2, which
// costs only CPU, so attackers who steal the hashes can test billions of
// guesses on GPUs. argon2id also needs memory for every guess, which makes
// that much more expensive. It is OWASP's first recommendation.
// golang.org/x/crypto is maintained by the Go team.
//
// Hashes are stored in the PHC string format, which carries its own
// parameters, so they can be raised later without breaking old hashes:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Parameters for new hashes: OWASP's minimum recommendation for argon2id
// (19 MiB of memory, 2 passes, 1 thread).
const (
	memoryKiB = 19 * 1024
	passes    = 2
	threads   = 1
	saltLen   = 16
	keyLen    = 32
)

// Limits on the parameters accepted when verifying, so that a tampered hash
// in the database cannot make one login use gigabytes of memory.
const (
	maxMemoryKiB = 256 * 1024
	maxPasses    = 10
	maxThreads   = 8
)

// Password rules. Length is what matters; composition rules ("one digit,
// one symbol") push users to predictable patterns (NIST SP 800-63B).
const (
	MinLength = 12
	// MaxBytes bounds the input hashed on every login attempt.
	MaxBytes = 256
)

var (
	// ErrTooShort and ErrTooLong are returned by Check.
	ErrTooShort = fmt.Errorf("password must have at least %d characters", MinLength)
	ErrTooLong  = fmt.Errorf("password must be at most %d bytes", MaxBytes)
	// ErrMalformed means a stored hash cannot be parsed.
	ErrMalformed = errors.New("malformed password hash")
)

// Check applies the password rules to a new password.
func Check(pw string) error {
	if utf8.RuneCountInString(pw) < MinLength {
		return ErrTooShort
	}
	if len(pw) > MaxBytes {
		return ErrTooLong
	}
	return nil
}

// Hash returns the PHC-encoded argon2id hash of pw, with a random salt.
func Hash(pw string) (string, error) {
	if len(pw) > MaxBytes {
		return "", ErrTooLong
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, passes, memoryKiB, threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, passes, threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether pw matches encoded. The comparison is constant
// time. A password over MaxBytes never matches.
func Verify(pw, encoded string) (bool, error) {
	p, err := parse(encoded)
	if err != nil {
		return false, err
	}
	if len(pw) > MaxBytes {
		return false, nil
	}
	key := argon2.IDKey([]byte(pw), p.salt, p.passes, p.memory, p.threads, uint32(len(p.key))) //nolint:gosec // G115: len(p.key) is bounded by parse
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

// dummy is a valid hash of a random password. Verifying against it when an
// account does not exist takes as long as a real check, so response times
// do not reveal which emails have an account.
var dummy = func() string {
	h, err := Hash(rand.Text())
	if err != nil {
		panic(err)
	}
	return h
}()

// VerifyDummy spends the time of a Verify and always returns false.
func VerifyDummy(pw string) {
	_, _ = Verify(pw, dummy)
}

type params struct {
	memory  uint32
	passes  uint32
	threads uint8
	salt    []byte
	key     []byte
}

func parse(encoded string) (params, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return params{}, ErrMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return params{}, ErrMalformed
	}
	var p params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.passes, &p.threads); err != nil {
		return params{}, ErrMalformed
	}
	if p.memory < 8*uint32(p.threads) || p.memory > maxMemoryKiB || p.passes < 1 || p.passes > maxPasses ||
		p.threads < 1 || p.threads > maxThreads {
		return params{}, ErrMalformed
	}
	b64 := base64.RawStdEncoding
	var err error
	if p.salt, err = b64.DecodeString(parts[4]); err != nil || len(p.salt) < 8 || len(p.salt) > 64 {
		return params{}, ErrMalformed
	}
	if p.key, err = b64.DecodeString(parts[5]); err != nil || len(p.key) < 16 || len(p.key) > 64 {
		return params{}, ErrMalformed
	}
	return p, nil
}
