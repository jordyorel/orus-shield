// Package totp implements time-based one-time passwords (RFC 6238), the
// six-digit codes of authenticator apps.
//
// Parameters are the ones every authenticator app supports: HMAC-SHA1,
// 6 digits, 30-second steps. A code is accepted one step before or after
// the current one, to absorb clock drift between the phone and the server.
//
// Why SHA-1 is fine here: the known attacks on SHA-1 are collisions, and
// HMAC does not rely on collision resistance. SHA-256 variants exist in
// the RFC but several popular apps silently ignore them and show wrong
// codes. The standard library has everything needed: no dependency.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: HMAC-SHA1 is what RFC 6238 apps implement; HMAC needs no collision resistance
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SecretLen is the secret size: 160 bits, the size RFC 4226 recommends
	// (the output size of SHA-1).
	SecretLen = 20
	// Period is the length of one time step.
	Period = 30 * time.Second
	// Digits is the length of a code.
	Digits = 6
	// Skew is how many steps before and after the current one are accepted.
	Skew = 1
)

// encoding is the base32 form authenticator apps expect, without padding.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("random totp secret: %w", err)
	}
	return s, nil
}

// Encode returns the secret as the user types it into an app.
func Encode(secret []byte) string { return encoding.EncodeToString(secret) }

// Step returns the time step of t.
func Step(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code returns the code of secret at step, with digits digits (RFC 4226
// section 5.3: HMAC, dynamic truncation, modulo 10^digits).
func Code(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: steps are positive (Unix time / 30)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Verify checks code against secret at time t. It returns the step that
// matched. Only steps after lastStep are tried: a code already used (or
// one older than the last used) is refused, so an observed code cannot be
// replayed within its validity window. The caller stores the returned
// step as the new lastStep, atomically.
func Verify(secret []byte, code string, t time.Time, lastStep int64) (step int64, ok bool) {
	if len(code) != Digits {
		return 0, false
	}
	now := Step(t)
	// Every candidate is computed and compared in constant time, so the
	// response time does not tell which step (if any) matched.
	for s := now - Skew; s <= now+Skew; s++ {
		match := subtle.ConstantTimeCompare([]byte(Code(secret, s, Digits)), []byte(code)) == 1
		if match && s > lastStep && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}

// URI returns the otpauth:// URI that authenticator apps read from a QR
// code (Key Uri Format). issuer and account are shown in the app.
func URI(secret []byte, issuer, account string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", Encode(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	// Some apps show a literal "+" for spaces: use %20, as in the label.
	return "otpauth://totp/" + label + "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}
