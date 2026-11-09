// Package finding defines the standard finding schema shared by every module.
//
// The dashboard, reports, alerts and the AI layer depend only on this schema,
// never on module internals. Any breaking change to the JSON shape must bump
// SchemaVersion.
package finding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// SchemaVersion is the version of the JSON shape produced by this package.
const SchemaVersion = "1"

// MaxEvidenceBytes bounds the raw evidence stored with a finding. Evidence
// comes from the target, which is untrusted input (security rule 7).
const MaxEvidenceBytes = 64 << 10 // 64 KiB

// Severity is how serious a finding is. It is a string type, not an int, so
// the JSON stays readable and unknown values can be rejected by Valid.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// Rank orders severities for sorting: info is 1, critical is 5.
// An unknown severity has rank 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// Status is the lifecycle state of a finding.
type Status string

const (
	StatusOpen         Status = "open"
	StatusFixed        Status = "fixed"
	StatusAcceptedRisk Status = "accepted_risk"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusFixed, StatusAcceptedRisk:
		return true
	default:
		return false
	}
}

// Finding is one security observation about one asset of a target.
//
// Modules fill the descriptive fields. FirstSeen, LastSeen, Status and
// FixedAt describe history across scans, so the engine sets them, not the
// module.
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	// ID is derived from ModuleID, CheckID, Target and Asset (see NewID), so
	// the same issue found by two scans has the same ID.
	ID       string `json:"id"`
	ModuleID string `json:"module_id"`
	// CheckID is a stable machine identifier for the kind of issue, such as
	// "dmarc-missing". Reports use it to show localized text.
	CheckID     string    `json:"check_id"`
	Target      string    `json:"target"` // what the customer registered, e.g. "example.com"
	Asset       string    `json:"asset"`  // what was checked, e.g. "_dmarc.example.com"
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`    // raw technical proof
	Remediation []string  `json:"remediation"` // ordered steps
	References  []string  `json:"references"`  // CVE IDs, standards, URLs
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Status      Status    `json:"status"`
	// FixedAt is when a scan first stopped seeing the finding; set only
	// while Status is fixed. The real fix happened between LastSeen and
	// FixedAt. Added in schema version 1 as an optional field: older
	// readers ignore it.
	FixedAt *time.Time `json:"fixed_at,omitempty"`
}

// NewID returns the deterministic ID of a finding: the hex SHA-256 of its
// identifying fields.
//
// Each field is prefixed with its length before hashing. Plain concatenation
// would be ambiguous ("ab"+"c" and "a"+"bc" give the same bytes), and a
// separator byte is not safe either because target data is untrusted and may
// contain it.
func NewID(moduleID, checkID, target, asset string) string {
	h := sha256.New()
	var lenBuf [binary.MaxVarintLen64]byte
	for _, field := range []string{moduleID, checkID, target, asset} {
		n := binary.PutUvarint(lenBuf[:], uint64(len(field)))
		h.Write(lenBuf[:n]) // hash.Hash.Write never returns an error
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks that f is complete and consistent. It returns every problem
// found, joined with errors.Join, rather than stopping at the first one.
func (f Finding) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if f.SchemaVersion != SchemaVersion {
		fail("schema_version: got %q, want %q", f.SchemaVersion, SchemaVersion)
	}
	if !isSlug(f.ModuleID) {
		fail("module_id: %q must be a non-empty lowercase slug (a-z, 0-9, -)", f.ModuleID)
	}
	if !isSlug(f.CheckID) {
		fail("check_id: %q must be a non-empty lowercase slug (a-z, 0-9, -)", f.CheckID)
	}
	if strings.TrimSpace(f.Target) == "" {
		fail("target: must not be empty")
	}
	if strings.TrimSpace(f.Asset) == "" {
		fail("asset: must not be empty")
	}
	if want := NewID(f.ModuleID, f.CheckID, f.Target, f.Asset); f.ID != want {
		fail("id: does not match module_id, check_id, target and asset")
	}
	if !f.Severity.Valid() {
		fail("severity: unknown value %q", f.Severity)
	}
	if strings.TrimSpace(f.Title) == "" {
		fail("title: must not be empty")
	}
	if strings.TrimSpace(f.Description) == "" {
		fail("description: must not be empty")
	}
	if len(f.Evidence) > MaxEvidenceBytes {
		fail("evidence: %d bytes exceeds the %d byte limit", len(f.Evidence), MaxEvidenceBytes)
	}
	for i, step := range f.Remediation {
		if strings.TrimSpace(step) == "" {
			fail("remediation[%d]: must not be empty", i)
		}
	}
	for i, ref := range f.References {
		if strings.TrimSpace(ref) == "" {
			fail("references[%d]: must not be empty", i)
		}
	}
	if f.FirstSeen.IsZero() {
		fail("first_seen: must be set")
	}
	if f.LastSeen.IsZero() {
		fail("last_seen: must be set")
	} else if f.LastSeen.Before(f.FirstSeen) {
		fail("last_seen: must not be before first_seen")
	}
	if !f.Status.Valid() {
		fail("status: unknown value %q", f.Status)
	}
	switch {
	case f.Status == StatusFixed && f.FixedAt == nil:
		fail("fixed_at: must be set when status is fixed")
	case f.Status != StatusFixed && f.FixedAt != nil:
		fail("fixed_at: must be empty unless status is fixed")
	case f.FixedAt != nil && f.FixedAt.Before(f.LastSeen):
		fail("fixed_at: must not be before last_seen")
	}

	return errors.Join(errs...)
}

// TruncateEvidence bounds s to MaxEvidenceBytes without cutting a multi-byte
// UTF-8 character in half. Modules call it on raw data from the target.
func TruncateEvidence(s string) string {
	if len(s) <= MaxEvidenceBytes {
		return s
	}
	cut := MaxEvidenceBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// isSlug reports whether s is a non-empty string of a-z, 0-9 and '-'.
func isSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
