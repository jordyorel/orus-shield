package finding

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// validFinding returns a complete finding that passes Validate.
// Tests mutate a copy to check each rule in isolation.
func validFinding() Finding {
	seen := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	return Finding{
		SchemaVersion: SchemaVersion,
		ID:            NewID("email", "dmarc-missing", "example.com", "_dmarc.example.com"),
		ModuleID:      "email",
		CheckID:       "dmarc-missing",
		Target:        "example.com",
		Asset:         "_dmarc.example.com",
		Severity:      SeverityHigh,
		Title:         "No DMARC record",
		Description:   "The domain publishes no DMARC policy.",
		Evidence:      "NXDOMAIN for _dmarc.example.com TXT",
		Remediation:   []string{"Publish a DMARC record with p=none, then tighten it."},
		References:    []string{"RFC 7489"},
		FirstSeen:     seen,
		LastSeen:      seen,
		Status:        StatusOpen,
	}
}

func TestSeverityValid(t *testing.T) {
	tests := []struct {
		in   Severity
		want bool
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, true},
		{SeverityInfo, true},
		{"", false},
		{"HIGH", false},
		{"severe", false},
	}
	for _, tt := range tests {
		if got := tt.in.Valid(); got != tt.want {
			t.Errorf("Severity(%q).Valid() = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSeverityRankOrder(t *testing.T) {
	ordered := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Rank() >= ordered[i].Rank() {
			t.Errorf("Rank(%q) = %d should be lower than Rank(%q) = %d",
				ordered[i-1], ordered[i-1].Rank(), ordered[i], ordered[i].Rank())
		}
	}
	if got := Severity("bogus").Rank(); got != 0 {
		t.Errorf("Rank of invalid severity = %d, want 0", got)
	}
}

func TestStatusValid(t *testing.T) {
	tests := []struct {
		in   Status
		want bool
	}{
		{StatusOpen, true},
		{StatusFixed, true},
		{StatusAcceptedRisk, true},
		{"", false},
		{"closed", false},
	}
	for _, tt := range tests {
		if got := tt.in.Valid(); got != tt.want {
			t.Errorf("Status(%q).Valid() = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNewID(t *testing.T) {
	a := NewID("email", "dmarc-missing", "example.com", "_dmarc.example.com")
	b := NewID("email", "dmarc-missing", "example.com", "_dmarc.example.com")
	if a != b {
		t.Fatalf("NewID is not deterministic: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("len(NewID) = %d, want 64 hex characters", len(a))
	}

	tests := []struct {
		name       string
		x, y       [4]string
		wantDiffer bool
	}{
		{"different asset", [4]string{"m", "c", "t", "a1"}, [4]string{"m", "c", "t", "a2"}, true},
		{"different module", [4]string{"m1", "c", "t", "a"}, [4]string{"m2", "c", "t", "a"}, true},
		// Naive concatenation would make these equal ("abc" + "d" == "ab" + "cd").
		{"boundary shift", [4]string{"abc", "d", "t", "a"}, [4]string{"ab", "cd", "t", "a"}, true},
		{"separator in input", [4]string{"a\x00b", "c", "t", "a"}, [4]string{"a", "b\x00c", "t", "a"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idX := NewID(tt.x[0], tt.x[1], tt.x[2], tt.x[3])
			idY := NewID(tt.y[0], tt.y[1], tt.y[2], tt.y[3])
			if (idX != idY) != tt.wantDiffer {
				t.Errorf("NewID(%q) vs NewID(%q): differ = %v, want %v", tt.x, tt.y, idX != idY, tt.wantDiffer)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(f *Finding)
		wantErr string // substring expected in the error; empty means valid
	}{
		{"valid finding", func(f *Finding) {}, ""},
		{"empty remediation and references allowed", func(f *Finding) {
			f.Remediation, f.References = nil, nil
		}, ""},
		{"wrong schema version", func(f *Finding) { f.SchemaVersion = "0" }, "schema_version"},
		{"missing module id", func(f *Finding) { f.ModuleID = "" }, "module_id"},
		{"module id not a slug", func(f *Finding) { f.ModuleID = "Email Check" }, "module_id"},
		{"missing check id", func(f *Finding) { f.CheckID = "" }, "check_id"},
		{"missing target", func(f *Finding) { f.Target = "" }, "target"},
		{"missing asset", func(f *Finding) { f.Asset = "" }, "asset"},
		{"missing title", func(f *Finding) { f.Title = "  " }, "title"},
		{"missing description", func(f *Finding) { f.Description = "" }, "description"},
		{"invalid severity", func(f *Finding) { f.Severity = "severe" }, "severity"},
		{"invalid status", func(f *Finding) { f.Status = "" }, "status"},
		{"evidence too large", func(f *Finding) {
			f.Evidence = strings.Repeat("x", MaxEvidenceBytes+1)
		}, "evidence"},
		{"evidence at limit", func(f *Finding) {
			f.Evidence = strings.Repeat("x", MaxEvidenceBytes)
		}, ""},
		{"empty remediation step", func(f *Finding) { f.Remediation = []string{""} }, "remediation"},
		{"empty reference", func(f *Finding) { f.References = []string{" "} }, "references"},
		{"missing first seen", func(f *Finding) { f.FirstSeen = time.Time{} }, "first_seen"},
		{"last seen before first seen", func(f *Finding) {
			f.LastSeen = f.FirstSeen.Add(-time.Hour)
		}, "last_seen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			tt.mutate(&f)
			// Recompute the ID so that each case checks exactly one rule.
			f.ID = NewID(f.ModuleID, f.CheckID, f.Target, f.Asset)
			err := f.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsMismatchedID(t *testing.T) {
	f := validFinding()
	f.Asset = "mail.example.com" // ID was computed for _dmarc.example.com
	err := f.Validate()
	if err == nil || !strings.Contains(err.Error(), "id:") {
		t.Fatalf("Validate() = %v, want an id mismatch error", err)
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	f := validFinding()
	f.Title = ""
	f.Severity = "bogus"
	err := f.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	for _, field := range []string{"title", "severity"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("Validate() = %q, want it to mention %q", err, field)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := validFinding()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// The JSON keys are the public contract: check a few explicitly.
	for _, key := range []string{`"schema_version"`, `"module_id"`, `"check_id"`, `"first_seen"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("JSON %s is missing key %s", data, key)
		}
	}
	var out Finding
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}
