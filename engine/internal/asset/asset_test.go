package asset

import (
	"net/netip"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::1")
	var fp [32]byte
	fp[0] = 0xab

	tests := []struct {
		name    string
		a       Asset
		wantErr string // empty: valid
	}{
		{"target domain", Hostname("example.com"), ""},
		{"subdomain", Hostname("WWW.Example.com."), ""},
		{"other domain refused", Hostname("mx.mailprovider.net"), "not example.com"},
		{"suffix trick refused", Hostname("evilexample.com"), "not example.com"},
		{"hostname not canonical", Asset{Kind: KindHostname, Value: "WWW.example.com"}, "canonical"},
		{"invalid hostname", Asset{Kind: KindHostname, Value: "a b.example.com"}, "hostname"},
		{"ipv4", IP(v4), ""},
		{"ipv4-mapped is stored as ipv4", IP(netip.MustParseAddr("::ffff:192.0.2.10")), ""},
		{"ipv6", IP(v6), ""},
		{"ip not canonical", Asset{Kind: KindIP, Value: "2001:DB8::1"}, "canonical"},
		{"ip garbage", Asset{Kind: KindIP, Value: "not-an-ip"}, "ip"},
		{"service v4", Service(v4, 443, nil), ""},
		{"service v6", Service(v6, 22, nil), ""},
		{"service without protocol", Asset{Kind: KindService, Value: "192.0.2.10:443"}, "/tcp"},
		{"service port 0", Asset{Kind: KindService, Value: "192.0.2.10:0/tcp"}, "canonical"},
		{"certificate", Certificate(fp, nil), ""},
		{"certificate uppercase", Asset{Kind: KindCertificate, Value: strings.Repeat("AB", 32)}, "lowercase hex"},
		{"certificate short", Asset{Kind: KindCertificate, Value: "abcd"}, "lowercase hex"},
		{"unknown kind", Asset{Kind: "laptop", Value: "x"}, "kind"},
		{"too many details", Service(v4, 443, manyDetails(MaxDetails+1)), "details"},
		{"detail too long", Service(v4, 443, map[string]string{"banner": strings.Repeat("x", MaxDetailValueBytes+1)}), "details[banner]"},
		{"detail invalid UTF-8", Service(v4, 443, map[string]string{"banner": "\xff"}), "details[banner]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.a.Validate("example.com")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", tt.a, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate(%+v) = %v, want error mentioning %q", tt.a, err, tt.wantErr)
			}
		})
	}
}

func manyDetails(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[strings.Repeat("k", i+1)] = "v"
	}
	return m
}

func TestConstructorsAreCanonical(t *testing.T) {
	if got := IP(netip.MustParseAddr("::ffff:192.0.2.10")).Value; got != "192.0.2.10" {
		t.Errorf("IP(mapped) = %q", got)
	}
	if got := Service(netip.MustParseAddr("2001:db8::1"), 22, nil).Value; got != "[2001:db8::1]:22/tcp" {
		t.Errorf("Service(v6) = %q", got)
	}
	if got := Hostname("WWW.Example.COM.").Value; got != "www.example.com" {
		t.Errorf("Hostname = %q", got)
	}
}

func TestSetMergesDuplicates(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	var s Set
	s.Add(Hostname("example.com"))
	s.Add(Service(ip, 443, map[string]string{"expected": "https"}))
	s.Add(Hostname("example.com"))
	s.Add(Service(ip, 443, map[string]string{"tls_version": "TLS 1.3"}))

	got := s.List()
	if len(got) != 2 || got[0].Kind != KindHostname || got[1].Kind != KindService {
		t.Fatalf("List() = %+v, want hostname then service, once each", got)
	}
	if d := got[1].Details; d["expected"] != "https" || d["tls_version"] != "TLS 1.3" {
		t.Errorf("merged details = %v, want both", d)
	}
	var empty Set
	if l := empty.List(); len(l) != 0 {
		t.Errorf("empty set List() = %v", l)
	}
}

func TestTruncateDetail(t *testing.T) {
	long := strings.Repeat("é", MaxDetailValueBytes) // 2 bytes each
	got := TruncateDetail(long)
	if len(got) > MaxDetailValueBytes || !strings.HasPrefix(long, got) {
		t.Errorf("TruncateDetail: %d bytes, prefix %v", len(got), strings.HasPrefix(long, got))
	}
	if got := TruncateDetail("a\xffb"); got != "a�b" {
		t.Errorf("TruncateDetail(invalid UTF-8) = %q", got)
	}
}
