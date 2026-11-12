package pdf

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	got := Encode("Été « test » 10 % – œuvre €\n✓")
	want := []byte{0xC9, 't', 0xE9, ' ', 0xAB, ' ', 't', 'e', 's', 't', ' ', 0xBB, ' ', '1', '0', 0xA0, '%', ' ', 0x96, ' ', 0x9C, 'u', 'v', 'r', 'e', ' ', 0x80, ' ', '?'}
	if !bytes.Equal(got, want) {
		t.Errorf("Encode = %x\nwant     %x", got, want)
	}
}

func TestWidthAndWrap(t *testing.T) {
	if w := Width(Helvetica, 10, "Hello"); w < 22 || w > 24 { // 722+556+222+222+556 = 2278
		t.Errorf("width = %v", w)
	}
	if Width(HelveticaBold, 10, "abc") <= Width(Helvetica, 10, "abc") {
		t.Error("bold is not wider")
	}
	lines := Wrap(Helvetica, 10, 60, "Une phrase assez longue pour tenir sur plusieurs lignes "+strings.Repeat("x", 40))
	if len(lines) < 4 {
		t.Fatalf("lines = %q", lines)
	}
	for _, l := range lines {
		if Width(Helvetica, 10, l) > 60 {
			t.Errorf("line %q is %v wide", l, Width(Helvetica, 10, l))
		}
	}
	if got := Wrap(Helvetica, 10, 100, "  "); len(got) != 0 {
		t.Errorf("blank = %q", got)
	}
}

// TestWrite checks the file's structure: header, objects at the offsets the
// cross-reference table gives, page count, and escaped text.
func TestWrite(t *testing.T) {
	d := New("Rapport (test)", "fr")
	p := d.AddPage()
	p.Rect(40, 40, 100, 20, Hex("#0C5DA5"))
	p.Line(40, 70, 200, 70, 1, Hex("#D5DAE1"))
	p.Text(40, 100, HelveticaBold, 14, Color{}, `Sécurité (a\b)`)
	d.AddPage().Text(40, 100, Helvetica, 10, Color{}, "page 2")

	var buf bytes.Buffer
	if err := d.Write(&buf, time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(out, []byte("%%EOF\n")) {
		t.Fatal("bad header or trailer")
	}
	if !bytes.Contains(out, []byte("/Count 2")) || !bytes.Contains(out, []byte("/Title (Rapport \\(test\\))")) || !bytes.Contains(out, []byte("/Lang (fr)")) {
		t.Error("catalog, pages or info missing")
	}

	// Every xref offset points at "N 0 obj".
	m := regexp.MustCompile(`startxref\n(\d+)`).FindSubmatch(out)
	xref, _ := strconv.Atoi(string(m[1]))
	entries := strings.Split(string(out[xref:]), "\n")[3:]
	for i, e := range entries {
		if !strings.HasSuffix(e, " n ") {
			break
		}
		off, _ := strconv.Atoi(e[:10])
		if want := strconv.Itoa(i+1) + " 0 obj"; !bytes.HasPrefix(out[off:], []byte(want)) {
			t.Errorf("xref entry %d points at %q", i+1, out[off:off+10])
		}
	}

	// The first page's content, decompressed, has the escaped text.
	start := bytes.Index(out, []byte("stream\n")) + len("stream\n")
	end := bytes.Index(out[start:], []byte("\nendstream"))
	zr, err := zlib.NewReader(bytes.NewReader(out[start : start+end]))
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(zr)
	if !bytes.Contains(content, append([]byte("(S"), append([]byte{0xE9}, []byte(`curit`)...)...)) ||
		!bytes.Contains(content, []byte(`\(a\\b\)`)) {
		t.Errorf("content = %q", content)
	}
}
