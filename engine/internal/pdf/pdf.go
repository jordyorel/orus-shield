// Package pdf writes simple PDF documents: A4 pages with text in the
// standard Helvetica fonts, filled rectangles and lines. It is what reports
// need, and nothing more.
//
// Why not a library: a text-and-shapes PDF is a small, documented format
// (ISO 32000), and the 14 standard fonts need no embedding. Writing it here
// keeps the engine free of a dependency for a few hundred lines, and every
// byte of the output is ours to review.
//
// Text is encoded in WinAnsi (Windows-1252), which covers French and other
// Western European languages: é, à, ç, œ, « », €... Characters outside it
// (other scripts, emoji) are written as "?": report data comes from scans and
// customers, and must never break the file.
//
// Coordinates are in points (1/72 inch), from the top-left corner of the
// page, y going down: the way layouts are written. The package converts to
// PDF's bottom-left origin.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// A4 page size in points.
const (
	PageWidth  = 595.28
	PageHeight = 841.89
)

// Font is one of the standard fonts we use.
type Font int

const (
	Helvetica Font = iota
	HelveticaBold
)

var fontNames = map[Font]string{Helvetica: "Helvetica", HelveticaBold: "Helvetica-Bold"}

// Color is an RGB color, each component 0 to 255.
type Color struct{ R, G, B uint8 }

// Hex parses "#RRGGBB"; it panics on a malformed constant (colors are
// written in code, never read from data).
func Hex(s string) Color {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "#"), 16, 32)
	if err != nil || len(strings.TrimPrefix(s, "#")) != 6 {
		panic("pdf: bad color " + s)
	}
	return Color{uint8(v >> 16), uint8(v >> 8), uint8(v)} //nolint:gosec // G115: v has 24 bits (6 hex digits, checked above); each byte is meant to be cut
}

func (c Color) ops() string {
	return fmt.Sprintf("%s %s %s", num(float64(c.R)/255), num(float64(c.G)/255), num(float64(c.B)/255))
}

// Document is a PDF being built.
type Document struct {
	pages []*Page
	title string
	lang  string
}

// New returns an empty document. title and lang ("fr", "en") go in its
// metadata: viewers show the title, screen readers use the language.
func New(title, lang string) *Document { return &Document{title: title, lang: lang} }

// Page is one page; draw on it, in order.
type Page struct {
	content bytes.Buffer
}

// AddPage appends a new page and returns it.
func (d *Document) AddPage() *Page {
	p := &Page{}
	d.pages = append(d.pages, p)
	return p
}

// Pages returns how many pages the document has.
func (d *Document) Pages() int { return len(d.pages) }

// Text writes s with its baseline at (x, y).
func (p *Page) Text(x, y float64, f Font, size float64, c Color, s string) {
	fmt.Fprintf(&p.content, "BT %s rg /F%d %s Tf %s %s Td (%s) Tj ET\n",
		c.ops(), f, num(size), num(x), num(PageHeight-y), escape(Encode(s)))
}

// Rect fills a rectangle whose top-left corner is (x, y).
func (p *Page) Rect(x, y, w, h float64, c Color) {
	fmt.Fprintf(&p.content, "%s rg %s %s %s %s re f\n", c.ops(), num(x), num(PageHeight-y-h), num(w), num(h))
}

// Line draws a line from (x1, y1) to (x2, y2).
func (p *Page) Line(x1, y1, x2, y2, width float64, c Color) {
	fmt.Fprintf(&p.content, "%s RG %s w %s %s m %s %s l S\n", c.ops(), num(width),
		num(x1), num(PageHeight-y1), num(x2), num(PageHeight-y2))
}

// num formats a number the way PDF wants it: no exponent, few decimals.
func num(f float64) string {
	s := strconv.FormatFloat(f, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

// escape protects the characters with a meaning inside a PDF string.
func escape(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch c {
		case '(', ')', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case '\r', '\n', '\t':
			sb.WriteByte(' ')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// Write writes the document. now is the creation date in the metadata
// (passed in so output is reproducible in tests).
func (d *Document) Write(w io.Writer, now time.Time) error {
	if len(d.pages) == 0 {
		d.AddPage()
	}
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n") // binary marker: the file has 8-bit bytes

	// Object numbers: 1 catalog, 2 page tree, 3 and 4 fonts, 5 info, then
	// two per page (page, content stream).
	n := len(d.pages)
	kids := make([]string, n)
	for i := range n {
		kids[i] = fmt.Sprintf("%d 0 R", 6+2*i)
	}
	lang := ""
	if d.lang != "" {
		lang = " /Lang (" + escape(Encode(d.lang)) + ")"
	}
	obj("<< /Type /Catalog /Pages 2 0 R" + lang + " >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n))
	for _, f := range []Font{Helvetica, HelveticaBold} {
		obj("<< /Type /Font /Subtype /Type1 /BaseFont /" + fontNames[f] + " /Encoding /WinAnsiEncoding >>")
	}
	obj(fmt.Sprintf("<< /Title (%s) /Producer (Orus Shield) /CreationDate (D:%s) >>",
		escape(Encode(d.title)), now.UTC().Format("20060102150405Z")))
	for i, p := range d.pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F0 3 0 R /F1 4 0 R >> >> /Contents %d 0 R >>",
			num(PageWidth), num(PageHeight), 7+2*i))
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		if _, err := zw.Write(p.content.Bytes()); err != nil {
			return fmt.Errorf("pdf: compress page: %w", err)
		}
		if err := zw.Close(); err != nil {
			return fmt.Errorf("pdf: compress page: %w", err)
		}
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(offsets), z.Len())
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")
	}

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	_, err := w.Write(out.Bytes())
	return err
}

// Page returns page i (0-based), to draw on it after later pages were
// added (footers with the page count).
func (d *Document) Page(i int) *Page { return d.pages[i] }
