package pdf

// winAnsiExtra maps the characters of Windows-1252 codes 0x80-0x9F, which
// are not at their Unicode position. Codes 0xA0-0xFF are Latin-1, the same
// as Unicode U+00A0-U+00FF.
var winAnsiExtra = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88,
	'‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E, '‘': 0x91, '’': 0x92, '“': 0x93,
	'”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9A, '›': 0x9B,
	'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F,
}

// Encode converts s to WinAnsi bytes. Control characters become spaces,
// characters WinAnsi lacks become "?".
func Encode(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			out = append(out, ' ')
		case r < 0x7f:
			out = append(out, byte(r))
		case r >= 0xA0 && r <= 0xFF:
			out = append(out, byte(r))
		case r == ' ' || r == ' ': // narrow spaces (French « », 10 %)
			out = append(out, 0xA0)
		default:
			if b, ok := winAnsiExtra[r]; ok {
				out = append(out, b)
			} else {
				out = append(out, '?')
			}
		}
	}
	return out
}

// Width returns the width of s in points, in font f at size.
func Width(f Font, size float64, s string) float64 {
	w := 0
	for _, b := range Encode(s) {
		w += charWidth(f, b)
	}
	return float64(w) * size / 1000
}

// charWidth is a WinAnsi byte's advance width in 1/1000 em, from Adobe's
// font metrics (AFM) for Helvetica and Helvetica-Bold. Accented letters
// have the width of their base letter.
func charWidth(f Font, b byte) int {
	t := &helvetica
	if f == HelveticaBold {
		t = &helveticaBold
	}
	switch {
	case b >= 32 && b < 127:
		return int(t[b-32])
	case b >= 0xC0:
		return latin(t, b)
	}
	switch b {
	case 0xA0:
		return int(t[0]) // no-break space
	case 0xAB, 0xBB: // « »
		return 556
	case 0x85, 0x97: // … —
		return 1000
	case 0x96, 0x80: // – €
		return 556
	case 0x92, 0x91: // ’ ‘
		return 222 + boldExtra(f, 56)
	case 0x93, 0x94: // “ ”
		return 333 + boldExtra(f, 167)
	case 0x95: // •
		return 350
	case 0xB0: // °
		return 400
	case 0x9C: // œ
		return 944
	case 0x8C: // Œ
		return 1000
	}
	return 556
}

func boldExtra(f Font, n int) int {
	if f == HelveticaBold {
		return n
	}
	return 0
}

// latin gives À-ÿ the width of their base letter.
func latin(t *[95]uint16, b byte) int {
	base := map[byte]byte{
		0xC0: 'A', 0xC1: 'A', 0xC2: 'A', 0xC3: 'A', 0xC4: 'A', 0xC5: 'A', 0xC6: 'E', 0xC7: 'C',
		0xC8: 'E', 0xC9: 'E', 0xCA: 'E', 0xCB: 'E', 0xCC: 'I', 0xCD: 'I', 0xCE: 'I', 0xCF: 'I',
		0xD0: 'D', 0xD1: 'N', 0xD2: 'O', 0xD3: 'O', 0xD4: 'O', 0xD5: 'O', 0xD6: 'O', 0xD7: '+',
		0xD8: 'O', 0xD9: 'U', 0xDA: 'U', 0xDB: 'U', 0xDC: 'U', 0xDD: 'Y', 0xDE: 'P', 0xDF: 'b',
		0xE0: 'a', 0xE1: 'a', 0xE2: 'a', 0xE3: 'a', 0xE4: 'a', 0xE5: 'a', 0xE6: 'm', 0xE7: 'c',
		0xE8: 'e', 0xE9: 'e', 0xEA: 'e', 0xEB: 'e', 0xEC: 'i', 0xED: 'i', 0xEE: 'i', 0xEF: 'i',
		0xF0: 'o', 0xF1: 'n', 0xF2: 'o', 0xF3: 'o', 0xF4: 'o', 0xF5: 'o', 0xF6: 'o', 0xF7: '+',
		0xF8: 'o', 0xF9: 'u', 0xFA: 'u', 0xFB: 'u', 0xFC: 'u', 0xFD: 'y', 0xFE: 'p', 0xFF: 'y',
	}[b]
	if base == 0 {
		return 556
	}
	return int(t[base-32])
}

// Widths of ASCII 32 (space) to 126 (~).
var helvetica = [95]uint16{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // space ! " # $ % & ' ( ) * + , - . /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0-9
	278, 278, 584, 584, 584, 556, 1015, // : ; < = > ? @
	667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, // A-M
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // N-Z
	278, 278, 278, 469, 556, 333, // [ \ ] ^ _ `
	556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, // a-m
	556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // n-z
	334, 260, 334, 584, // { | } ~
}

var helveticaBold = [95]uint16{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	333, 333, 584, 584, 584, 611, 975,
	722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
	333, 278, 333, 584, 556, 333,
	556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
	611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
	389, 280, 389, 584,
}

// Wrap splits s into lines no wider than width, breaking at spaces; a word
// longer than a line is cut.
func Wrap(f Font, size, width float64, s string) []string {
	var lines []string
	var line []rune
	lineW := 0.0
	space := Width(f, size, " ")
	for _, word := range splitWords(s) {
		ww := Width(f, size, word)
		for ww > width { // cut words longer than a line (URLs, hashes)
			if len(line) > 0 {
				lines = append(lines, string(line))
				line, lineW = nil, 0
			}
			r := []rune(word)
			cut := len(r)
			for cut > 1 && Width(f, size, string(r[:cut])) > width {
				cut--
			}
			lines = append(lines, string(r[:cut]))
			word = string(r[cut:])
			ww = Width(f, size, word)
		}
		if word == "" {
			continue
		}
		switch {
		case len(line) == 0:
			line, lineW = []rune(word), ww
		case lineW+space+ww <= width:
			line = append(append(line, ' '), []rune(word)...)
			lineW += space + ww
		default:
			lines = append(lines, string(line))
			line, lineW = []rune(word), ww
		}
	}
	if len(line) > 0 {
		lines = append(lines, string(line))
	}
	return lines
}

func splitWords(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
