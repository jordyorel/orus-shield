package ports

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// identity is what a port says about the software behind it.
type identity struct {
	// service is the protocol, e.g. "SSH", "HTTP", "MySQL".
	service string
	// product and version, when the service announces them, e.g.
	// "OpenSSH" and "9.6p1". version may be empty.
	product string
	version string
}

func (id identity) known() bool { return id.service != "" || id.product != "" }

// label is "OpenSSH 9.6p1", or the service alone.
func (id identity) label() string {
	switch {
	case id.product != "" && id.version != "":
		return id.product + " " + id.version
	case id.product != "":
		return id.product
	}
	return id.service
}

var (
	reSSH      = regexp.MustCompile(`^SSH-[\d.]+-([A-Za-z][\w.-]*?)[_-]v?(\d[\w.]*)`)
	reSSHName  = regexp.MustCompile(`^SSH-[\d.]+-([A-Za-z][\w.-]*)`)
	reFTP      = regexp.MustCompile(`(?i)\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[ ]?v?([\d][\w.]*)?`)
	reSMTP     = regexp.MustCompile(`(?i)\bE?SMTP\b.*?\b(Postfix|Exim|Sendmail|Microsoft ESMTP MAIL Service|qmail|OpenSMTPD)\b[ ]?v?([\d][\w.]*)?`)
	reIMAPPOP  = regexp.MustCompile(`(?i)\b(Dovecot|Courier|Cyrus|Zimbra)\b[ ]?v?([\d][\w.]*)?`)
	reServer   = regexp.MustCompile(`^([A-Za-z][\w.-]*?)(?:/v?(\d[\w.]*))?(?:[\s(;\[]|$)`)
	reVersion  = regexp.MustCompile(`^\d[\w.+-]*`)
	httpStatus = []byte("HTTP/1.")
)

// identifyBanner reads what a service sent on its own when the connection
// opened. raw is the bytes as received (MySQL's greeting is binary); text
// is the sanitized banner. Unknown banners give a zero identity.
func identifyBanner(raw []byte, text string) identity {
	switch {
	case strings.HasPrefix(text, "SSH-"):
		if m := reSSH.FindStringSubmatch(text); m != nil {
			return identity{service: "SSH", product: m[1], version: m[2]}
		}
		if m := reSSHName.FindStringSubmatch(text); m != nil {
			return identity{service: "SSH", product: m[1]}
		}
		return identity{service: "SSH"}
	case strings.HasPrefix(text, "RFB "):
		return identity{service: "VNC", version: strings.TrimPrefix(text, "RFB ")}
	case strings.HasPrefix(text, "+OK"):
		return withProduct(identity{service: "POP3"}, reIMAPPOP, text)
	case strings.HasPrefix(text, "* OK"):
		return withProduct(identity{service: "IMAP"}, reIMAPPOP, text)
	case strings.HasPrefix(text, "220"):
		if strings.Contains(strings.ToUpper(text), "SMTP") {
			return withProduct(identity{service: "SMTP"}, reSMTP, text)
		}
		return withProduct(identity{service: "FTP"}, reFTP, text)
	case bytes.HasPrefix(raw, httpStatus):
		return identifyHTTP(raw)
	}
	if id, ok := mysqlGreeting(raw); ok {
		return id
	}
	return identity{}
}

// withProduct fills product and version from the first match of re.
func withProduct(id identity, re *regexp.Regexp, text string) identity {
	if m := re.FindStringSubmatch(text); m != nil {
		id.product = m[1]
		if len(m) > 2 {
			id.version = m[2]
		}
	}
	return id
}

// mysqlGreeting decodes the handshake a MySQL or MariaDB server sends
// first: a 4-byte packet header, protocol 10, then the version as a
// NUL-terminated string ("8.0.36", "10.11.6-MariaDB-0ubuntu0.24.04.1").
func mysqlGreeting(raw []byte) (identity, bool) {
	if len(raw) < 6 || raw[4] != 0x0a {
		return identity{}, false
	}
	end := bytes.IndexByte(raw[5:], 0)
	if end <= 0 || end > 60 {
		return identity{}, false
	}
	v := sanitizeBanner(raw[5 : 5+end])
	if !reVersion.MatchString(v) {
		return identity{}, false
	}
	product := "MySQL"
	if strings.Contains(v, "MariaDB") {
		product = "MariaDB"
		v = strings.TrimPrefix(v, "5.5.5-") // MariaDB's compatibility prefix
		if i := strings.Index(v, "-MariaDB"); i > 0 {
			v = v[:i]
		}
	}
	return identity{service: "MySQL", product: product, version: v}, true
}

// identifyHTTP reads the status line and the Server header of an HTTP
// response. Only the headers are parsed; the body is never read. Without
// an HTTP status line it is not HTTP: zero identity.
func identifyHTTP(raw []byte) identity {
	if !bytes.HasPrefix(raw, httpStatus) {
		return identity{}
	}
	id := identity{service: "HTTP"}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, len(raw)), len(raw)+1)
	first := true
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if first {
			first = false
			if !strings.HasPrefix(line, "HTTP/1.") {
				return identity{}
			}
			continue
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Server") {
			continue
		}
		v := sanitizeBanner([]byte(strings.TrimSpace(value)))
		if m := reServer.FindStringSubmatch(v); m != nil {
			id.product, id.version = m[1], m[2]
		}
	}
	return id
}
