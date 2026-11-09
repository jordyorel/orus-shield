package tlscheck

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

const (
	refCertProfile = "RFC 5280"
	refHostname    = "RFC 9525"
	refTLSVersions = "RFC 8996"
	refBaseline    = "CA/Browser Forum Baseline Requirements"

	// expiryWarning starts warning before expiry; expiryUrgent raises the
	// severity. Automated renewal (Let's Encrypt) renews 30 days ahead, so a
	// certificate inside this window usually means renewal is broken.
	expiryWarning = 30 * 24 * time.Hour
	expiryUrgent  = 7 * 24 * time.Hour

	// maxChainCerts bounds how many certificates from the server we use as
	// intermediates. The chain comes from the target (rule 7).
	maxChainCerts = 10
)

// certIssues analyzes the certificate the server presented.
func certIssues(asset string, dest module.Destination, state tls.ConnectionState, roots *x509.CertPool, now time.Time) []issue {
	chain := state.PeerCertificates
	if len(chain) == 0 {
		return nil // TLS always sends a certificate here; nothing to analyze otherwise
	}
	if len(chain) > maxChainCerts {
		chain = chain[:maxChainCerts]
	}
	leaf := chain[0]
	evidence := describe(dest, state.Version, leaf)
	base := issue{asset: asset, evidence: evidence}

	var issues []issue

	// Validity period.
	switch left := leaf.NotAfter.Sub(now); {
	case left < 0:
		i := base
		i.checkID = CheckCertExpired
		i.severity = finding.SeverityCritical
		i.title = "Certificate has expired"
		i.description = fmt.Sprintf("The certificate expired on %s. Browsers show a full-page security warning and most visitors leave.", leaf.NotAfter.UTC().Format(time.DateOnly))
		i.remediation = renewSteps()
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	case now.Before(leaf.NotBefore):
		i := base
		i.checkID = CheckCertNotYetValid
		i.severity = finding.SeverityHigh
		i.title = "Certificate is not valid yet"
		i.description = fmt.Sprintf("The certificate only becomes valid on %s. Browsers reject it until then. This often means the server clock is wrong or a new certificate was installed too early.", leaf.NotBefore.UTC().Format(time.DateOnly))
		i.remediation = []string{"Check the server's clock (enable NTP) and that the right certificate is installed."}
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	case left <= expiryWarning:
		i := base
		i.checkID = CheckCertExpiringSoon
		i.severity = finding.SeverityMedium
		if left <= expiryUrgent {
			i.severity = finding.SeverityHigh
		}
		daysLeft := int(left.Hours() / 24)
		i.title = fmt.Sprintf("Certificate expires in %d days", daysLeft)
		i.description = fmt.Sprintf("The certificate expires on %s. After that date, browsers will block the site with a security warning. Automatic renewal normally happens earlier, so it may be broken.", leaf.NotAfter.UTC().Format(time.DateOnly))
		i.remediation = renewSteps()
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	}

	// Hostname.
	if err := leaf.VerifyHostname(dest.Host); err != nil {
		i := base
		i.checkID = CheckCertHostnameMismatch
		i.severity = finding.SeverityHigh
		i.title = "Certificate does not match the site name"
		i.description = fmt.Sprintf("The certificate is not valid for %s. Browsers show a security warning, and visitors cannot tell the real site from an impostor.", dest.Host)
		i.remediation = []string{
			fmt.Sprintf("Issue a certificate that includes %s in its names (most providers let you add both the domain and its www. version).", dest.Host),
		}
		i.references = []string{refHostname}
		issues = append(issues, i)
	}

	// Trust chain. Checked at a time inside the validity period, so that an
	// expired certificate is reported once (above), not also as untrusted.
	at := now
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at}); err != nil {
		i := base
		i.checkID = CheckCertUntrusted
		i.severity = finding.SeverityHigh
		i.title = "Certificate is not trusted by browsers"
		i.description = "Browsers cannot link the certificate to a trusted certificate authority. It may be self-signed, issued by an unknown authority, or the server may not send the intermediate certificates. Visitors see a security warning."
		i.evidence = evidence + "\nverification error: " + err.Error()
		i.remediation = []string{
			"Use a certificate from a public authority (Let's Encrypt is free).",
			"Configure the server to send the full chain (often a file named fullchain.pem), not only the site certificate.",
		}
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	}

	// Key strength.
	if desc, weak := weakKey(leaf); weak {
		i := base
		i.checkID = CheckCertWeakKey
		i.severity = finding.SeverityMedium
		i.title = "Certificate key is too weak"
		i.description = fmt.Sprintf("The certificate uses a %s key. Public authorities no longer issue keys this short because they are within reach of well-funded attackers.", desc)
		i.remediation = []string{"Generate a new key (RSA 2048 bits or more, or ECDSA P-256) and a new certificate."}
		i.references = []string{refBaseline}
		issues = append(issues, i)
	}

	return issues
}

// weakKey reports keys below RSA 2048 or ECDSA 256 bits.
func weakKey(cert *x509.Certificate) (string, bool) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return fmt.Sprintf("%d-bit RSA", bits), bits < 2048
	case *ecdsa.PublicKey:
		bits := k.Params().BitSize
		return fmt.Sprintf("%d-bit ECDSA", bits), bits < 256
	default:
		return "", false // Ed25519 and others: fine
	}
}

func handshakeFailed(asset string, dest module.Destination, err error) issue {
	return issue{
		checkID:     CheckHandshakeFailed,
		asset:       asset,
		severity:    finding.SeverityMedium,
		title:       "HTTPS connection fails",
		description: "The server accepts connections on port 443 but no secure (TLS) session could be established. Visitors using https:// get an error.",
		evidence:    fmt.Sprintf("host: %s (%s)\nerror: %v", dest.Host, addrPort(dest), err),
		remediation: []string{
			"Check that the web server has HTTPS enabled on port 443 with a valid certificate.",
			"If port 443 is used by another service, move it or stop exposing it.",
		},
		references: []string{refTLSVersions},
	}
}

func legacyVersion(asset string, dest module.Destination, state tls.ConnectionState) issue {
	return issue{
		checkID:     CheckLegacyVersion,
		asset:       asset,
		severity:    finding.SeverityMedium,
		title:       "Server accepts outdated TLS versions",
		description: fmt.Sprintf("The server still accepts %s. TLS 1.0 and 1.1 have known weaknesses and were formally deprecated in 2021; modern browsers no longer use them, so keeping them only helps attackers.", tls.VersionName(state.Version)),
		evidence:    fmt.Sprintf("host: %s (%s)\naccepted: %s with %s", dest.Host, addrPort(dest), tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)),
		remediation: []string{"Disable TLS 1.0 and 1.1 in the web server or hosting panel; keep TLS 1.2 and 1.3."},
		references:  []string{refTLSVersions},
	}
}

func renewSteps() []string {
	return []string{
		"Renew the certificate now and install it on the server.",
		"Set up automatic renewal (for example certbot with Let's Encrypt, or the auto-renewal option of your host).",
	}
}

// describe returns the technical evidence about the certificate. All of it
// comes from the server; TruncateEvidence bounds its size later.
func describe(dest module.Destination, version uint16, leaf *x509.Certificate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "host: %s (%s)\n", dest.Host, addrPort(dest))
	fmt.Fprintf(&b, "tls version: %s\n", tls.VersionName(version))
	fmt.Fprintf(&b, "subject: %s\n", leaf.Subject)
	fmt.Fprintf(&b, "issuer: %s\n", leaf.Issuer)
	fmt.Fprintf(&b, "names: %s\n", strings.Join(leaf.DNSNames, ", "))
	fmt.Fprintf(&b, "valid from: %s\n", leaf.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "valid until: %s\n", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "sha256: %x", sha256.Sum256(leaf.Raw))
	return b.String()
}

func addrPort(dest module.Destination) string {
	// This module only ever connects to httpsPort; using the constant avoids
	// converting an arbitrary int to uint16.
	return netip.AddrPortFrom(dest.IP, httpsPort).String()
}
