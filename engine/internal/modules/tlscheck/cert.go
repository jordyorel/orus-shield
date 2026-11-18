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
		i.fr = finding.Text{
			Title:       "Le certificat a expiré",
			Description: fmt.Sprintf("Le certificat a expiré le %s. Les navigateurs affichent une alerte de sécurité en pleine page, et la plupart des visiteurs quittent le site.", finding.FrenchDate(leaf.NotAfter)),
			Remediation: renewStepsFR(),
		}
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	case now.Before(leaf.NotBefore):
		i := base
		i.checkID = CheckCertNotYetValid
		i.severity = finding.SeverityHigh
		i.title = "Certificate is not valid yet"
		i.description = fmt.Sprintf("The certificate only becomes valid on %s. Browsers reject it until then. This often means the server clock is wrong or a new certificate was installed too early.", leaf.NotBefore.UTC().Format(time.DateOnly))
		i.remediation = []string{"Check the server's clock (enable NTP) and that the right certificate is installed."}
		i.fr = finding.Text{
			Title:       "Le certificat n’est pas encore valide",
			Description: fmt.Sprintf("Le certificat ne devient valide que le %s. D’ici là, les navigateurs le refusent. C’est souvent le signe d’une horloge serveur déréglée ou d’un nouveau certificat installé trop tôt.", finding.FrenchDate(leaf.NotBefore)),
			Remediation: []string{"Vérifiez l’horloge du serveur (activez la synchronisation NTP) et que le bon certificat est installé."},
		}
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
		i.fr = finding.Text{
			Title:       fmt.Sprintf("Le certificat expire dans %d jour%s", daysLeft, finding.Plural(daysLeft, "s")),
			Description: fmt.Sprintf("Le certificat expire le %s. Passé cette date, les navigateurs bloqueront le site avec une alerte de sécurité. Le renouvellement automatique intervient normalement plus tôt : il est peut-être en panne.", finding.FrenchDate(leaf.NotAfter)),
			Remediation: renewStepsFR(),
		}
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
		i.fr = finding.Text{
			Title:       "Le certificat ne correspond pas au nom du site",
			Description: fmt.Sprintf("Le certificat n’est pas valable pour %s. Les navigateurs affichent une alerte de sécurité, et vos visiteurs ne peuvent pas distinguer le vrai site d’une imitation.", dest.Host),
			Remediation: []string{
				fmt.Sprintf("Faites émettre un certificat qui inclut %s dans ses noms (la plupart des fournisseurs permettent d’ajouter le domaine et sa version www.).", dest.Host),
			},
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
		i.fr = finding.Text{
			Title:       "Le certificat n’est pas reconnu par les navigateurs",
			Description: "Les navigateurs ne parviennent pas à rattacher le certificat à une autorité de certification reconnue. Il est peut-être auto-signé, émis par une autorité inconnue, ou le serveur n’envoie pas les certificats intermédiaires. Vos visiteurs voient une alerte de sécurité.",
			Remediation: []string{
				"Utilisez un certificat émis par une autorité publique (Let’s Encrypt est gratuit).",
				"Configurez le serveur pour qu’il envoie la chaîne complète (souvent un fichier nommé fullchain.pem), et pas seulement le certificat du site.",
			},
		}
		i.references = []string{refCertProfile}
		issues = append(issues, i)
	}

	// Key strength.
	if desc, descFR, weak := weakKey(leaf); weak {
		i := base
		i.checkID = CheckCertWeakKey
		i.severity = finding.SeverityMedium
		i.title = "Certificate key is too weak"
		i.description = fmt.Sprintf("The certificate uses a %s key. Public authorities no longer issue keys this short because they are within reach of well-funded attackers.", desc)
		i.remediation = []string{"Generate a new key (RSA 2048 bits or more, or ECDSA P-256) and a new certificate."}
		i.fr = finding.Text{
			Title:       "La clé du certificat est trop faible",
			Description: fmt.Sprintf("Le certificat utilise une clé %s. Les autorités publiques n’émettent plus de clés aussi courtes, car elles sont à la portée d’attaquants disposant de moyens importants.", descFR),
			Remediation: []string{"Générez une nouvelle clé (RSA de 2048 bits ou plus, ou ECDSA P-256) et un nouveau certificat."},
		}
		i.references = []string{refBaseline}
		issues = append(issues, i)
	}

	return issues
}

// weakKey reports keys below RSA 2048 or ECDSA 256 bits.
// weakKey describes the certificate's key in English and French, and tells
// whether it is too short.
func weakKey(cert *x509.Certificate) (string, string, bool) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return fmt.Sprintf("%d-bit RSA", bits), fmt.Sprintf("RSA de %d bits", bits), bits < 2048
	case *ecdsa.PublicKey:
		bits := k.Params().BitSize
		return fmt.Sprintf("%d-bit ECDSA", bits), fmt.Sprintf("ECDSA de %d bits", bits), bits < 256
	default:
		return "", "", false // Ed25519 and others: fine
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
		fr: finding.Text{
			Title:       "La connexion HTTPS échoue",
			Description: "Le serveur accepte les connexions sur le port 443, mais aucune session sécurisée (TLS) n’a pu être établie. Les visiteurs qui utilisent https:// obtiennent une erreur.",
			Remediation: []string{
				"Vérifiez que le serveur web a bien HTTPS activé sur le port 443, avec un certificat valide.",
				"Si le port 443 est utilisé par un autre service, déplacez ce service ou cessez de l’exposer.",
			},
		},
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
		fr: finding.Text{
			Title:       "Le serveur accepte des versions de TLS obsolètes",
			Description: fmt.Sprintf("Le serveur accepte encore %s. TLS 1.0 et 1.1 présentent des faiblesses connues et sont officiellement abandonnés depuis 2021 ; les navigateurs modernes ne les utilisent plus, les garder ne profite donc qu’aux attaquants.", tls.VersionName(state.Version)),
			Remediation: []string{"Désactivez TLS 1.0 et 1.1 dans le serveur web ou le panneau de votre hébergeur ; gardez TLS 1.2 et 1.3."},
		},
	}
}

func renewStepsFR() []string {
	return []string{
		"Renouvelez le certificat dès maintenant et installez-le sur le serveur.",
		"Mettez en place le renouvellement automatique (par exemple certbot avec Let’s Encrypt, ou l’option de renouvellement automatique de votre hébergeur).",
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
