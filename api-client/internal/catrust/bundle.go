// Package catrust keeps the VaulTLS root CAs present in the host's system trust
// store, so that any local client — curl, psql, openssl — accepts certificates
// issued by VaulTLS.
package catrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// Anchor is one CA certificate ready to be written into the trust store.
type Anchor struct {
	Fingerprint string // SHA-256 of the DER body, lowercase hex
	FileName    string // vaultls-<slug(CN)>-<fp[:8]><ext>
	PEM         []byte // exactly one CERTIFICATE block
}

// ParseBundle splits a concatenated PEM into one Anchor per certificate,
// dropping duplicates. One certificate per file is deliberate:
// update-ca-certificates hashes only the first block of a multi-cert file, so
// every certificate after the first would silently never be trusted.
func ParseBundle(raw []byte, ext string) ([]Anchor, error) {
	var out []Anchor
	seen := map[string]bool{}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca bundle: unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: parse certificate: %w", err)
		}
		sum := sha256.Sum256(cert.Raw)
		fp := hex.EncodeToString(sum[:])
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, Anchor{
			Fingerprint: fp,
			FileName:    fmt.Sprintf("vaultls-%s-%s%s", slug(cert.Subject.CommonName), fp[:8], ext),
			PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ca bundle: no certificates found")
	}
	return out, nil
}

// slug turns a CN into a filename-safe fragment. The fingerprint suffix carries
// uniqueness, so collapsing punctuation here is safe.
func slug(cn string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(cn) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return "ca"
	}
	return s
}
