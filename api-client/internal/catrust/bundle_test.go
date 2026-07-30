package catrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSigned returns a throwaway CA certificate in PEM form.
func selfSigned(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseBundleSplitsPerCertificate(t *testing.T) {
	a := selfSigned(t, "VaulTLS Root CA")
	b := selfSigned(t, "VaulTLS Intermediate CA")

	got, err := ParseBundle(append(append([]byte{}, a...), b...), ".crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d anchors, want 2", len(got))
	}
	if !strings.HasPrefix(got[0].FileName, "vaultls-vaultls-root-ca-") ||
		!strings.HasSuffix(got[0].FileName, ".crt") {
		t.Fatalf("unexpected file name %q", got[0].FileName)
	}
	if len(got[0].Fingerprint) != 64 {
		t.Fatalf("fingerprint %q is not a sha256 hex digest", got[0].Fingerprint)
	}
	if got[0].Fingerprint == got[1].Fingerprint {
		t.Fatal("distinct certificates share a fingerprint")
	}
	// Each anchor must hold exactly one certificate: update-ca-certificates only
	// hashes the first block of a multi-cert file.
	if n := strings.Count(string(got[0].PEM), "BEGIN CERTIFICATE"); n != 1 {
		t.Fatalf("anchor holds %d certificates, want 1", n)
	}
}

func TestParseBundleRejectsTruncatedTrailingBlock(t *testing.T) {
	a := selfSigned(t, "VaulTLS Root CA")
	b := selfSigned(t, "VaulTLS Intermediate CA")
	full := append(append([]byte{}, a...), b...)
	// Simulate a response cut short mid-transfer: the first block is intact,
	// the second is chopped off partway through.
	truncated := full[:len(a)+len(b)/2]

	got, err := ParseBundle(truncated, ".crt")
	if err == nil {
		t.Fatalf("expected error for truncated bundle, got %d anchors", len(got))
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("err = %v, want a trailing-bytes error", err)
	}
}

func TestParseBundleExtensionAndEmptyCN(t *testing.T) {
	got, err := ParseBundle(selfSigned(t, ""), ".pem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got[0].FileName, "vaultls-ca-") || !strings.HasSuffix(got[0].FileName, ".pem") {
		t.Fatalf("unexpected file name %q", got[0].FileName)
	}
}

func TestParseBundleDeduplicates(t *testing.T) {
	a := selfSigned(t, "VaulTLS Root CA")
	got, err := ParseBundle(append(append([]byte{}, a...), a...), ".crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d anchors, want 1 after dedup", len(got))
	}
}

func TestParseBundleRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":            []byte(""),
		"no pem":           []byte("not a certificate at all"),
		"wrong block type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"undecodable der":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
	}
	for label, raw := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := ParseBundle(raw, ".crt"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
