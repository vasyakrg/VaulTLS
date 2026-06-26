package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func makeP12(t *testing.T, pass string) ([]byte, string) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(0x0a1b2c)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"*.example.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	pfx, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca}, pass)
	if err != nil {
		t.Fatal(err)
	}
	// leafSerial 0x0a1b2c formats via %X as "A1B2C" (leading zero dropped).
	return pfx, "A1B2C"
}

func TestDecodeProducesAllForms(t *testing.T) {
	pfx, wantSerial := makeP12(t, "pw")
	b, err := Decode(pfx, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if b.Serial != wantSerial {
		t.Fatalf("serial = %q want %q", b.Serial, wantSerial)
	}
	if !bytes.Contains(b.Fullchain, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("fullchain missing cert PEM")
	}
	if bytes.Count(b.Fullchain, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatal("fullchain should contain leaf + CA")
	}
	if !bytes.Contains(b.PrivKey, []byte("PRIVATE KEY")) {
		t.Fatal("privkey missing key PEM")
	}
	if bytes.Count(b.Cert, []byte("BEGIN CERTIFICATE")) != 1 {
		t.Fatal("cert.pem should contain only leaf")
	}
	if !bytes.Contains(b.Haproxy, []byte("PRIVATE KEY")) ||
		!bytes.Contains(b.Haproxy, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("haproxy.pem must contain cert+key")
	}
	if !strings.HasPrefix(string(b.Haproxy), "-----BEGIN CERTIFICATE") {
		t.Fatal("haproxy.pem must start with cert, then key")
	}
}

func TestDecodeWrongPassword(t *testing.T) {
	pfx, _ := makeP12(t, "pw")
	if _, err := Decode(pfx, "wrong"); err == nil {
		t.Fatal("expected error on wrong password")
	}
}
