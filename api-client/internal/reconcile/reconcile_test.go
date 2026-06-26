package reconcile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/store"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type fakeAPI struct {
	certs    []vaultls.Cert
	p12      []byte
	password string
	dlCount  int
}

func (f *fakeAPI) List(context.Context) ([]vaultls.Cert, error) { return f.certs, nil }
func (f *fakeAPI) Password(context.Context, int64) (string, error) { return f.password, nil }
func (f *fakeAPI) Download(context.Context, int64) ([]byte, error) {
	f.dlCount++
	return f.p12, nil
}

func makeP12(t *testing.T, serial int64) []byte {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "*.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	pfx, _ := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca}, "pw")
	return pfx
}

func newDomain(dir string) config.Domain {
	return config.Domain{Name: "*.example.com", OutDir: dir, Formats: []string{"pem", "haproxy"},
		Mode: "0640", Reload: "true"}
}

func TestReconcileWritesAndRenews(t *testing.T) {
	dir := t.TempDir()
	api := &fakeAPI{
		certs:    []vaultls.Cert{{ID: 2, Name: "*.example.com", ValidUntil: time.Now().Add(48 * time.Hour).UnixMilli()}},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	m := metrics.New()
	r := New(api, m, time.Now)
	if err := r.Domain(context.Background(), newDomain(dir)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"fullchain.pem", "privkey.pem", "cert.pem", "chain.pem", "haproxy.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	info, _ := os.Stat(filepath.Join(dir, "privkey.pem"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("privkey mode = %v, want 0600", info.Mode().Perm())
	}
	hinfo, _ := os.Stat(filepath.Join(dir, "haproxy.pem"))
	if hinfo.Mode().Perm() != 0o600 {
		t.Errorf("haproxy mode = %v, want 0600", hinfo.Mode().Perm())
	}
	st, _ := store.Read(dir)
	if st.Serial != "A1B2C" {
		t.Errorf("state serial = %q", st.Serial)
	}
}

func TestReconcileSkipsWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	vu := time.Now().Add(48 * time.Hour).UnixMilli()
	api := &fakeAPI{
		certs:    []vaultls.Cert{{ID: 2, Name: "*.example.com", ValidUntil: vu}},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	m := metrics.New()
	r := New(api, m, time.Now)
	ctx := context.Background()
	d := newDomain(dir)
	if err := r.Domain(ctx, d); err != nil {
		t.Fatal(err)
	}
	first := api.dlCount
	if err := r.Domain(ctx, d); err != nil {
		t.Fatal(err)
	}
	if api.dlCount != first {
		t.Errorf("second reconcile should not download (cheap skip), dlCount %d -> %d", first, api.dlCount)
	}
}

func TestReconcileDomainNotFound(t *testing.T) {
	dir := t.TempDir()
	api := &fakeAPI{certs: []vaultls.Cert{{ID: 1, Name: "other", ValidUntil: 1}}}
	m := metrics.New()
	r := New(api, m, time.Now)
	if err := r.Domain(context.Background(), newDomain(dir)); err == nil {
		t.Fatal("expected error when domain cert not found")
	}
}

func TestReconcileSelectsByCertID(t *testing.T) {
	dir := t.TempDir()
	vu := time.Now().Add(48 * time.Hour).UnixMilli()
	// Two certs: the Name does not match either; CertID must drive selection.
	api := &fakeAPI{
		certs: []vaultls.Cert{
			{ID: 7, Name: "wrong-a", ValidUntil: vu},
			{ID: 9, Name: "wrong-b", ValidUntil: vu},
		},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	m := metrics.New()
	r := New(api, m, time.Now)
	d := newDomain(dir)
	d.Name = "no-such-name"
	d.CertID = 9
	if err := r.Domain(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if api.dlCount != 1 {
		t.Errorf("expected one download for the cert picked by CertID, dlCount = %d", api.dlCount)
	}
	if _, err := os.Stat(filepath.Join(dir, "fullchain.pem")); err != nil {
		t.Errorf("missing fullchain.pem: %v", err)
	}
	st, _ := store.Read(dir)
	if st.CertID != 9 {
		t.Errorf("state cert_id = %d, want 9 (selected by CertID)", st.CertID)
	}
}

func TestReconcileCertIDOnlyDistinctLabels(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	vu := time.Now().Add(48 * time.Hour).UnixMilli()
	api := &fakeAPI{
		certs: []vaultls.Cert{
			{ID: 7, Name: "", ValidUntil: vu},
			{ID: 9, Name: "", ValidUntil: vu},
		},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	m := metrics.New()
	r := New(api, m, time.Now)
	ctx := context.Background()

	dA := config.Domain{OutDir: dirA, Formats: []string{"pem"}, Mode: "0640", Reload: "true", CertID: 7}
	dB := config.Domain{OutDir: dirB, Formats: []string{"pem"}, Mode: "0640", Reload: "true", CertID: 9}
	if err := r.Domain(ctx, dA); err != nil {
		t.Fatal(err)
	}
	if err := r.Domain(ctx, dB); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `domain="`+dirA+`"`) {
		t.Errorf("metrics missing label for dirA %q\n%s", dirA, body)
	}
	if !strings.Contains(body, `domain="`+dirB+`"`) {
		t.Errorf("metrics missing label for dirB %q\n%s", dirB, body)
	}
	if strings.Contains(body, `domain=""`) {
		t.Errorf("metrics has empty domain label (collision)\n%s", body)
	}
}
