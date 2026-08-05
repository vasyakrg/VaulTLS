package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/reconcile"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

type failAPI struct{}

func (failAPI) List(context.Context) ([]vaultls.Cert, error)    { return nil, context.Canceled }
func (failAPI) Password(context.Context, int64) (string, error) { return "", nil }
func (failAPI) Download(context.Context, int64) ([]byte, error) { return nil, nil }

func contextClock() time.Time { return time.Unix(0, 0) }

func TestReconcileAllIsolatesFailures(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", OutDir: t.TempDir(), Formats: []string{"nginx"}, Mode: "0640", Reload: "true"},
		{Name: "b", OutDir: t.TempDir(), Formats: []string{"nginx"}, Mode: "0640", Reload: "true"},
	}}
	r := reconcile.New(failAPI{}, metrics.New(), contextClock)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	// Must not panic and must attempt both domains despite errors.
	ReconcileAll(context.Background(), cfg, r, log)
	if got := bytes.Count(buf.Bytes(), []byte("reconcile failed")); got != 2 {
		t.Fatalf("expected 2 logged failures, got %d", got)
	}
}

type bundleAPI struct {
	body []byte
	err  error
	hits int
}

func (b *bundleAPI) CABundle(context.Context) ([]byte, error) {
	b.hits++
	return b.body, b.err
}

func TestSyncCATrustSkippedWhenDisabled(t *testing.T) {
	cfg := &config.Config{}
	f := &bundleAPI{}
	var buf bytes.Buffer
	SyncCATrust(context.Background(), cfg, f, metrics.New(), slog.New(slog.NewTextHandler(&buf, nil)))
	if f.hits != 0 {
		t.Fatalf("disabled ca_trust must not call the server (hits=%d)", f.hits)
	}
}

// selfSignedCA returns a throwaway CA certificate in PEM form.
func selfSignedCA(t *testing.T, cn string) []byte {
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

// caTrustStateDir is a package var precisely so this test can point it at a
// temp dir: without that, a test reaching the success path would read and
// write the real /etc/ssl/vaultls on whatever machine runs it.
func TestSyncCATrustSuccessUsesOverriddenStateDir(t *testing.T) {
	orig := caTrustStateDir
	stateDir := t.TempDir()
	caTrustStateDir = stateDir
	t.Cleanup(func() { caTrustStateDir = orig })

	anchorDir := t.TempDir()
	cfg := &config.Config{CATrust: config.CATrust{
		Enabled:       true,
		AnchorDir:     anchorDir,
		UpdateCommand: "true",
	}}
	f := &bundleAPI{body: selfSignedCA(t, "Test Root CA")}
	var buf bytes.Buffer
	SyncCATrust(context.Background(), cfg, f, metrics.New(), slog.New(slog.NewTextHandler(&buf, nil)))

	if bytes.Contains(buf.Bytes(), []byte("ca trust sync failed")) {
		t.Fatalf("unexpected failure logged:\n%s", buf.String())
	}
	entries, err := os.ReadDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("anchor dir = %v, want exactly one anchor file", entries)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "ca-trust.json")); err != nil {
		t.Fatalf("state file not written to the overridden state dir: %v", err)
	}
}

// A trust-store failure is logged and counted, but must never abort the run:
// certificates for the domains still have to be deployed.
func TestSyncCATrustLogsFailure(t *testing.T) {
	cfg := &config.Config{CATrust: config.CATrust{
		Enabled:       true,
		AnchorDir:     t.TempDir(),
		UpdateCommand: "true",
	}}
	f := &bundleAPI{err: context.Canceled}
	var buf bytes.Buffer
	SyncCATrust(context.Background(), cfg, f, metrics.New(), slog.New(slog.NewTextHandler(&buf, nil)))
	if f.hits != 1 {
		t.Fatalf("expected one bundle fetch, got %d", f.hits)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ca trust sync failed")) {
		t.Fatalf("failure not logged:\n%s", buf.String())
	}
}
