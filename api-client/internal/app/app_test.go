package app

import (
	"bytes"
	"context"
	"log/slog"
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
		{Name: "a", OutDir: t.TempDir(), Formats: []string{"pem"}, Mode: "0640", Reload: "true"},
		{Name: "b", OutDir: t.TempDir(), Formats: []string{"pem"}, Mode: "0640", Reload: "true"},
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
