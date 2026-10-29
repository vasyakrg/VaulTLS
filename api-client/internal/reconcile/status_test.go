package reconcile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/status"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

// A successful pass must land in the tracker as ok with the deployed serial.
func TestDomainReportsOkToTracker(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(48 * time.Hour).UnixMilli()
	api := &fakeAPI{
		certs:    []vaultls.Cert{{ID: 2, Name: "*.example.com", ValidUntil: expiry}},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	tr := status.New()
	r := New(api, metrics.New(), time.Now, nil, tr)
	if err := r.Domain(context.Background(), newDomain(dir)); err != nil {
		t.Fatal(err)
	}

	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 tracked domain, got %d", len(snap))
	}
	d := snap[0]
	if d.Status != "ok" || d.Error != "" || d.Stage != "" {
		t.Fatalf("expected clean ok, got %+v", d)
	}
	if d.Serial == "" {
		t.Fatal("deployed serial must be reported")
	}
	if d.ExpiryMS != expiry {
		t.Fatalf("expiry not carried: %d", d.ExpiryMS)
	}
	if d.Name != "*.example.com" || d.Destination != dir || d.Target != "file" {
		t.Fatalf("identity fields wrong: %+v", d)
	}
}

// The cheap-skip path (nothing new to deploy) still reports ok with the
// previous serial — the dashboard must not show stale emptiness.
func TestDomainReportsOkOnCheapSkip(t *testing.T) {
	dir := t.TempDir()
	api := &fakeAPI{
		certs:    []vaultls.Cert{{ID: 2, Name: "*.example.com", ValidUntil: time.Now().Add(48 * time.Hour).UnixMilli()}},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	tr := status.New()
	r := New(api, metrics.New(), time.Now, nil, tr)
	if err := r.Domain(context.Background(), newDomain(dir)); err != nil {
		t.Fatal(err)
	}
	first := tr.Snapshot()[0]

	if err := r.Domain(context.Background(), newDomain(dir)); err != nil {
		t.Fatal(err)
	}
	second := tr.Snapshot()[0]
	if second.Status != "ok" || second.Serial != first.Serial {
		t.Fatalf("cheap skip must keep ok+serial: %+v", second)
	}
}

// A failing pass must land as error naming the stage, without clobbering the
// healthy neighbour entry.
func TestDomainReportsErrorWithStage(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	api := &fakeAPI{
		certs:    []vaultls.Cert{{ID: 2, Name: "*.example.com", ValidUntil: time.Now().Add(48 * time.Hour).UnixMilli()}},
		p12:      makeP12(t, 0x0a1b2c),
		password: "pw",
	}
	// bad.example has no matching cert: reconcile dies at the select stage.
	dBad := newDomain(dirB)
	dBad.Name = "bad.example"

	tr := status.New()
	r := New(api, metrics.New(), time.Now, nil, tr)
	if err := r.Domain(context.Background(), newDomain(dirA)); err != nil {
		t.Fatal(err)
	}
	if err := r.Domain(context.Background(), dBad); err == nil {
		t.Fatal("expected reconcile failure")
	}

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("want 2 tracked domains, got %d", len(snap))
	}
	var bad status.Domain
	for _, d := range snap {
		if d.Name == "bad.example" {
			bad = d
		}
	}
	if bad.Status != "error" || bad.Stage != "select" {
		t.Fatalf("error entry wrong: %+v", bad)
	}
	if !strings.Contains(bad.Error, "no certificate found") {
		t.Fatalf("error text missing: %+v", bad)
	}
}
