package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

func runReloadForTest(t *testing.T, cfg *config.Config, opts ReloadOptions) (stdout, logs string, err error) {
	t.Helper()
	var out, logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	opts.Stdout = &out
	opts.Stderr = &out
	err = runReload(context.Background(), cfg, log, opts)
	return out.String(), logBuf.String(), err
}

func TestReloadRunsEveryDomainByDefault(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", Reload: "echo one"},
		{Name: "b", Reload: "echo two"},
		{Name: "c"}, // no reload command: skipped, not an error
	}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{})
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if !strings.Contains(stdout, "one") || !strings.Contains(stdout, "two") {
		t.Fatalf("both commands must run, got %q", stdout)
	}
}

func TestReloadDomainFilter(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", Reload: "echo one"},
		{Name: "b", Reload: "echo two"},
	}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{Domains: []string{"b"}})
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if !strings.Contains(stdout, "two") || strings.Contains(stdout, "one") {
		t.Fatalf("only the selected domain must run, got %q", stdout)
	}
}

// Two config entries may share one name (different certs to different
// destinations); --domain must run the command of every entry with that name.
func TestReloadSharedNameRunsEveryMatch(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", OutDir: "/srv/a", Reload: "echo first"},
		{Name: "a", OutDir: "/srv/b", Reload: "echo second"},
		{Name: "b", Reload: "echo other"},
	}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{Domains: []string{"a"}})
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if !strings.Contains(stdout, "first") || !strings.Contains(stdout, "second") || strings.Contains(stdout, "other") {
		t.Fatalf("every shared-name entry must run and only those, got %q", stdout)
	}
}

func TestReloadUnknownDomainFails(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", Reload: "echo one"},
	}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{Domains: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), "not in the config") {
		t.Fatalf("unknown domain must be an error, got %v", err)
	}
	if !strings.Contains(err.Error(), "a") {
		t.Fatalf("error should list configured names, got %q", err.Error())
	}
	if strings.Contains(stdout, "one") {
		t.Fatalf("nothing must run on an unknown domain, got %q", stdout)
	}
}

func TestReloadCACommand(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", Reload: "echo one"},
	}, CATrust: config.CATrust{UpdateCommand: "echo ca-updated"}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{CA: true})
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if !strings.Contains(stdout, "ca-updated") || !strings.Contains(stdout, "one") {
		t.Fatalf("both domain and CA commands must run, got %q", stdout)
	}
}

func TestReloadCAMissingCommandWarns(t *testing.T) {
	cfg := &config.Config{}
	_, logs, err := runReloadForTest(t, cfg, ReloadOptions{CA: true})
	if err != nil {
		t.Fatalf("missing ca command is a warning, not an error, got %v", err)
	}
	if !strings.Contains(logs, "ca_trust.update_command is not set") {
		t.Fatalf("warning not logged:\n%s", logs)
	}
}

// One failing command must not stop the rest — same isolation as ReconcileAll.
func TestReloadFailureIsolatedAndReported(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "bad", Reload: "false"},
		{Name: "good", Reload: "echo fine"},
	}}
	stdout, _, err := runReloadForTest(t, cfg, ReloadOptions{})
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("expected failure summary, got %v", err)
	}
	if !strings.Contains(stdout, "fine") {
		t.Fatalf("the healthy command must still run, got %q", stdout)
	}
}
