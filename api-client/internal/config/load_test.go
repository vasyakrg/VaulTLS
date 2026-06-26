package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaultsAndExpandsEnv(t *testing.T) {
	t.Setenv("VAULTLS_SECRET", "s3cr3t")
	p := writeTmp(t, `
server:
  url: https://vaultls.example.com
  client_id: svc_abc
  secret: ${VAULTLS_SECRET}
domains:
  - name: "*.example.com"
    reload: "systemctl reload nginx"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Secret != "s3cr3t" {
		t.Fatalf("secret not expanded: %q", cfg.Server.Secret)
	}
	if cfg.Schedule != "0 3 1 * *" {
		t.Fatalf("default schedule = %q", cfg.Schedule)
	}
	if cfg.RenewBefore != 720*time.Hour {
		t.Fatalf("default renew_before = %v", cfg.RenewBefore)
	}
	if cfg.Exporter.Listen != "127.0.0.1:9105" {
		t.Fatalf("default listen = %q", cfg.Exporter.Listen)
	}
	d := cfg.Domains[0]
	if d.OutDir != "/etc/ssl/vaultls/example.com" {
		t.Fatalf("default out_dir = %q", d.OutDir)
	}
	if len(d.Formats) != 1 || d.Formats[0] != "pem" {
		t.Fatalf("default formats = %v", d.Formats)
	}
}

func TestLoadRejectsMissingServerURL(t *testing.T) {
	p := writeTmp(t, "domains:\n  - name: a\n    reload: x\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing server.url")
	}
}

func TestFileModeParsesOctal(t *testing.T) {
	d := Domain{Mode: "0600"}
	m, err := d.FileMode()
	if err != nil || m != 0o600 {
		t.Fatalf("FileMode() = %v, %v", m, err)
	}
}
