package wizard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

func TestRenderProducesLoadableConfig(t *testing.T) {
	a := Answers{
		URL: "https://vaultls.example.com", ClientID: "svc_abc", Secret: "pw",
		Domain: "*.example.com", Reload: "systemctl reload nginx",
	}
	out, err := Render(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, out, 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("rendered config not loadable: %v", err)
	}
	if cfg.Domains[0].Name != "*.example.com" || cfg.Server.ClientID != "svc_abc" {
		t.Fatalf("unexpected cfg %+v", cfg)
	}
}

func TestRenderEscapesSpecialSecret(t *testing.T) {
	const secret = "p@ss:word #1"
	a := Answers{
		URL: "https://vaultls.example.com", ClientID: "svc_abc", Secret: secret,
		Domain: "*.example.com", Reload: "systemctl reload nginx",
	}
	out, err := Render(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, out, 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("rendered config not loadable: %v", err)
	}
	if cfg.Server.Secret != secret {
		t.Fatalf("secret mangled: got %q want %q", cfg.Server.Secret, secret)
	}
}

func TestRenderEscapesQuotedReload(t *testing.T) {
	const reload = `sh -c "systemctl reload nginx"`
	a := Answers{
		URL: "https://vaultls.example.com", ClientID: "svc_abc", Secret: "pw",
		Domain: "*.example.com", Reload: reload,
	}
	out, err := Render(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, out, 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("rendered config not loadable: %v", err)
	}
	if cfg.Domains[0].Reload != reload {
		t.Fatalf("reload mangled: got %q want %q", cfg.Domains[0].Reload, reload)
	}
}

func TestRunInteractiveFillsMissing(t *testing.T) {
	preset := Answers{URL: "https://vaultls.example.com", ClientID: "svc_abc"}
	in := strings.NewReader("topsecret\n*.example.com\nsystemctl reload nginx\n")
	got, err := RunInteractive(in, &strings.Builder{}, preset)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "topsecret" || got.Domain != "*.example.com" || got.Reload != "systemctl reload nginx" {
		t.Fatalf("interactive answers = %+v", got)
	}
	if got.URL != preset.URL {
		t.Fatal("preset URL should be preserved, not prompted")
	}
}
