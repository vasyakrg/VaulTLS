# vaultls-agent CA Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Научить `vaultls-agent` поддерживать корневые CA VaulTLS в системном доверенном хранилище хоста, по умолчанию выключено.

**Architecture:** Новый пакет `internal/catrust` тянет публичный `GET /api/certificates/ca/bundle`, раскладывает каждый CA в отдельный файл анкор-каталога, ведёт учёт своих файлов в `/etc/ssl/vaultls/ca-trust.json` и однократно запускает `update-ca-certificates`. Вызывается перед раскладкой доменов на старте агента и в каждом плановом цикле, поэтому «обновился агент» и «обновился сертификат» покрыты одним механизмом.

**Tech Stack:** Go 1.26, stdlib (`crypto/x509`, `encoding/pem`, `crypto/sha256`), `gopkg.in/yaml.v3`, `prometheus/client_golang`, `nfpm` + systemd.

**Spec:** `docs/superpowers/specs/2026-07-30-agent-ca-trust-design.md`

## Global Constraints

- Рабочий каталог всех команд: `api-client/`. Тесты — `go test ./...`, сборка — `make build`.
- Module path: `github.com/vasyakrg/vaultls-agent`. Импорты внутренних пакетов — от него.
- Новых внешних зависимостей не добавлять: всё покрывается stdlib.
- Фича выключена по умолчанию. Нулевое значение `config.CATrust` = выключено; конфиги без секции `ca_trust` обязаны продолжать работать без правок.
- Агент удаляет из анкор-каталога **только** файлы, числящиеся в собственном state. Чужие анкоры не трогаются никогда.
- `ca_trust.enabled: false` не приводит к удалению ранее установленного — снятие доверия делает оператор или `apt purge`.
- Комментарии в коде — на английском, как во всём `api-client/`.
- Каждая задача завершается коммитом; сообщения коммитов на английском.

---

### Task 1: Клиент — загрузка CA bundle

**Files:**
- Modify: `api-client/internal/vaultls/client.go` (после `Download`, строка 216)
- Test: `api-client/internal/vaultls/client_test.go`

**Interfaces:**
- Consumes: существующий `(*Client).do(ctx, path)`.
- Produces: `func (c *Client) CABundle(ctx context.Context) ([]byte, error)` — конкатенированный PEM всех TLS CA.

- [ ] **Step 1: Написать падающий тест**

В конец `api-client/internal/vaultls/client_test.go`:

```go
func TestCABundle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok123", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/api/certificates/ca/bundle", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	raw, err := New(srv.URL, "svc_abc", "pw", false).CABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatalf("CABundle = %q", raw)
	}
}

func TestCABundleNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok123", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/api/certificates/ca/bundle", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "svc_abc", "pw", false)
	c.retryBase = time.Millisecond
	if _, err := c.CABundle(context.Background()); err == nil {
		t.Fatal("expected error on 404")
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/vaultls/ -run TestCABundle -v`
Expected: FAIL — `c.CABundle undefined (type *Client has no field or method CABundle)`

- [ ] **Step 3: Реализовать метод**

В `api-client/internal/vaultls/client.go` после `Download`:

```go
// CABundle downloads every TLS CA certificate as one concatenated PEM. The
// endpoint is public, but the call goes through do() anyway so it inherits the
// bounded retry and the single forced re-auth on 401.
func (c *Client) CABundle(ctx context.Context) ([]byte, error) {
	return c.do(ctx, "/api/certificates/ca/bundle")
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/vaultls/ -v`
Expected: PASS, включая `TestCABundle` и `TestCABundleNotFound`

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/vaultls/client.go api-client/internal/vaultls/client_test.go
git commit -m "feat(agent): add CABundle client method"
```

---

### Task 2: Конфиг — секция ca_trust с автодетектом

**Files:**
- Modify: `api-client/internal/config/config.go`
- Modify: `api-client/internal/config/load.go`
- Test: `api-client/internal/config/load_test.go`

**Interfaces:**
- Consumes: существующие `applyDefaults`, `validate` в `load.go`.
- Produces:
  - `type CATrust struct { Enabled bool; AnchorDir string; UpdateCommand string }`
  - `func (c CATrust) FileExt() string` → `".pem"` для путей под `/etc/pki/`, иначе `".crt"`
  - поле `Config.CATrust CATrust` (yaml-ключ `ca_trust`)

- [ ] **Step 1: Написать падающие тесты**

В конец `api-client/internal/config/load_test.go`:

```go
func TestCATrustDisabledByDefault(t *testing.T) {
	p := writeTmp(t, `
server:
  url: https://vaultls.example.com
  client_id: svc_abc
  secret: pw
domains:
  - name: "*.example.com"
    reload: "true"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CATrust.Enabled {
		t.Fatal("ca_trust must be off when the section is absent")
	}
	if cfg.CATrust.AnchorDir != "" || cfg.CATrust.UpdateCommand != "" {
		t.Fatalf("no defaults must be applied while disabled: %+v", cfg.CATrust)
	}
}

func TestCATrustExplicitOverridesKept(t *testing.T) {
	p := writeTmp(t, `
server:
  url: https://vaultls.example.com
  client_id: svc_abc
  secret: pw
ca_trust:
  enabled: true
  anchor_dir: /etc/pki/ca-trust/source/anchors
  update_command: "update-ca-trust extract"
domains:
  - name: "*.example.com"
    reload: "true"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CATrust.AnchorDir != "/etc/pki/ca-trust/source/anchors" ||
		cfg.CATrust.UpdateCommand != "update-ca-trust extract" {
		t.Fatalf("overrides lost: %+v", cfg.CATrust)
	}
	if cfg.CATrust.FileExt() != ".pem" {
		t.Fatalf("FileExt = %q, want .pem under /etc/pki", cfg.CATrust.FileExt())
	}
}

func TestCATrustRejectsRelativeAnchorDir(t *testing.T) {
	p := writeTmp(t, `
server:
  url: https://vaultls.example.com
  client_id: svc_abc
  secret: pw
ca_trust:
  enabled: true
  anchor_dir: relative/anchors
  update_command: "true"
domains:
  - name: "*.example.com"
    reload: "true"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for relative ca_trust.anchor_dir")
	}
}

// Detection is exercised through an injected existence probe so the test does
// not depend on which trust store the build host happens to have.
func TestApplyCATrustDefaultsDetection(t *testing.T) {
	cases := map[string]struct {
		present     string
		in          CATrust
		wantDir     string
		wantCommand string
		wantErr     bool
	}{
		"debian": {
			present: "/usr/local/share/ca-certificates", in: CATrust{Enabled: true},
			wantDir: "/usr/local/share/ca-certificates", wantCommand: "update-ca-certificates",
		},
		"rhel": {
			present: "/etc/pki/ca-trust/source/anchors", in: CATrust{Enabled: true},
			wantDir: "/etc/pki/ca-trust/source/anchors", wantCommand: "update-ca-trust extract",
		},
		"command derived from known anchor_dir": {
			present: "", in: CATrust{Enabled: true, AnchorDir: "/usr/local/share/ca-certificates"},
			wantDir: "/usr/local/share/ca-certificates", wantCommand: "update-ca-certificates",
		},
		"unknown anchor_dir without command": {
			present: "", in: CATrust{Enabled: true, AnchorDir: "/opt/anchors"},
			wantErr: true,
		},
		"nothing detected": {
			present: "", in: CATrust{Enabled: true}, wantErr: true,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			got := tc.in
			err := applyCATrustDefaults(&got, func(dir string) bool { return dir == tc.present })
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.AnchorDir != tc.wantDir || got.UpdateCommand != tc.wantCommand {
				t.Fatalf("got %+v, want dir=%q command=%q", got, tc.wantDir, tc.wantCommand)
			}
		})
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cd api-client && go test ./internal/config/ -run 'CATrust' -v`
Expected: FAIL — `cfg.CATrust undefined`, `undefined: CATrust`, `undefined: applyCATrustDefaults`

- [ ] **Step 3: Добавить тип в config.go**

В `api-client/internal/config/config.go` после типа `Log`:

```go
// CATrust configures publishing the VaulTLS root CAs into the host's system
// trust store. Disabled by default: the agent must never change host-wide trust
// without an explicit opt-in.
type CATrust struct {
	Enabled       bool   `yaml:"enabled"`
	AnchorDir     string `yaml:"anchor_dir"`
	UpdateCommand string `yaml:"update_command"`
}

// FileExt is the anchor file extension implied by AnchorDir. Debian's
// update-ca-certificates only picks up .crt, RHEL's ca-trust anchors are .pem;
// deriving it from the directory keeps an anchor_dir override self-sufficient.
func (c CATrust) FileExt() string {
	if strings.HasPrefix(c.AnchorDir, "/etc/pki/") {
		return ".pem"
	}
	return ".crt"
}
```

И поле в `Config` — после `Log`:

```go
	CATrust   CATrust       `yaml:"ca_trust"`
```

- [ ] **Step 4: Добавить автодетект и валидацию в load.go**

В `api-client/internal/config/load.go` — импортировать `path/filepath`, добавить:

```go
// caTrustPlatforms lists the system trust stores the agent knows, in probe
// order. The package only ships as a .deb, but the binary builds anywhere, so
// RHEL-style hosts are detected instead of requiring a manual override.
var caTrustPlatforms = []struct{ dir, command string }{
	{"/usr/local/share/ca-certificates", "update-ca-certificates"},
	{"/etc/pki/ca-trust/source/anchors", "update-ca-trust extract"},
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// applyCATrustDefaults fills anchor_dir/update_command from the detected
// platform. exists is injected so tests do not depend on the host's layout.
func applyCATrustDefaults(c *CATrust, exists func(string) bool) error {
	if c.AnchorDir == "" {
		for _, p := range caTrustPlatforms {
			if exists(p.dir) {
				c.AnchorDir = p.dir
				break
			}
		}
	}
	if c.AnchorDir == "" {
		return fmt.Errorf("ca_trust.enabled is set but no known system trust store was found: " +
			"set ca_trust.anchor_dir and ca_trust.update_command explicitly")
	}
	if c.UpdateCommand == "" {
		for _, p := range caTrustPlatforms {
			if p.dir == c.AnchorDir {
				c.UpdateCommand = p.command
				break
			}
		}
	}
	if c.UpdateCommand == "" {
		return fmt.Errorf("ca_trust.update_command is required for anchor_dir %q", c.AnchorDir)
	}
	return nil
}
```

В `applyDefaults`, перед циклом по `cfg.Domains`:

```go
	if cfg.CATrust.Enabled {
		if err := applyCATrustDefaults(&cfg.CATrust, dirExists); err != nil {
			return err
		}
	}
```

В `validate`, сразу после проверки `cfg.Server.ClientID`:

```go
	if cfg.CATrust.Enabled && !filepath.IsAbs(cfg.CATrust.AnchorDir) {
		return fmt.Errorf("ca_trust.anchor_dir must be an absolute path, got %q", cfg.CATrust.AnchorDir)
	}
```

- [ ] **Step 5: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/config/ -v`
Expected: PASS, включая все `CATrust`-тесты и прежние тесты конфига

- [ ] **Step 6: Коммит**

```bash
git add api-client/internal/config/
git commit -m "feat(agent): add ca_trust config section with trust-store detection"
```

---

### Task 3: catrust — разбор bundle и имена анкор-файлов

**Files:**
- Create: `api-client/internal/catrust/bundle.go`
- Test: `api-client/internal/catrust/bundle_test.go`

**Interfaces:**
- Consumes: ничего из предыдущих задач.
- Produces:
  - `type Anchor struct { Fingerprint string; FileName string; PEM []byte }`
  - `func ParseBundle(raw []byte, ext string) ([]Anchor, error)`

- [ ] **Step 1: Написать падающий тест**

Создать `api-client/internal/catrust/bundle_test.go`:

```go
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
		"empty":              []byte(""),
		"no pem":             []byte("not a certificate at all"),
		"wrong block type":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"undecodable der":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
	}
	for label, raw := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := ParseBundle(raw, ".crt"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/catrust/ -v`
Expected: FAIL — `undefined: ParseBundle`

- [ ] **Step 3: Реализовать разбор**

Создать `api-client/internal/catrust/bundle.go`:

```go
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
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/catrust/ -v`
Expected: PASS — все четыре теста

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/catrust/
git commit -m "feat(agent): parse CA bundle into per-certificate anchors"
```

---

### Task 4: catrust — состояние на диске

**Files:**
- Create: `api-client/internal/catrust/state.go`
- Test: `api-client/internal/catrust/state_test.go`

**Interfaces:**
- Consumes: пакет `catrust` из Task 3.
- Produces:
  - `type State struct { Certs map[string]string; PendingUpdate bool; LastSync int64 }`
  - `func ReadState(dir string) (State, error)` — отсутствующий файл даёт нулевое состояние без ошибки
  - `func WriteState(dir string, s State) error`

- [ ] **Step 1: Написать падающий тест**

Создать `api-client/internal/catrust/state_test.go`:

```go
package catrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadStateMissingFileIsZero(t *testing.T) {
	got, err := ReadState(t.TempDir())
	if err != nil {
		t.Fatalf("missing state must not be an error: %v", err)
	}
	if len(got.Certs) != 0 || got.PendingUpdate || got.LastSync != 0 {
		t.Fatalf("got %+v, want zero state", got)
	}
}

func TestWriteReadStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := State{
		Certs:         map[string]string{"abc123": "vaultls-root-abc123.crt"},
		PendingUpdate: true,
		LastSync:      1753848000000,
	}
	if err := WriteState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Certs["abc123"] != want.Certs["abc123"] || !got.PendingUpdate || got.LastSync != want.LastSync {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	fi, err := os.Stat(filepath.Join(dir, "ca-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestReadStateRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca-trust.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(dir); err == nil {
		t.Fatal("expected error for corrupt state")
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/catrust/ -run State -v`
Expected: FAIL — `undefined: ReadState`, `undefined: WriteState`, `undefined: State`

- [ ] **Step 3: Реализовать состояние**

Создать `api-client/internal/catrust/state.go`:

```go
package catrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const stateFileName = "ca-trust.json"

// State records the anchor files the agent owns, keyed by certificate
// fingerprint. Only files listed here are ever removed, so foreign anchors
// sharing the directory are safe.
//
// PendingUpdate marks that files are on disk but the trust-store update command
// has not succeeded yet; it forces the next run to retry the command instead of
// concluding that the fingerprint set already matches.
type State struct {
	Certs         map[string]string `json:"certs"`
	PendingUpdate bool              `json:"pending_update"`
	LastSync      int64             `json:"last_sync"`
}

func ReadState(dir string) (State, error) {
	var s State
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read ca-trust state: %w", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("parse ca-trust state: %w", err)
	}
	return s, nil
}

func WriteState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir ca-trust state dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ca-trust state: %w", err)
	}
	final := filepath.Join(dir, stateFileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write ca-trust state tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename ca-trust state: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/catrust/ -v`
Expected: PASS — тесты Task 3 и Task 4

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/catrust/state.go api-client/internal/catrust/state_test.go
git commit -m "feat(agent): persist ca-trust anchor ownership state"
```

---

### Task 5: catrust — Sync

**Files:**
- Create: `api-client/internal/catrust/catrust.go`
- Test: `api-client/internal/catrust/catrust_test.go`

**Interfaces:**
- Consumes: `ParseBundle`, `Anchor` (Task 3); `State`, `ReadState`, `WriteState` (Task 4); `config.CATrust` с методом `FileExt()` (Task 2); `reloader.Run` (существует).
- Produces:
  - `type Fetcher interface { CABundle(ctx context.Context) ([]byte, error) }` — удовлетворяется `*vaultls.Client` из Task 1
  - `type Runner interface { Run(ctx context.Context, command string) error }`
  - `type ShellRunner struct{ Timeout time.Duration }` — продовая реализация `Runner`
  - `type Result struct { Installed int; Changed bool }`
  - `type Error struct { Stage Stage; Err error }` с константами `StageFetch`/`StageParse`/`StageState`/`StageWrite`/`StageUpdate`
  - `func Sync(ctx context.Context, f Fetcher, r Runner, cfg config.CATrust, stateDir string, now func() time.Time) (Result, error)`

- [ ] **Step 1: Написать падающие тесты**

Создать `api-client/internal/catrust/catrust_test.go`:

```go
package catrust

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

type fakeFetcher struct {
	body []byte
	err  error
}

func (f *fakeFetcher) CABundle(context.Context) ([]byte, error) { return f.body, f.err }

type fakeRunner struct {
	calls int
	err   error
}

func (r *fakeRunner) Run(context.Context, string) error {
	r.calls++
	return r.err
}

func fixedClock() time.Time { return time.Unix(1753848000, 0) }

type harness struct {
	anchorDir string
	stateDir  string
	cfg       config.CATrust
	fetcher   *fakeFetcher
	runner    *fakeRunner
}

func newHarness(t *testing.T, body []byte) *harness {
	t.Helper()
	anchor := t.TempDir()
	return &harness{
		anchorDir: anchor,
		stateDir:  t.TempDir(),
		cfg:       config.CATrust{Enabled: true, AnchorDir: anchor, UpdateCommand: "update-ca-certificates"},
		fetcher:   &fakeFetcher{body: body},
		runner:    &fakeRunner{},
	}
}

func (h *harness) sync(ctx context.Context) (Result, error) {
	return Sync(ctx, h.fetcher, h.runner, h.cfg, h.stateDir, fixedClock)
}

func anchorNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestSyncInstallsAnchors(t *testing.T) {
	body := append(selfSigned(t, "Root A"), selfSigned(t, "Root B")...)
	h := newHarness(t, body)

	res, err := h.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Installed != 2 || !res.Changed {
		t.Fatalf("res = %+v, want 2 installed and changed", res)
	}
	if names := anchorNames(t, h.anchorDir); len(names) != 2 {
		t.Fatalf("anchor dir holds %v, want 2 files", names)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Certs) != 2 || st.PendingUpdate || st.LastSync != fixedClock().UnixMilli() {
		t.Fatalf("state = %+v", st)
	}
}

func TestSyncSecondRunIsNoop(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.runner.calls = 0

	res, err := h.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("unchanged bundle must not report a change")
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command called %d times on a no-op run", h.runner.calls)
	}
}

func TestSyncRemovesRetiredAnchor(t *testing.T) {
	oldCA := selfSigned(t, "Root Old")
	h := newHarness(t, oldCA)
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := anchorNames(t, h.anchorDir)

	h.fetcher.body = selfSigned(t, "Root New")
	h.runner.calls = 0
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := anchorNames(t, h.anchorDir)
	if len(after) != 1 {
		t.Fatalf("anchor dir holds %v, want exactly the new anchor", after)
	}
	if after[0] == before[0] {
		t.Fatal("retired CA still trusted")
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
}

func TestSyncRestoresDeletedAnchor(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	name := anchorNames(t, h.anchorDir)[0]
	if err := os.Remove(filepath.Join(h.anchorDir, name)); err != nil {
		t.Fatal(err)
	}
	h.runner.calls = 0

	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.anchorDir, name)); err != nil {
		t.Fatalf("anchor not restored: %v", err)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
}

func TestSyncLeavesForeignAnchorsAlone(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	foreign := filepath.Join(h.anchorDir, "other-corp.crt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.fetcher.body = selfSigned(t, "Root B")
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign anchor was removed: %v", err)
	}
}

func TestSyncRejectsGarbageWithoutTouchingDisk(t *testing.T) {
	h := newHarness(t, []byte("definitely not a pem"))

	_, err := h.sync(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageParse {
		t.Fatalf("err = %v, want a parse-stage Error", err)
	}
	if names := anchorNames(t, h.anchorDir); len(names) != 0 {
		t.Fatalf("anchor dir touched: %v", names)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command called %d times", h.runner.calls)
	}
}

func TestSyncFetchErrorIsStaged(t *testing.T) {
	h := newHarness(t, nil)
	h.fetcher.err = errors.New("connection refused")

	_, err := h.sync(context.Background())
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageFetch {
		t.Fatalf("err = %v, want a fetch-stage Error", err)
	}
}

// A failed update command must leave pending_update set so the next run retries
// it instead of concluding the fingerprint set already matches.
func TestSyncRetriesFailedUpdateCommand(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	h.runner.err = errors.New("update-ca-certificates: exit 1")

	_, err := h.sync(context.Background())
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageUpdate {
		t.Fatalf("err = %v, want an update-stage Error", err)
	}
	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.PendingUpdate {
		t.Fatal("pending_update must stay set after a failed update command")
	}

	h.runner.err = nil
	h.runner.calls = 0
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command retried %d times, want 1", h.runner.calls)
	}
	st, err = ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PendingUpdate {
		t.Fatal("pending_update must clear after a successful update command")
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cd api-client && go test ./internal/catrust/ -run Sync -v`
Expected: FAIL — `undefined: Sync`, `undefined: Error`, `undefined: StageParse`

- [ ] **Step 3: Реализовать Sync**

Создать `api-client/internal/catrust/catrust.go`:

```go
package catrust

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/reloader"
)

// Fetcher supplies the concatenated PEM of every TLS CA. *vaultls.Client
// satisfies it.
type Fetcher interface {
	CABundle(ctx context.Context) ([]byte, error)
}

// Runner applies the platform's trust-store update command.
type Runner interface {
	Run(ctx context.Context, command string) error
}

// ShellRunner runs the command through sh -c under its own timeout, so a hung
// update-ca-certificates cannot stall the reconcile loop.
type ShellRunner struct{ Timeout time.Duration }

func (s ShellRunner) Run(ctx context.Context, command string) error {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return reloader.Run(c, command)
}

// Stage names the step a Sync failure came from, so callers can label metrics
// without string-matching error text.
type Stage string

const (
	StageFetch  Stage = "fetch"
	StageParse  Stage = "parse"
	StageState  Stage = "state"
	StageWrite  Stage = "write"
	StageUpdate Stage = "update"
)

type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("ca trust %s: %v", e.Stage, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

type Result struct {
	Installed int  // how many CAs the agent now owns
	Changed   bool // whether the trust store was rewritten this run
}

// Sync makes the anchor directory match the server's CA bundle and applies the
// change with a single update command. It is idempotent: an unchanged bundle
// whose files are all present costs one HTTP call and nothing else.
func Sync(ctx context.Context, f Fetcher, r Runner, cfg config.CATrust, stateDir string, now func() time.Time) (Result, error) {
	raw, err := f.CABundle(ctx)
	if err != nil {
		return Result{}, &Error{StageFetch, err}
	}
	anchors, err := ParseBundle(raw, cfg.FileExt())
	if err != nil {
		return Result{}, &Error{StageParse, err}
	}
	prev, err := ReadState(stateDir)
	if err != nil {
		return Result{}, &Error{StageState, err}
	}
	if !needsSync(prev, anchors, cfg.AnchorDir) {
		return Result{Installed: len(anchors), Changed: false}, nil
	}

	if err := os.MkdirAll(cfg.AnchorDir, 0o755); err != nil {
		return Result{}, &Error{StageWrite, fmt.Errorf("mkdir anchor dir: %w", err)}
	}
	next := State{Certs: make(map[string]string, len(anchors)), LastSync: prev.LastSync, PendingUpdate: true}
	for _, a := range anchors {
		if err := writeAnchor(cfg.AnchorDir, a); err != nil {
			return Result{}, &Error{StageWrite, err}
		}
		next.Certs[a.Fingerprint] = a.FileName
	}
	// Drop anchors we installed earlier that the bundle no longer carries:
	// otherwise a retired CA stays trusted forever. Only our own files are
	// considered — anything not in prev.Certs is somebody else's.
	for fp, name := range prev.Certs {
		if _, keep := next.Certs[fp]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(cfg.AnchorDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Result{}, &Error{StageWrite, fmt.Errorf("remove retired anchor %s: %w", name, err)}
		}
	}
	// Ownership is recorded before the command runs so a failing command cannot
	// cost us the record of files already on disk.
	if err := WriteState(stateDir, next); err != nil {
		return Result{}, &Error{StageState, err}
	}
	if err := r.Run(ctx, cfg.UpdateCommand); err != nil {
		return Result{Installed: len(anchors), Changed: true}, &Error{StageUpdate, err}
	}
	next.PendingUpdate = false
	next.LastSync = now().UnixMilli()
	if err := WriteState(stateDir, next); err != nil {
		return Result{Installed: len(anchors), Changed: true}, &Error{StageState, err}
	}
	return Result{Installed: len(anchors), Changed: true}, nil
}

// needsSync reports whether the anchor directory has to be rewritten: the
// fingerprint set moved, a file we own vanished, or a previous update command
// never succeeded.
func needsSync(prev State, anchors []Anchor, anchorDir string) bool {
	if prev.PendingUpdate || len(prev.Certs) != len(anchors) {
		return true
	}
	for _, a := range anchors {
		name, ok := prev.Certs[a.Fingerprint]
		if !ok || name != a.FileName {
			return true
		}
		if _, err := os.Stat(filepath.Join(anchorDir, name)); err != nil {
			return true
		}
	}
	return false
}

// writeAnchor writes one anchor atomically. Mode 0644: CA certificates are
// public, and every local TLS client has to be able to read them.
func writeAnchor(dir string, a Anchor) error {
	final := filepath.Join(dir, a.FileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, a.PEM, 0o644); err != nil {
		return fmt.Errorf("write anchor %s: %w", a.FileName, err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod anchor %s: %w", a.FileName, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename anchor %s: %w", a.FileName, err)
	}
	return nil
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/catrust/ -v`
Expected: PASS — все тесты пакета (Tasks 3–5)

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/catrust/catrust.go api-client/internal/catrust/catrust_test.go
git commit -m "feat(agent): sync VaulTLS CAs into the system trust store"
```

---

### Task 6: Метрики ca_trust

**Files:**
- Modify: `api-client/internal/metrics/metrics.go`
- Test: `api-client/internal/metrics/metrics_test.go`

**Interfaces:**
- Consumes: существующий тип `Metrics`.
- Produces:
  - `func (m *Metrics) SetCATrustCerts(n float64)`
  - `func (m *Metrics) MarkCATrustSync(unixSeconds float64)`
  - `func (m *Metrics) IncCATrustError(stage string)`

- [ ] **Step 1: Написать падающий тест**

В конец `api-client/internal/metrics/metrics_test.go`:

```go
func TestExposesCATrustMetrics(t *testing.T) {
	m := New()
	m.SetCATrustCerts(2)
	m.MarkCATrustSync(1753848000)
	m.IncCATrustError("update")

	body := scrape(m)
	for _, want := range []string{
		"vaultls_agent_ca_trust_certs 2",
		"vaultls_agent_ca_trust_last_sync_timestamp_seconds 1.753848e+09",
		`vaultls_agent_ca_trust_errors_total{stage="update"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n%s", want, body)
		}
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/metrics/ -run CATrust -v`
Expected: FAIL — `m.SetCATrustCerts undefined`

- [ ] **Step 3: Добавить метрики**

В `api-client/internal/metrics/metrics.go` — поля структуры `Metrics` после `tokenErrors`:

```go
	caTrustCerts    prometheus.Gauge
	caTrustLastSync prometheus.Gauge
	caTrustErrors   *prometheus.CounterVec
```

В `New()`, в литерал `&Metrics{...}` после `tokenErrors`:

```go
		caTrustCerts:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_ca_trust_certs", Help: "CA certificates the agent keeps in the system trust store."}),
		caTrustLastSync: prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_ca_trust_last_sync_timestamp_seconds", Help: "Last successful trust-store sync."}),
		caTrustErrors:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_agent_ca_trust_errors_total", Help: "Trust-store sync errors by stage."}, []string{"stage"}),
```

В `reg.MustRegister(...)` — дописать `m.caTrustCerts, m.caTrustLastSync, m.caTrustErrors`.

В конец файла:

```go
// Trust-store metrics carry no domain labels: the feature is host-wide.
func (m *Metrics) SetCATrustCerts(n float64) { m.caTrustCerts.Set(n) }

func (m *Metrics) MarkCATrustSync(unixSeconds float64) { m.caTrustLastSync.Set(unixSeconds) }

func (m *Metrics) IncCATrustError(stage string) { m.caTrustErrors.WithLabelValues(stage).Inc() }
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/metrics/ -v`
Expected: PASS — включая `TestExposesCATrustMetrics`

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/metrics/
git commit -m "feat(agent): expose ca_trust metrics"
```

---

### Task 7: Интеграция в жизненный цикл агента

**Files:**
- Modify: `api-client/internal/app/app.go`
- Test: `api-client/internal/app/app_test.go`

**Interfaces:**
- Consumes: `catrust.Sync`, `catrust.Fetcher`, `catrust.ShellRunner`, `catrust.Error`, `catrust.Stage` (Task 5); `metrics.SetCATrustCerts`/`MarkCATrustSync`/`IncCATrustError` (Task 6); `config.Config.CATrust` (Task 2); `(*vaultls.Client).CABundle` (Task 1).
- Produces: `func SyncCATrust(ctx context.Context, cfg *config.Config, f catrust.Fetcher, m *metrics.Metrics, log *slog.Logger)` — вызывается из `Run` и `RunOnce` до `ReconcileAll`.

- [ ] **Step 1: Написать падающий тест**

В конец `api-client/internal/app/app_test.go`:

```go
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
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/app/ -run CATrust -v`
Expected: FAIL — `undefined: SyncCATrust`

- [ ] **Step 3: Реализовать SyncCATrust и подключить**

В `api-client/internal/app/app.go` — импортировать `errors` и `github.com/vasyakrg/vaultls-agent/internal/catrust`, затем добавить после `ReconcileAll`:

```go
// caTrustStateDir holds the record of anchors the agent owns. It lives in the
// directory postinstall already creates and the unit already allows writing to.
const caTrustStateDir = "/etc/ssl/vaultls"

// SyncCATrust keeps the VaulTLS CAs present in the host trust store. Failures
// are logged and counted but never propagate: an unreachable CA endpoint must
// not stop certificates from being deployed.
func SyncCATrust(ctx context.Context, cfg *config.Config, f catrust.Fetcher, m *metrics.Metrics, log *slog.Logger) {
	if !cfg.CATrust.Enabled {
		return
	}
	res, err := catrust.Sync(ctx, f, catrust.ShellRunner{}, cfg.CATrust, caTrustStateDir, time.Now)
	if err != nil {
		stage := string(catrust.StageUpdate)
		var se *catrust.Error
		if errors.As(err, &se) {
			stage = string(se.Stage)
		}
		m.IncCATrustError(stage)
		log.Error("ca trust sync failed", "stage", stage, "err", err)
		return
	}
	m.SetCATrustCerts(float64(res.Installed))
	m.MarkCATrustSync(float64(time.Now().Unix()))
	if res.Changed {
		log.Info("ca trust store updated", "certs", res.Installed, "anchor_dir", cfg.CATrust.AnchorDir)
	} else {
		log.Debug("ca trust store already current", "certs", res.Installed)
	}
}
```

В `Run`, между созданием `r := reconcile.New(...)` и блоком exporter'а — ничего; вызов ставится непосредственно перед initial reconcile, заменяя строку `ReconcileAll(ctx, cfg, r, log)`:

```go
	// Initial reconcile, then scheduled loop.
	SyncCATrust(ctx, cfg, api, m, log)
	ReconcileAll(ctx, cfg, r, log)
	return scheduler.Run(ctx, cfg.Schedule, cfg.Jitter, func(c context.Context) {
		SyncCATrust(c, cfg, api, m, log)
		ReconcileAll(c, cfg, r, log)
	})
```

В `RunOnce` — заменить `ReconcileAll(ctx, cfg, r, log)` на:

```go
	SyncCATrust(ctx, cfg, api, m, log)
	ReconcileAll(ctx, cfg, r, log)
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./... && go vet ./...`
Expected: PASS по всем пакетам, `go vet` без замечаний

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/app/
git commit -m "feat(agent): run ca-trust sync on startup and every scheduled cycle"
```

---

### Task 8: setup --ca-trust и рендер конфига

**Files:**
- Modify: `api-client/internal/wizard/wizard.go`
- Modify: `api-client/cmd/vaultls-agent/setup.go:13-35`
- Test: `api-client/internal/wizard/wizard_test.go`

**Interfaces:**
- Consumes: существующие `wizard.Answers`, `wizard.Render`.
- Produces: поле `Answers.CATrust bool`; `Render` пишет секцию `ca_trust` только когда оно взведено.

- [ ] **Step 1: Написать падающий тест**

В конец `api-client/internal/wizard/wizard_test.go`:

```go
func TestRenderOmitsCATrustByDefault(t *testing.T) {
	body, err := Render(Answers{
		URL: "https://vaultls.example.com", ClientID: "svc", Secret: "pw",
		Domain: "*.example.com", Reload: "systemctl reload nginx",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "ca_trust") {
		t.Fatalf("ca_trust must not appear unless requested:\n%s", body)
	}
}

func TestRenderWritesCATrustWhenRequested(t *testing.T) {
	body, err := Render(Answers{
		URL: "https://vaultls.example.com", ClientID: "svc", Secret: "pw",
		Domain: "*.example.com", Reload: "systemctl reload nginx", CATrust: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CATrust struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"ca_trust"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.CATrust.Enabled {
		t.Fatalf("ca_trust.enabled not set:\n%s", body)
	}
}
```

`strings` в этом файле уже импортирован; добавить в его блок импортов `"gopkg.in/yaml.v3"`.

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd api-client && go test ./internal/wizard/ -run CATrust -v`
Expected: FAIL — `unknown field 'CATrust' in struct literal of type Answers`

- [ ] **Step 3: Реализовать**

В `api-client/internal/wizard/wizard.go`:

```go
type Answers struct {
	URL      string
	ClientID string
	Secret   string
	Domain   string
	Reload   string
	CATrust  bool
}

// caTrustDoc is a pointer field in renderDoc so the section is omitted entirely
// when the operator did not ask for it.
type caTrustDoc struct {
	Enabled bool `yaml:"enabled"`
}
```

В `renderDoc` — поле после `Exporter`:

```go
	CATrust *caTrustDoc `yaml:"ca_trust,omitempty"`
```

В `Render` — перед `return`:

```go
	if a.CATrust {
		doc.CATrust = &caTrustDoc{Enabled: true}
	}
```

В `api-client/cmd/vaultls-agent/setup.go` — новый флаг после `enable`:

```go
	caTrust := fs.Bool("ca-trust", false, "install VaulTLS root CAs into the system trust store")
```

и передать его в preset:

```go
	preset := wizard.Answers{URL: *url, ClientID: *clientID, Secret: *secret, Domain: *domain, Reload: *reload, CATrust: *caTrust}
```

Интерактивный опрос новым вопросом не дополняется: `RunInteractive` спрашивает только строковые поля, а флаг остаётся админской опцией командной строки.

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd api-client && go test ./internal/wizard/ ./cmd/... -v && go build ./...`
Expected: PASS, сборка успешна

- [ ] **Step 5: Коммит**

```bash
git add api-client/internal/wizard/ api-client/cmd/vaultls-agent/setup.go
git commit -m "feat(agent): add --ca-trust flag to setup"
```

---

### Task 9: Пакетирование, systemd и документация

**Files:**
- Modify: `api-client/packaging/systemd/vaultls-agent.service`
- Modify: `api-client/packaging/scripts/postremove.sh`
- Modify: `api-client/packaging/config.example.yaml`
- Modify: `api-client/README.md`

**Interfaces:**
- Consumes: имя файла состояния `ca-trust.json` и его формат (Task 4); ключи конфига `ca_trust.*` (Task 2).
- Produces: ничего для кода — задача закрывает рантайм-права и документацию.

- [ ] **Step 1: Расширить ReadWritePaths**

В `api-client/packaging/systemd/vaultls-agent.service` заменить строку `ReadWritePaths=...` и комментарий над ней на:

```
# ProtectSystem=full makes /usr, /boot and /etc read-only except the paths below.
# A domain out_dir outside these locations fails to write at runtime — add it
# here via a drop-in override, e.g. ReadWritePaths+=/your/path
# The trust-store paths are prefixed with '-' so a host without them still starts.
ReadWritePaths=/etc/ssl/vaultls /etc/vaultls -/usr/local/share/ca-certificates -/etc/ssl/certs -/etc/pki/ca-trust/source/anchors -/etc/pki/ca-trust/extracted
```

- [ ] **Step 2: Проверить синтаксис unit-файла**

Run: `cd api-client && grep -n 'ReadWritePaths' packaging/systemd/vaultls-agent.service`
Expected: одна строка, содержащая все шесть путей, четыре из них с префиксом `-`

- [ ] **Step 3: Чистка доверия при purge**

Заменить содержимое `api-client/packaging/scripts/postremove.sh` на:

```sh
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl stop vaultls-agent 2>/dev/null || true
  systemctl disable vaultls-agent 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi
if [ "$1" = "purge" ]; then
  # Remove only the anchors recorded in the agent's own state file. Every entry
  # is a "<sha256>": "<filename>" pair on its own line (json.MarshalIndent).
  state=/etc/ssl/vaultls/ca-trust.json
  if [ -f "$state" ]; then
    sed -n 's/.*"[0-9a-f]\{64\}"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state" |
      while read -r f; do
        [ -n "$f" ] || continue
        rm -f "/usr/local/share/ca-certificates/$f" "/etc/pki/ca-trust/source/anchors/$f"
      done
    rm -f "$state"
    if command -v update-ca-certificates >/dev/null 2>&1; then
      update-ca-certificates >/dev/null 2>&1 || true
    elif command -v update-ca-trust >/dev/null 2>&1; then
      update-ca-trust extract >/dev/null 2>&1 || true
    fi
  fi
fi
```

- [ ] **Step 4: Проверить извлечение имён из реального state**

Run:
```bash
cd api-client && cat > /tmp/ca-trust.json <<'EOF'
{
  "certs": {
    "6d3f7a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f": "vaultls-vaultls-root-ca-6d3f7a0b.crt"
  },
  "pending_update": false,
  "last_sync": 1753848000000
}
EOF
sed -n 's/.*"[0-9a-f]\{64\}"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/ca-trust.json
```
Expected: одна строка `vaultls-vaultls-root-ca-6d3f7a0b.crt`

- [ ] **Step 5: Документировать секцию в примере конфига**

В `api-client/packaging/config.example.yaml` — после блока `exporter:`, перед `domains:`:

```yaml
# Publish the VaulTLS root CAs into the host's system trust store, so any local
# client (curl, psql, openssl) accepts certificates issued by VaulTLS.
# OFF by default: enabling it changes trust for the WHOLE host.
# anchor_dir/update_command are detected automatically (Debian and RHEL layouts);
# set them explicitly on any other system.
# ca_trust:
#   enabled: true
#   anchor_dir: /usr/local/share/ca-certificates
#   update_command: "update-ca-certificates"
```

- [ ] **Step 6: Раздел в README**

В `api-client/README.md` — новый раздел непосредственно перед `## Metrics & exporter`. Дополнительно в разделе `## systemd and ` + "`ReadWritePaths`" привести процитированную там строку `ReadWritePaths=` к новому виду из Step 1, а в `## Configuration reference` добавить строки таблицы:

| ключ | смысл |
|---|---|
| `ca_trust.enabled` | публиковать корневые CA VaulTLS в системном доверенном хранилище (по умолчанию `false`) |
| `ca_trust.anchor_dir` | каталог анкоров; определяется автоматически |
| `ca_trust.update_command` | команда применения хранилища; определяется автоматически |

Сам новый раздел:

```markdown
## System trust store (optional)

By default the agent only writes certificates into `out_dir`. It can also keep
the VaulTLS root CAs in the host's system trust store, so `curl`, `psql`,
`openssl s_client` and anything else on the box accepts VaulTLS-issued
certificates without a per-command `--cacert`.

This is **off by default** — enabling it changes trust for the whole host:

```yaml
ca_trust:
  enabled: true
```

`anchor_dir` and `update_command` are detected automatically:

| Platform | anchor_dir | update_command |
|---|---|---|
| Debian/Ubuntu | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| RHEL/Fedora | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust extract` |

On any other layout set both explicitly:

```yaml
ca_trust:
  enabled: true
  anchor_dir: /opt/pki/anchors
  update_command: "/opt/pki/refresh.sh"
```

The CAs come from the server's public `GET /api/certificates/ca/bundle`, so the
service account needs no extra scope. Each CA is written as its own file named
`vaultls-<cn>-<fingerprint>.crt`, and the agent records what it owns in
`/etc/ssl/vaultls/ca-trust.json`. Only files listed there are ever removed —
anchors placed by anything else are left alone. The check runs on every startup
and on every scheduled cycle, so a rotated CA is picked up even when no
certificate changed.

Setting `enabled: false` later does **not** remove already-installed CAs:
dropping host trust is an explicit operator action. `apt purge vaultls-agent`
removes them and refreshes the trust store.

Metrics: `vaultls_agent_ca_trust_certs`,
`vaultls_agent_ca_trust_last_sync_timestamp_seconds`,
`vaultls_agent_ca_trust_errors_total{stage}`.
```

- [ ] **Step 7: Полная проверка сборки и тестов**

Run: `cd api-client && go vet ./... && go test ./... && make build`
Expected: vet чист, все тесты PASS, `dist/vaultls-agent` собран

- [ ] **Step 8: Коммит**

```bash
git add api-client/packaging/ api-client/README.md
git commit -m "feat(agent): package and document the ca-trust feature"
```

---

## Проверка вручную (после Task 9)

Не входит в задачи, но выполняется перед релизом на тестовом Debian-хосте:

```bash
sudo dpkg -i dist/vaultls-agent_<ver>_amd64.deb
sudo sed -i 's/^exporter:/ca_trust:\n  enabled: true\nexporter:/' /etc/vaultls/config.yaml
sudo systemctl restart vaultls-agent
ls -l /usr/local/share/ca-certificates/vaultls-*
sudo cat /etc/ssl/vaultls/ca-trust.json
curl -sS https://<хост-с-сертом-от-VaulTLS>/ -o /dev/null && echo "trust ok"
curl -s 127.0.0.1:9105/metrics | grep ca_trust
```
