# vaultls-agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Debian (.deb) systemd service in Go that periodically pulls TLS certificates from VaulTLS by service account, writes them as PEM on the host, reloads the target service only when the certificate actually changed, and exposes Prometheus metrics.

**Architecture:** A single long-running daemon (`vaultls-agent run`) hosts an internal cron-spec scheduler and a Prometheus exporter. On each tick it reconciles every configured domain independently: cheap check against local state, then download p12, decode to PEM, compare serial, write atomically, reload on real change. Packaged with nfpm into a `.deb`. Configuration via `vaultls-agent setup` (flags = non-interactive, missing flags = interactive wizard).

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` (config), `software.sslmate.com/src/go-pkcs12` (p12 decode), `github.com/robfig/cron/v3` (cron-spec parsing via `cron.ParseStandard`), `github.com/prometheus/client_golang` (exporter), stdlib `net/http` (VaulTLS client). Packaging: `nfpm`.

## Global Constraints

- Go module path: `github.com/vasyakrg/vaultls-agent`; all packages live under `api-client/` in the repo; internal packages imported as `github.com/vasyakrg/vaultls-agent/internal/<pkg>`.
- Target platform: Debian amd64. Build binary with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.
- VaulTLS API (paths relative to configured `server.url`, all under `/api`):
  - `POST /api/auth/token` body `{"client_id","secret"}` → `{"access_token","token_type","expires_in","scopes"}`.
  - `GET /api/certificates` (Bearer) → array of `{id,name,created_on,valid_until,certificate_type,user_id,renew_method,ca_id,revoked_at}`. Timestamps are **Unix milliseconds**. `data`/serial are NOT present.
  - `GET /api/certificates/<id>/password` (Bearer) → JSON string.
  - `GET /api/certificates/<id>/download` (Bearer) → raw `.p12` bytes (PKCS12).
- Private key files are ALWAYS written with mode `0600`, regardless of configured `mode`.
- All file writes are atomic: write to `*.tmp` in the same dir, then `os.Rename`.
- Reload runs ONLY when the decoded serial differs from the stored serial.
- Per-domain failures must be isolated — one domain failing never aborts others.
- Default exporter listen address: `127.0.0.1:9105`. Default schedule: `0 3 1 * *`. Default `renew_before`: `720h`.
- GitHub repo for self-update version check: `vasyakrg/VaulTLS`.

---

### Task 1: Go module bootstrap + version command

**Files:**
- Create: `api-client/go.mod`
- Create: `api-client/cmd/vaultls-agent/main.go`
- Create: `api-client/internal/version/version.go`
- Test: `api-client/internal/version/version_test.go`

**Interfaces:**
- Produces: `version.Version` (string, default `"dev"`, overridable via `-ldflags -X`); `version.String() string` returning e.g. `vaultls-agent dev`.

- [ ] **Step 1: Initialize the module**

Run from `api-client/`:
```bash
cd api-client
go mod init github.com/vasyakrg/vaultls-agent
go mod edit -go=1.26
```

- [ ] **Step 2: Write the failing test**

`api-client/internal/version/version_test.go`:
```go
package version

import "testing"

func TestStringIncludesVersion(t *testing.T) {
	Version = "1.2.3"
	if got := String(); got != "vaultls-agent 1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "vaultls-agent 1.2.3")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd api-client && go test ./internal/version/...`
Expected: FAIL (package/symbol not defined).

- [ ] **Step 4: Implement version package**

`api-client/internal/version/version.go`:
```go
package version

// Version is overridden at build time via -ldflags "-X .../version.Version=...".
var Version = "dev"

// String returns a human-readable build identifier.
func String() string {
	return "vaultls-agent " + Version
}
```

- [ ] **Step 5: Implement minimal CLI skeleton**

`api-client/cmd/vaultls-agent/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/vasyakrg/vaultls-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vaultls-agent <run|setup|check|version>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version.String())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
```

- [ ] **Step 6: Run test + build to verify pass**

Run: `cd api-client && go test ./... && go build ./...`
Expected: PASS, build succeeds.

- [ ] **Step 7: Commit**

```bash
git add api-client/go.mod api-client/cmd api-client/internal/version
git commit -m "feat(agent): bootstrap go module + version command"
```

---

### Task 2: Config loading, validation, defaults

**Files:**
- Create: `api-client/internal/config/config.go`
- Create: `api-client/internal/config/load.go`
- Test: `api-client/internal/config/load_test.go`

**Interfaces:**
- Produces:
  - Types:
    ```go
    type Server struct {
        URL                string
        ClientID           string
        Secret             string
        InsecureSkipVerify bool
    }
    type Domain struct {
        Name    string   // VaulTLS cert name, e.g. "*.example.com"
        OutDir  string
        Formats []string // subset of {"pem","haproxy"}
        Owner   string
        Group   string
        Mode    string   // octal string e.g. "0640"
        Reload  string
        CertID  int64    // 0 = unset, search by name
    }
    type Config struct {
        Server      Server
        Schedule    string
        Jitter      time.Duration
        RenewBefore time.Duration
        Exporter    struct{ Listen string }
        Domains     []Domain
    }
    ```
  - `func Load(path string) (*Config, error)` — reads YAML, expands `${ENV}` in string fields, applies defaults, validates.
  - `func (d Domain) FileMode() (os.FileMode, error)` — parses octal `Mode` (default `0640`).

- [ ] **Step 1: Add yaml dependency**

```bash
cd api-client && go get gopkg.in/yaml.v3
```

- [ ] **Step 2: Write the failing test**

`api-client/internal/config/load_test.go`:
```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd api-client && go test ./internal/config/...`
Expected: FAIL (undefined `Load`).

- [ ] **Step 4: Implement types**

`api-client/internal/config/config.go`:
```go
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	URL                string `yaml:"url"`
	ClientID           string `yaml:"client_id"`
	Secret             string `yaml:"secret"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type Domain struct {
	Name    string   `yaml:"name"`
	OutDir  string   `yaml:"out_dir"`
	Formats []string `yaml:"formats"`
	Owner   string   `yaml:"owner"`
	Group   string   `yaml:"group"`
	Mode    string   `yaml:"mode"`
	Reload  string   `yaml:"reload"`
	CertID  int64    `yaml:"cert_id"`
}

type Config struct {
	Server      Server        `yaml:"server"`
	Schedule    string        `yaml:"schedule"`
	Jitter      time.Duration `yaml:"-"`
	JitterRaw   string        `yaml:"jitter"`
	RenewBefore time.Duration `yaml:"-"`
	RenewRaw    string        `yaml:"renew_before"`
	Exporter    struct {
		Listen string `yaml:"listen"`
	} `yaml:"exporter"`
	Domains []Domain `yaml:"domains"`
}

// FileMode parses the octal Mode string, defaulting to 0640.
func (d Domain) FileMode() (os.FileMode, error) {
	s := d.Mode
	if s == "" {
		s = "0640"
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid mode %q: %w", d.Mode, err)
	}
	return os.FileMode(v), nil
}
```

- [ ] **Step 5: Implement Load with defaults, env expansion, validation**

`api-client/internal/config/load.go`:
```go
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.Expand(string(raw), func(k string) string { return os.Getenv(k) })

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.Schedule == "" {
		cfg.Schedule = "0 3 1 * *"
	}
	if cfg.Exporter.Listen == "" {
		cfg.Exporter.Listen = "127.0.0.1:9105"
	}
	cfg.RenewBefore = 720 * time.Hour
	if cfg.RenewRaw != "" {
		d, err := time.ParseDuration(cfg.RenewRaw)
		if err != nil {
			return fmt.Errorf("invalid renew_before: %w", err)
		}
		cfg.RenewBefore = d
	}
	if cfg.JitterRaw != "" {
		d, err := time.ParseDuration(cfg.JitterRaw)
		if err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
		cfg.Jitter = d
	}
	for i := range cfg.Domains {
		d := &cfg.Domains[i]
		if len(d.Formats) == 0 {
			d.Formats = []string{"pem"}
		}
		if d.OutDir == "" {
			d.OutDir = "/etc/ssl/vaultls/" + strings.TrimPrefix(d.Name, "*.")
		}
	}
	return nil
}

func validate(cfg *Config) error {
	if cfg.Server.URL == "" {
		return fmt.Errorf("server.url is required")
	}
	if cfg.Server.ClientID == "" || cfg.Server.Secret == "" {
		return fmt.Errorf("server.client_id and server.secret are required")
	}
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for i, d := range cfg.Domains {
		if d.Name == "" && d.CertID == 0 {
			return fmt.Errorf("domain[%d]: name or cert_id required", i)
		}
		if d.Reload == "" {
			return fmt.Errorf("domain[%d] (%s): reload is required", i, d.Name)
		}
		for _, f := range d.Formats {
			if f != "pem" && f != "haproxy" {
				return fmt.Errorf("domain[%d] (%s): unknown format %q", i, d.Name, f)
			}
		}
		if _, err := d.FileMode(); err != nil {
			return fmt.Errorf("domain[%d] (%s): %w", i, d.Name, err)
		}
	}
	return nil
}
```

- [ ] **Step 6: Run tests to verify pass**

Run: `cd api-client && go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add api-client/internal/config api-client/go.mod api-client/go.sum
git commit -m "feat(agent): config loading with defaults, env expansion, validation"
```

---

### Task 3: PKI — p12 decode to PEM bundles + serial

**Files:**
- Create: `api-client/internal/pki/pki.go`
- Test: `api-client/internal/pki/pki_test.go`

**Interfaces:**
- Produces:
  - ```go
    type Bundle struct {
        Fullchain []byte // leaf + chain PEM
        PrivKey   []byte // private key PEM
        Cert      []byte // leaf only PEM
        Chain     []byte // intermediates/CA PEM
        Haproxy   []byte // fullchain + privkey PEM
        Serial    string // uppercase hex, no separators
    }
    ```
  - `func Decode(p12 []byte, password string) (*Bundle, error)` — decodes PKCS12 into all PEM forms and serial.

- [ ] **Step 1: Add pkcs12 dependency**

```bash
cd api-client && go get software.sslmate.com/src/go-pkcs12
```

- [ ] **Step 2: Write the failing test**

`api-client/internal/pki/pki_test.go` (generates a self-signed leaf + a CA, packs them into a p12 in-test so there is no binary fixture):
```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd api-client && go test ./internal/pki/...`
Expected: FAIL (undefined `Decode`).

- [ ] **Step 4: Implement Decode**

`api-client/internal/pki/pki.go`:
```go
package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type Bundle struct {
	Fullchain []byte
	PrivKey   []byte
	Cert      []byte
	Chain     []byte
	Haproxy   []byte
	Serial    string
}

func Decode(p12 []byte, password string) (*Bundle, error) {
	key, leaf, caCerts, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		return nil, fmt.Errorf("decode pkcs12: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	var chain bytes.Buffer
	for _, c := range caCerts {
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	var full bytes.Buffer
	full.Write(leafPEM)
	full.Write(chain.Bytes())

	var haproxy bytes.Buffer
	haproxy.Write(full.Bytes())
	haproxy.Write(keyPEM)

	return &Bundle{
		Fullchain: full.Bytes(),
		PrivKey:   keyPEM,
		Cert:      leafPEM,
		Chain:     chain.Bytes(),
		Haproxy:   haproxy.Bytes(),
		Serial:    strings.ToUpper(fmt.Sprintf("%X", leaf.SerialNumber)),
	}, nil
}
```

Note: `%X` on a `*big.Int` yields uppercase hex with no separators; `strings.ToUpper` is belt-and-suspenders for single-digit cases.

- [ ] **Step 5: Run tests to verify pass**

Run: `cd api-client && go test ./internal/pki/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api-client/internal/pki api-client/go.mod api-client/go.sum
git commit -m "feat(agent): pkcs12 decode to PEM bundles + serial extraction"
```

---

### Task 4: State store (serial + identity next to certs)

**Files:**
- Create: `api-client/internal/store/store.go`
- Test: `api-client/internal/store/store_test.go`

**Interfaces:**
- Produces:
  - ```go
    type State struct {
        CertID      int64  `json:"cert_id"`
        Serial      string `json:"serial"`
        ValidUntil  int64  `json:"valid_until"`  // unix ms, mirrors VaulTLS
        LastCheck   int64  `json:"last_check"`   // unix ms
        LastRenewal int64  `json:"last_renewal"` // unix ms
    }
    ```
  - `func Read(outDir string) (State, error)` — returns zero State if file absent (no error).
  - `func Write(outDir string, s State) error` — atomic write of `.vaultls-state.json`.

- [ ] **Step 1: Write the failing test**

`api-client/internal/store/store_test.go`:
```go
package store

import (
	"testing"
)

func TestReadMissingReturnsZero(t *testing.T) {
	s, err := Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read missing: %v", err)
	}
	if s.Serial != "" || s.CertID != 0 {
		t.Fatalf("expected zero state, got %+v", s)
	}
}

func TestWriteThenRead(t *testing.T) {
	dir := t.TempDir()
	want := State{CertID: 123, Serial: "0A1B2C", ValidUntil: 1790000000000, LastCheck: 1782000000000}
	if err := Write(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/store/...`
Expected: FAIL (undefined `Read`).

- [ ] **Step 3: Implement store**

`api-client/internal/store/store.go`:
```go
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const fileName = ".vaultls-state.json"

type State struct {
	CertID      int64  `json:"cert_id"`
	Serial      string `json:"serial"`
	ValidUntil  int64  `json:"valid_until"`
	LastCheck   int64  `json:"last_check"`
	LastRenewal int64  `json:"last_renewal"`
}

func Read(outDir string) (State, error) {
	var s State
	raw, err := os.ReadFile(filepath.Join(outDir, fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("parse state: %w", err)
	}
	return s, nil
}

func Write(outDir string, s State) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	final := filepath.Join(outDir, fileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write state tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd api-client && go test ./internal/store/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api-client/internal/store
git commit -m "feat(agent): per-domain state store with atomic writes"
```

---

### Task 5: VaulTLS API client

**Files:**
- Create: `api-client/internal/vaultls/client.go`
- Test: `api-client/internal/vaultls/client_test.go`

**Interfaces:**
- Produces:
  - ```go
    type Cert struct {
        ID         int64  `json:"id"`
        Name       string `json:"name"`
        CreatedOn  int64  `json:"created_on"`
        ValidUntil int64  `json:"valid_until"`
        RevokedAt  *int64 `json:"revoked_at"`
    }
    type Client struct { /* unexported */ }
    func New(baseURL, clientID, secret string, insecure bool) *Client
    func (c *Client) List(ctx context.Context) ([]Cert, error)
    func (c *Client) Password(ctx context.Context, id int64) (string, error)
    func (c *Client) Download(ctx context.Context, id int64) ([]byte, error)
    ```
  - Token is fetched lazily, cached until ~30s before `expires_in`, and one automatic re-auth happens on a 401.
  - `func SelectForName(certs []Cert, name string) (Cert, bool)` — picks the non-revoked cert with matching name and the greatest ValidUntil.

- [ ] **Step 1: Write the failing test (httptest VaulTLS)**

`api-client/internal/vaultls/client_test.go`:
```go
package vaultls

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["client_id"] != "svc_abc" || body["secret"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok123", "token_type": "Bearer",
			"expires_in": 3600, "scopes": []string{"cert:read"},
		})
	})
	mux.HandleFunc("/api/certificates", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode([]Cert{
			{ID: 1, Name: "*.example.com", ValidUntil: 100, RevokedAt: nil},
			{ID: 2, Name: "*.example.com", ValidUntil: 200, RevokedAt: nil},
		})
	})
	mux.HandleFunc("/api/certificates/2/password", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode("p12pass")
	})
	mux.HandleFunc("/api/certificates/2/download", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("RAWP12BYTES"))
	})
	return httptest.NewServer(mux)
}

func TestListPasswordDownload(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	c := New(srv.URL, "svc_abc", "pw", false)
	ctx := context.Background()

	certs, err := c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := SelectForName(certs, "*.example.com")
	if !ok || cert.ID != 2 {
		t.Fatalf("SelectForName picked %+v ok=%v (want id 2)", cert, ok)
	}
	pw, err := c.Password(ctx, 2)
	if err != nil || pw != "p12pass" {
		t.Fatalf("Password = %q, %v", pw, err)
	}
	raw, err := c.Download(ctx, 2)
	if err != nil || string(raw) != "RAWP12BYTES" {
		t.Fatalf("Download = %q, %v", raw, err)
	}
}

func TestSelectSkipsRevoked(t *testing.T) {
	rev := int64(5)
	certs := []Cert{
		{ID: 2, Name: "a", ValidUntil: 200, RevokedAt: &rev},
		{ID: 1, Name: "a", ValidUntil: 100, RevokedAt: nil},
	}
	got, ok := SelectForName(certs, "a")
	if !ok || got.ID != 1 {
		t.Fatalf("expected non-revoked id 1, got %+v ok=%v", got, ok)
	}
}

func TestBadCredentials(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	c := New(srv.URL, "svc_abc", "wrong", false)
	if _, err := c.List(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "auth") {
		t.Fatalf("expected auth error, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/vaultls/...`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement the client**

`api-client/internal/vaultls/client.go`:
```go
package vaultls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Cert struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedOn  int64  `json:"created_on"`
	ValidUntil int64  `json:"valid_until"`
	RevokedAt  *int64 `json:"revoked_at"`
}

type Client struct {
	base     string
	clientID string
	secret   string
	http     *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func New(baseURL, clientID, secret string, insecure bool) *Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		base:     strings.TrimRight(baseURL, "/"),
		clientID: clientID,
		secret:   secret,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

func (c *Client) authToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]string{"client_id": c.clientID, "secret": c.secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("auth decode: %w", err)
	}
	c.token = tr.AccessToken
	c.expires = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - 30*time.Second)
	return c.token, nil
}

// do performs an authenticated GET, retrying once with a fresh token on 401.
func (c *Client) do(ctx context.Context, path string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.authToken(ctx, attempt == 1)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request %s: %w", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("GET %s: unauthorized after re-auth", path)
}

func (c *Client) List(ctx context.Context) ([]Cert, error) {
	raw, err := c.do(ctx, "/api/certificates")
	if err != nil {
		return nil, err
	}
	var certs []Cert
	if err := json.Unmarshal(raw, &certs); err != nil {
		return nil, fmt.Errorf("decode certificates: %w", err)
	}
	return certs, nil
}

func (c *Client) Password(ctx context.Context, id int64) (string, error) {
	raw, err := c.do(ctx, fmt.Sprintf("/api/certificates/%d/password", id))
	if err != nil {
		return "", err
	}
	var pw string
	if err := json.Unmarshal(raw, &pw); err != nil {
		return "", fmt.Errorf("decode password: %w", err)
	}
	return pw, nil
}

func (c *Client) Download(ctx context.Context, id int64) ([]byte, error) {
	return c.do(ctx, fmt.Sprintf("/api/certificates/%d/download", id))
}

// SelectForName returns the non-revoked cert with the given name and the
// greatest ValidUntil.
func SelectForName(certs []Cert, name string) (Cert, bool) {
	var best Cert
	found := false
	for _, c := range certs {
		if c.Name != name || c.RevokedAt != nil {
			continue
		}
		if !found || c.ValidUntil > best.ValidUntil {
			best = c
			found = true
		}
	}
	return best, found
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd api-client && go test ./internal/vaultls/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api-client/internal/vaultls
git commit -m "feat(agent): VaulTLS API client with token cache + cert selection"
```

---

### Task 6: Reloader

**Files:**
- Create: `api-client/internal/reloader/reloader.go`
- Test: `api-client/internal/reloader/reloader_test.go`

**Interfaces:**
- Produces: `func Run(ctx context.Context, command string) error` — runs `command` via `sh -c`, returns error including combined output on non-zero exit.

- [ ] **Step 1: Write the failing test**

`api-client/internal/reloader/reloader_test.go`:
```go
package reloader

import (
	"context"
	"strings"
	"testing"
)

func TestRunSuccess(t *testing.T) {
	if err := Run(context.Background(), "true"); err != nil {
		t.Fatalf("Run(true) = %v", err)
	}
}

func TestRunFailureIncludesOutput(t *testing.T) {
	err := Run(context.Background(), "echo boom >&2; false")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error containing output, got %v", err)
	}
}

func TestRunEmptyIsNoop(t *testing.T) {
	if err := Run(context.Background(), ""); err != nil {
		t.Fatalf("empty command should be no-op, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/reloader/...`
Expected: FAIL (undefined `Run`).

- [ ] **Step 3: Implement reloader**

`api-client/internal/reloader/reloader.go`:
```go
package reloader

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Run executes command through sh -c. Empty command is a no-op.
func Run(ctx context.Context, command string) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload %q failed: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd api-client && go test ./internal/reloader/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api-client/internal/reloader
git commit -m "feat(agent): reloader executing shell reload commands"
```

---

### Task 7: Metrics registry

**Files:**
- Create: `api-client/internal/metrics/metrics.go`
- Test: `api-client/internal/metrics/metrics_test.go`

**Interfaces:**
- Produces:
  - ```go
    type Metrics struct { /* holds prometheus collectors + registry */ }
    func New() *Metrics
    func (m *Metrics) Handler() http.Handler
    func (m *Metrics) SetUp()
    func (m *Metrics) SetBuildInfo(version string)
    func (m *Metrics) SetUpdateAvailable(available bool, latest string)
    func (m *Metrics) SetCertExpiry(domain string, unixSeconds float64)
    func (m *Metrics) SetCertSerial(domain, serial string)
    func (m *Metrics) MarkCheck(domain string, unixSeconds float64)
    func (m *Metrics) MarkRenewal(domain string, unixSeconds float64)
    func (m *Metrics) IncReconcileError(domain, stage string)
    func (m *Metrics) IncReloadFailure(domain string)
    func (m *Metrics) IncTokenError()
    ```

- [ ] **Step 1: Add prometheus dependency**

```bash
cd api-client && go get github.com/prometheus/client_golang/prometheus github.com/prometheus/client_golang/prometheus/promhttp
```

- [ ] **Step 2: Write the failing test**

`api-client/internal/metrics/metrics_test.go`:
```go
package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(m *Metrics) string {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestExposesCoreMetrics(t *testing.T) {
	m := New()
	m.SetUp()
	m.SetBuildInfo("1.2.3")
	m.SetUpdateAvailable(true, "1.3.0")
	m.SetCertExpiry("example.com", 1790000000)
	m.SetCertSerial("example.com", "0A1B2C")
	m.IncReconcileError("example.com", "download")
	m.IncReloadFailure("example.com")
	m.IncTokenError()

	body := scrape(m)
	for _, want := range []string{
		"vaultls_agent_up 1",
		`vaultls_agent_build_info{version="1.2.3"} 1`,
		"vaultls_agent_update_available 1",
		`vaultls_agent_latest_version_info{version="1.3.0"} 1`,
		`vaultls_cert_expiry_timestamp_seconds{domain="example.com"} 1.79e+09`,
		`vaultls_cert_serial_info{domain="example.com",serial="0A1B2C"} 1`,
		`vaultls_reconcile_errors_total{domain="example.com",stage="download"} 1`,
		`vaultls_reload_failures_total{domain="example.com"} 1`,
		"vaultls_scrape_token_errors_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd api-client && go test ./internal/metrics/...`
Expected: FAIL (undefined `New`).

- [ ] **Step 4: Implement metrics**

`api-client/internal/metrics/metrics.go`:
```go
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg *prometheus.Registry

	up               prometheus.Gauge
	buildInfo        *prometheus.GaugeVec
	updateAvailable  prometheus.Gauge
	latestVersion    *prometheus.GaugeVec
	certExpiry       *prometheus.GaugeVec
	certSerial       *prometheus.GaugeVec
	lastCheck        *prometheus.GaugeVec
	lastRenewal      *prometheus.GaugeVec
	reconcileErrors  *prometheus.CounterVec
	reloadFailures   *prometheus.CounterVec
	tokenErrors      prometheus.Counter

	mu             sync.Mutex
	buildVersion   string
	latestVersions map[string]struct{}
	serials        map[string]string
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg:            reg,
		latestVersions: map[string]struct{}{},
		serials:        map[string]string{},
		up:             prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_up", Help: "1 if the agent is running."}),
		buildInfo:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_build_info", Help: "Build info."}, []string{"version"}),
		updateAvailable: prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_update_available", Help: "1 if a newer release exists."}),
		latestVersion:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_latest_version_info", Help: "Latest known release."}, []string{"version"}),
		certExpiry:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_expiry_timestamp_seconds", Help: "Cert NotAfter."}, []string{"domain"}),
		certSerial:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_serial_info", Help: "Current serial."}, []string{"domain", "serial"}),
		lastCheck:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_check_timestamp_seconds", Help: "Last reconcile check."}, []string{"domain"}),
		lastRenewal:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_renewal_timestamp_seconds", Help: "Last actual renewal."}, []string{"domain"}),
		reconcileErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reconcile_errors_total", Help: "Reconcile errors by stage."}, []string{"domain", "stage"}),
		reloadFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reload_failures_total", Help: "Reload failures."}, []string{"domain"}),
		tokenErrors:    prometheus.NewCounter(prometheus.CounterOpts{Name: "vaultls_scrape_token_errors_total", Help: "Token/auth errors."}),
	}
	reg.MustRegister(m.up, m.buildInfo, m.updateAvailable, m.latestVersion,
		m.certExpiry, m.certSerial, m.lastCheck, m.lastRenewal,
		m.reconcileErrors, m.reloadFailures, m.tokenErrors)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

func (m *Metrics) SetUp() { m.up.Set(1) }

func (m *Metrics) SetBuildInfo(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *Metrics) SetUpdateAvailable(available bool, latest string) {
	if available {
		m.updateAvailable.Set(1)
	} else {
		m.updateAvailable.Set(0)
	}
	if latest != "" {
		m.latestVersion.Reset()
		m.latestVersion.WithLabelValues(latest).Set(1)
	}
}

func (m *Metrics) SetCertExpiry(domain string, unixSeconds float64) {
	m.certExpiry.WithLabelValues(domain).Set(unixSeconds)
}

// SetCertSerial replaces any prior serial series for the domain so only the
// current serial is exposed.
func (m *Metrics) SetCertSerial(domain, serial string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.serials[domain]; ok && old != serial {
		m.certSerial.DeleteLabelValues(domain, old)
	}
	m.serials[domain] = serial
	m.certSerial.WithLabelValues(domain, serial).Set(1)
}

func (m *Metrics) MarkCheck(domain string, unixSeconds float64) {
	m.lastCheck.WithLabelValues(domain).Set(unixSeconds)
}

func (m *Metrics) MarkRenewal(domain string, unixSeconds float64) {
	m.lastRenewal.WithLabelValues(domain).Set(unixSeconds)
}

func (m *Metrics) IncReconcileError(domain, stage string) {
	m.reconcileErrors.WithLabelValues(domain, stage).Inc()
}

func (m *Metrics) IncReloadFailure(domain string) {
	m.reloadFailures.WithLabelValues(domain).Inc()
}

func (m *Metrics) IncTokenError() { m.tokenErrors.Inc() }
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd api-client && go test ./internal/metrics/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api-client/internal/metrics api-client/go.mod api-client/go.sum
git commit -m "feat(agent): prometheus metrics registry"
```

---

### Task 8: Reconcile core (per-domain orchestration)

**Files:**
- Create: `api-client/internal/reconcile/reconcile.go`
- Create: `api-client/internal/reconcile/write.go`
- Test: `api-client/internal/reconcile/reconcile_test.go`

**Interfaces:**
- Consumes: `config.Domain`, `vaultls.Cert`, `vaultls.SelectForName`, `pki.Decode`/`pki.Bundle`, `store.State`/`store.Read`/`store.Write`, `reloader.Run`, `metrics.Metrics`.
- Produces:
  - ```go
    type API interface {
        List(ctx context.Context) ([]vaultls.Cert, error)
        Password(ctx context.Context, id int64) (string, error)
        Download(ctx context.Context, id int64) ([]byte, error)
    }
    type Clock func() time.Time
    type Reconciler struct { /* api, metrics, clock, renewBefore */ }
    func New(api API, m *metrics.Metrics, renewBefore time.Duration, clock Clock) *Reconciler
    func (r *Reconciler) Domain(ctx context.Context, d config.Domain) error
    ```
  - `Domain` performs: list → select (by CertID or Name) → cheap-skip check → download+password → decode → serial compare → atomic write of selected formats → state update → reload-on-change. Errors increment metrics by stage and are returned (caller logs, continues with other domains).

- [ ] **Step 1: Write the failing test (fake API + temp dir)**

`api-client/internal/reconcile/reconcile_test.go`:
```go
package reconcile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
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
	r := New(api, m, 720*time.Hour, time.Now)
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
	r := New(api, m, 720*time.Hour, time.Now)
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
	r := New(api, m, 720*time.Hour, time.Now)
	if err := r.Domain(context.Background(), newDomain(dir)); err == nil {
		t.Fatal("expected error when domain cert not found")
	}
}
```

Note: serial `0x0a1b2c` formats as `A1B2C` via `%X` (leading zero dropped) — the test asserts that exact value.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/reconcile/...`
Expected: FAIL (undefined `New`).

- [ ] **Step 3: Implement the writer helper**

`api-client/internal/reconcile/write.go`:
```go
package reconcile

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
)

// writeFile atomically writes data to dir/name with the given mode, then
// best-effort applies owner/group from the domain.
func writeFile(dir, name string, data []byte, mode os.FileMode, d config.Domain) error {
	final := filepath.Join(dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if uid, gid, ok := lookupOwner(d); ok {
		_ = os.Chown(tmp, uid, gid)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename %s: %w", name, err)
	}
	return nil
}

func lookupOwner(d config.Domain) (int, int, bool) {
	if d.Owner == "" && d.Group == "" {
		return 0, 0, false
	}
	uid, gid := -1, -1
	if d.Owner != "" {
		if u, err := user.Lookup(d.Owner); err == nil {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}
	if d.Group != "" {
		if g, err := user.LookupGroup(d.Group); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if uid < 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// writeBundle writes the requested formats. privkey is always 0600.
func writeBundle(dir string, b *pki.Bundle, d config.Domain) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir out_dir: %w", err)
	}
	mode, err := d.FileMode()
	if err != nil {
		return err
	}
	for _, f := range d.Formats {
		switch f {
		case "pem":
			if err := writeFile(dir, "fullchain.pem", b.Fullchain, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "cert.pem", b.Cert, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "chain.pem", b.Chain, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "privkey.pem", b.PrivKey, 0o600, d); err != nil {
				return err
			}
		case "haproxy":
			if err := writeFile(dir, "haproxy.pem", b.Haproxy, 0o600, d); err != nil {
				return err
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Implement the reconciler**

`api-client/internal/reconcile/reconcile.go`:
```go
package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/reloader"
	"github.com/vasyakrg/vaultls-agent/internal/store"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

type API interface {
	List(ctx context.Context) ([]vaultls.Cert, error)
	Password(ctx context.Context, id int64) (string, error)
	Download(ctx context.Context, id int64) ([]byte, error)
}

type Clock func() time.Time

type Reconciler struct {
	api         API
	m           *metrics.Metrics
	renewBefore time.Duration
	now         Clock
}

func New(api API, m *metrics.Metrics, renewBefore time.Duration, now Clock) *Reconciler {
	return &Reconciler{api: api, m: m, renewBefore: renewBefore, now: now}
}

func (r *Reconciler) Domain(ctx context.Context, d config.Domain) error {
	label := d.Name
	now := r.now()
	r.m.MarkCheck(label, float64(now.Unix()))

	certs, err := r.api.List(ctx)
	if err != nil {
		r.m.IncReconcileError(label, "list")
		r.m.IncTokenError()
		return fmt.Errorf("list certs: %w", err)
	}

	cert, ok := selectCert(certs, d)
	if !ok {
		r.m.IncReconcileError(label, "select")
		return fmt.Errorf("no certificate found for domain %q (cert_id=%d)", d.Name, d.CertID)
	}

	r.m.SetCertExpiry(label, float64(cert.ValidUntil)/1000.0)

	prev, err := store.Read(d.OutDir)
	if err != nil {
		r.m.IncReconcileError(label, "state")
		return fmt.Errorf("read state: %w", err)
	}

	// Cheap skip: same identity and not within renew window.
	remaining := time.Until(time.UnixMilli(cert.ValidUntil))
	if prev.CertID == cert.ID && prev.ValidUntil == cert.ValidUntil &&
		prev.Serial != "" && remaining > r.renewBefore {
		prev.LastCheck = now.UnixMilli()
		_ = store.Write(d.OutDir, prev)
		r.m.SetCertSerial(label, prev.Serial)
		return nil
	}

	password, err := r.api.Password(ctx, cert.ID)
	if err != nil {
		r.m.IncReconcileError(label, "password")
		return fmt.Errorf("get password: %w", err)
	}
	p12, err := r.api.Download(ctx, cert.ID)
	if err != nil {
		r.m.IncReconcileError(label, "download")
		return fmt.Errorf("download: %w", err)
	}
	bundle, err := pki.Decode(p12, password)
	if err != nil {
		r.m.IncReconcileError(label, "decode")
		return fmt.Errorf("decode p12: %w", err)
	}

	changed := bundle.Serial != prev.Serial
	if changed {
		if err := writeBundle(d.OutDir, bundle, d); err != nil {
			r.m.IncReconcileError(label, "write")
			return fmt.Errorf("write bundle: %w", err)
		}
	}

	next := store.State{
		CertID: cert.ID, Serial: bundle.Serial, ValidUntil: cert.ValidUntil,
		LastCheck: now.UnixMilli(), LastRenewal: prev.LastRenewal,
	}
	if changed {
		next.LastRenewal = now.UnixMilli()
	}
	if err := store.Write(d.OutDir, next); err != nil {
		r.m.IncReconcileError(label, "state")
		return fmt.Errorf("write state: %w", err)
	}
	r.m.SetCertSerial(label, bundle.Serial)

	if changed {
		r.m.MarkRenewal(label, float64(now.Unix()))
		if err := reloader.Run(ctx, d.Reload); err != nil {
			r.m.IncReloadFailure(label)
			return fmt.Errorf("reload: %w", err)
		}
	}
	return nil
}

func selectCert(certs []vaultls.Cert, d config.Domain) (vaultls.Cert, bool) {
	if d.CertID != 0 {
		for _, c := range certs {
			if c.ID == d.CertID && c.RevokedAt == nil {
				return c, true
			}
		}
		return vaultls.Cert{}, false
	}
	return vaultls.SelectForName(certs, d.Name)
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd api-client && go test ./internal/reconcile/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api-client/internal/reconcile
git commit -m "feat(agent): reconcile core with cheap-skip, serial compare, reload-on-change"
```

---

### Task 9: Scheduler (cron-spec + jitter)

**Files:**
- Create: `api-client/internal/scheduler/scheduler.go`
- Test: `api-client/internal/scheduler/scheduler_test.go`

**Interfaces:**
- Produces:
  - `func ParseSpec(spec string) (cron.Schedule, error)` — wraps `cron.ParseStandard`.
  - `func NextWithJitter(s cron.Schedule, from time.Time, jitter time.Duration, rnd func() float64) time.Time` — next fire time plus `rnd()*jitter`.
  - `func Run(ctx context.Context, spec string, jitter time.Duration, job func(context.Context)) error` — blocks, runs `job` at each scheduled time until ctx is cancelled.

- [ ] **Step 1: Add cron dependency**

```bash
cd api-client && go get github.com/robfig/cron/v3
```

- [ ] **Step 2: Write the failing test**

`api-client/internal/scheduler/scheduler_test.go`:
```go
package scheduler

import (
	"testing"
	"time"
)

func TestParseSpecValid(t *testing.T) {
	if _, err := ParseSpec("0 3 1 * *"); err != nil {
		t.Fatalf("ParseSpec valid: %v", err)
	}
}

func TestParseSpecInvalid(t *testing.T) {
	if _, err := ParseSpec("not a cron"); err == nil {
		t.Fatal("expected error for invalid spec")
	}
}

func TestNextWithJitterAddsOffset(t *testing.T) {
	s, _ := ParseSpec("0 3 1 * *")
	from := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	base := s.Next(from)
	got := NextWithJitter(s, from, time.Hour, func() float64 { return 0.5 })
	want := base.Add(30 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("NextWithJitter = %v, want %v", got, want)
	}
}

func TestNextWithJitterZero(t *testing.T) {
	s, _ := ParseSpec("0 3 1 * *")
	from := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	got := NextWithJitter(s, from, 0, func() float64 { return 0.9 })
	if !got.Equal(s.Next(from)) {
		t.Fatal("zero jitter must equal base next")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd api-client && go test ./internal/scheduler/...`
Expected: FAIL (undefined `ParseSpec`).

- [ ] **Step 4: Implement scheduler**

`api-client/internal/scheduler/scheduler.go`:
```go
package scheduler

import (
	"context"
	"math/rand"
	"time"

	"github.com/robfig/cron/v3"
)

func ParseSpec(spec string) (cron.Schedule, error) {
	return cron.ParseStandard(spec)
}

// NextWithJitter returns the next scheduled time plus rnd()*jitter.
func NextWithJitter(s cron.Schedule, from time.Time, jitter time.Duration, rnd func() float64) time.Time {
	next := s.Next(from)
	if jitter <= 0 {
		return next
	}
	return next.Add(time.Duration(rnd() * float64(jitter)))
}

// Run blocks, invoking job at each scheduled time until ctx is cancelled.
func Run(ctx context.Context, spec string, jitter time.Duration, job func(context.Context)) error {
	s, err := ParseSpec(spec)
	if err != nil {
		return err
	}
	for {
		next := NextWithJitter(s, time.Now(), jitter, rand.Float64)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			job(ctx)
		}
	}
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd api-client && go test ./internal/scheduler/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api-client/internal/scheduler api-client/go.mod api-client/go.sum
git commit -m "feat(agent): cron-spec scheduler with jitter"
```

---

### Task 10: Self-update version check (GitHub Releases)

**Files:**
- Create: `api-client/internal/selfupdate/selfupdate.go`
- Test: `api-client/internal/selfupdate/selfupdate_test.go`

**Interfaces:**
- Produces:
  - `func Check(ctx context.Context, apiBase, repo, current string) (latest string, outdated bool, err error)` — GETs `apiBase + "/repos/" + repo + "/releases/latest"`, compares tag (stripping leading `v`) to `current` using semantic-ish comparison; `apiBase` defaults handled by caller.
  - `func compareVersions(a, b string) int` — returns -1/0/1 comparing dotted numeric versions.

- [ ] **Step 1: Write the failing test**

`api-client/internal/selfupdate/selfupdate_test.go`:
```go
package selfupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckOutdated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/vasyakrg/VaulTLS/releases/latest" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "v1.5.0"})
	}))
	defer srv.Close()

	latest, outdated, err := Check(context.Background(), srv.URL, "vasyakrg/VaulTLS", "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if latest != "1.5.0" || !outdated {
		t.Fatalf("latest=%q outdated=%v", latest, outdated)
	}
}

func TestCheckUpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "v1.2.0"})
	}))
	defer srv.Close()
	_, outdated, err := Check(context.Background(), srv.URL, "vasyakrg/VaulTLS", "1.2.0")
	if err != nil || outdated {
		t.Fatalf("outdated=%v err=%v", outdated, err)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.2.0", 0},
		{"1.2.0", "1.3.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/selfupdate/...`
Expected: FAIL (undefined `Check`).

- [ ] **Step 3: Implement selfupdate**

`api-client/internal/selfupdate/selfupdate.go`:
```go
package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Check queries GitHub Releases latest and compares with current.
func Check(ctx context.Context, apiBase, repo, current string) (string, bool, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(apiBase, "/"), repo)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("github request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("github status %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", false, fmt.Errorf("decode release: %w", err)
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	cur := strings.TrimPrefix(current, "v")
	if cur == "dev" || cur == "" {
		return latest, false, nil
	}
	return latest, compareVersions(cur, latest) < 0, nil
}

func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd api-client && go test ./internal/selfupdate/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api-client/internal/selfupdate
git commit -m "feat(agent): github releases version check"
```

---

### Task 11: Setup wizard + config writer

**Files:**
- Create: `api-client/internal/wizard/wizard.go`
- Test: `api-client/internal/wizard/wizard_test.go`

**Interfaces:**
- Produces:
  - ```go
    type Answers struct {
        URL, ClientID, Secret string
        Domain, Reload        string
    }
    func Render(a Answers) ([]byte, error) // produces config.yaml bytes
    func RunInteractive(in io.Reader, out io.Writer, preset Answers) (Answers, error)
    ```
  - `Render` output must be parseable by `config.Load`.

- [ ] **Step 1: Write the failing test**

`api-client/internal/wizard/wizard_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/wizard/...`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement wizard**

`api-client/internal/wizard/wizard.go`:
```go
package wizard

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"text/template"
)

type Answers struct {
	URL      string
	ClientID string
	Secret   string
	Domain   string
	Reload   string
}

const tmpl = `server:
  url: {{ .URL }}
  client_id: {{ .ClientID }}
  secret: {{ .Secret }}
schedule: "0 3 1 * *"
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "{{ .Domain }}"
    formats: [pem]
    reload: "{{ .Reload }}"
`

func Render(a Answers) ([]byte, error) {
	t, err := template.New("config").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := t.Execute(&b, a); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// RunInteractive prompts only for fields empty in preset.
func RunInteractive(in io.Reader, out io.Writer, preset Answers) (Answers, error) {
	r := bufio.NewReader(in)
	ask := func(label string, cur *string) error {
		if *cur != "" {
			return nil
		}
		fmt.Fprintf(out, "%s: ", label)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read %s: %w", label, err)
		}
		*cur = strings.TrimSpace(line)
		return nil
	}
	for _, f := range []struct {
		label string
		ptr   *string
	}{
		{"VaulTLS URL", &preset.URL},
		{"Client ID", &preset.ClientID},
		{"Secret", &preset.Secret},
		{"Domain (cert name, e.g. *.example.com)", &preset.Domain},
		{"Reload command", &preset.Reload},
	} {
		if err := ask(f.label, f.ptr); err != nil {
			return preset, err
		}
	}
	return preset, nil
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd api-client && go test ./internal/wizard/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api-client/internal/wizard
git commit -m "feat(agent): setup wizard + config renderer"
```

---

### Task 12: CLI wiring — run/setup/check commands (daemon)

**Files:**
- Modify: `api-client/cmd/vaultls-agent/main.go`
- Create: `api-client/cmd/vaultls-agent/run.go`
- Create: `api-client/cmd/vaultls-agent/setup.go`
- Create: `api-client/internal/app/app.go`
- Test: `api-client/internal/app/app_test.go`

**Interfaces:**
- Consumes: all prior packages.
- Produces:
  - `func ReconcileAll(ctx context.Context, cfg *config.Config, r *reconcile.Reconciler, log *slog.Logger)` — iterates domains, isolating per-domain errors (logs, continues).
  - `func Run(ctx context.Context, configPath, githubAPIBase string) error` — loads config, builds metrics/client/reconciler, starts exporter HTTP server + initial reconcile + scheduler loop + daily self-update check.

- [ ] **Step 1: Write the failing test (per-domain isolation)**

`api-client/internal/app/app_test.go`:
```go
package app

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/reconcile"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

type failAPI struct{}

func (failAPI) List(context.Context) ([]vaultls.Cert, error) { return nil, context.Canceled }
func (failAPI) Password(context.Context, int64) (string, error) { return "", nil }
func (failAPI) Download(context.Context, int64) ([]byte, error) { return nil, nil }

func TestReconcileAllIsolatesFailures(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{
		{Name: "a", OutDir: t.TempDir(), Formats: []string{"pem"}, Mode: "0640", Reload: "true"},
		{Name: "b", OutDir: t.TempDir(), Formats: []string{"pem"}, Mode: "0640", Reload: "true"},
	}}
	r := reconcile.New(failAPI{}, metrics.New(), 0, contextClock)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	// Must not panic and must attempt both domains despite errors.
	ReconcileAll(context.Background(), cfg, r, log)
	if got := bytes.Count(buf.Bytes(), []byte("reconcile failed")); got != 2 {
		t.Fatalf("expected 2 logged failures, got %d", got)
	}
}
```

Add helper in the test file:
```go
import "time"
func contextClock() time.Time { return time.Unix(0, 0) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-client && go test ./internal/app/...`
Expected: FAIL (undefined `ReconcileAll`).

- [ ] **Step 3: Implement app package**

`api-client/internal/app/app.go`:
```go
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/reconcile"
	"github.com/vasyakrg/vaultls-agent/internal/scheduler"
	"github.com/vasyakrg/vaultls-agent/internal/selfupdate"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
	"github.com/vasyakrg/vaultls-agent/internal/version"
)

func ReconcileAll(ctx context.Context, cfg *config.Config, r *reconcile.Reconciler, log *slog.Logger) {
	for _, d := range cfg.Domains {
		if err := r.Domain(ctx, d); err != nil {
			log.Error("reconcile failed", "domain", d.Name, "err", err)
		} else {
			log.Info("reconcile ok", "domain", d.Name)
		}
	}
}

func Run(ctx context.Context, configPath, githubAPIBase string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := slog.Default()
	m := metrics.New()
	m.SetUp()
	m.SetBuildInfo(version.Version)

	api := vaultls.New(cfg.Server.URL, cfg.Server.ClientID, cfg.Server.Secret, cfg.Server.InsecureSkipVerify)
	r := reconcile.New(api, m, cfg.RenewBefore, time.Now)

	// Exporter.
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	srv := &http.Server{Addr: cfg.Exporter.Listen, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("exporter server", "err", err)
		}
	}()
	defer srv.Shutdown(context.Background())

	// Self-update check now and daily.
	checkUpdate(ctx, m, githubAPIBase, log)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				checkUpdate(ctx, m, githubAPIBase, log)
			}
		}
	}()

	// Initial reconcile, then scheduled loop.
	ReconcileAll(ctx, cfg, r, log)
	return scheduler.Run(ctx, cfg.Schedule, cfg.Jitter, func(c context.Context) {
		ReconcileAll(c, cfg, r, log)
	})
}

func checkUpdate(ctx context.Context, m *metrics.Metrics, apiBase string, log *slog.Logger) {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	latest, outdated, err := selfupdate.Check(ctx, apiBase, "vasyakrg/VaulTLS", version.Version)
	if err != nil {
		log.Warn("version check failed", "err", err)
		return
	}
	m.SetUpdateAvailable(outdated, latest)
	if outdated {
		log.Warn("a newer vaultls-agent release is available", "current", version.Version, "latest", latest)
	}
}
```

- [ ] **Step 4: Wire the CLI commands**

`api-client/cmd/vaultls-agent/run.go`:
```go
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/vasyakrg/vaultls-agent/internal/app"
)

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/vaultls/config.yaml", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, *configPath, ""); err != nil && err != context.Canceled {
		os.Stderr.WriteString(err.Error() + "\n")
		return 1
	}
	return 0
}
```

`api-client/cmd/vaultls-agent/setup.go`:
```go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/vasyakrg/vaultls-agent/internal/wizard"
)

func cmdSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	url := fs.String("url", "", "VaulTLS server URL")
	clientID := fs.String("client-id", "", "service account client id")
	secret := fs.String("secret", "", "service account secret")
	domain := fs.String("domain", "", "certificate name, e.g. *.example.com")
	reload := fs.String("reload", "", "reload command")
	out := fs.String("out", "/etc/vaultls/config.yaml", "config output path")
	enable := fs.Bool("enable", true, "enable+start the systemd service after writing config")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	preset := wizard.Answers{URL: *url, ClientID: *clientID, Secret: *secret, Domain: *domain, Reload: *reload}
	ans := preset
	if preset.URL == "" || preset.ClientID == "" || preset.Secret == "" || preset.Domain == "" || preset.Reload == "" {
		var err error
		ans, err = wizard.RunInteractive(os.Stdin, os.Stdout, preset)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	body, err := wizard.Render(ans)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll("/etc/vaultls", 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote %s\n", *out)
	if *enable {
		_ = exec.Command("systemctl", "enable", "--now", "vaultls-agent").Run()
	}
	return 0
}
```

`api-client/cmd/vaultls-agent/main.go` (replace the switch):
```go
package main

import (
	"fmt"
	"os"

	"github.com/vasyakrg/vaultls-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vaultls-agent <run|setup|check|version>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "setup":
		os.Exit(cmdSetup(os.Args[2:]))
	case "check":
		os.Exit(cmdRun(append([]string{"--config", configFromArgs(os.Args[2:])}, "--once"))) // see note
	case "version":
		fmt.Println(version.String())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
```

Implementation note for `check`: instead of the placeholder above, add a `--once` bool to `cmdRun`'s flagset; when set, after building everything run `ReconcileAll` a single time and return (skip starting the scheduler/exporter). Concretely, change `run.go` to accept `--once` and branch:
```go
once := fs.Bool("once", false, "run one reconcile pass and exit")
...
if *once {
    return app.RunOnce(ctx, *configPath)
}
```
and add to `app.go`:
```go
func RunOnce(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	m := metrics.New()
	api := vaultls.New(cfg.Server.URL, cfg.Server.ClientID, cfg.Server.Secret, cfg.Server.InsecureSkipVerify)
	r := reconcile.New(api, m, cfg.RenewBefore, time.Now)
	ReconcileAll(ctx, cfg, r, slog.Default())
	return nil
}
```
Then `check` simply calls `cmdRun([]string{"--once"})` and the default config path applies. Remove the `configFromArgs` placeholder — it is not needed.

- [ ] **Step 5: Run tests + build to verify pass**

Run: `cd api-client && go test ./... && go build ./...`
Expected: PASS, build succeeds.

- [ ] **Step 6: Commit**

```bash
git add api-client/cmd api-client/internal/app
git commit -m "feat(agent): CLI wiring (run/setup/check) + daemon orchestration"
```

---

### Task 13: Packaging — systemd unit, nfpm, example config, CI

**Files:**
- Create: `api-client/packaging/systemd/vaultls-agent.service`
- Create: `api-client/packaging/config.example.yaml`
- Create: `api-client/packaging/nfpm.yaml`
- Create: `api-client/packaging/scripts/postinstall.sh`
- Create: `api-client/Makefile`
- Create: `.github/workflows/agent-release.yml`

**Interfaces:**
- Produces a buildable `.deb` via `nfpm pkg`. No Go code; verification is a successful package build and lint.

- [ ] **Step 1: Write the systemd unit**

`api-client/packaging/systemd/vaultls-agent.service`:
```ini
[Unit]
Description=VaulTLS certificate agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vaultls-agent run --config /etc/vaultls/config.yaml
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/etc/ssl/vaultls /etc/vaultls
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write the example config**

`api-client/packaging/config.example.yaml`:
```yaml
server:
  url: https://vaultls.example.com
  client_id: svc_xxxxxxxx
  secret: ${VAULTLS_SECRET}
  insecure_skip_verify: false
schedule: "0 3 1 * *"
jitter: 30m
renew_before: 720h
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "*.example.com"
    out_dir: /etc/ssl/vaultls/example.com
    formats: [pem, haproxy]
    owner: root
    group: ssl-cert
    mode: "0640"
    reload: "systemctl reload nginx"
```

- [ ] **Step 3: Write the postinstall script**

`api-client/packaging/scripts/postinstall.sh`:
```sh
#!/bin/sh
set -e
systemctl daemon-reload || true
mkdir -p /etc/ssl/vaultls
if [ ! -f /etc/vaultls/config.yaml ]; then
  echo "vaultls-agent installed. Configure it with:"
  echo "  sudo vaultls-agent setup"
  echo "or copy /etc/vaultls/config.example.yaml to /etc/vaultls/config.yaml"
else
  systemctl try-restart vaultls-agent || true
fi
```

- [ ] **Step 4: Write the nfpm config**

`api-client/packaging/nfpm.yaml`:
```yaml
name: vaultls-agent
arch: amd64
platform: linux
version: ${VERSION}
section: utils
priority: optional
maintainer: vasyakrg <vasyakrg@users.noreply.github.com>
description: VaulTLS certificate agent (pulls certs, writes PEM, reloads services)
homepage: https://github.com/vasyakrg/VaulTLS
license: MIT
contents:
  - src: ./dist/vaultls-agent
    dst: /usr/bin/vaultls-agent
    file_info:
      mode: 0755
  - src: ./packaging/systemd/vaultls-agent.service
    dst: /lib/systemd/system/vaultls-agent.service
  - src: ./packaging/config.example.yaml
    dst: /etc/vaultls/config.example.yaml
    type: config|noreplace
scripts:
  postinstall: ./packaging/scripts/postinstall.sh
```

- [ ] **Step 5: Write the Makefile**

`api-client/Makefile`:
```makefile
VERSION ?= dev
LDFLAGS := -s -w -X github.com/vasyakrg/vaultls-agent/internal/version.Version=$(VERSION)

.PHONY: test build deb clean

test:
	go test ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/vaultls-agent ./cmd/vaultls-agent

deb: build
	VERSION=$(VERSION) nfpm pkg --packager deb --config packaging/nfpm.yaml --target dist/

clean:
	rm -rf dist
```

- [ ] **Step 6: Build the deb locally to verify**

Run:
```bash
cd api-client
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
make deb VERSION=0.1.0
ls dist/*.deb
```
Expected: `dist/vaultls-agent_0.1.0_amd64.deb` exists. Inspect with `dpkg-deb -c dist/*.deb` to confirm `/usr/bin/vaultls-agent`, the unit, and the example config are present.

- [ ] **Step 7: Write the release workflow**

`.github/workflows/agent-release.yml`:
```yaml
name: agent-release
on:
  push:
    tags: ["agent-v*"]
jobs:
  build:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: api-client
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - run: go test ./...
      - run: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
      - name: Build deb
        run: |
          VERSION="${GITHUB_REF_NAME#agent-v}"
          make deb VERSION="$VERSION"
      - uses: softprops/action-gh-release@v2
        with:
          files: api-client/dist/*.deb
```

- [ ] **Step 8: Commit**

```bash
git add api-client/packaging api-client/Makefile .github/workflows/agent-release.yml
git commit -m "build(agent): nfpm deb packaging, systemd unit, release workflow"
```

---

### Task 14: README + final integration build

**Files:**
- Create: `api-client/README.md`

**Interfaces:** none (docs + verification).

- [ ] **Step 1: Write the README**

`api-client/README.md` — document: purpose (certbot-analog for VaulTLS), install (`dpkg -i`), `vaultls-agent setup` (flags + interactive), config reference table (all fields from `config.example.yaml`), wildcard mapping note, metrics list (copy the 9 metric names from the spec §7), and a Prometheus scrape snippet for `127.0.0.1:9105`.

- [ ] **Step 2: Full test + vet + build**

Run:
```bash
cd api-client
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/vasyakrg/vaultls-agent/internal/version.Version=0.1.0" -o dist/vaultls-agent ./cmd/vaultls-agent
./dist/vaultls-agent version || true   # on linux prints "vaultls-agent 0.1.0"
```
Expected: vet clean, all tests pass, binary builds.

- [ ] **Step 3: Commit**

```bash
git add api-client/README.md
git commit -m "docs(agent): README with install, config, metrics reference"
```

---

## Self-Review

**Spec coverage check (spec §→task):**
- §1 назначение → Task 1/14 (CLI + README). ✓
- §2 API-контракт → Task 5 (client, exact paths). ✓
- §3 архитектура (пакеты) → Tasks 1–13 (one package each). ✓
- §4 конфиг + wildcard mapping → Task 2 (config), Task 8 `selectCert`/`SelectForName`. ✓
- §4 раскладка PEM + haproxy → Task 3 (pki) + Task 8 (writeBundle), privkey 0600 enforced. ✓
- §5 поток reconcile (cheap skip → download → serial compare → atomic write → reload) → Task 8. ✓
- §6 store → Task 4. ✓
- §7 метрики (9 серий) → Task 7, asserted in test. ✓
- §8 обработка ошибок (per-domain isolation, stages, token errors) → Task 8 (stage metrics) + Task 12 (`ReconcileAll` isolation, tested). ✓
- §9 deb/nfpm/systemd/postinst/setup → Tasks 12–13. ✓
- §10 self-update → Task 10 + Task 12 wiring. ✓
- §11 distribution (.deb in Releases) → Task 13 workflow. ✓
- §12 тестирование (unit + httptest integration) → every task is TDD; Task 5/8 cover integration-style httptest/fake API. ✓

**Placeholder scan:** The only narrative note is in Task 12 `check` command, which is explicitly resolved in the same step (replace placeholder switch with `--once` flow, remove `configFromArgs`). No "TBD"/"add error handling"/"similar to" placeholders remain.

**Type consistency:** `pki.Bundle` fields (Fullchain/PrivKey/Cert/Chain/Haproxy/Serial) are consumed verbatim in Task 8 `writeBundle`. `store.State` fields match across Tasks 4/8. `vaultls.Cert` fields (ID/Name/ValidUntil/RevokedAt) used consistently in Tasks 5/8. `metrics.Metrics` method names match calls in Tasks 8/12. Serial formatting `%X` of `big.NewInt(0x0a1b2c)` yields `A1B2C` (leading zero dropped) — Task 3 and Task 8 both assert `"A1B2C"` for the same fixture serial. Aligned. ✓
