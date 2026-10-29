package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasyakrg/vaultls-agent/internal/status"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

func clientForTest(t *testing.T, base string) *vaultls.Client {
	t.Helper()
	return vaultls.New(base, "svc_test", "secret", false)
}

// captureAPI records the last payload and answers with the given status.
type captureAPI struct {
	status  int
	payload Payload
}

func (c *captureAPI) PostJSON(_ context.Context, _ string, payload any) error {
	raw, _ := json.Marshal(payload)
	_ = json.Unmarshal(raw, &c.payload)
	if c.status != 0 {
		return errFake{}
	}
	return nil
}

type errFake struct{}

func (errFake) Error() string { return "boom" }

func TestSendPayloadCarriesSnapshotAndMeta(t *testing.T) {
	tr := status.New()
	tr.Observe(status.Domain{Name: "a.example", Destination: "/a", Status: "ok", Serial: "S1", ExpiryMS: 42, LastCheckMS: 7})
	api := &captureAPI{}
	r := NewReporter(api, tr, Meta{Version: "0.8.0", Schedule: "0 3 1 * *", IntervalSec: 300, CATrustOn: true},
		"explicit-id", t.TempDir())

	if err := r.Send(context.Background()); err != nil {
		t.Fatalf("Send = %v", err)
	}
	p := api.payload
	if p.AgentID != "explicit-id" {
		t.Fatalf("override must win, got %q", p.AgentID)
	}
	if p.Version != "0.8.0" || p.Schedule != "0 3 1 * *" || p.HeartbeatIntervalSec != 300 || !p.CATrustEnabled {
		t.Fatalf("meta not carried: %+v", p)
	}
	if p.OS == "" || p.Arch == "" {
		t.Fatalf("os/arch must be reported: %+v", p)
	}
	if len(p.Domains) != 1 || p.Domains[0].Serial != "S1" {
		t.Fatalf("snapshot not carried: %+v", p.Domains)
	}
	// The override must not create an id file.
	if _, err := os.Stat(filepath.Join(t.TempDir(), "agent-id")); err == nil {
		t.Fatal("override must not write agent-id")
	}
}

func TestGeneratedIDPersistsAcrossReporters(t *testing.T) {
	dir := t.TempDir()
	tr := status.New()

	r1 := NewReporter(&captureAPI{}, tr, Meta{}, "", dir)
	id1, err := r1.agentID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id1) != 32 || strings.ContainsAny(id1, "{}-") {
		t.Fatalf("expected 32-hex v4 uuid, got %q", id1)
	}

	// A second reporter on the same state dir must reuse the id, not regenerate.
	r2 := NewReporter(&captureAPI{}, tr, Meta{}, "", dir)
	id2, err := r2.agentID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("agent-id must persist: %q vs %q", id1, id2)
	}

	// A blank file (truncated write) is regenerated rather than trusted.
	if err := os.WriteFile(filepath.Join(dir, "agent-id"), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r3 := NewReporter(&captureAPI{}, tr, Meta{}, "", dir)
	id3, err := r3.agentID()
	if err != nil {
		t.Fatal(err)
	}
	if id3 == "" {
		t.Fatal("blank id file must be regenerated")
	}
}

// The wire payload must use snake_case keys the server DTO expects.
func TestPayloadJSONKeys(t *testing.T) {
	raw, err := json.Marshal(Payload{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"agent_id", "heartbeat_interval_sec", "ca_trust_enabled", "domains"} {
		if !bytes.Contains(raw, []byte(`"`+key+`"`)) {
			t.Fatalf("payload missing key %q: %s", key, raw)
		}
	}
}

func TestSendPropagatesAPIError(t *testing.T) {
	r := NewReporter(&captureAPI{status: 500}, status.New(), Meta{}, "x", t.TempDir())
	if err := r.Send(context.Background()); err == nil {
		t.Fatal("API error must propagate to the caller (loop logs it)")
	}
}

// End-to-end against an httptest server: auth exchange then heartbeat POST.
func TestSendAgainstHTTPServer(t *testing.T) {
	var gotPath, gotBody string
	var authCalls, beats int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/token":
			authCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case "/api/agents/heartbeat":
			beats++
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			gotBody = buf.String()
			gotPath = r.URL.Path
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	api := clientForTest(t, srv.URL)
	tr := status.New()
	tr.Observe(status.Domain{Name: "x.example", Destination: "/x", Status: "ok"})
	r := NewReporter(api, tr, Meta{Version: "0.8.0"}, "", t.TempDir())
	if err := r.Send(context.Background()); err != nil {
		t.Fatalf("Send = %v", err)
	}
	if gotPath != "/api/agents/heartbeat" {
		t.Fatalf("posted to %q", gotPath)
	}
	if !strings.Contains(gotBody, `"x.example"`) || !strings.Contains(gotBody, `"0.8.0"`) {
		t.Fatalf("body missing expected fields: %s", gotBody)
	}
	if authCalls != 1 || beats != 1 {
		t.Fatalf("auth=%d beats=%d", authCalls, beats)
	}
}
