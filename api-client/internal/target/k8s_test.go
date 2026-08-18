package target

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/k8s"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/store"
)

type call struct {
	method string
	path   string
	body   []byte
}

// fakeAPIServer serves one Secret. exists drives whether GET returns it, so a
// test can exercise both the create and the patch path.
type fakeAPIServer struct {
	t      *testing.T
	exists bool
	secret k8s.Secret
	calls  []call
}

func (f *fakeAPIServer) start() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.calls = append(f.calls, call{r.Method, r.URL.Path, body})
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			f.t.Errorf("Authorization = %q", got)
		}
		switch r.Method {
		case http.MethodGet:
			if !f.exists {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","message":"secrets \"x\" not found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.secret)
		case http.MethodPost:
			f.exists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(body)
		case http.MethodPatch:
			if ct := r.Header.Get("Content-Type"); ct != "application/merge-patch+json" {
				f.t.Errorf("patch Content-Type = %q", ct)
			}
			_, _ = w.Write(body)
		}
	}))
}

func k8sDomain(includeCA bool) config.Domain {
	return config.Domain{
		Name:   "*.example.com",
		Target: config.TargetK8s,
		K8s: config.K8s{
			Namespace: "default",
			Secret:    "wildcard-example-com",
			IncludeCA: includeCA,
			Labels:    map[string]string{"vaultls.io/replicate": "true"},
		},
	}
}

func bundle() *pki.Bundle {
	return &pki.Bundle{
		Fullchain: []byte("FULLCHAIN"),
		PrivKey:   []byte("KEY"),
		Chain:     []byte("CHAIN"),
		Serial:    "A1B2C",
	}
}

func newTarget(t *testing.T, srv *httptest.Server, d config.Domain) K8s {
	t.Helper()
	return K8s{c: k8s.NewForTest(srv.URL, "tok", srv.Client()), d: d}
}

func TestK8sApplyCreatesTLSSecret(t *testing.T) {
	f := &fakeAPIServer{t: t}
	srv := f.start()
	defer srv.Close()

	if err := newTarget(t, srv, k8sDomain(true)).Apply(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[1].method != http.MethodPost {
		t.Fatalf("expected GET then POST, got %+v", f.calls)
	}
	var got k8s.Secret
	if err := json.Unmarshal(f.calls[1].body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "kubernetes.io/tls" {
		t.Errorf("type = %q", got.Type)
	}
	if string(got.Data["tls.crt"]) != "FULLCHAIN" || string(got.Data["tls.key"]) != "KEY" {
		t.Errorf("data = %v", got.Data)
	}
	if string(got.Data["ca.crt"]) != "CHAIN" {
		t.Errorf("ca.crt = %q, want the chain", got.Data["ca.crt"])
	}
	if got.Metadata.Labels["app.kubernetes.io/managed-by"] != "vaultls-agent" ||
		got.Metadata.Labels["vaultls.io/replicate"] != "true" {
		t.Errorf("labels = %v", got.Metadata.Labels)
	}
}

// The patch must not carry the Secret type (immutable) and must not carry
// annotations, so state written by SaveState and labels added by other
// controllers survive a certificate rotation.
func TestK8sApplyPatchesExistingSecret(t *testing.T) {
	f := &fakeAPIServer{t: t, exists: true}
	srv := f.start()
	defer srv.Close()

	if err := newTarget(t, srv, k8sDomain(true)).Apply(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[1].method != http.MethodPatch {
		t.Fatalf("expected GET then PATCH, got %+v", f.calls)
	}
	var patch map[string]any
	if err := json.Unmarshal(f.calls[1].body, &patch); err != nil {
		t.Fatal(err)
	}
	if _, ok := patch["type"]; ok {
		t.Error("patch must not contain the immutable type field")
	}
	meta := patch["metadata"].(map[string]any)
	if _, ok := meta["annotations"]; ok {
		t.Error("data patch must not touch annotations")
	}
	data := patch["data"].(map[string]any)
	if data["tls.crt"] != "RlVMTENIQUlO" { // base64("FULLCHAIN")
		t.Errorf("tls.crt = %v", data["tls.crt"])
	}
}

// include_ca off must actively delete a chain left by an earlier run; a merge
// patch does that only with an explicit null.
func TestK8sApplyRemovesCAWhenDisabled(t *testing.T) {
	f := &fakeAPIServer{t: t, exists: true}
	srv := f.start()
	defer srv.Close()

	if err := newTarget(t, srv, k8sDomain(false)).Apply(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	var patch map[string]any
	if err := json.Unmarshal(f.calls[1].body, &patch); err != nil {
		t.Fatal(err)
	}
	data := patch["data"].(map[string]any)
	v, ok := data["ca.crt"]
	if !ok || v != nil {
		t.Errorf("ca.crt = %v (present=%v), want an explicit null", v, ok)
	}
}

func TestK8sStateRoundTrip(t *testing.T) {
	f := &fakeAPIServer{t: t, exists: true}
	srv := f.start()
	defer srv.Close()
	tgt := newTarget(t, srv, k8sDomain(true))
	ctx := context.Background()

	want := store.State{CertID: 9, Serial: "A1B2C", ValidUntil: 1700, LastCheck: 1800, LastRenewal: 1750}
	if err := tgt.SaveState(ctx, want); err != nil {
		t.Fatal(err)
	}
	var patch struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(f.calls[0].body, &patch); err != nil {
		t.Fatal(err)
	}
	f.secret = k8s.Secret{}
	f.secret.Metadata.Annotations = patch.Metadata.Annotations

	got, err := tgt.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("LoadState() = %+v, want %+v", got, want)
	}
}

// A missing Secret is the first-deployment case, not an error.
func TestK8sLoadStateMissingSecret(t *testing.T) {
	f := &fakeAPIServer{t: t}
	srv := f.start()
	defer srv.Close()

	got, err := newTarget(t, srv, k8sDomain(true)).LoadState(context.Background())
	if err != nil {
		t.Fatalf("missing secret must not error: %v", err)
	}
	if (got != store.State{}) {
		t.Errorf("state = %+v, want zero", got)
	}
}

// An API error must surface: silently treating a 403 as "nothing deployed yet"
// would make the agent redeploy on every pass and hide broken RBAC.
func TestK8sLoadStateForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"secrets is forbidden"}`))
	}))
	defer srv.Close()

	_, err := newTarget(t, srv, k8sDomain(true)).LoadState(context.Background())
	if err == nil {
		t.Fatal("expected an error for 403")
	}
}
