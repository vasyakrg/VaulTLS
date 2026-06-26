package vaultls

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestRetriesTransient500(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok123", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/api/certificates", func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode([]Cert{{ID: 1, Name: "a", ValidUntil: 1}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "svc_abc", "pw", false)
	c.retryBase = time.Millisecond
	certs, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if hits != 3 {
		t.Fatalf("expected handler hit 3 times, got %d", hits)
	}
}

func TestPersistent500FailsAfterRetries(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok123", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/api/certificates", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "svc_abc", "pw", false)
	c.retryBase = time.Millisecond
	if _, err := c.List(context.Background()); err == nil {
		t.Fatal("expected error after bounded retries on persistent 500")
	}
	if hits != 3 {
		t.Fatalf("expected 3 attempts, got %d", hits)
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
