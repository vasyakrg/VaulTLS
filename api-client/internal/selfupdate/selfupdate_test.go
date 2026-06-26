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
