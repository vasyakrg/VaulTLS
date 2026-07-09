package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
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
	l := CertLabels{Domain: "example.com", CertID: "11", OutDir: "/etc/ssl/vaultls/a"}
	m.SetUp()
	m.SetBuildInfo("1.2.3")
	m.SetUpdateAvailable(true, "1.3.0")
	m.SetCertExpiry(l, 1790000000)
	m.SetCertSerial(l, "0A1B2C")
	m.IncReconcileError(l, "download")
	m.IncReloadFailure(l)
	m.IncTokenError()

	body := scrape(m)
	for _, want := range []string{
		"vaultls_agent_up 1",
		`vaultls_agent_build_info{version="1.2.3"} 1`,
		"vaultls_agent_update_available 1",
		`vaultls_agent_latest_version_info{version="1.3.0"} 1`,
		`vaultls_cert_expiry_timestamp_seconds{cert_id="11",domain="example.com",out_dir="/etc/ssl/vaultls/a"} 1.79e+09`,
		`vaultls_cert_serial_info{cert_id="11",domain="example.com",out_dir="/etc/ssl/vaultls/a",serial="0A1B2C"} 1`,
		`vaultls_reconcile_errors_total{cert_id="11",domain="example.com",out_dir="/etc/ssl/vaultls/a",stage="download"} 1`,
		`vaultls_reload_failures_total{cert_id="11",domain="example.com",out_dir="/etc/ssl/vaultls/a"} 1`,
		"vaultls_scrape_token_errors_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}

// A renewal must replace the domain's serial series, not accumulate a second one,
// and must not disturb the series of a sibling entry sharing the same domain name.
func TestSetCertSerialReplacesOnlyOwnSeries(t *testing.T) {
	m := New()
	a := CertLabels{Domain: "example.com", CertID: "11", OutDir: "/a"}
	b := CertLabels{Domain: "example.com", CertID: "14", OutDir: "/b"}
	m.SetCertSerial(a, "OLD")
	m.SetCertSerial(b, "BBB")
	m.SetCertSerial(a, "NEW")

	body := scrape(m)
	if strings.Contains(body, `serial="OLD"`) {
		t.Errorf("stale serial series left behind\n%s", body)
	}
	for _, want := range []string{`cert_id="11"`, `serial="NEW"`, `cert_id="14"`, `serial="BBB"`} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n%s", want, body)
		}
	}
}

func TestSetUpdateAvailableConcurrentScrape(t *testing.T) {
	m := New()
	const iters = 2000
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			m.SetUpdateAvailable(true, "1.3.0")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = scrape(m)
		}
	}()

	wg.Wait()
}

func TestLatestVersionNeverEmptyUnderConcurrency(t *testing.T) {
	m := New()
	m.SetUpdateAvailable(true, "1.0.0")
	const iters = 5000
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if i%2 == 0 {
				m.SetUpdateAvailable(true, "1.3.0")
			} else {
				m.SetUpdateAvailable(true, "1.4.0")
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			body := scrape(m)
			if !strings.Contains(body, "vaultls_agent_latest_version_info{") {
				t.Errorf("scrape exposed no latest_version_info series (empty window)")
				return
			}
		}
	}()

	wg.Wait()
}
