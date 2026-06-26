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
