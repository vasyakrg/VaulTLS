package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg *prometheus.Registry

	up              prometheus.Gauge
	buildInfo       *prometheus.GaugeVec
	updateAvailable prometheus.Gauge
	latestVersion   *prometheus.GaugeVec
	certExpiry      *prometheus.GaugeVec
	certSerial      *prometheus.GaugeVec
	lastCheck       *prometheus.GaugeVec
	lastRenewal     *prometheus.GaugeVec
	reconcileErrors *prometheus.CounterVec
	reloadFailures  *prometheus.CounterVec
	tokenErrors     prometheus.Counter

	mu                 sync.Mutex
	serials            map[string]string
	latestVersionLabel string
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg:             reg,
		serials:         map[string]string{},
		up:              prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_up", Help: "1 if the agent is running."}),
		buildInfo:       prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_build_info", Help: "Build info."}, []string{"version"}),
		updateAvailable: prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_update_available", Help: "1 if a newer release exists."}),
		latestVersion:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_latest_version_info", Help: "Latest known release."}, []string{"version"}),
		certExpiry:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_expiry_timestamp_seconds", Help: "Cert NotAfter."}, []string{"domain"}),
		certSerial:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_serial_info", Help: "Current serial."}, []string{"domain", "serial"}),
		lastCheck:       prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_check_timestamp_seconds", Help: "Last reconcile check."}, []string{"domain"}),
		lastRenewal:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_renewal_timestamp_seconds", Help: "Last actual renewal."}, []string{"domain"}),
		reconcileErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reconcile_errors_total", Help: "Reconcile errors by stage."}, []string{"domain", "stage"}),
		reloadFailures:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reload_failures_total", Help: "Reload failures."}, []string{"domain"}),
		tokenErrors:     prometheus.NewCounter(prometheus.CounterOpts{Name: "vaultls_scrape_token_errors_total", Help: "Token/auth errors."}),
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
		// Set the new series BEFORE deleting the stale one so a concurrent
		// scrape never observes an empty vaultls_agent_latest_version_info
		// series. A bare Reset()+Set() leaves a window where the series is
		// momentarily gone; the registry's Gather() does not take m.mu, so a
		// mutex around Reset()+Set() would not close that window either.
		m.mu.Lock()
		defer m.mu.Unlock()
		m.latestVersion.WithLabelValues(latest).Set(1)
		if old := m.latestVersionLabel; old != "" && old != latest {
			m.latestVersion.DeleteLabelValues(old)
		}
		m.latestVersionLabel = latest
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
