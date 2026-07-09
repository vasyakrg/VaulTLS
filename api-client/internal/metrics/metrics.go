package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// CertLabels identifies one config entry. Domain alone is not unique: several
// entries may track the same wildcard domain via different cert_id/out_dir, so
// every per-certificate series is keyed by all three.
type CertLabels struct {
	Domain string
	CertID string
	OutDir string
}

func (l CertLabels) values() []string { return []string{l.Domain, l.CertID, l.OutDir} }

var certLabelNames = []string{"domain", "cert_id", "out_dir"}

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
	serials            map[CertLabels]string
	latestVersionLabel string
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg:             reg,
		serials:         map[CertLabels]string{},
		up:              prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_up", Help: "1 if the agent is running."}),
		buildInfo:       prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_build_info", Help: "Build info."}, []string{"version"}),
		updateAvailable: prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultls_agent_update_available", Help: "1 if a newer release exists."}),
		latestVersion:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_agent_latest_version_info", Help: "Latest known release."}, []string{"version"}),
		certExpiry:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_expiry_timestamp_seconds", Help: "Cert NotAfter."}, certLabelNames),
		certSerial:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_cert_serial_info", Help: "Current serial."}, append(append([]string{}, certLabelNames...), "serial")),
		lastCheck:       prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_check_timestamp_seconds", Help: "Last reconcile check."}, certLabelNames),
		lastRenewal:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "vaultls_last_renewal_timestamp_seconds", Help: "Last actual renewal."}, certLabelNames),
		reconcileErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reconcile_errors_total", Help: "Reconcile errors by stage."}, append(append([]string{}, certLabelNames...), "stage")),
		reloadFailures:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vaultls_reload_failures_total", Help: "Reload failures."}, certLabelNames),
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

func (m *Metrics) SetCertExpiry(l CertLabels, unixSeconds float64) {
	m.certExpiry.WithLabelValues(l.values()...).Set(unixSeconds)
}

// SetCertSerial replaces any prior serial series for this config entry so only
// the current serial is exposed. Sibling entries on the same domain keep theirs.
func (m *Metrics) SetCertSerial(l CertLabels, serial string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.serials[l]; ok && old != serial {
		m.certSerial.DeleteLabelValues(append(l.values(), old)...)
	}
	m.serials[l] = serial
	m.certSerial.WithLabelValues(append(l.values(), serial)...).Set(1)
}

func (m *Metrics) MarkCheck(l CertLabels, unixSeconds float64) {
	m.lastCheck.WithLabelValues(l.values()...).Set(unixSeconds)
}

func (m *Metrics) MarkRenewal(l CertLabels, unixSeconds float64) {
	m.lastRenewal.WithLabelValues(l.values()...).Set(unixSeconds)
}

func (m *Metrics) IncReconcileError(l CertLabels, stage string) {
	m.reconcileErrors.WithLabelValues(append(l.values(), stage)...).Inc()
}

func (m *Metrics) IncReloadFailure(l CertLabels) {
	m.reloadFailures.WithLabelValues(l.values()...).Inc()
}

func (m *Metrics) IncTokenError() { m.tokenErrors.Inc() }
