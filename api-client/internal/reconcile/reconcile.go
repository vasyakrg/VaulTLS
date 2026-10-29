package reconcile

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/reloader"
	"github.com/vasyakrg/vaultls-agent/internal/status"
	"github.com/vasyakrg/vaultls-agent/internal/store"
	"github.com/vasyakrg/vaultls-agent/internal/target"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
)

type API interface {
	List(ctx context.Context) ([]vaultls.Cert, error)
	Password(ctx context.Context, id int64) (string, error)
	Download(ctx context.Context, id int64) ([]byte, error)
}

type Clock func() time.Time

type Reconciler struct {
	api     API
	m       *metrics.Metrics
	now     Clock
	targets *target.Factory
	status  *status.Tracker
}

func New(api API, m *metrics.Metrics, now Clock, targets *target.Factory, st *status.Tracker) *Reconciler {
	if targets == nil {
		targets = target.NewFactory()
	}
	return &Reconciler{api: api, m: m, now: now, targets: targets, status: st}
}

// certLabels keys metric series by the whole config entry: two entries may share
// one domain name while pulling different certificates to different
// destinations. dest is the target's own identity — an out_dir for file
// targets, namespace/secret for cluster ones.
func certLabels(d config.Domain, dest string) metrics.CertLabels {
	domain := d.Name
	if domain == "" {
		domain = dest
	}
	certID := ""
	if d.CertID != 0 {
		certID = strconv.FormatInt(d.CertID, 10)
	}
	return metrics.CertLabels{Domain: domain, CertID: certID, OutDir: dest}
}

func (r *Reconciler) Domain(ctx context.Context, d config.Domain) (err error) {
	tgt, err := r.targets.For(d)
	if err != nil {
		r.m.IncReconcileError(certLabels(d, d.OutDir), "target")
		return fmt.Errorf("resolve target: %w", err)
	}
	label := certLabels(d, tgt.Describe())
	now := r.now()
	r.m.MarkCheck(label, float64(now.Unix()))

	// st mirrors this run's outcome into the heartbeat snapshot; stage marks
	// the step about to run so an error report names where it failed. The
	// deferred observe turns every return below into a snapshot update.
	st := status.Domain{
		Name: d.Name, CertID: d.CertID, Target: d.Kind(),
		Destination: tgt.Describe(), LastCheckMS: now.UnixMilli(),
	}
	if r.status != nil {
		defer func() {
			if err != nil {
				st.Status = "error"
				st.Error = err.Error()
			} else {
				st.Status = "ok"
				st.Stage = "" // stage only names where a failure happened
			}
			r.status.Observe(st)
		}()
	}
	stage := func(s string) { st.Stage = s }

	stage("list")
	certs, err := r.api.List(ctx)
	if err != nil {
		r.m.IncReconcileError(label, "list")
		r.m.IncTokenError()
		return fmt.Errorf("list certs: %w", err)
	}

	stage("select")
	cert, ok := selectCert(certs, d)
	if !ok {
		r.m.IncReconcileError(label, "select")
		return fmt.Errorf("no certificate found for domain %q (cert_id=%d)", d.Name, d.CertID)
	}

	r.m.SetCertExpiry(label, float64(cert.ValidUntil)/1000.0)

	stage("state_read")
	prev, err := tgt.LoadState(ctx)
	if err != nil {
		r.m.IncReconcileError(label, "state_read")
		return fmt.Errorf("read state: %w", err)
	}

	// Cheap skip: same cert identity already deployed — vault hasn't issued a new
	// one. Renewal in this pull-based design is detected purely via (CertID,
	// ValidUntil); until either changes we have nothing new to deploy.
	if prev.CertID == cert.ID && prev.ValidUntil == cert.ValidUntil && prev.Serial != "" {
		prev.LastCheck = now.UnixMilli()
		if err := tgt.SaveState(ctx, prev); err != nil {
			r.m.IncReconcileError(label, "state_write")
			return fmt.Errorf("write state: %w", err)
		}
		r.m.SetCertSerial(label, prev.Serial)
		st.Serial, st.ExpiryMS = prev.Serial, prev.ValidUntil
		return nil
	}

	stage("password")
	password, err := r.api.Password(ctx, cert.ID)
	if err != nil {
		r.m.IncReconcileError(label, "password")
		return fmt.Errorf("get password: %w", err)
	}
	stage("download")
	p12, err := r.api.Download(ctx, cert.ID)
	if err != nil {
		r.m.IncReconcileError(label, "download")
		return fmt.Errorf("download: %w", err)
	}
	stage("decode")
	bundle, err := pki.Decode(p12, password)
	if err != nil {
		r.m.IncReconcileError(label, "decode")
		return fmt.Errorf("decode p12: %w", err)
	}

	changed := bundle.Serial != prev.Serial
	if changed {
		stage("write")
		if err := tgt.Apply(ctx, bundle); err != nil {
			r.m.IncReconcileError(label, "write")
			return fmt.Errorf("deploy bundle: %w", err)
		}
	}

	next := store.State{
		CertID: cert.ID, Serial: bundle.Serial, ValidUntil: cert.ValidUntil,
		LastCheck: now.UnixMilli(), LastRenewal: prev.LastRenewal,
	}
	if changed {
		next.LastRenewal = now.UnixMilli()
	}
	stage("state_write")
	if err := tgt.SaveState(ctx, next); err != nil {
		r.m.IncReconcileError(label, "state_write")
		return fmt.Errorf("write state: %w", err)
	}
	r.m.SetCertSerial(label, bundle.Serial)
	st.Serial, st.ExpiryMS = bundle.Serial, cert.ValidUntil

	if changed {
		r.m.MarkRenewal(label, float64(now.Unix()))
		stage("reload")
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
