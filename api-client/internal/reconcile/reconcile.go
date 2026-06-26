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

	// Cheap skip: same cert identity already deployed — vault hasn't issued a new one.
	// The renewal window (renewBefore) is used by the vault operator to decide when
	// to issue a replacement; until ValidUntil changes we have nothing new to deploy.
	if prev.CertID == cert.ID && prev.ValidUntil == cert.ValidUntil && prev.Serial != "" {
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
