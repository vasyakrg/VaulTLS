package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/catrust"
	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/metrics"
	"github.com/vasyakrg/vaultls-agent/internal/reconcile"
	"github.com/vasyakrg/vaultls-agent/internal/scheduler"
	"github.com/vasyakrg/vaultls-agent/internal/selfupdate"
	"github.com/vasyakrg/vaultls-agent/internal/vaultls"
	"github.com/vasyakrg/vaultls-agent/internal/version"
)

func ReconcileAll(ctx context.Context, cfg *config.Config, r *reconcile.Reconciler, log *slog.Logger) {
	for _, d := range cfg.Domains {
		log.Debug("reconciling domain", "domain", d.Name, "cert_id", d.CertID, "out_dir", d.OutDir)
		if err := r.Domain(ctx, d); err != nil {
			log.Error("reconcile failed", "domain", d.Name, "cert_id", d.CertID, "err", err)
		} else {
			log.Info("reconcile ok", "domain", d.Name, "cert_id", d.CertID)
		}
	}
}

// caTrustStateDir holds the record of anchors the agent owns. It lives in the
// directory postinstall already creates and the unit already allows writing
// to. A var, not a const, so tests can point it at a temp dir instead of
// reading and writing the real /etc/ssl/vaultls on the host running them.
var caTrustStateDir = "/etc/ssl/vaultls"

// SyncCATrust keeps the VaulTLS CAs present in the host trust store. Failures
// are logged and counted but never propagate: an unreachable CA endpoint must
// not stop certificates from being deployed.
func SyncCATrust(ctx context.Context, cfg *config.Config, f catrust.Fetcher, m *metrics.Metrics, log *slog.Logger) {
	if !cfg.CATrust.Enabled {
		return
	}
	res, err := catrust.Sync(ctx, f, catrust.ShellRunner{}, cfg.CATrust, caTrustStateDir, time.Now)
	if err != nil {
		stage := string(catrust.StageUpdate)
		var se *catrust.Error
		if errors.As(err, &se) {
			stage = string(se.Stage)
		}
		m.IncCATrustError(stage)
		log.Error("ca trust sync failed", "stage", stage, "err", err)
		return
	}
	m.SetCATrustCerts(float64(res.Installed))
	m.MarkCATrustSync(float64(time.Now().Unix()))
	if res.Changed {
		log.Info("ca trust store updated", "certs", res.Installed, "anchor_dir", cfg.CATrust.AnchorDir)
	} else {
		log.Debug("ca trust store already current", "certs", res.Installed)
	}
}

func Run(ctx context.Context, configPath, githubAPIBase string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log, err := newLogger(cfg.Log)
	if err != nil {
		return err
	}
	slog.SetDefault(log)
	log.Info("vaultls-agent starting",
		"version", version.Version,
		"server", cfg.Server.URL,
		"domains", len(cfg.Domains),
		"schedule", cfg.Schedule,
	)
	m := metrics.New()
	m.SetUp()
	m.SetBuildInfo(version.Version)

	api := vaultls.New(cfg.Server.URL, cfg.Server.ClientID, cfg.Server.Secret, cfg.Server.InsecureSkipVerify)
	r := reconcile.New(api, m, time.Now)

	// Exporter.
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	srv := &http.Server{Addr: cfg.Exporter.Listen, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("exporter server", "err", err)
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	// Self-update check now and daily.
	checkUpdate(ctx, m, githubAPIBase, log)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				checkUpdate(ctx, m, githubAPIBase, log)
			}
		}
	}()

	// Initial CA trust sync and domain reconcile, then the same pair on every
	// scheduled run.
	SyncCATrust(ctx, cfg, api, m, log)
	ReconcileAll(ctx, cfg, r, log)
	return scheduler.Run(ctx, cfg.Schedule, cfg.Jitter, func(c context.Context) {
		SyncCATrust(c, cfg, api, m, log)
		ReconcileAll(c, cfg, r, log)
	})
}

func RunOnce(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log, err := newLogger(cfg.Log)
	if err != nil {
		return err
	}
	m := metrics.New()
	api := vaultls.New(cfg.Server.URL, cfg.Server.ClientID, cfg.Server.Secret, cfg.Server.InsecureSkipVerify)
	r := reconcile.New(api, m, time.Now)
	SyncCATrust(ctx, cfg, api, m, log)
	ReconcileAll(ctx, cfg, r, log)
	return nil
}

func checkUpdate(ctx context.Context, m *metrics.Metrics, apiBase string, log *slog.Logger) {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	latest, outdated, err := selfupdate.Check(ctx, apiBase, "vasyakrg/VaulTLS", version.Version)
	if err != nil {
		log.Warn("version check failed", "err", err)
		return
	}
	m.SetUpdateAvailable(outdated, latest)
	if outdated {
		log.Warn("a newer vaultls-agent release is available", "current", version.Version, "latest", latest)
	}
}
