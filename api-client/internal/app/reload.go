package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/reloader"
)

// ReloadOptions configures the reload subcommand: a debug tool that runs the
// configured commands on demand, without contacting the server and without
// touching the reconcile state.
type ReloadOptions struct {
	Domains []string  // domain names to run; empty means all
	CA      bool      // also run ca_trust.update_command
	Stdout  io.Writer // live output of the commands (default os.Stdout)
	Stderr  io.Writer // live output of the commands (default os.Stderr)
}

// Reload loads the config and runs the selected reload commands. It exists for
// debugging the scripts behind domains[].reload and ca_trust.update_command:
// normally those run only when a certificate or the trust store actually
// changed, which makes iterating on them awkward. The config is loaded without
// semantic validation — the subcommand never contacts the server, so a minimal
// config with just domains[].name/reload is enough.
func Reload(ctx context.Context, configPath string, opts ReloadOptions) error {
	cfg, err := config.LoadUnvalidated(configPath)
	if err != nil {
		return err
	}
	log, err := newLogger(cfg.Log)
	if err != nil {
		return err
	}
	return runReload(ctx, cfg, log, opts)
}

func runReload(ctx context.Context, cfg *config.Config, log *slog.Logger, opts ReloadOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	selected, err := selectReloadDomains(cfg.Domains, opts.Domains)
	if err != nil {
		return err
	}

	ran, failed := 0, 0
	for _, d := range selected {
		if strings.TrimSpace(d.Reload) == "" {
			log.Info("no reload command configured, skipping", "domain", d.Name, "cert_id", d.CertID)
			continue
		}
		log.Info("running reload command", "domain", d.Name, "cert_id", d.CertID, "command", d.Reload)
		ran++
		if err := reloader.RunAttached(ctx, d.Reload, opts.Stdout, opts.Stderr); err != nil {
			log.Error("reload command failed", "domain", d.Name, "cert_id", d.CertID, "err", err)
			failed++
		}
	}
	if opts.CA {
		if strings.TrimSpace(cfg.CATrust.UpdateCommand) == "" {
			log.Warn("ca_trust.update_command is not set, nothing to run")
		} else {
			log.Info("running ca trust update command", "command", cfg.CATrust.UpdateCommand)
			ran++
			if err := reloader.RunAttached(ctx, cfg.CATrust.UpdateCommand, opts.Stdout, opts.Stderr); err != nil {
				log.Error("ca trust update command failed", "err", err)
				failed++
			}
		}
	}
	if ran == 0 {
		log.Info("nothing to run: no reload commands selected")
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d reload command(s) failed", failed, ran)
	}
	return nil
}

// selectReloadDomains filters config entries down to those whose Name matches
// one of names. Several entries may share a name (one domain, different certs
// or destinations), so every match runs. An unknown name is an error: a typo in
// a debugging tool must fail loudly, not silently run everything.
func selectReloadDomains(all []config.Domain, names []string) ([]config.Domain, error) {
	if len(names) == 0 {
		return all, nil
	}
	var available []string
	seen := map[string]bool{}
	for _, d := range all {
		if d.Name != "" && !seen[d.Name] {
			seen[d.Name] = true
			available = append(available, d.Name)
		}
	}
	var out []config.Domain
	for _, want := range names {
		matched := false
		for _, d := range all {
			if d.Name != "" && d.Name == want {
				out = append(out, d)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("domain %q is not in the config (configured: %s)", want, strings.Join(available, ", "))
		}
	}
	return out, nil
}
