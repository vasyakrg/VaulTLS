package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vasyakrg/vaultls-agent/internal/app"
)

// domainList collects repeated --domain flags into one slice.
type domainList []string

func (d *domainList) String() string { return strings.Join(*d, ",") }

func (d *domainList) Set(v string) error { *d = append(*d, v); return nil }

func cmdReload(args []string) int {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/vaultls/config.yaml", "path to config.yaml")
	var domains domainList
	fs.Var(&domains, "domain", "run only this domain's reload command; repeatable (default: all domains)")
	fs.Var(&domains, "d", "shorthand for --domain")
	ca := fs.Bool("ca", false, "also run the ca_trust update command")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Reload(ctx, *configPath, app.ReloadOptions{Domains: domains, CA: *ca}); err != nil && err != context.Canceled {
		os.Stderr.WriteString(err.Error() + "\n")
		return 1
	}
	return 0
}
