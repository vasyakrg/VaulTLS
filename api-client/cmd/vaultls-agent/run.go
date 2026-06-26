package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/vasyakrg/vaultls-agent/internal/app"
)

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/vaultls/config.yaml", "path to config.yaml")
	once := fs.Bool("once", false, "run one reconcile pass and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := app.RunOnce(ctx, *configPath); err != nil && err != context.Canceled {
			os.Stderr.WriteString(err.Error() + "\n")
			return 1
		}
		return 0
	}
	if err := app.Run(ctx, *configPath, ""); err != nil && err != context.Canceled {
		os.Stderr.WriteString(err.Error() + "\n")
		return 1
	}
	return 0
}
