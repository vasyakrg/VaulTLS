package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vasyakrg/vaultls-agent/internal/wizard"
)

func cmdSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	url := fs.String("url", "", "VaulTLS server URL")
	clientID := fs.String("client-id", "", "service account client id")
	secret := fs.String("secret", "", "service account secret")
	domain := fs.String("domain", "", "certificate name, e.g. *.example.com")
	reload := fs.String("reload", "", "reload command")
	out := fs.String("out", "/etc/vaultls/config.yaml", "config output path")
	enable := fs.Bool("enable", true, "enable+start the systemd service after writing config")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	preset := wizard.Answers{URL: *url, ClientID: *clientID, Secret: *secret, Domain: *domain, Reload: *reload}
	ans := preset
	if preset.URL == "" || preset.ClientID == "" || preset.Secret == "" || preset.Domain == "" || preset.Reload == "" {
		var err error
		ans, err = wizard.RunInteractive(os.Stdin, os.Stdout, preset)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	body, err := wizard.Render(ans)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote %s\n", *out)
	if *enable {
		_ = exec.Command("systemctl", "enable", "--now", "vaultls-agent").Run()
	}
	return 0
}
