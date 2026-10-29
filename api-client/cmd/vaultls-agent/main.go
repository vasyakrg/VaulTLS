package main

import (
	"fmt"
	"os"

	"github.com/vasyakrg/vaultls-agent/internal/version"
)

// usage is the top-level help. Printed to stderr with exit 2 when the command
// line is wrong, to stdout with exit 0 for an explicit help request.
const usage = `usage: vaultls-agent <command> [flags]

Commands:
  run      Start the daemon (used by the systemd unit)
  setup    Generate /etc/vaultls/config.yaml and optionally enable the service
  check    Run a single reconcile pass and exit
  reload   Run the configured reload commands on demand (debugging)
  version  Print the build version

Run 'vaultls-agent <command> --help' for the command's flags.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "setup":
		os.Exit(cmdSetup(os.Args[2:]))
	case "check":
		os.Exit(cmdRun(append(os.Args[2:], "--once")))
	case "reload":
		os.Exit(cmdReload(os.Args[2:]))
	case "version":
		fmt.Println(version.String())
	case "help", "--help", "-h":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
}
