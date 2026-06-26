package main

import (
	"fmt"
	"os"

	"github.com/vasyakrg/vaultls-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vaultls-agent <run|setup|check|version>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "setup":
		os.Exit(cmdSetup(os.Args[2:]))
	case "check":
		os.Exit(cmdRun(append(os.Args[2:], "--once")))
	case "version":
		fmt.Println(version.String())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
