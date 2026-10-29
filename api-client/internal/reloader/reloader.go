package reloader

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Run executes command through sh -c, capturing its combined output into the
// error on failure. Empty command is a no-op.
func Run(ctx context.Context, command string) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload %q failed: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RunAttached executes command through sh -c with its output streamed live to
// the given writers instead of captured. It backs the reload subcommand, where
// the operator iterates on a script and wants to watch it work as it runs.
// Empty command is a no-op.
func RunAttached(ctx context.Context, command string, stdout, stderr io.Writer) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reload %q failed: %w", command, err)
	}
	return nil
}
