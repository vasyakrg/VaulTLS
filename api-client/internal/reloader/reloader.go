package reloader

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Run executes command through sh -c. Empty command is a no-op.
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
