package app

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

// newLogger builds the agent logger from config. Defaults preserve the previous
// behaviour: INFO level, text format, stderr (captured by journald). Setting
// log.file redirects output to that file so operators get logs under /var/log
// even when journald is unavailable or trimmed.
func newLogger(cfg config.Log) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", cfg.Level)
	}

	var out io.Writer = os.Stderr
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf("open log file %q: %w", cfg.File, err)
		}
		out = f // kept open for the process lifetime
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "text":
		h = slog.NewTextHandler(out, opts)
	case "json":
		h = slog.NewJSONHandler(out, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q", cfg.Format)
	}
	return slog.New(h), nil
}
