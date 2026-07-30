package catrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const stateFileName = "ca-trust.json"

// State records the anchor files the agent owns, keyed by certificate
// fingerprint. Only files listed here are ever removed, so foreign anchors
// sharing the directory are safe.
//
// PendingUpdate marks that files are on disk but the trust-store update command
// has not succeeded yet; it forces the next run to retry the command instead of
// concluding that the fingerprint set already matches.
type State struct {
	Certs         map[string]string `json:"certs"`
	PendingUpdate bool              `json:"pending_update"`
	LastSync      int64             `json:"last_sync"`
}

// ReadState loads the ca-trust state from dir. A missing file is not an
// error: it returns the zero State, matching a host the agent has never
// touched.
func ReadState(dir string) (State, error) {
	var s State
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read ca-trust state: %w", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("parse ca-trust state: %w", err)
	}
	return s, nil
}

// WriteState persists s to dir, creating the directory if needed. The write
// is atomic: it writes to a temp file and renames it into place, so a crash
// mid-write never leaves a truncated state file.
func WriteState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir ca-trust state dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ca-trust state: %w", err)
	}
	final := filepath.Join(dir, stateFileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write ca-trust state tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename ca-trust state: %w", err)
	}
	return nil
}
