package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const fileName = ".vaultls-state.json"

type State struct {
	CertID      int64  `json:"cert_id"`
	Serial      string `json:"serial"`
	ValidUntil  int64  `json:"valid_until"`
	LastCheck   int64  `json:"last_check"`
	LastRenewal int64  `json:"last_renewal"`
}

func Read(outDir string) (State, error) {
	var s State
	raw, err := os.ReadFile(filepath.Join(outDir, fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("parse state: %w", err)
	}
	return s, nil
}

func Write(outDir string, s State) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	final := filepath.Join(outDir, fileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write state tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
