package catrust

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/reloader"
)

// Fetcher supplies the concatenated PEM of every TLS CA. *vaultls.Client
// satisfies it.
type Fetcher interface {
	CABundle(ctx context.Context) ([]byte, error)
}

// Runner applies the platform's trust-store update command.
type Runner interface {
	Run(ctx context.Context, command string) error
}

// ShellRunner runs the command through sh -c under its own timeout, so a hung
// update-ca-certificates cannot stall the reconcile loop.
type ShellRunner struct{ Timeout time.Duration }

func (s ShellRunner) Run(ctx context.Context, command string) error {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return reloader.Run(c, command)
}

// Stage names the step a Sync failure came from, so callers can label metrics
// without string-matching error text.
type Stage string

const (
	StageFetch  Stage = "fetch"
	StageParse  Stage = "parse"
	StageState  Stage = "state"
	StageWrite  Stage = "write"
	StageUpdate Stage = "update"
)

type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("ca trust %s: %v", e.Stage, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

type Result struct {
	Installed int  // how many CAs the agent now owns
	Changed   bool // whether the trust store was rewritten this run
}

// Sync makes the anchor directory match the server's CA bundle and applies the
// change with a single update command. It is idempotent: an unchanged bundle
// whose files are all present costs one HTTP call and nothing else.
//
// A disabled config is a no-op: the package enforces the default-off
// invariant itself rather than trusting every caller to check cfg.Enabled
// first.
func Sync(ctx context.Context, f Fetcher, r Runner, cfg config.CATrust, stateDir string, now func() time.Time) (Result, error) {
	if !cfg.Enabled {
		return Result{}, nil
	}
	raw, err := f.CABundle(ctx)
	if err != nil {
		return Result{}, &Error{StageFetch, err}
	}
	anchors, err := ParseBundle(raw, cfg.FileExt())
	if err != nil {
		return Result{}, &Error{StageParse, err}
	}
	prev, err := ReadState(stateDir)
	if err != nil {
		return Result{}, &Error{StageState, err}
	}
	if !needsSync(prev, anchors, cfg.AnchorDir) {
		return Result{Installed: len(anchors), Changed: false}, nil
	}

	if err := os.MkdirAll(cfg.AnchorDir, 0o755); err != nil {
		return Result{}, &Error{StageWrite, fmt.Errorf("mkdir anchor dir: %w", err)}
	}
	next := State{Certs: make(map[string]string, len(anchors)), LastSync: prev.LastSync, PendingUpdate: true}
	for _, a := range anchors {
		if err := writeAnchor(cfg.AnchorDir, a); err != nil {
			// Anchors written before this failure are already on disk; if we
			// return without recording them, they become invisible to the retire
			// and purge logic and stay trusted forever. Best-effort: if this write
			// also fails there is nothing more we can do, and the original error
			// is what matters to the caller.
			_ = WriteState(stateDir, next)
			return Result{}, &Error{StageWrite, err}
		}
		next.Certs[a.Fingerprint] = a.FileName
	}
	// Drop anchors we installed earlier that the bundle no longer carries:
	// otherwise a retired CA stays trusted forever. Only our own files are
	// considered — anything not in prev.Certs is somebody else's.
	removed := map[string]bool{}
	for fp, name := range prev.Certs {
		if _, keep := next.Certs[fp]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(cfg.AnchorDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			// The file this call failed on, plus anything not reached yet (map
			// iteration order is random), are still on disk. Carry their
			// ownership over into next so they stay tracked instead of becoming
			// permanently untracked-but-trusted anchors.
			for fp2, name2 := range prev.Certs {
				if _, keep := next.Certs[fp2]; keep || removed[fp2] {
					continue
				}
				next.Certs[fp2] = name2
			}
			_ = WriteState(stateDir, next)
			return Result{}, &Error{StageWrite, fmt.Errorf("remove retired anchor %s: %w", name, err)}
		}
		removed[fp] = true
	}
	// Ownership is recorded before the command runs so a failing command cannot
	// cost us the record of files already on disk.
	if err := WriteState(stateDir, next); err != nil {
		return Result{}, &Error{StageState, err}
	}
	if err := r.Run(ctx, cfg.UpdateCommand); err != nil {
		return Result{Installed: len(anchors), Changed: true}, &Error{StageUpdate, err}
	}
	next.PendingUpdate = false
	next.LastSync = now().UnixMilli()
	if err := WriteState(stateDir, next); err != nil {
		return Result{Installed: len(anchors), Changed: true}, &Error{StageState, err}
	}
	return Result{Installed: len(anchors), Changed: true}, nil
}

// needsSync reports whether the anchor directory has to be rewritten: the
// fingerprint set moved, a file we own vanished, or a previous update command
// never succeeded.
func needsSync(prev State, anchors []Anchor, anchorDir string) bool {
	if prev.PendingUpdate || len(prev.Certs) != len(anchors) {
		return true
	}
	for _, a := range anchors {
		name, ok := prev.Certs[a.Fingerprint]
		if !ok || name != a.FileName {
			return true
		}
		if _, err := os.Stat(filepath.Join(anchorDir, name)); err != nil {
			return true
		}
	}
	return false
}

// writeAnchor writes one anchor atomically. Mode 0644: CA certificates are
// public, and every local TLS client has to be able to read them.
//
// The temp file is named with a leading dot and a distinct prefix rather than
// a "<final>.tmp" suffix: Debian's update-ca-certificates globs only *.crt and
// would ignore either name, but RHEL's p11-kit reads every file under
// source/anchors, ".tmp" suffix included. A crash between the write and the
// rename must not leave a half-written certificate that some trust-store tool
// picks up and trusts — and since purge cleanup only knows about files in the
// state file, such a leftover would never get cleaned up either. The dot
// prefix keeps every trust-store tool we know of from reading it, and the tmp
// file stays in the same directory as final so the rename is atomic.
func writeAnchor(dir string, a Anchor) error {
	final := filepath.Join(dir, a.FileName)
	tmp := filepath.Join(dir, ".vaultls-tmp-"+a.FileName)
	if err := os.WriteFile(tmp, a.PEM, 0o644); err != nil {
		return fmt.Errorf("write anchor %s: %w", a.FileName, err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod anchor %s: %w", a.FileName, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename anchor %s: %w", a.FileName, err)
	}
	return nil
}
