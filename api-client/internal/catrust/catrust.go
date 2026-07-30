package catrust

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	// A crashed earlier run can have left a half-written anchor behind. p11-kit
	// parses every entry under source/anchors regardless of its name, so the
	// leftover has to actually be deleted before this run writes.
	if err := sweepStaleTempAnchors(cfg.AnchorDir); err != nil {
		return Result{}, &Error{StageWrite, err}
	}
	next := State{Certs: make(map[string]string, len(anchors)), LastSync: prev.LastSync, PendingUpdate: true}
	for _, a := range anchors {
		if err := writeAnchor(cfg.AnchorDir, a); err != nil {
			// Two sets of files are on disk right now: the anchors of this bundle
			// written before the failure, and every anchor from the previous run —
			// the removal loop below has not run yet, so even the ones this bundle
			// retires are still there. The state file is the only record of
			// ownership, so persisting just `next` would orphan the previous run's
			// files: nothing could ever retire them and purge cleanup would never
			// see them. Persist the union instead, exactly as the removal path
			// does. Best effort: if this write also fails there is nothing more we
			// can do, and the original error is what matters to the caller.
			_ = WriteState(stateDir, union(prev, next))
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

// union returns next with every prev entry it does not already carry folded
// back in: the record of what this run installed plus everything the previous
// run left on disk. Used on the failure paths, where the removal loop has not
// finished (or not started), so no prev file can be assumed gone.
func union(prev, next State) State {
	out := State{
		Certs:         make(map[string]string, len(prev.Certs)+len(next.Certs)),
		LastSync:      next.LastSync,
		PendingUpdate: next.PendingUpdate,
	}
	for fp, name := range prev.Certs {
		out.Certs[fp] = name
	}
	for fp, name := range next.Certs {
		out.Certs[fp] = name
	}
	return out
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

// tempAnchorPrefix marks the half-written files writeAnchor renames into place.
// It doubles as the sweep's ownership test, so only files the agent itself
// created are ever deleted by sweepStaleTempAnchors.
const tempAnchorPrefix = ".vaultls-tmp-"

// sweepStaleTempAnchors deletes half-written anchors a crashed earlier run left
// between writeAnchor's write and its rename.
//
// This is not belt-and-braces: p11-kit's loader_load_directory (trust/token.c)
// pushes every readdir entry with no dot-file and no extension filter, and
// p11_parse_file then sniffs the content rather than the name. So on RHEL no
// choice of temp name can keep a leftover out of the trust store — it has to
// actually be removed, and this is the only place that can do it.
func sweepStaleTempAnchors(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("scan anchor dir: %w", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), tempAnchorPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove stale temp anchor %s: %w", e.Name(), err)
		}
	}
	return nil
}

// writeAnchor writes one anchor atomically. Mode 0644: CA certificates are
// public, and every local TLS client has to be able to read them.
//
// The temp name drops the anchor extension: Debian's update-ca-certificates
// enumerates local anchors with `find -L "$LOCALCERTSDIR" -type f -name
// '*.crt'`, and find's -name uses fnmatch without FNM_PERIOD, so a leading dot
// does NOT hide anything from it — only the missing .crt does. RHEL's p11-kit
// reads every entry under source/anchors whatever it is called, so nothing in
// the name helps there and sweepStaleTempAnchors handles that side instead.
// The dot prefix survives merely to keep the file out of casual `ls` output.
//
// The temp file stays in the same directory as final, so the rename is a
// same-filesystem atomic replace.
func writeAnchor(dir string, a Anchor) error {
	final := filepath.Join(dir, a.FileName)
	base := strings.TrimSuffix(a.FileName, filepath.Ext(a.FileName))
	tmp := filepath.Join(dir, tempAnchorPrefix+base)
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
