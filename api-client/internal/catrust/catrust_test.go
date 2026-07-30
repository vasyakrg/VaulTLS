package catrust

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

type fakeFetcher struct {
	body []byte
	err  error
	hits int
}

func (f *fakeFetcher) CABundle(context.Context) ([]byte, error) {
	f.hits++
	return f.body, f.err
}

type fakeRunner struct {
	calls int
	err   error
}

func (r *fakeRunner) Run(context.Context, string) error {
	r.calls++
	return r.err
}

func fixedClock() time.Time { return time.Unix(1753848000, 0) }

type harness struct {
	anchorDir string
	stateDir  string
	cfg       config.CATrust
	fetcher   *fakeFetcher
	runner    *fakeRunner
}

func newHarness(t *testing.T, body []byte) *harness {
	t.Helper()
	anchor := t.TempDir()
	return &harness{
		anchorDir: anchor,
		stateDir:  t.TempDir(),
		cfg:       config.CATrust{Enabled: true, AnchorDir: anchor, UpdateCommand: "update-ca-certificates"},
		fetcher:   &fakeFetcher{body: body},
		runner:    &fakeRunner{},
	}
}

func (h *harness) sync(ctx context.Context) (Result, error) {
	return Sync(ctx, h.fetcher, h.runner, h.cfg, h.stateDir, fixedClock)
}

func anchorNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestSyncInstallsAnchors(t *testing.T) {
	body := append(selfSigned(t, "Root A"), selfSigned(t, "Root B")...)
	h := newHarness(t, body)

	res, err := h.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Installed != 2 || !res.Changed {
		t.Fatalf("res = %+v, want 2 installed and changed", res)
	}
	if names := anchorNames(t, h.anchorDir); len(names) != 2 {
		t.Fatalf("anchor dir holds %v, want 2 files", names)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Certs) != 2 || st.PendingUpdate || st.LastSync != fixedClock().UnixMilli() {
		t.Fatalf("state = %+v", st)
	}
}

func TestSyncSecondRunIsNoop(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.runner.calls = 0

	res, err := h.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("unchanged bundle must not report a change")
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command called %d times on a no-op run", h.runner.calls)
	}
}

func TestSyncRemovesRetiredAnchor(t *testing.T) {
	oldCA := selfSigned(t, "Root Old")
	h := newHarness(t, oldCA)
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := anchorNames(t, h.anchorDir)

	h.fetcher.body = selfSigned(t, "Root New")
	h.runner.calls = 0
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := anchorNames(t, h.anchorDir)
	if len(after) != 1 {
		t.Fatalf("anchor dir holds %v, want exactly the new anchor", after)
	}
	if after[0] == before[0] {
		t.Fatal("retired CA still trusted")
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
}

func TestSyncRestoresDeletedAnchor(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	name := anchorNames(t, h.anchorDir)[0]
	if err := os.Remove(filepath.Join(h.anchorDir, name)); err != nil {
		t.Fatal(err)
	}
	h.runner.calls = 0

	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.anchorDir, name)); err != nil {
		t.Fatalf("anchor not restored: %v", err)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command called %d times, want 1", h.runner.calls)
	}
}

func TestSyncLeavesForeignAnchorsAlone(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	foreign := filepath.Join(h.anchorDir, "other-corp.crt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.fetcher.body = selfSigned(t, "Root B")
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign anchor was removed: %v", err)
	}
}

func TestSyncRejectsGarbageWithoutTouchingDisk(t *testing.T) {
	h := newHarness(t, []byte("definitely not a pem"))

	_, err := h.sync(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageParse {
		t.Fatalf("err = %v, want a parse-stage Error", err)
	}
	if names := anchorNames(t, h.anchorDir); len(names) != 0 {
		t.Fatalf("anchor dir touched: %v", names)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command called %d times", h.runner.calls)
	}
}

// occupy replaces path with a non-empty directory, so os.WriteFile, os.Rename
// and os.Remove all refuse to work through it. It is the injection used to
// provoke real write/rename/remove failures inside Sync and writeAnchor.
func occupy(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A crash between writeAnchor's os.WriteFile and its os.Rename must not leave
// behind a file the platform trust tooling will enumerate. Debian's
// update-ca-certificates collects local anchors with
//
//	find -L "$LOCALCERTSDIR" -type f -name '*.crt'
//
// which matches dot-prefixed names perfectly well, so a leading dot buys
// nothing there: what keeps the leftover out of its view is the name not
// ending in the anchor extension. The failure is provoked for real (the rename
// target is occupied by a non-empty directory) so the assertion is made about
// the name writeAnchor actually used, not one the test re-derived.
func TestWriteAnchorCrashLeftoverIsInvisibleToTrustTooling(t *testing.T) {
	dir := t.TempDir()
	anchors, err := ParseBundle(selfSigned(t, "Root A"), ".crt")
	if err != nil {
		t.Fatal(err)
	}
	a := anchors[0]
	occupy(t, filepath.Join(dir, a.FileName))

	if err := writeAnchor(dir, a); err == nil {
		t.Fatal("test setup: expected the rename onto an occupied path to fail")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var leftovers []string
	for _, e := range entries {
		if e.Name() == a.FileName {
			continue // the blocker directory
		}
		leftovers = append(leftovers, e.Name())
	}
	if len(leftovers) != 1 {
		t.Fatalf("anchor dir leftovers = %v, want exactly the half-written temp file", leftovers)
	}
	name := leftovers[0]
	for _, ext := range []string{".crt", ".pem"} {
		if strings.Contains(name, ext) {
			t.Fatalf("crash leftover %q carries %q: `find -name '*%s'` and p11-kit both read it", name, ext, ext)
		}
		if ok, _ := filepath.Match("*"+ext, name); ok {
			t.Fatalf("crash leftover %q matches update-ca-certificates' `-name '*%s'` glob", name, ext)
		}
	}
}

// p11-kit's loader_load_directory walks source/anchors with readdir and pushes
// every entry — no dot-file filter, no extension filter — so on RHEL no naming
// scheme can hide a half-written anchor from the trust store. A leftover has to
// actually be deleted, which means a run that is about to write must first
// sweep its own stale temp files out of the anchor directory.
func TestSyncSweepsStaleTempAnchors(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	// ".vaultls-tmp-" spelled out rather than taken from the constant: this is
	// the on-disk name a crashed previous run leaves, and the sweep has to keep
	// recognising it.
	stale := filepath.Join(h.anchorDir, ".vaultls-tmp-vaultls-root-old-deadbeef")
	if err := os.WriteFile(stale, []byte("-----BEGIN CERTIFICATE-----\nhalf writ"), 0o644); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(h.anchorDir, "other-corp.crt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale temp anchor survived the sync (stat err = %v); p11-kit parses it on RHEL", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("sweep removed a foreign anchor: %v", err)
	}
}

// A write failure partway through a multi-anchor sync (e.g. ENOSPC) must not
// lose track of the anchors already written: otherwise they sit on disk,
// trusted, but recorded nowhere — invisible to the retire logic and to purge
// cleanup. The failure is injected by occupying the second anchor's final path
// with a non-empty directory, which os.Rename refuses to replace.
func TestSyncWriteFailureLeavesPartialStateRecorded(t *testing.T) {
	body := append(selfSigned(t, "Root A"), selfSigned(t, "Root B")...)
	h := newHarness(t, body)

	anchors, err := ParseBundle(body, h.cfg.FileExt())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("test setup: got %d anchors, want 2", len(anchors))
	}
	occupy(t, filepath.Join(h.anchorDir, anchors[1].FileName))

	_, err = h.sync(context.Background())
	if err == nil {
		t.Fatal("expected error from blocked anchor write")
	}
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageWrite {
		t.Fatalf("err = %v, want a write-stage Error", err)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command must not run when a write fails, got %d calls", h.runner.calls)
	}

	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Certs) != 1 || st.Certs[anchors[0].Fingerprint] != anchors[0].FileName {
		t.Fatalf("state = %+v, want the successfully written anchor recorded", st)
	}
}

// Same failure, but starting from a NON-EMPTY prior state whose CA the new
// bundle retires. The write loop runs before the removal loop, so at the moment
// of the failure the prior anchor is still on disk and still un-retired.
// Persisting only the anchors of the current bundle written so far therefore
// drops it from the state file — and the state file is the sole record of
// ownership, so that file can never be retired by the agent and is never seen
// by purge cleanup. It stays trusted on the host forever.
func TestSyncWriteFailureKeepsPriorOwnership(t *testing.T) {
	oldBody := selfSigned(t, "Root Old A")
	h := newHarness(t, oldBody)
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldAnchors, err := ParseBundle(oldBody, h.cfg.FileExt())
	if err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(h.anchorDir, oldAnchors[0].FileName)
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("test setup: first sync did not install the old anchor: %v", err)
	}

	newBody := selfSigned(t, "Root New")
	newAnchors, err := ParseBundle(newBody, h.cfg.FileExt())
	if err != nil {
		t.Fatal(err)
	}
	// The new bundle retires Root Old A; block the new anchor's rename target so
	// the write loop aborts before the removal loop ever runs.
	occupy(t, filepath.Join(h.anchorDir, newAnchors[0].FileName))
	h.fetcher.body = newBody
	h.runner.calls = 0

	_, err = h.sync(context.Background())
	if err == nil {
		t.Fatal("expected error from blocked anchor write")
	}
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageWrite {
		t.Fatalf("err = %v, want a write-stage Error", err)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command must not run when a write fails, got %d calls", h.runner.calls)
	}
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("test setup: the retired anchor should still be on disk: %v", err)
	}

	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Certs[oldAnchors[0].Fingerprint] != oldAnchors[0].FileName {
		t.Fatalf("anchor %s still on disk but dropped from state: %+v", oldAnchors[0].FileName, st)
	}
}

// A retire-loop failure (e.g. EPERM on os.Remove) must not lose ownership of
// anchors it never got to remove: they are still on disk and must stay
// tracked, or they become untracked-but-trusted forever. The failure is
// injected by turning one retired anchor into a non-empty directory, which
// os.Remove refuses to delete.
func TestSyncRemovalFailureKeepsUnremovedAnchorsTracked(t *testing.T) {
	oldA := selfSigned(t, "Root Old A")
	oldB := selfSigned(t, "Root Old B")
	h := newHarness(t, append(append([]byte{}, oldA...), oldB...))
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Certs) != 2 {
		t.Fatalf("test setup: state = %+v, want 2 anchors", before)
	}

	// Block removal of one of the two: swap the file for a non-empty directory.
	var blockedName string
	for _, name := range before.Certs {
		blockedName = name
		break
	}
	occupy(t, filepath.Join(h.anchorDir, blockedName))

	newBody := selfSigned(t, "Root New")
	h.fetcher.body = newBody
	h.runner.calls = 0
	_, err = h.sync(context.Background())
	if err == nil {
		t.Fatal("expected error from blocked anchor removal")
	}
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageWrite {
		t.Fatalf("err = %v, want a write-stage Error", err)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command must not run when removal fails, got %d calls", h.runner.calls)
	}

	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	// The write loop ran to completion before the removal loop failed, so the
	// new anchor is on disk; it must be tracked too, or it becomes an
	// untracked-but-trusted anchor exactly like the old ones this test guards.
	newAnchors, err := ParseBundle(newBody, h.cfg.FileExt())
	if err != nil {
		t.Fatal(err)
	}
	if st.Certs[newAnchors[0].Fingerprint] != newAnchors[0].FileName {
		t.Fatalf("newly written anchor lost from state: %+v", st)
	}
	// Anything still physically on disk from the old set must still be tracked;
	// blockedName in particular can never have been removed (os.Remove refuses
	// a non-empty directory), so it must always be among them.
	sawBlocked := false
	for fp, name := range before.Certs {
		if _, statErr := os.Stat(filepath.Join(h.anchorDir, name)); statErr != nil {
			continue // successfully removed
		}
		if name == blockedName {
			sawBlocked = true
		}
		if st.Certs[fp] != name {
			t.Fatalf("anchor %s still on disk but lost from state: %+v", name, st.Certs)
		}
	}
	if !sawBlocked {
		t.Fatal("test setup: blocked anchor should still be on disk")
	}
}

// Sync must enforce the default-off invariant itself, not rely on every
// caller checking cfg.Enabled first.
func TestSyncDisabledIsNoop(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	h.cfg.Enabled = false

	res, err := h.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res != (Result{}) {
		t.Fatalf("res = %+v, want zero Result", res)
	}
	if h.fetcher.hits != 0 {
		t.Fatalf("disabled config must not call the server (hits=%d)", h.fetcher.hits)
	}
	if names := anchorNames(t, h.anchorDir); len(names) != 0 {
		t.Fatalf("anchor dir touched while disabled: %v", names)
	}
	if h.runner.calls != 0 {
		t.Fatalf("update command called %d times while disabled", h.runner.calls)
	}
}

func TestSyncFetchErrorIsStaged(t *testing.T) {
	h := newHarness(t, nil)
	h.fetcher.err = errors.New("connection refused")

	_, err := h.sync(context.Background())
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageFetch {
		t.Fatalf("err = %v, want a fetch-stage Error", err)
	}
}

// A failed update command must leave pending_update set so the next run retries
// it instead of concluding the fingerprint set already matches.
func TestSyncRetriesFailedUpdateCommand(t *testing.T) {
	h := newHarness(t, selfSigned(t, "Root A"))
	h.runner.err = errors.New("update-ca-certificates: exit 1")

	_, err := h.sync(context.Background())
	var se *Error
	if !errors.As(err, &se) || se.Stage != StageUpdate {
		t.Fatalf("err = %v, want an update-stage Error", err)
	}
	st, err := ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.PendingUpdate {
		t.Fatal("pending_update must stay set after a failed update command")
	}

	h.runner.err = nil
	h.runner.calls = 0
	if _, err := h.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.runner.calls != 1 {
		t.Fatalf("update command retried %d times, want 1", h.runner.calls)
	}
	st, err = ReadState(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PendingUpdate {
		t.Fatal("pending_update must clear after a successful update command")
	}
}
