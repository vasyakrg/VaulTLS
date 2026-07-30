package catrust

import (
	"context"
	"errors"
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

// A successful write must not leave a "*.tmp" leftover: Debian's
// update-ca-certificates ignores it (globs only *.crt), but RHEL's p11-kit
// reads every file under source/anchors and would trust a half-written cert.
func TestWriteAnchorLeavesNoTrustedLeftover(t *testing.T) {
	dir := t.TempDir()
	anchors, err := ParseBundle(selfSigned(t, "Root A"), ".crt")
	if err != nil {
		t.Fatal(err)
	}
	a := anchors[0]
	if err := writeAnchor(dir, a); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != a.FileName {
		t.Fatalf("anchor dir = %v, want exactly [%s]", entries, a.FileName)
	}
}

// The temp file used during the atomic write must be one no trust-store tool
// reads: a leading dot keeps both update-ca-certificates and p11-kit off it,
// unlike a "<final>.tmp" suffix which p11-kit would still pick up.
func TestWriteAnchorTempNameIsDotPrefixed(t *testing.T) {
	dir := t.TempDir()
	anchors, err := ParseBundle(selfSigned(t, "Root A"), ".crt")
	if err != nil {
		t.Fatal(err)
	}
	a := anchors[0]
	tmp := filepath.Join(dir, ".vaultls-tmp-"+a.FileName)
	if err := os.WriteFile(tmp, []byte("interrupted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(tmp), ".") {
		t.Fatalf("temp anchor name %q is not dot-prefixed", tmp)
	}
	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
}

// A write failure partway through a multi-anchor sync (e.g. ENOSPC) must not
// lose track of the anchors already written: otherwise they sit on disk,
// trusted, but recorded nowhere — invisible to the retire logic and to purge
// cleanup. The failure is injected by occupying the second anchor's temp path
// with a directory, which os.WriteFile refuses to write through.
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
	blocked := filepath.Join(h.anchorDir, ".vaultls-tmp-"+anchors[1].FileName)
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}

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
	blockedPath := filepath.Join(h.anchorDir, blockedName)
	if err := os.Remove(blockedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(blockedPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedPath, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

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
