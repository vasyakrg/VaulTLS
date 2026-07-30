package catrust

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/config"
)

type fakeFetcher struct {
	body []byte
	err  error
}

func (f *fakeFetcher) CABundle(context.Context) ([]byte, error) { return f.body, f.err }

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
