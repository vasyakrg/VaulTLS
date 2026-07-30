package catrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadStateMissingFileIsZero(t *testing.T) {
	got, err := ReadState(t.TempDir())
	if err != nil {
		t.Fatalf("missing state must not be an error: %v", err)
	}
	if len(got.Certs) != 0 || got.PendingUpdate || got.LastSync != 0 {
		t.Fatalf("got %+v, want zero state", got)
	}
}

func TestWriteReadStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := State{
		Certs:         map[string]string{"abc123": "vaultls-root-abc123.crt"},
		PendingUpdate: true,
		LastSync:      1753848000000,
	}
	if err := WriteState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Certs["abc123"] != want.Certs["abc123"] || !got.PendingUpdate || got.LastSync != want.LastSync {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	fi, err := os.Stat(filepath.Join(dir, "ca-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestReadStateRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca-trust.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(dir); err == nil {
		t.Fatal("expected error for corrupt state")
	}
}
