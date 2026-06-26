package store

import (
	"testing"
)

func TestReadMissingReturnsZero(t *testing.T) {
	s, err := Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read missing: %v", err)
	}
	if s.Serial != "" || s.CertID != 0 {
		t.Fatalf("expected zero state, got %+v", s)
	}
}

func TestWriteThenRead(t *testing.T) {
	dir := t.TempDir()
	want := State{CertID: 123, Serial: "0A1B2C", ValidUntil: 1790000000000, LastCheck: 1782000000000}
	if err := Write(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}
