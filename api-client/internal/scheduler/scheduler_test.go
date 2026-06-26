package scheduler

import (
	"testing"
	"time"
)

func TestParseSpecValid(t *testing.T) {
	if _, err := ParseSpec("0 3 1 * *"); err != nil {
		t.Fatalf("ParseSpec valid: %v", err)
	}
}

func TestParseSpecInvalid(t *testing.T) {
	if _, err := ParseSpec("not a cron"); err == nil {
		t.Fatal("expected error for invalid spec")
	}
}

func TestNextWithJitterAddsOffset(t *testing.T) {
	s, _ := ParseSpec("0 3 1 * *")
	from := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	base := s.Next(from)
	got := NextWithJitter(s, from, time.Hour, func() float64 { return 0.5 })
	want := base.Add(30 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("NextWithJitter = %v, want %v", got, want)
	}
}

func TestNextWithJitterZero(t *testing.T) {
	s, _ := ParseSpec("0 3 1 * *")
	from := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	got := NextWithJitter(s, from, 0, func() float64 { return 0.9 })
	if !got.Equal(s.Next(from)) {
		t.Fatal("zero jitter must equal base next")
	}
}
