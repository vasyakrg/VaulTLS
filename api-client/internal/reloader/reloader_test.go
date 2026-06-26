package reloader

import (
	"context"
	"strings"
	"testing"
)

func TestRunSuccess(t *testing.T) {
	if err := Run(context.Background(), "true"); err != nil {
		t.Fatalf("Run(true) = %v", err)
	}
}

func TestRunFailureIncludesOutput(t *testing.T) {
	err := Run(context.Background(), "echo boom >&2; false")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error containing output, got %v", err)
	}
}

func TestRunEmptyIsNoop(t *testing.T) {
	if err := Run(context.Background(), ""); err != nil {
		t.Fatalf("empty command should be no-op, got %v", err)
	}
}
