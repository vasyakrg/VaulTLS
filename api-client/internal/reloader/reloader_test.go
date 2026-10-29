package reloader

import (
	"bytes"
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

func TestRunAttachedStreamsBothStreams(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := RunAttached(context.Background(), "echo to-out; echo to-err >&2", &out, &errOut); err != nil {
		t.Fatalf("RunAttached = %v", err)
	}
	if !strings.Contains(out.String(), "to-out") || !strings.Contains(errOut.String(), "to-err") {
		t.Fatalf("output not streamed to its writer: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRunAttachedStreamsOutputEvenOnFailure(t *testing.T) {
	var out, errOut bytes.Buffer
	err := RunAttached(context.Background(), "echo boom; false", &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("expected failure error, got %v", err)
	}
	if !strings.Contains(out.String(), "boom") {
		t.Fatalf("output must still reach the writer on failure, got %q", out.String())
	}
}

func TestRunAttachedEmptyIsNoop(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := RunAttached(context.Background(), "  ", &out, &errOut); err != nil {
		t.Fatalf("empty command should be no-op, got %v", err)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("no-op must write nothing, got stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
