package version

import "testing"

func TestStringIncludesVersion(t *testing.T) {
	Version = "1.2.3"
	if got := String(); got != "vaultls-agent 1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "vaultls-agent 1.2.3")
	}
}
