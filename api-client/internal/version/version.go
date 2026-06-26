package version

// Version is overridden at build time via -ldflags "-X .../version.Version=...".
var Version = "dev"

// String returns a human-readable build identifier.
func String() string {
	return "vaultls-agent " + Version
}
