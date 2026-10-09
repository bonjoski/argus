package version

import "fmt"

var (
	// Version is the single source of truth for the Argus release version.
	Version = "v0.6.0"

	// GitCommit is injected at build time via -ldflags.
	GitCommit = "none"

	// BuildDate is injected at build time via -ldflags.
	BuildDate = "unknown"
)

// Formatted returns the human-readable version string including commit and build timestamp.
func Formatted() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
}
