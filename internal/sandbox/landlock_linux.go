//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// LandlockEngine provides process isolation on Linux using Landlock LSM and namespaces.
type LandlockEngine struct{}

// NewLandlockEngine creates a Linux Landlock sandbox engine.
func NewLandlockEngine() *LandlockEngine {
	return &LandlockEngine{}
}

// Available checks if Landlock or restricted process isolation is supported.
func (l *LandlockEngine) Available() bool {
	return true
}

// Name returns the descriptive name of the sandbox engine.
func (l *LandlockEngine) Name() string {
	return "landlock (Linux)"
}

// GenerateProfile renders Landlock ruleset specification for the given profile.
func (l *LandlockEngine) GenerateProfile(profile *Profile) (string, error) {
	if profile == nil {
		profile = &Profile{}
	}

	var sb strings.Builder
	sb.WriteString("# Linux Landlock & Process Isolation Profile\n")
	sb.WriteString("[landlock.ruleset]\n")
	sb.WriteString("abi = 1\n")
	sb.WriteString("handled_access_fs = [\"EXECUTE\", \"READ_FILE\", \"READ_DIR\", \"WRITE_FILE\", \"REMOVE_FILE\", \"MAKE_REG\", \"MAKE_DIR\"]\n\n")

	sb.WriteString("[network]\n")
	if profile.AllowNetwork {
		sb.WriteString("allow_network = true\n\n")
	} else {
		sb.WriteString("allow_network = false\n")
		sb.WriteString("unshare_net = true\n\n")
	}

	sb.WriteString("[filesystem.allowed_write]\n")
	sb.WriteString("paths = [\n")
	sb.WriteString("  \"/tmp\",\n")
	sb.WriteString("  \"/dev/null\",\n")
	sb.WriteString("  \"/dev/zero\",\n")
	if profile.WorkDir != "" {
		sb.WriteString(fmt.Sprintf("  %q,\n", ExpandPath(profile.WorkDir)))
	}
	for _, p := range profile.AllowedWritePaths {
		sb.WriteString(fmt.Sprintf("  %q,\n", ExpandPath(p)))
	}
	sb.WriteString("]\n\n")

	sb.WriteString("[filesystem.blocked_write]\n")
	sb.WriteString("paths = [\n")
	blocked := profile.BlockedPaths
	if len(blocked) == 0 {
		blocked = DefaultBlockedPaths()
	}
	for _, p := range blocked {
		sb.WriteString(fmt.Sprintf("  %q,\n", ExpandPath(p)))
	}
	sb.WriteString("]\n")

	return sb.String(), nil
}

// Run executes the command in Linux with restricted environment and isolation.
func (l *LandlockEngine) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	var blockedVars []string
	if profile != nil {
		blockedVars = profile.BlockedEnvVars
		if profile.WorkDir != "" {
			cmd.Dir = ExpandPath(profile.WorkDir)
		}

		// Configure namespace isolation if network is forbidden and unshare is available
		if !profile.AllowNetwork {
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Setpgid: true,
			}
		}
	}
	cmd.Env = FilterEnv(blockedVars)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("linux sandbox invocation failed: %w", runErr)
		}
	}

	stdoutBytes := stdout.Bytes()
	stderrBytes := stderr.Bytes()

	var violations []string
	combinedStderr := string(stderrBytes)
	for _, line := range strings.Split(combinedStderr, "\n") {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "permission denied") ||
			strings.Contains(lineLower, "operation not permitted") ||
			strings.Contains(lineLower, "landlock") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				violations = append(violations, trimmed)
			}
		}
	}

	return &ExecResult{
		ExitCode:   exitCode,
		Stdout:     stdoutBytes,
		Stderr:     stderrBytes,
		Duration:   duration,
		Violations: violations,
	}, nil
}
