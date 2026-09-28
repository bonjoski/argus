package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FallbackEngine provides baseline process isolation and environment filtering.
type FallbackEngine struct{}

// NewFallbackEngine creates a fallback process isolation engine.
func NewFallbackEngine() *FallbackEngine {
	return &FallbackEngine{}
}

// Available always returns true as process execution is supported universally.
func (f *FallbackEngine) Available() bool {
	return true
}

// Name returns the descriptive name of the sandbox engine.
func (f *FallbackEngine) Name() string {
	return "fallback (restricted process)"
}

// GenerateProfile renders a human-readable security policy profile.
func (f *FallbackEngine) GenerateProfile(profile *Profile) (string, error) {
	if profile == nil {
		profile = &Profile{}
	}

	var sb strings.Builder
	sb.WriteString("# Argus Fallback Isolation Profile\n")
	sb.WriteString(fmt.Sprintf("allow_network = %v\n", profile.AllowNetwork))
	if profile.WorkDir != "" {
		sb.WriteString(fmt.Sprintf("work_dir = %q\n", ExpandPath(profile.WorkDir)))
	}
	sb.WriteString("allowed_write_paths = [\n")
	for _, p := range profile.AllowedWritePaths {
		sb.WriteString(fmt.Sprintf("  %q,\n", ExpandPath(p)))
	}
	sb.WriteString("]\n")

	sb.WriteString("blocked_paths = [\n")
	blocked := profile.BlockedPaths
	if len(blocked) == 0 {
		blocked = DefaultBlockedPaths()
	}
	for _, p := range blocked {
		sb.WriteString(fmt.Sprintf("  %q,\n", ExpandPath(p)))
	}
	sb.WriteString("]\n")

	sb.WriteString("blocked_env_vars = [\n")
	envVars := profile.BlockedEnvVars
	if len(envVars) == 0 {
		envVars = DefaultBlockedEnvVars()
	}
	for _, v := range envVars {
		sb.WriteString(fmt.Sprintf("  %q,\n", v))
	}
	sb.WriteString("]\n")

	return sb.String(), nil
}

// Run executes the command with stripped environment variables and bounded working directory.
func (f *FallbackEngine) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	var blockedVars []string
	if profile != nil {
		blockedVars = profile.BlockedEnvVars
		if profile.WorkDir != "" {
			cmd.Dir = ExpandPath(profile.WorkDir)
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
			return nil, fmt.Errorf("fallback command execution failed: %w", runErr)
		}
	}

	stdoutBytes := stdout.Bytes()
	stderrBytes := stderr.Bytes()

	var violations []string
	combinedStderr := string(stderrBytes)
	for _, line := range strings.Split(combinedStderr, "\n") {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "permission denied") ||
			strings.Contains(lineLower, "operation not permitted") {
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
