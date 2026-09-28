//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SeatbeltEngine implements process isolation on macOS using sandbox-exec and SBPL.
type SeatbeltEngine struct{}

// NewSeatbeltEngine creates a macOS Seatbelt sandbox engine.
func NewSeatbeltEngine() *SeatbeltEngine {
	return &SeatbeltEngine{}
}

// Available checks if the sandbox-exec binary is accessible on macOS.
func (s *SeatbeltEngine) Available() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

// Name returns the descriptive name of the sandbox engine.
func (s *SeatbeltEngine) Name() string {
	return "seatbelt (macOS)"
}

// GenerateProfile renders minimal-privilege Scheme syntax adhering to Sentinel precedence rules.
func (s *SeatbeltEngine) GenerateProfile(profile *Profile) (string, error) {
	if profile == nil {
		profile = &Profile{}
	}

	var sb strings.Builder

	// 1. SBPL Header: Default Deny Baseline
	sb.WriteString("(version 1)\n(deny default)\n\n")

	// 2. Core Execution and Kernel Interfaces
	sb.WriteString(";; 1. Core Execution and Process Management\n")
	sb.WriteString("(allow process-exec*)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow signal (target self))\n\n")

	// 3. Read Permissions
	sb.WriteString(";; 2. Read Access Permissions\n")
	sb.WriteString("(allow file-read*)\n\n")

	// 4. Network Permissions
	if profile.AllowNetwork {
		sb.WriteString(";; 3. Network Outbound and Inbound Allowed\n")
		sb.WriteString("(allow network-outbound)\n")
		sb.WriteString("(allow network-inbound)\n")
		sb.WriteString("(allow system-socket)\n\n")
	}

	// 5. Allowed Write Paths (ALLOW FIRST)
	sb.WriteString(";; 4. Allowed Filesystem Write Paths (General/Broad Allows)\n")
	sb.WriteString("(allow file-write*\n")
	sb.WriteString("    (literal \"/dev/null\")\n")
	sb.WriteString("    (literal \"/dev/zero\")\n")
	sb.WriteString("    (literal \"/dev/dtracehelper\")\n")
	sb.WriteString("    (literal \"/dev/tty\")\n")
	sb.WriteString("    (literal \"/dev/stdout\")\n")
	sb.WriteString("    (literal \"/dev/stderr\")\n")
	sb.WriteString("    (subpath \"/tmp\")\n")
	sb.WriteString("    (subpath \"/private/tmp\")\n")
	sb.WriteString("    (subpath \"/var/folders\")\n")
	sb.WriteString("    (subpath \"/private/var/folders\")\n")

	allowedWrites := make(map[string]struct{})
	if profile.WorkDir != "" {
		for _, resolved := range ResolveAllPaths(profile.WorkDir) {
			if _, exists := allowedWrites[resolved]; !exists {
				allowedWrites[resolved] = struct{}{}
				sb.WriteString(fmt.Sprintf("    (subpath %q)\n", resolved))
			}
		}
	}

	for _, p := range profile.AllowedWritePaths {
		for _, resolved := range ResolveAllPaths(p) {
			if _, exists := allowedWrites[resolved]; !exists {
				allowedWrites[resolved] = struct{}{}
				sb.WriteString(fmt.Sprintf("    (subpath %q)\n", resolved))
			}
		}
	}
	sb.WriteString(")\n\n")

	// 6. CRITICAL Sentinel Rule: Specific (deny ...) MUST appear AFTER general (allow ...) rules!
	sb.WriteString(";; 5. CRITICAL Sentinel Rule Precedence: Specific Denials MUST Appear AFTER Broad Allows\n")
	sb.WriteString("(deny file-write*\n")

	// Protect .git repository inside workdir or allowed directories
	if profile.WorkDir != "" {
		for _, resolved := range ResolveAllPaths(profile.WorkDir) {
			sb.WriteString(fmt.Sprintf("    (subpath %q)\n", filepath.Join(resolved, ".git")))
		}
	}

	blockedPaths := profile.BlockedPaths
	if len(blockedPaths) == 0 {
		blockedPaths = DefaultBlockedPaths()
	}

	seenBlocked := make(map[string]struct{})
	for _, p := range blockedPaths {
		for _, resolved := range ResolveAllPaths(p) {
			if _, exists := seenBlocked[resolved]; !exists {
				seenBlocked[resolved] = struct{}{}
				sb.WriteString(fmt.Sprintf("    (subpath %q)\n", resolved))
			}
		}
	}
	sb.WriteString(")\n\n")

	// 7. Protect Sensitive Credentials from Read Access
	sb.WriteString(";; 6. Credential Read Denials\n")
	sb.WriteString("(deny file-read*\n")
	if profile.WorkDir != "" {
		for _, resolved := range ResolveAllPaths(profile.WorkDir) {
			sb.WriteString(fmt.Sprintf("    (subpath %q)\n", filepath.Join(resolved, ".env")))
		}
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		for _, resolvedHome := range ResolveAllPaths(home) {
			sb.WriteString(fmt.Sprintf("    (subpath %q)\n", filepath.Join(resolvedHome, ".ssh")))
			sb.WriteString(fmt.Sprintf("    (subpath %q)\n", filepath.Join(resolvedHome, ".aws")))
			sb.WriteString(fmt.Sprintf("    (subpath %q)\n", filepath.Join(resolvedHome, ".gnupg")))
		}
	}
	sb.WriteString("    (subpath \"/Library/Keychains\")\n")
	sb.WriteString(")\n")

	return sb.String(), nil
}

// Run executes the given command within a macOS Seatbelt sandbox.
func (s *SeatbeltEngine) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	if !s.Available() {
		return nil, errors.New("seatbelt engine is not available: sandbox-exec not found")
	}

	scheme, err := s.GenerateProfile(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seatbelt profile: %w", err)
	}

	execArgs := append([]string{"-p", scheme, command}, args...)
	cmd := exec.CommandContext(ctx, "sandbox-exec", execArgs...)

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
			return nil, fmt.Errorf("sandbox-exec invocation failed: %w", runErr)
		}
	}

	stdoutBytes := stdout.Bytes()
	stderrBytes := stderr.Bytes()

	var violations []string
	combinedStderr := string(stderrBytes)
	for _, line := range strings.Split(combinedStderr, "\n") {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "operation not permitted") ||
			strings.Contains(lineLower, "permission denied") ||
			strings.Contains(lineLower, "sandbox-exec:") ||
			strings.Contains(lineLower, "sandbox violation") {
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
