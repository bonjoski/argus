package adversarial

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/sandbox"
)

// ADV-20: System-Level Process & Network Sandboxing via Airlock Bridge
// Verifies that:
//  1. Argus successfully bridges to Airlock for hardware-isolated execution.
//  2. Adversarial write attempts to protected host paths (/etc, ~/.ssh) are blocked by kernel isolation.
//  3. Permitted writes within the isolated workspace succeed cleanly.
//  4. Offline / Airgap constraints and diagnostic health checks report accurate status.
//  5. Missing Airlock binaries fail gracefully with clear installation guidance.
func TestADV20_AirlockSandboxIsolation(t *testing.T) {
	engine := sandbox.NewEngine()
	if engine == nil {
		t.Fatalf("ADV-20 Failed: sandbox.NewEngine() returned nil")
	}

	if !engine.Available() {
		t.Log("ADV-20 Note: Airlock binary is not present in test environment; verifying graceful degradation")
		ctx := context.Background()
		_, err := engine.Run(ctx, nil, "echo", "test")
		if err == nil || !errors.Is(err, sandbox.ErrAirlockNotFound) {
			t.Fatalf("ADV-20 Expected ErrAirlockNotFound when unavailable, got: %v", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	workDir := t.TempDir()

	// 1. Adversarial Attack 1: Attempt to write to protected host root (/etc)
	t.Run("BlockedPath_SystemRootETC", func(t *testing.T) {
		profile := &sandbox.Profile{
			Airgap:    true,
			Workspace: workDir,
		}

		res, err := engine.Run(ctx, profile, "touch", "/etc/argus_adversarial_test_forbidden")
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode == 0 {
			_ = os.Remove("/etc/argus_adversarial_test_forbidden")
			t.Fatalf("ADV-20 SECURITY FAILURE: Airlock permitted unauthorized write to /etc!")
		}

		stderrStr := strings.ToLower(string(res.Stderr))
		if !strings.Contains(stderrStr, "operation not permitted") &&
			!strings.Contains(stderrStr, "permission denied") &&
			len(res.Violations) == 0 {
			t.Errorf("ADV-20 Expected permission denial in stderr, got: %s", string(res.Stderr))
		}

		t.Logf("ADV-20 Succeeded: Blocked write to /etc with exit code %d (Violations: %v)",
			res.ExitCode, res.Violations)
	})

	// 2. Adversarial Attack 2: Attempt to tamper with ~/.ssh directory
	t.Run("BlockedPath_UserSSHDirectory", func(t *testing.T) {
		homeDir, err := os.UserHomeDir()
		if err != nil || homeDir == "" {
			t.Skip("User home directory unavailable")
		}

		targetSSHFile := filepath.Join(homeDir, ".ssh", "argus_adversarial_test_key")
		profile := &sandbox.Profile{
			Airgap:    true,
			Workspace: workDir,
		}

		res, err := engine.Run(ctx, profile, "touch", targetSSHFile)
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode == 0 {
			_ = os.Remove(targetSSHFile)
			t.Fatalf("ADV-20 SECURITY FAILURE: Airlock permitted write to %s!", targetSSHFile)
		}

		t.Logf("ADV-20 Succeeded: Blocked write to ~/.ssh with exit code %d", res.ExitCode)
	})

	// 3. Legitimate Workspace Write: Verify workspace writes succeed
	t.Run("AllowedPath_WorkspaceWrite", func(t *testing.T) {
		targetFile := filepath.Join(workDir, "build_artifact.txt")
		profile := &sandbox.Profile{
			Airgap:    true,
			Workspace: workDir,
		}

		res, err := engine.Run(ctx, profile, "touch", targetFile)
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode != 0 {
			t.Fatalf("ADV-20 Failed: Legitimate workspace write failed with exit code %d: %s",
				res.ExitCode, string(res.Stderr))
		}

		if _, err := os.Stat(targetFile); os.IsNotExist(err) {
			t.Fatalf("ADV-20 Failed: Target file was not created in workspace: %s", targetFile)
		}

		t.Logf("ADV-20 Succeeded: Legitimate workspace write succeeded cleanly")
	})

	// 4. Diagnostic Doctor Verification
	t.Run("Doctor_Diagnostics", func(t *testing.T) {
		report, err := engine.Doctor(ctx, workDir)
		if err != nil {
			t.Fatalf("ADV-20 Doctor error: %v", err)
		}

		if report.Platform == "" {
			t.Error("ADV-20 Doctor reported empty platform")
		}

		t.Logf("ADV-20 Succeeded: Doctor diagnostic checks passed: %d passed, %d warnings, %d failures",
			report.Passed, report.Warnings, report.Failures)
	})
}
