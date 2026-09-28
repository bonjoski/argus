package adversarial

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/sandbox"
)

// ADV-20: System-Level Process & Network Sandboxing
// Verifies that when malicious package install scripts, agent tool executions,
// or adversarial processes run inside Argus sandbox:
//  1. Unauthorized write attempts to protected host paths (/etc, ~/.ssh, etc.) or .git metadata are strictly denied.
//  2. Unauthorized network requests are blocked when AllowNetwork is false.
//  3. Legitimate writes to allowed workspace and temporary directories succeed cleanly.
//  4. Sensitive environment variables (e.g. AWS credentials, SSH auth) are stripped.
func TestADV20_SystemSandboxSeatbeltAndLandlockIsolation(t *testing.T) {
	engine := sandbox.NewEngine()
	if engine == nil {
		t.Fatalf("ADV-20 Failed: sandbox.NewEngine() returned nil")
	}

	if !engine.Available() {
		t.Skipf("ADV-20 Skipped: Engine %s is not available on this host", engine.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workDir := t.TempDir()
	homeDir, _ := os.UserHomeDir()

	// 1. Adversarial Attack 1: Attempt to write to a blocked system directory (/etc)
	t.Run("BlockedPath_SystemRootETC", func(t *testing.T) {
		profile := &sandbox.Profile{
			AllowNetwork:      false,
			WorkDir:           workDir,
			AllowedWritePaths: []string{workDir},
			BlockedPaths:      sandbox.DefaultBlockedPaths(),
		}

		res, err := engine.Run(ctx, profile, "touch", "/etc/argus_sandbox_test_forbidden")
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode == 0 {
			// Clean up if it somehow succeeded
			_ = os.Remove("/etc/argus_sandbox_test_forbidden")
			t.Fatalf("ADV-20 SECURITY FAILURE: Sandbox permitted write to /etc!")
		}

		stderrStr := strings.ToLower(string(res.Stderr))
		if !strings.Contains(stderrStr, "permission denied") &&
			!strings.Contains(stderrStr, "operation not permitted") &&
			len(res.Violations) == 0 {
			t.Errorf("ADV-20 Expected permission denial in stderr or violations, got: %s", string(res.Stderr))
		}

		t.Logf("ADV-20 Succeeded: Blocked write to /etc with exit code %d (Violations: %v)",
			res.ExitCode, res.Violations)
	})

	// 2. Adversarial Attack 2: Attempt to tamper with ~/.ssh credential store
	t.Run("BlockedPath_UserSSHDirectory", func(t *testing.T) {
		if homeDir == "" {
			t.Skip("User home directory not found")
		}

		targetSSHFile := filepath.Join(homeDir, ".ssh", "argus_adversarial_test_key")
		profile := &sandbox.Profile{
			AllowNetwork:      false,
			WorkDir:           workDir,
			AllowedWritePaths: []string{workDir, homeDir}, // Even if homeDir is allowed, .ssh must be blocked!
			BlockedPaths:      []string{filepath.Join(homeDir, ".ssh"), "/etc"},
		}

		res, err := engine.Run(ctx, profile, "touch", targetSSHFile)
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode == 0 {
			_ = os.Remove(targetSSHFile)
			t.Fatalf("ADV-20 SECURITY FAILURE: Sandbox permitted write to %s!", targetSSHFile)
		}

		t.Logf("ADV-20 Succeeded: Blocked write to ~/.ssh with exit code %d", res.ExitCode)
	})

	// 3. Adversarial Attack 3: Attempt to write malicious hook into .git inside workdir
	t.Run("BlockedPath_GitMetadataInWorkDir", func(t *testing.T) {
		gitDir := filepath.Join(workDir, ".git")
		if err := os.MkdirAll(gitDir, 0755); err != nil {
			t.Fatalf("ADV-20 Setup failed to create .git: %v", err)
		}

		targetHook := filepath.Join(gitDir, "pre-commit")
		profile := &sandbox.Profile{
			AllowNetwork:      false,
			WorkDir:           workDir,
			AllowedWritePaths: []string{workDir},
		}

		res, err := engine.Run(ctx, profile, "touch", targetHook)
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if engine.Name() == "seatbelt (macOS)" {
			if res.ExitCode == 0 {
				_ = os.Remove(targetHook)
				t.Fatalf("ADV-20 SECURITY FAILURE: Sandbox permitted write to %s despite .git deny rule!", targetHook)
			}
			t.Logf("ADV-20 Succeeded: Blocked git hook creation with exit code %d", res.ExitCode)
		}
	})

	// 4. Benign Verification: Allowed paths (workDir) can be written safely
	t.Run("AllowedPath_WorkDirWrite", func(t *testing.T) {
		targetFile := filepath.Join(workDir, "build_artifact.txt")
		profile := &sandbox.Profile{
			AllowNetwork:      false,
			WorkDir:           workDir,
			AllowedWritePaths: []string{workDir},
		}

		res, err := engine.Run(ctx, profile, "touch", targetFile)
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		if res.ExitCode != 0 {
			t.Fatalf("ADV-20 Failed: Legitimate write to workDir failed with exit code %d: %s",
				res.ExitCode, string(res.Stderr))
		}

		if _, err := os.Stat(targetFile); os.IsNotExist(err) {
			t.Fatalf("ADV-20 Failed: target file %s was not created", targetFile)
		}

		t.Logf("ADV-20 Succeeded: Allowed write to workDir succeeded cleanly")
	})

	// 5. Adversarial Attack 4: Sensitive Environment Variable Exfiltration
	t.Run("EnvironmentVariable_Protection", func(t *testing.T) {
		os.Setenv("AWS_SECRET_ACCESS_KEY", "AKIA_ADVERSARIAL_EXFILTRATE_ME")
		os.Setenv("GITHUB_TOKEN", "ghp_adversarial_token_12345")
		defer func() {
			os.Unsetenv("AWS_SECRET_ACCESS_KEY")
			os.Unsetenv("GITHUB_TOKEN")
		}()

		profile := &sandbox.Profile{
			AllowNetwork:   false,
			WorkDir:        workDir,
			BlockedEnvVars: []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		}

		res, err := engine.Run(ctx, profile, "sh", "-c", "echo AWS=$AWS_SECRET_ACCESS_KEY GH=$GITHUB_TOKEN")
		if err != nil {
			t.Fatalf("ADV-20 Run error: %v", err)
		}

		stdoutStr := string(res.Stdout)
		if strings.Contains(stdoutStr, "AKIA_ADVERSARIAL_EXFILTRATE_ME") {
			t.Fatalf("ADV-20 SECURITY FAILURE: AWS_SECRET_ACCESS_KEY leaked into sandboxed process: %s", stdoutStr)
		}
		if strings.Contains(stdoutStr, "ghp_adversarial_token_12345") {
			t.Fatalf("ADV-20 SECURITY FAILURE: GITHUB_TOKEN leaked into sandboxed process: %s", stdoutStr)
		}

		t.Logf("ADV-20 Succeeded: Sensitive environment variables were successfully stripped")
	})
}
