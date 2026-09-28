package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEngineSelection(t *testing.T) {
	eng := NewEngine()
	if eng == nil {
		t.Fatal("NewEngine returned nil")
	}

	if !eng.Available() {
		t.Errorf("NewEngine returned unavailable engine: %s", eng.Name())
	}

	switch runtime.GOOS {
	case "darwin":
		if eng.Name() != "seatbelt (macOS)" && eng.Name() != "fallback (restricted process)" {
			t.Errorf("Unexpected engine on darwin: %s", eng.Name())
		}
	case "linux":
		if eng.Name() != "landlock (Linux)" && eng.Name() != "fallback (restricted process)" {
			t.Errorf("Unexpected engine on linux: %s", eng.Name())
		}
	default:
		if eng.Name() != "fallback (restricted process)" {
			t.Errorf("Unexpected engine on %s: %s", runtime.GOOS, eng.Name())
		}
	}

	// Test NewEngineByName
	autoEng, err := NewEngineByName("auto")
	if err != nil || autoEng == nil {
		t.Fatalf("NewEngineByName(auto) failed: %v", err)
	}

	fallbackEng, err := NewEngineByName("fallback")
	if err != nil || fallbackEng == nil || fallbackEng.Name() != "fallback (restricted process)" {
		t.Fatalf("NewEngineByName(fallback) failed: %v", err)
	}

	_, err = NewEngineByName("non-existent-engine")
	if err == nil {
		t.Error("Expected error for invalid engine name, got nil")
	}
}

func TestSeatbeltProfileRulePrecedence(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt tests only apply to macOS (darwin)")
	}

	sb := NewSeatbeltEngine()
	workDir := "/Users/testuser/project"
	profile := &Profile{
		AllowNetwork:      false,
		WorkDir:           workDir,
		AllowedWritePaths: []string{"/tmp/custom_write"},
		BlockedPaths:      []string{"/Users/testuser/project/.git", "/etc", "/Users/testuser/.ssh"},
		BlockedEnvVars:    []string{"SECRET_KEY"},
	}

	scheme, err := sb.GenerateProfile(profile)
	if err != nil {
		t.Fatalf("GenerateProfile failed: %v", err)
	}

	// 1. Invariant: Specific (deny ...) MUST appear AFTER general (allow ...) rules
	allowWriteIdx := strings.Index(scheme, "(allow file-write*")
	denyWriteIdx := strings.Index(scheme, "(deny file-write*")

	if allowWriteIdx == -1 {
		t.Fatal("Scheme missing (allow file-write*) rule")
	}
	if denyWriteIdx == -1 {
		t.Fatal("Scheme missing (deny file-write*) rule")
	}
	if denyWriteIdx <= allowWriteIdx {
		t.Fatalf("CRITICAL Sentinel Violation: (deny file-write*) at %d appears BEFORE (allow file-write*) at %d",
			denyWriteIdx, allowWriteIdx)
	}

	// 2. Invariant: Subpath wildcard bug check - no subpath with literal *
	lines := strings.Split(scheme, "\n")
	for i, line := range lines {
		if strings.Contains(line, "(subpath") && strings.Contains(line, "*") {
			t.Errorf("CRITICAL Sentinel Violation: Line %d contains invalid wildcard subpath: %s", i+1, line)
		}
	}

	// 3. Network disabled: allow network should not appear
	if strings.Contains(scheme, "(allow network-outbound)") {
		t.Error("Scheme contains (allow network-outbound) when AllowNetwork is false")
	}

	// 4. Test with AllowNetwork = true
	profile.AllowNetwork = true
	schemeWithNet, err := sb.GenerateProfile(profile)
	if err != nil {
		t.Fatalf("GenerateProfile with network failed: %v", err)
	}
	if !strings.Contains(schemeWithNet, "(allow network-outbound)") {
		t.Error("Scheme missing (allow network-outbound) when AllowNetwork is true")
	}
}

func TestEnvironmentVariableFiltering(t *testing.T) {
	// Set test environment variables
	os.Setenv("ARGUS_TEST_SECRET", "super_secret_value")
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("SAFE_VAR", "safe_value")
	defer func() {
		os.Unsetenv("ARGUS_TEST_SECRET")
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("SAFE_VAR")
	}()

	filtered := FilterEnv([]string{"ARGUS_TEST_SECRET", "AWS_ACCESS_KEY_ID"})

	foundSecret := false
	foundAWS := false
	foundSafe := false
	foundArgusSandbox := false

	for _, env := range filtered {
		if strings.HasPrefix(env, "ARGUS_TEST_SECRET=") {
			foundSecret = true
		}
		if strings.HasPrefix(env, "AWS_ACCESS_KEY_ID=") {
			foundAWS = true
		}
		if strings.HasPrefix(env, "SAFE_VAR=") {
			foundSafe = true
		}
		if env == "ARGUS_SANDBOX=1" {
			foundArgusSandbox = true
		}
	}

	if foundSecret {
		t.Error("FilterEnv failed to strip ARGUS_TEST_SECRET")
	}
	if foundAWS {
		t.Error("FilterEnv failed to strip AWS_ACCESS_KEY_ID")
	}
	if !foundSafe {
		t.Error("FilterEnv stripped SAFE_VAR unintentionally")
	}
	if !foundArgusSandbox {
		t.Error("FilterEnv missing ARGUS_SANDBOX=1 marker")
	}
}

func TestFallbackEngineExecution(t *testing.T) {
	fb := NewFallbackEngine()
	if !fb.Available() {
		t.Fatal("FallbackEngine should always be available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	workDir := t.TempDir()
	profile := &Profile{
		WorkDir: workDir,
	}

	res, err := fb.Run(ctx, profile, "echo", "argus_fallback_test")
	if err != nil {
		t.Fatalf("FallbackEngine.Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "argus_fallback_test") {
		t.Errorf("Expected stdout to contain 'argus_fallback_test', got %q", string(res.Stdout))
	}
	if res.Duration <= 0 {
		t.Error("Expected positive execution duration")
	}

	// Test profile generation
	profText, err := fb.GenerateProfile(profile)
	if err != nil {
		t.Fatalf("FallbackEngine.GenerateProfile failed: %v", err)
	}
	if !strings.Contains(profText, "Argus Fallback Isolation Profile") {
		t.Errorf("Fallback profile missing header: %s", profText)
	}
}

func TestDefaultBlockedPathsAndEnvVars(t *testing.T) {
	paths := DefaultBlockedPaths()
	if len(paths) == 0 {
		t.Fatal("DefaultBlockedPaths returned empty slice")
	}

	home, _ := os.UserHomeDir()
	foundSSH := false
	for _, p := range paths {
		if home != "" && p == filepath.Join(home, ".ssh") {
			foundSSH = true
		}
	}
	if home != "" && !foundSSH {
		t.Errorf("DefaultBlockedPaths missing ~/.ssh (%s)", filepath.Join(home, ".ssh"))
	}

	envVars := DefaultBlockedEnvVars()
	if len(envVars) == 0 {
		t.Fatal("DefaultBlockedEnvVars returned empty slice")
	}
	foundAWSEnv := false
	for _, v := range envVars {
		if v == "AWS_ACCESS_KEY_ID" {
			foundAWSEnv = true
		}
	}
	if !foundAWSEnv {
		t.Error("DefaultBlockedEnvVars missing AWS_ACCESS_KEY_ID")
	}
}
