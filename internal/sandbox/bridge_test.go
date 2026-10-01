package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFindAirlock(t *testing.T) {
	bin, found := FindAirlock()
	if !found {
		t.Log("FindAirlock: no binary detected in standard paths or PATH (expected in isolated CI environments)")
		return
	}
	if bin == "" {
		t.Fatal("FindAirlock reported true but returned empty string")
	}
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("Stat on found binary failed: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("Found binary is a directory: %s", bin)
	}
	t.Logf("Found Airlock binary at: %s", bin)
}

func TestAirlockBridge_Unavailable(t *testing.T) {
	bridge := &AirlockBridge{binaryPath: ""}
	if bridge.Available() {
		t.Error("expected bridge with empty binary path to report Available() == false")
	}
	if bridge.Name() != "airlock" {
		t.Errorf("expected engine name 'airlock', got %q", bridge.Name())
	}

	ctx := context.Background()
	_, err := bridge.Run(ctx, nil, "echo", "test")
	if err == nil || !strings.Contains(err.Error(), "airlock binary not found") {
		t.Errorf("expected ErrAirlockNotFound error from Run(), got: %v", err)
	}

	_, err = bridge.Doctor(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "airlock binary not found") {
		t.Errorf("expected ErrAirlockNotFound error from Doctor(), got: %v", err)
	}

	_, err = bridge.Version(ctx)
	if err == nil || !strings.Contains(err.Error(), "airlock binary not found") {
		t.Errorf("expected ErrAirlockNotFound error from Version(), got: %v", err)
	}
}

func TestAirlockBridge_Execution(t *testing.T) {
	engine := NewEngine()
	if !engine.Available() {
		t.Skip("Airlock binary not available on host; skipping execution test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Test Version
	ver, err := engine.Version(ctx)
	if err != nil {
		t.Fatalf("Version failed: %v", err)
	}
	if !strings.Contains(ver, "Airlock") {
		t.Errorf("expected version output to contain 'Airlock', got: %s", ver)
	}
	t.Logf("Airlock version: %s", ver)

	// 2. Test Doctor
	report, err := engine.Doctor(ctx, "")
	if err != nil {
		t.Fatalf("Doctor failed: %v", err)
	}
	if report.Platform == "" {
		t.Error("Doctor report has empty platform")
	}
	t.Logf("Doctor report: Healthy=%v, Passed=%d, Warnings=%d, Failures=%d",
		report.Healthy, report.Passed, report.Warnings, report.Failures)

	// 3. Test Run with clean command
	tmpDir := t.TempDir()
	profile := &Profile{
		Airgap:    true,
		Workspace: tmpDir,
	}

	res, err := engine.Run(ctx, profile, "/bin/echo", "hello", "from", "bridge")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d (stderr: %s)", res.ExitCode, string(res.Stderr))
	}
	if !strings.Contains(string(res.Stdout), "hello from bridge") {
		t.Errorf("expected stdout 'hello from bridge', got: %s", string(res.Stdout))
	}

	// 4. Test Adversarial Write Restriction
	res2, err := engine.Run(ctx, profile, "touch", "/etc/argus_bridge_adversarial_forbidden")
	if err != nil {
		t.Fatalf("Run error on adversarial write: %v", err)
	}
	if res2.ExitCode == 0 {
		_ = os.Remove("/etc/argus_bridge_adversarial_forbidden")
		t.Fatal("SECURITY FAILURE: Airlock permitted write to /etc!")
	}
	t.Logf("Airlock blocked /etc write with exit code %d (Violations: %v)", res2.ExitCode, res2.Violations)
}

func TestNewBridge_CustomPath(t *testing.T) {
	engine := NewBridge("/nonexistent/path/to/airlock")
	if engine.BinaryPath() == "/nonexistent/path/to/airlock" {
		t.Error("expected non-existent custom path to fall back to detected engine")
	}

	// Test valid custom binary if available
	if detectedBin, found := FindAirlock(); found {
		engine2 := NewBridge(detectedBin)
		if engine2.BinaryPath() != detectedBin {
			rel, _ := filepath.Rel(".", detectedBin)
			if engine2.BinaryPath() != detectedBin && engine2.BinaryPath() != rel {
				t.Errorf("expected %s, got %s", detectedBin, engine2.BinaryPath())
			}
		}
	}
}
