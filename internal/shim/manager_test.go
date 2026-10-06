package shim

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestExtractTargets(t *testing.T) {
	tests := []struct {
		tool            string
		args            []string
		expectedEco     model.Ecosystem
		expectedTargets []string
		expectedInstall bool
	}{
		{
			tool:            "npm",
			args:            []string{"install", "express"},
			expectedEco:     model.EcosystemNPM,
			expectedTargets: []string{"express"},
			expectedInstall: true,
		},
		{
			tool:            "npm",
			args:            []string{"i", "-D", "@types/node", "tslib"},
			expectedEco:     model.EcosystemNPM,
			expectedTargets: []string{"@types/node", "tslib"},
			expectedInstall: true,
		},
		{
			tool:            "npm",
			args:            []string{"test"},
			expectedEco:     "",
			expectedTargets: nil,
			expectedInstall: false,
		},
		{
			tool:            "pip",
			args:            []string{"install", "requests", "numpy"},
			expectedEco:     model.EcosystemPyPI,
			expectedTargets: []string{"requests", "numpy"},
			expectedInstall: true,
		},
		{
			tool:            "pip",
			args:            []string{"install", "-r", "requirements.txt", "flask"},
			expectedEco:     model.EcosystemPyPI,
			expectedTargets: []string{"flask"},
			expectedInstall: true,
		},
		{
			tool:            "cargo",
			args:            []string{"add", "tokio", "--features", "full"},
			expectedEco:     model.EcosystemCargo,
			expectedTargets: []string{"tokio"},
			expectedInstall: true,
		},
		{
			tool:            "cargo",
			args:            []string{"build"},
			expectedEco:     "",
			expectedTargets: nil,
			expectedInstall: false,
		},
		{
			tool:            "go",
			args:            []string{"get", "github.com/gin-gonic/gin@v1.9.1"},
			expectedEco:     model.EcosystemGo,
			expectedTargets: []string{"github.com/gin-gonic/gin@v1.9.1"},
			expectedInstall: true,
		},
		{
			tool:            "gem",
			args:            []string{"install", "rails", "--no-document"},
			expectedEco:     model.EcosystemRubyGems,
			expectedTargets: []string{"rails"},
			expectedInstall: true,
		},
		{
			tool:            "composer",
			args:            []string{"require", "guzzlehttp/guzzle"},
			expectedEco:     model.EcosystemPackagist,
			expectedTargets: []string{"guzzlehttp/guzzle"},
			expectedInstall: true,
		},
	}

	for _, tc := range tests {
		eco, targets, isInstall := ExtractTargets(tc.tool, tc.args)
		if isInstall != tc.expectedInstall {
			t.Errorf("ExtractTargets(%s, %v) isInstall = %v, expected %v", tc.tool, tc.args, isInstall, tc.expectedInstall)
		}
		if eco != tc.expectedEco {
			t.Errorf("ExtractTargets(%s, %v) eco = %v, expected %v", tc.tool, tc.args, eco, tc.expectedEco)
		}
		if !reflect.DeepEqual(targets, tc.expectedTargets) {
			t.Errorf("ExtractTargets(%s, %v) targets = %v, expected %v", tc.tool, tc.args, targets, tc.expectedTargets)
		}
	}
}

func TestShimLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus-shim-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Verify initially empty
	stat0 := Status(tmpDir)
	if len(stat0.Installed) != 0 {
		t.Errorf("expected 0 installed shims, got %d", len(stat0.Installed))
	}
	if len(stat0.Missing) != len(SupportedTools) {
		t.Errorf("expected %d missing shims, got %d", len(SupportedTools), len(stat0.Missing))
	}

	// Install shims
	if err := Install(tmpDir, "/usr/local/bin/argus"); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	stat1 := Status(tmpDir)
	if len(stat1.Installed) != len(SupportedTools) {
		t.Errorf("expected %d installed shims, got %d", len(SupportedTools), len(stat1.Installed))
	}
	if len(stat1.Missing) != 0 {
		t.Errorf("expected 0 missing shims, got %d", len(stat1.Missing))
	}

	// Verify shims are executable
	for _, tool := range SupportedTools {
		path := filepath.Join(tmpDir, tool)
		fi, err := os.Stat(path)
		if err != nil {
			t.Errorf("shim %s missing: %v", tool, err)
			continue
		}
		if runtime.GOOS != "windows" && (fi.Mode()&0111 == 0) {
			t.Errorf("shim %s is not executable", tool)
		}
	}

	// Uninstall shims
	if err := Uninstall(tmpDir); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	stat2 := Status(tmpDir)
	if len(stat2.Installed) != 0 {
		t.Errorf("expected 0 installed shims after uninstall, got %d", len(stat2.Installed))
	}
}

func TestFindRealBinary(t *testing.T) {
	testCmd := "sh"
	if runtime.GOOS == "windows" {
		testCmd = "cmd"
	}
	path, err := FindRealBinary(testCmd, "/fake/shim/dir")
	if err != nil {
		t.Fatalf("FindRealBinary(%q) failed: %v", testCmd, err)
	}
	if path == "" {
		t.Errorf("expected non-empty path for %q", testCmd)
	}
}
