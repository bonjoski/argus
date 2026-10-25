package gitdiff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DiffFindingSeverity represents how dangerous a diff change is.
type DiffFindingSeverity string

const (
	DiffSeverityCritical DiffFindingSeverity = "CRITICAL"
	DiffSeverityHigh     DiffFindingSeverity = "HIGH"
	DiffSeverityMedium   DiffFindingSeverity = "MEDIUM"
	DiffSeverityLow      DiffFindingSeverity = "LOW"
)

// DiffFinding represents a single weaponization finding in a workspace diff.
type DiffFinding struct {
	File        string              `json:"file"`
	Severity    DiffFindingSeverity `json:"severity"`
	Category    string              `json:"category"`
	Description string              `json:"description"`
}

// DiffAuditReport contains the aggregated findings of a workspace diff audit.
type DiffAuditReport struct {
	Allowed  bool          `json:"allowed"`
	Findings []DiffFinding `json:"findings"`
}

// SemanticDiffAuditor inspects workspace diffs for delayed host execution traps and weaponized artifacts.
type SemanticDiffAuditor struct {
	baseDir string
}

// NewSemanticDiffAuditor creates a new SemanticDiffAuditor.
func NewSemanticDiffAuditor(baseDir string) *SemanticDiffAuditor {
	return &SemanticDiffAuditor{baseDir: baseDir}
}

// AuditFiles inspects a list of added and modified relative file paths inside targetDir.
func (a *SemanticDiffAuditor) AuditFiles(ctx context.Context, targetDir string, changedFiles []string) (*DiffAuditReport, error) {
	report := &DiffAuditReport{
		Allowed:  true,
		Findings: make([]DiffFinding, 0),
	}

	if targetDir == "" {
		targetDir = a.baseDir
	}
	if targetDir == "" {
		targetDir = "."
	}

	for _, rel := range changedFiles {
		fullPath := filepath.Join(targetDir, rel)
		fi, err := os.Lstat(fullPath)
		if err != nil {
			// If file does not exist on disk, we still audit path patterns
			a.auditPathPattern(rel, report)
			continue
		}

		// 1. Path pattern inspection
		a.auditPathPattern(rel, report)

		// 2. Node.js package.json lifecycle hooks
		if filepath.Base(rel) == "package.json" {
			if findings := checkPackageJSONHooks(fullPath); len(findings) > 0 {
				report.Findings = append(report.Findings, findings...)
			}
		}

		// 3. Compiled binaries / executable headers
		if fi.Mode().IsRegular() {
			if fi.Mode().Perm()&0111 != 0 {
				report.Findings = append(report.Findings, DiffFinding{
					File:        rel,
					Severity:    DiffSeverityMedium,
					Category:    "Executable-Permissions",
					Description: fmt.Sprintf("File %s has executable bit set (0%o)", rel, fi.Mode().Perm()),
				})
			}

			// Read first 4 bytes for binary magic headers
			if isBinaryExecutable(fullPath) {
				report.Findings = append(report.Findings, DiffFinding{
					File:        rel,
					Severity:    DiffSeverityCritical,
					Category:    "Binary-Drop",
					Description: fmt.Sprintf("File %s contains executable binary magic header (ELF/Mach-O/PE)", rel),
				})
			}
		}
	}

	for _, f := range report.Findings {
		if f.Severity == DiffSeverityCritical || f.Severity == DiffSeverityHigh {
			report.Allowed = false
			break
		}
	}

	return report, nil
}

// auditPathPattern checks known dangerous configuration and build traps based on path.
func (a *SemanticDiffAuditor) auditPathPattern(rel string, report *DiffAuditReport) {
	relLower := strings.ToLower(rel)

	// Git configuration/submodule traps
	if relLower == ".gitmodules" {
		report.Findings = append(report.Findings, DiffFinding{
			File:        rel,
			Severity:    DiffSeverityCritical,
			Category:    "Git-Persistence",
			Description: "Modification to .gitmodules can trigger arbitrary command execution during git submodule update",
		})
	}
	if relLower == ".gitattributes" {
		report.Findings = append(report.Findings, DiffFinding{
			File:        rel,
			Severity:    DiffSeverityHigh,
			Category:    "Git-Smudge-Filter",
			Description: "Modification to .gitattributes can register custom smudge/clean filter scripts",
		})
	}

	// CI/CD workflow modifications
	if strings.HasPrefix(rel, ".github/workflows/") || strings.HasPrefix(rel, ".gitlab-ci.yml") {
		report.Findings = append(report.Findings, DiffFinding{
			File:        rel,
			Severity:    DiffSeverityHigh,
			Category:    "CI-Poisoning",
			Description: "Modification to CI/CD pipeline definition files can trigger supply chain token theft upon push",
		})
	}

	// IDE auto-run tasks (.vscode/tasks.json or .vscode/launch.json)
	if rel == ".vscode/tasks.json" || rel == ".vscode/launch.json" {
		report.Findings = append(report.Findings, DiffFinding{
			File:        rel,
			Severity:    DiffSeverityHigh,
			Category:    "IDE-AutoRun",
			Description: "Modification to VS Code task/launch definitions can trigger automated execution when opened in editor",
		})
	}

	// Rust build.rs build script
	if filepath.Base(rel) == "build.rs" {
		report.Findings = append(report.Findings, DiffFinding{
			File:        rel,
			Severity:    DiffSeverityHigh,
			Category:    "Build-Script-Execution",
			Description: "Addition of Rust build.rs script executes native code unconditionally during cargo build",
		})
	}
}

// AuditDiffStream analyzes raw unified diff stream lines for weaponized changes.
func (a *SemanticDiffAuditor) AuditDiffStream(r io.Reader) (*DiffAuditReport, error) {
	report := &DiffAuditReport{
		Allowed:  true,
		Findings: make([]DiffFinding, 0),
	}

	fileDiffs, err := ParseDiff(r)
	if err != nil {
		return nil, fmt.Errorf("failed parsing diff: %w", err)
	}

	for _, fd := range fileDiffs {
		a.auditPathPattern(fd.Path, report)

		if filepath.Base(fd.Path) == "package.json" {
			// Check if any added line in package.json touches dangerous hooks
			dangerousHooks := []string{"preinstall", "postinstall", "prepare", "prepack", "prepublish"}
			for _, al := range fd.AddedLines {
				for _, hook := range dangerousHooks {
					if strings.Contains(al.Content, `"`+hook+`"`) {
						report.Findings = append(report.Findings, DiffFinding{
							File:        fd.Path,
							Severity:    DiffSeverityCritical,
							Category:    "Supply-Chain-Lifecycle-Hook",
							Description: fmt.Sprintf("package.json diff introduces suspicious %q lifecycle hook: %s", hook, strings.TrimSpace(al.Content)),
						})
					}
				}
			}
		}
	}

	for _, f := range report.Findings {
		if f.Severity == DiffSeverityCritical || f.Severity == DiffSeverityHigh {
			report.Allowed = false
			break
		}
	}

	return report, nil
}

func checkPackageJSONHooks(filePath string) []DiffFinding {
	var findings []DiffFinding
	data, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings
	}

	dangerousHooks := []string{"preinstall", "postinstall", "prepare", "prepack", "prepublish"}
	for _, hook := range dangerousHooks {
		if cmd, ok := pkg.Scripts[hook]; ok && strings.TrimSpace(cmd) != "" {
			findings = append(findings, DiffFinding{
				File:        filePath,
				Severity:    DiffSeverityCritical,
				Category:    "Supply-Chain-Lifecycle-Hook",
				Description: fmt.Sprintf("package.json defines suspicious %q lifecycle hook: %s", hook, cmd),
			})
		}
	}

	return findings
}

func isBinaryExecutable(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 4)
	n, err := f.Read(header)
	if err != nil || n < 4 {
		return false
	}

	// ELF: \x7fELF
	if bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'}) {
		return true
	}
	// Mach-O 32/64 bit and Fat: \xfe\xed\xfa\xce, \xfe\xed\xfa\xcf, \xce\xfa\xed\xfe, \xcf\xfa\xed\xfe, \xca\xfe\xba\xbe
	machOMagics := [][]byte{
		{0xfe, 0xed, 0xfa, 0xce},
		{0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe},
		{0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
	}
	for _, m := range machOMagics {
		if bytes.Equal(header, m) {
			return true
		}
	}
	// Windows PE: MZ
	if header[0] == 'M' && header[1] == 'Z' {
		return true
	}

	return false
}
