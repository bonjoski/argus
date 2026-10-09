package adversarial

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/ast"
	"bonjoski/argus/internal/gitdiff"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

type mockVCSVerifier struct{}

func (m *mockVCSVerifier) Verify(ctx context.Context, eco model.Ecosystem, pkgName, repoURL string) (*vcs.VCSResult, error) {
	return &vcs.VCSResult{
		Status:        model.VCSStatusVerified,
		RepoURL:       repoURL,
		ManifestFound: true,
		ManifestName:  pkgName,
		AgeMonths:     36,
		CommitsCount:  500,
	}, nil
}

// ADV-19: Source AST & Pre-Commit Slop Sentinel (argus diff and argus scan --ast)
// Verifies:
// 1. Git pre-commit diff interception of hallucinated Python packages (404 on PyPI).
// 2. Clean passage of legitimate packages (e.g. requests) and stdlib exclusion (e.g. os).
// 3. Interception of hallucinated JavaScript/TypeScript dependencies (e.g. express-auth-phantom).
// 4. Interception of hallucinated Go modules (e.g. github.com/phantom/fake-pkg).
// 5. Raw workspace source AST scanning without requiring an existing lockfile.
func TestADV19_DiffSentinel(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Mock Upstream Registries
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// PyPI endpoints
		if strings.HasPrefix(path, "/pypi/") {
			pkgPath := strings.TrimPrefix(path, "/pypi/")
			if strings.HasPrefix(pkgPath, "requests_jwt_validator") {
				http.NotFound(w, r)
				return
			}
			if strings.HasPrefix(pkgPath, "requests") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"info": {
						"name": "requests",
						"version": "2.31.0",
						"author": "Kenneth Reitz",
						"home_page": "https://requests.readthedocs.io",
						"project_urls": {
							"Source": "https://github.com/psf/requests"
						}
					},
					"releases": {
						"1.0.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}],
						"2.30.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}],
						"2.31.0": [
							{
								"filename": "requests-2.31.0-py3-none-any.whl",
								"packagetype": "bdist_wheel",
								"upload_time_iso_8601": "2023-05-22T00:00:00Z",
								"has_sigstore": true,
								"digests": {"sha256": "abcdef123456"}
							}
						]
					}
				}`))
				return
			}
			http.NotFound(w, r)
			return
		}

		// NPM endpoints
		if path == "/express-auth-phantom" {
			http.NotFound(w, r)
			return
		}
		if path == "/express" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "express",
				"dist-tags": {"latest": "4.18.2"},
				"time": {
					"created": "2010-12-29T00:00:00Z",
					"modified": "2023-10-01T00:00:00Z",
					"4.18.2": "2022-10-08T00:00:00Z"
				},
				"versions": {
					"4.18.2": {
						"name": "express",
						"version": "4.18.2",
						"dist": {"integrity": "sha512-clean"}
					}
				}
			}`))
			return
		}

		// Go Proxy endpoints
		if strings.Contains(path, "github.com/phantom/fake-pkg") {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(path, "github.com/gin-gonic/gin") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("v1.9.1\n"))
			return
		}

		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	// 2. Setup Adapters and VettingService
	pypiAdapter := registry.NewPyPIAdapter(mockServer.Client())
	pypiAdapter.SetBaseURL(mockServer.URL + "/pypi")

	npmAdapter := registry.NewNPMAdapter(mockServer.Client())
	npmAdapter.SetRegistryURL(mockServer.URL)

	goAdapter := registry.NewGoModAdapter(mockServer.Client())
	goAdapter.SetProxyURL(mockServer.URL)

	adapters := []registry.Adapter{pypiAdapter, npmAdapter, goAdapter}
	evaluator := heuristics.DefaultEngine()
	mockVCS := &mockVCSVerifier{}
	vettingService := service.NewVettingService(nil, adapters, mockVCS, evaluator, 24*time.Hour)

	// Helper function to evaluate candidates and compute exit code
	evaluateCandidates := func(cands []ast.ImportCandidate) (blockedCount int, warningCount int, reports []*model.RiskReport) {
		for _, cand := range cands {
			rep, err := vettingService.Vet(ctx, cand.Ecosystem, cand.PackageName, "")
			if err != nil {
				// Registry 404 / resolution error marks candidate as critical phantom package
				rep = &model.RiskReport{
					Package:         cand.PackageName,
					Ecosystem:       cand.Ecosystem,
					ResolvedVersion: "phantom",
					TotalScore:      85,
					RiskLevel:       model.RiskLevelCritical,
					Penalties: []model.HeuristicFinding{
						{
							RuleID:      "HR-05A",
							Name:        "Phantom / Unresolved Dependency",
							Points:      85,
							Description: fmt.Sprintf("Failed to resolve from upstream: %v", err),
							Triggered:   true,
						},
					},
				}
			}
			reports = append(reports, rep)
			if rep.TotalScore >= 50 || rep.RiskLevel == model.RiskLevelCritical {
				blockedCount++
			} else if rep.TotalScore >= 30 {
				warningCount++
			}
		}
		return blockedCount, warningCount, reports
	}

	// 3. Initialize Git Test Repository
	repoDir := t.TempDir()
	initCmd := exec.Command("git", "init", repoDir)
	if err := initCmd.Run(); err != nil {
		t.Fatalf("failed to git init: %v", err)
	}
	_ = exec.Command("git", "-C", repoDir, "config", "user.email", "adversarial@argus.security").Run()
	_ = exec.Command("git", "-C", repoDir, "config", "user.name", "Adversarial Sentinel").Run()
	_ = exec.Command("git", "-C", repoDir, "config", "commit.gpgsign", "false").Run()

	// Initial clean baseline commit
	baseFile := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(baseFile, []byte("# Initial Project\n"), 0644); err != nil {
		t.Fatalf("failed to write base file: %v", err)
	}
	_ = exec.Command("git", "-C", repoDir, "add", "README.md").Run()
	_ = exec.Command("git", "-C", repoDir, "commit", "--no-gpg-sign", "--no-verify", "-m", "initial commit").Run()

	// --- Subtest 1: Hallucinated Python package in staged git diff ---
	t.Run("Python_Hallucinated_Diff_Blocked", func(t *testing.T) {
		pyFile := filepath.Join(repoDir, "service.py")
		code := `import os
import requests_jwt_validator

def authenticate():
    pass
`
		if err := os.WriteFile(pyFile, []byte(code), 0644); err != nil {
			t.Fatalf("failed to write pyFile: %v", err)
		}
		_ = exec.Command("git", "-C", repoDir, "add", "service.py").Run()

		cands, err := gitdiff.InspectDiff(ctx, nil, repoDir, true)
		if err != nil {
			t.Fatalf("InspectDiff failed: %v", err)
		}

		if len(cands) != 1 {
			t.Fatalf("expected 1 non-stdlib candidate, got %d: %+v", len(cands), cands)
		}
		if cands[0].PackageName != "requests_jwt_validator" {
			t.Fatalf("expected candidate requests_jwt_validator, got %s", cands[0].PackageName)
		}

		blockedCount, _, reports := evaluateCandidates(cands)
		if blockedCount == 0 {
			t.Fatalf("ADV-19 FAILED: expected hallucinated Python package to be blocked (exit 1), but passed: %+v", reports)
		}
		t.Logf("ADV-19 Succeeded: Hallucinated Python package blocked with risk score %d/100 (%s)",
			reports[0].TotalScore, reports[0].RiskLevel)
	})

	// --- Subtest 2: Valid Python import and Stdlib pass cleanly ---
	t.Run("Python_Valid_And_Stdlib_Allowed", func(t *testing.T) {
		// Clean up staged file
		_ = exec.Command("git", "-C", repoDir, "reset", "HEAD", "service.py").Run()
		_ = os.Remove(filepath.Join(repoDir, "service.py"))

		cleanFile := filepath.Join(repoDir, "clean.py")
		code := `import os
import sys
import requests

def fetch():
    return requests.get("https://example.com")
`
		if err := os.WriteFile(cleanFile, []byte(code), 0644); err != nil {
			t.Fatalf("failed to write cleanFile: %v", err)
		}
		_ = exec.Command("git", "-C", repoDir, "add", "clean.py").Run()

		cands, err := gitdiff.InspectDiff(ctx, nil, repoDir, true)
		if err != nil {
			t.Fatalf("InspectDiff failed: %v", err)
		}

		if len(cands) != 1 {
			t.Fatalf("expected exactly 1 candidate (requests), got %d: %+v", len(cands), cands)
		}
		if cands[0].PackageName != "requests" {
			t.Fatalf("expected candidate requests, got %s", cands[0].PackageName)
		}

		blockedCount, warningCount, _ := evaluateCandidates(cands)
		if blockedCount > 0 || warningCount > 0 {
			t.Fatalf("ADV-19 FAILED: legitimate requests should pass with Exit Code 0, got blocked=%d, warnings=%d",
				blockedCount, warningCount)
		}
		t.Log("ADV-19 Succeeded: Legitimate requests + os stdlib passed cleanly with Exit Code 0")
	})

	// --- Subtest 3: Hallucinated JavaScript/TypeScript package ---
	t.Run("JavaScript_Hallucinated_Require_Blocked", func(t *testing.T) {
		_ = exec.Command("git", "-C", repoDir, "reset", "HEAD", "clean.py").Run()
		_ = os.Remove(filepath.Join(repoDir, "clean.py"))

		jsFile := filepath.Join(repoDir, "auth.js")
		code := `const path = require('path');
const phantom = require('express-auth-phantom');

module.exports = { phantom };
`
		if err := os.WriteFile(jsFile, []byte(code), 0644); err != nil {
			t.Fatalf("failed to write jsFile: %v", err)
		}
		_ = exec.Command("git", "-C", repoDir, "add", "auth.js").Run()

		cands, err := gitdiff.InspectDiff(ctx, nil, repoDir, true)
		if err != nil {
			t.Fatalf("InspectDiff failed: %v", err)
		}

		if len(cands) != 1 {
			t.Fatalf("expected 1 candidate, got %d: %+v", len(cands), cands)
		}
		if cands[0].PackageName != "express-auth-phantom" {
			t.Fatalf("expected express-auth-phantom, got %s", cands[0].PackageName)
		}

		blockedCount, _, reports := evaluateCandidates(cands)
		if blockedCount == 0 {
			t.Fatalf("ADV-19 FAILED: expected express-auth-phantom to be blocked, got: %+v", reports)
		}
		t.Logf("ADV-19 Succeeded: Hallucinated JS dependency blocked with score %d/100 (%s)",
			reports[0].TotalScore, reports[0].RiskLevel)
	})

	// --- Subtest 4: Hallucinated Go module in staged diff ---
	t.Run("Go_Hallucinated_Module_Blocked", func(t *testing.T) {
		_ = exec.Command("git", "-C", repoDir, "reset", "HEAD", "auth.js").Run()
		_ = os.Remove(filepath.Join(repoDir, "auth.js"))

		goFile := filepath.Join(repoDir, "main.go")
		code := `package main

import (
	"fmt"
	"github.com/phantom/fake-pkg"
)

func main() {
	fmt.Println("test")
}
`
		if err := os.WriteFile(goFile, []byte(code), 0644); err != nil {
			t.Fatalf("failed to write goFile: %v", err)
		}
		_ = exec.Command("git", "-C", repoDir, "add", "main.go").Run()

		cands, err := gitdiff.InspectDiff(ctx, nil, repoDir, true)
		if err != nil {
			t.Fatalf("InspectDiff failed: %v", err)
		}

		if len(cands) != 1 {
			t.Fatalf("expected 1 candidate, got %d: %+v", len(cands), cands)
		}
		if cands[0].PackageName != "github.com/phantom/fake-pkg" {
			t.Fatalf("expected github.com/phantom/fake-pkg, got %s", cands[0].PackageName)
		}

		blockedCount, _, reports := evaluateCandidates(cands)
		if blockedCount == 0 {
			t.Fatalf("ADV-19 FAILED: expected hallucinated Go module to be blocked, got: %+v", reports)
		}
		t.Logf("ADV-19 Succeeded: Hallucinated Go module blocked with score %d/100 (%s)",
			reports[0].TotalScore, reports[0].RiskLevel)
	})

	// --- Subtest 5: argus scan --ast recursive directory scan ---
	t.Run("AST_Directory_Scan", func(t *testing.T) {
		workDir := t.TempDir()

		// Write multiple source files
		_ = os.WriteFile(filepath.Join(workDir, "a.py"), []byte("import requests_jwt_validator\nimport os\n"), 0644)
		_ = os.WriteFile(filepath.Join(workDir, "b.ts"), []byte("import { x } from 'express-auth-phantom';\n"), 0644)
		_ = os.WriteFile(filepath.Join(workDir, "c.go"), []byte("package p\nimport \"github.com/phantom/fake-pkg\"\n"), 0644)

		var extractedCands []ast.ImportCandidate
		for _, f := range []string{"a.py", "b.ts", "c.go"} {
			c, err := ast.ExtractImportsFromFile(filepath.Join(workDir, f))
			if err != nil {
				t.Fatalf("failed to extract imports from %s: %v", f, err)
			}
			extractedCands = append(extractedCands, c...)
		}

		if len(extractedCands) != 3 {
			t.Fatalf("expected 3 extracted candidates from AST scan, got %d: %+v", len(extractedCands), extractedCands)
		}

		blockedCount, _, _ := evaluateCandidates(extractedCands)
		if blockedCount != 3 {
			t.Fatalf("ADV-19 FAILED: expected all 3 hallucinated dependencies to be blocked by AST scanner, got %d", blockedCount)
		}
		t.Log("ADV-19 Succeeded: Full AST directory scanner intercepted all 3 cross-ecosystem phantom packages")
	})
}
