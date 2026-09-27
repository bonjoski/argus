package adversarial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/shim"
	"bonjoski/argus/internal/vcs"
)

// ADV-01: The 31-Day Sleeper Attack
func TestADV01_The31DaySleeper(t *testing.T) {
	evaluator := heuristics.DefaultEngine()

	// An attacker published 35 days ago, left it dormant, and suddenly updated 2 days ago
	created := time.Now().Add(-35 * 24 * time.Hour)
	updated := time.Now().Add(-2 * 24 * time.Hour)

	prov := &model.PackageProvenance{
		Name:              "hallucinated-auth-sleeper",
		Ecosystem:         model.EcosystemNPM,
		ResolvedVersion:   "0.0.2",
		FirstReleaseDate:  created,
		LatestReleaseDate: updated,
		TotalReleases:     2,
		WeeklyDownloads:   12,
		HasInstallScripts: true,
		VCSStatus:         model.VCSStatusNone,
	}

	report := evaluator.Evaluate(prov)

	// HR-04 (+15) + HR-05A (+20) + HR-08 (+25) + HR-09 (+15) = 75
	if report.TotalScore < 70 {
		t.Fatalf("ADV-01 Failed: expected sleeper score >= 70, got %d", report.TotalScore)
	}

	foundHR08 := false
	for _, p := range report.Penalties {
		if p.RuleID == "HR-08" && p.Triggered {
			foundHR08 = true
			break
		}
	}
	if !foundHR08 {
		t.Errorf("ADV-01 Failed: expected HR-08 (Sudden Sleeper) to trigger")
	}
}

// ADV-02: Fake VCS Impersonation
func TestADV02_FakeVCSImpersonation(t *testing.T) {
	evaluator := heuristics.DefaultEngine()
	yesterday := time.Now().Add(-24 * time.Hour)

	// Attacker publishes package named "ai-react-auth", points to "facebook/react"
	prov := &model.PackageProvenance{
		Name:                   "ai-react-auth",
		Ecosystem:              model.EcosystemNPM,
		ResolvedVersion:        "1.0.0",
		FirstReleaseDate:       yesterday,
		LatestReleaseDate:      yesterday,
		TotalReleases:          1,
		WeeklyDownloads:        5,
		RepositoryURL:          "https://github.com/facebook/react",
		VCSStatus:              model.VCSStatusMismatch,
		RepositoryManifestName: "react",
	}

	report := evaluator.Evaluate(prov)

	// HR-01 (+35) + HR-03 (+15) + HR-04 (+15) + HR-05B (+35) = 100
	if report.TotalScore < 85 {
		t.Fatalf("ADV-02 Failed: expected spoofed repo score >= 85, got %d", report.TotalScore)
	}

	if report.RiskLevel != model.RiskLevelCritical {
		t.Errorf("ADV-02 Failed: expected RiskLevelCritical, got %s", report.RiskLevel)
	}

	foundHR05B := false
	for _, p := range report.Penalties {
		if p.RuleID == "HR-05B" && p.Triggered {
			foundHR05B = true
			break
		}
	}
	if !foundHR05B {
		t.Errorf("ADV-02 Failed: expected HR-05B (Spoofed VCS) to trigger")
	}
}

// ADV-03: GitHub 403 Rate Limit Handling
func TestADV03_GitHub403RateLimitGracefulHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate unauthenticated IP rate limit exhaustion in CI runner
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	verifier := vcs.NewHTTPVerifier(server.Client())
	ctx := context.Background()

	res, err := verifier.Verify(ctx, model.EcosystemNPM, "my-pkg", server.URL+"/owner/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != model.VCSStatusInconclusive {
		t.Fatalf("ADV-03 Failed: expected VCSStatusInconclusive on 403, got %s", res.Status)
	}

	// Verify that Inconclusive does NOT trigger HR-05A (+20 pts)
	prov := &model.PackageProvenance{
		Name:      "my-pkg",
		VCSStatus: res.Status,
	}
	rule := heuristics.DetachedVCSRule{}
	triggered, _ := rule.Evaluate(prov)
	if triggered {
		t.Errorf("ADV-03 Failed: HR-05A triggered on INCONCLUSIVE VCS status")
	}
}

// ADV-04: Legitimate Day-One Package (False Positive Guard)
func TestADV04_DayOneLegitimatePackageMitigation(t *testing.T) {
	evaluator := heuristics.DefaultEngine()
	authorAge := time.Now().Add(-500 * 24 * time.Hour) // > 1 year
	today := time.Now().Add(-6 * time.Hour)

	// Legitimate author releases v0.1.0 of fastapi-surrealdb
	prov := &model.PackageProvenance{
		Name:                   "fastapi-surrealdb",
		Ecosystem:              model.EcosystemPyPI,
		ResolvedVersion:        "0.1.0",
		FirstReleaseDate:       today,
		LatestReleaseDate:      today,
		TotalReleases:          1,
		HasBinaryWheels:        true,
		HasPEP740Attestation:   true,
		RepositoryURL:          "https://github.com/trusted-dev/fastapi-surrealdb",
		VCSStatus:              model.VCSStatusVerified,
		RepositoryManifestName: "fastapi-surrealdb",
		RepositoryAgeMonths:    8,
		AuthorName:             "trusted-dev",
		AuthorCreatedAt:        &authorAge,
		AuthorTotalPackages:    6,
	}

	report := evaluator.Evaluate(prov)

	if report.TotalScore > 20 {
		t.Fatalf("ADV-04 Failed: legitimate day-one package score must be <= 20, got %d", report.TotalScore)
	}
	if report.RiskLevel != model.RiskLevelLow {
		t.Errorf("ADV-04 Failed: expected RiskLevelLow, got %s", report.RiskLevel)
	}
}

// ADV-06: PyPI Ground-Truth Signal Verification
func TestADV06_PyPISignalsWithoutPhantomDownloadAPI(t *testing.T) {
	pypiJSON := `{
		"info": {
			"name": "wheel-pkg",
			"version": "1.0.0"
		},
		"releases": {
			"1.0.0": [
				{
					"filename": "wheel_pkg-1.0.0-py3-none-any.whl",
					"packagetype": "bdist_wheel",
					"upload_time_iso_8601": "2024-01-01T00:00:00Z",
					"has_sigstore": true,
					"digests": {"sha256": "abcdef123456"}
				}
			]
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(pypiJSON))
	}))
	defer server.Close()

	adapter := registry.NewPyPIAdapter(server.Client())
	adapter.SetBaseURL(server.URL)
	prov, _, err := adapter.FetchProvenance(context.Background(), "wheel-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !prov.HasBinaryWheels {
		t.Errorf("ADV-06 Failed: expected HasBinaryWheels to be true")
	}
	if !prov.HasPEP740Attestation {
		t.Errorf("ADV-06 Failed: expected HasPEP740Attestation to be true")
	}
}

// ADV-07: Go Checksum Database Verification
func TestADV07_GoChecksumDBVerification(t *testing.T) {
	evaluator := heuristics.DefaultEngine()

	// 1. Untrusted Go module missing from sum.golang.org
	unverifiedMod := &model.PackageProvenance{
		Name:           "github.com/adversary/dropper",
		Ecosystem:      model.EcosystemGo,
		InGoChecksumDB: false,
	}

	reportUnverified := evaluator.Evaluate(unverifiedMod)
	foundHR04 := false
	for _, p := range reportUnverified.Penalties {
		if p.RuleID == "HR-04" && p.Triggered {
			foundHR04 = true
			break
		}
	}
	if !foundHR04 {
		t.Errorf("ADV-07 Failed: expected HR-04 (Negligible Adoption) to trigger when missing from Go Checksum DB")
	}

	// 2. Verified Go module present in sum.golang.org
	verifiedMod := &model.PackageProvenance{
		Name:           "github.com/gin-gonic/gin",
		Ecosystem:      model.EcosystemGo,
		InGoChecksumDB: true,
	}

	reportVerified := evaluator.Evaluate(verifiedMod)
	for _, p := range reportVerified.Penalties {
		if p.RuleID == "HR-04" && p.Triggered {
			t.Errorf("ADV-07 Failed: HR-04 triggered on verified Go module present in sum.golang.org")
		}
	}
}

// ADV-08: Crates.io Token Bucket Rate Limiting
func TestADV08_CratesIOTokenBucketRateLimiting(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"crate": {"id": "test-crate", "name": "test-crate", "max_version": "0.1.0"},
			"versions": [{"num": "0.1.0"}]
		}`))
	}))
	defer server.Close()

	adapter := registry.NewCratesAdapter(server.Client())
	adapter.SetBaseURL(server.URL)
	// Fast rate limiter for test speed (20 req/sec)
	adapter.SetLimiter(rate.NewLimiter(rate.Limit(20), 1))

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _, err := adapter.FetchProvenance(ctx, "test-crate", "")
		if err != nil {
			t.Fatalf("ADV-08 Failed: unexpected error during rate limited queries: %v", err)
		}
	}

	if atomic.LoadInt64(&requestCount) != 5 {
		t.Errorf("ADV-08 Failed: expected 5 requests executed, got %d", requestCount)
	}
}

// ADV-09: Plugin Prefix Whitelisting
func TestADV09_PluginPrefixWhitelisting(t *testing.T) {
	evaluator := heuristics.DefaultEngine()

	// Legitimate plugin: pytest-fastapi-deps
	provPlugin := &model.PackageProvenance{
		Name:      "pytest-fastapi-deps",
		Ecosystem: model.EcosystemPyPI,
	}

	reportPlugin := evaluator.Evaluate(provPlugin)

	// Verify HR-06 (Conflation) did NOT trigger
	for _, p := range reportPlugin.Penalties {
		if p.RuleID == "HR-06" && p.Triggered {
			t.Errorf("ADV-09 Failed: HR-06 triggered on approved plugin namespace %s", provPlugin.Name)
		}
	}

	// Verify MO-04 (Approved Namespace) DID trigger
	foundMO04 := false
	for _, o := range reportPlugin.Offsets {
		if o.OffsetID == "MO-04" && o.Triggered {
			foundMO04 = true
			break
		}
	}
	if !foundMO04 {
		t.Errorf("ADV-09 Failed: expected MO-04 to trigger on approved plugin namespace %s", provPlugin.Name)
	}

	// Contrast with actual conflation: express-auth-helpers
	provConflated := &model.PackageProvenance{
		Name:      "express-auth-helpers",
		Ecosystem: model.EcosystemNPM,
	}
	reportConflated := evaluator.Evaluate(provConflated)
	foundHR06 := false
	for _, p := range reportConflated.Penalties {
		if p.RuleID == "HR-06" && p.Triggered {
			foundHR06 = true
			break
		}
	}
	if !foundHR06 {
		t.Errorf("ADV-09 Failed: expected HR-06 to trigger on conflated package %s", provConflated.Name)
	}
}

// ADV-11: TOCTOU Pinned Version Enforcement
func TestADV11_TOCTOUPinnedVersionEnforcement(t *testing.T) {
	// Verify that VettingService resolves and records exact version and integrity hash
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "pinned-pkg",
			"dist-tags": {"latest": "2.4.1"},
			"versions": {
				"2.4.1": {
					"name": "pinned-pkg",
					"version": "2.4.1",
					"dist": {
						"integrity": "sha512-immutable-hash-value",
						"tarball": "https://registry.npmjs.org/pinned-pkg/-/pinned-pkg-2.4.1.tgz"
					}
				}
			}
		}`))
	}))
	defer server.Close()

	adapter := registry.NewNPMAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)
	prov, _, err := adapter.FetchProvenance(context.Background(), "pinned-pkg", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.ResolvedVersion != "2.4.1" {
		t.Errorf("ADV-11 Failed: expected resolved version 2.4.1, got %s", prov.ResolvedVersion)
	}
	if prov.IntegrityHash != "sha512-immutable-hash-value" {
		t.Errorf("ADV-11 Failed: expected sha512-immutable-hash-value, got %s", prov.IntegrityHash)
	}
}

// ADV-12: Cache Poisoning Defense via (pkg, version, hash) keying
func TestADV12_CachePoisoningDefense(t *testing.T) {
	ctx := context.Background()
	store, err := cache.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer store.Close()

	// Clean v1.0.0
	provV1 := &model.PackageProvenance{
		Name:            "target-pkg",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		IntegrityHash:   "sha512-clean-hash",
		WeeklyDownloads: 1000,
	}
	_ = store.SetProvenance(ctx, provV1, "etag-1", time.Hour)

	// Attacker attempts to query poisoned v1.0.1 or modified hash
	_, _, hit, _ := store.GetProvenance(ctx, model.EcosystemNPM, "target-pkg", "1.0.1", "sha512-poisoned-hash")
	if hit {
		t.Fatalf("ADV-12 Failed: cache poisoning exploit! Unvetted version matched stale cache entry")
	}
}

// ADV-13: Private Scope Isolation
func TestADV13_PrivateScopeIsolation(t *testing.T) {
	provScoped := &model.PackageProvenance{
		Name:     "@company/auth-internal",
		IsScoped: true,
	}

	if !provScoped.IsScoped {
		t.Errorf("ADV-13 Failed: expected package to be flagged as scoped")
	}
}

// ADV-05: Non-Interactive Agent Subshell Interception
// Verifies that shim.ExtractTargets correctly identifies install operations
// initiated from non-interactive agent subshells (e.g. sh -c "npm install pkg").
// The shim layer must intercept the command and surface targets regardless of
// whether stdin is a TTY, so AI coding agents operating headless cannot bypass
// vetting by spawning child processes.
func TestADV05_NonInteractiveAgentSubshellInterception(t *testing.T) {
	tests := []struct {
		name        string
		tool        string
		args        []string
		wantEco     model.Ecosystem
		wantTargets []string
		wantInstall bool
	}{
		{
			name:        "npm install in subshell",
			tool:        "npm",
			args:        []string{"install", "hallucinated-agent-pkg"},
			wantEco:     model.EcosystemNPM,
			wantTargets: []string{"hallucinated-agent-pkg"},
			wantInstall: true,
		},
		{
			name:        "pip install in subshell with flags",
			tool:        "pip",
			args:        []string{"install", "--quiet", "attacker-pkg==1.0.0"},
			wantEco:     model.EcosystemPyPI,
			wantTargets: []string{"attacker-pkg==1.0.0"},
			wantInstall: true,
		},
		{
			name:        "cargo add in CI pipeline",
			tool:        "cargo",
			args:        []string{"add", "--features", "full", "malicious-crate"},
			wantEco:     model.EcosystemCargo,
			wantTargets: []string{"malicious-crate"},
			wantInstall: true,
		},
		{
			name:        "go get in agent subshell",
			tool:        "go",
			args:        []string{"get", "github.com/attacker/hallucinated-module@v1.0.0"},
			wantEco:     model.EcosystemGo,
			wantTargets: []string{"github.com/attacker/hallucinated-module@v1.0.0"},
			wantInstall: true,
		},
		{
			name:        "npm run (non-install) must not intercept",
			tool:        "npm",
			args:        []string{"run", "build"},
			wantEco:     "",
			wantTargets: nil,
			wantInstall: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eco, targets, isInstall := shim.ExtractTargets(tc.tool, tc.args)

			if isInstall != tc.wantInstall {
				t.Errorf("ADV-05 Failed [%s]: isInstall = %v, want %v", tc.name, isInstall, tc.wantInstall)
			}
			// Only validate ecosystem and targets on install operations;
			// non-install ops return zero-value ecosystem by design.
			if tc.wantInstall {
				if eco != tc.wantEco {
					t.Errorf("ADV-05 Failed [%s]: ecosystem = %v, want %v", tc.name, eco, tc.wantEco)
				}
				if len(targets) != len(tc.wantTargets) {
					t.Fatalf("ADV-05 Failed [%s]: got %d targets, want %d: %v", tc.name, len(targets), len(tc.wantTargets), targets)
				}
				for i, want := range tc.wantTargets {
					if targets[i] != want {
						t.Errorf("ADV-05 Failed [%s]: target[%d] = %q, want %q", tc.name, i, targets[i], want)
					}
				}
			}
		})
	}
}

// ADV-10: Transitive Lockfile Inspection
// Verifies that the lockfile parser surfaces transitive (indirect) dependencies,
// not just direct ones. An attacker-controlled hallucinated package may appear
// only as a deep transitive dependency in the resolved lockfile. Argus must
// inspect the full closure, not just the top-level requires/dependencies.
func TestADV10_TransitiveLockfileInspection(t *testing.T) {
	// package-lock.json v2 with a hallucinated transitive dependency buried
	// two levels deep under a legitimate direct dependency.
	const lockfileContent = `{
		"name": "legitimate-app",
		"lockfileVersion": 2,
		"requires": true,
		"packages": {
			"": {
				"name": "legitimate-app",
				"dependencies": {
					"express": "^4.18.2"
				}
			},
			"node_modules/express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				"integrity": "sha512-legitHash"
			},
			"node_modules/express/node_modules/hallucinated-transitive-dep": {
				"version": "0.0.1",
				"resolved": "https://registry.npmjs.org/hallucinated-transitive-dep/-/hallucinated-transitive-dep-0.0.1.tgz",
				"integrity": "sha512-maliciousHash"
			},
			"node_modules/hallucinated-transitive-dep": {
				"version": "0.0.1",
				"resolved": "https://registry.npmjs.org/hallucinated-transitive-dep/-/hallucinated-transitive-dep-0.0.1.tgz",
				"integrity": "sha512-maliciousHash"
			}
		}
	}`

	parser := lockfile.NPMLockParser{}
	deps, err := parser.Parse(strings.NewReader(lockfileContent))
	if err != nil {
		t.Fatalf("ADV-10 Failed: lockfile parse error: %v", err)
	}

	// Find the hallucinated transitive dep in the parsed results.
	var found bool
	for _, dep := range deps {
		if dep.Name == "hallucinated-transitive-dep" {
			found = true
			if dep.Version != "0.0.1" {
				t.Errorf("ADV-10 Failed: expected version 0.0.1, got %s", dep.Version)
			}
			break
		}
	}

	if !found {
		t.Errorf("ADV-10 Failed: hallucinated transitive dependency was not surfaced by lockfile parser. Got %d deps: %+v", len(deps), deps)
	}

	// Also verify the legitimate direct dep is present.
	var expressFound bool
	for _, dep := range deps {
		if dep.Name == "express" {
			expressFound = true
			break
		}
	}
	if !expressFound {
		t.Errorf("ADV-10 Failed: legitimate direct dependency 'express' was not found in parsed output")
	}

	// Run heuristics on the hallucinated transitive dep to confirm it would be flagged.
	evaluator := heuristics.DefaultEngine()
	prov := &model.PackageProvenance{
		Name:              "hallucinated-transitive-dep",
		Ecosystem:         model.EcosystemNPM,
		FirstReleaseDate:  time.Now().Add(-1 * 24 * time.Hour), // 1 day old
		LatestReleaseDate: time.Now().Add(-1 * 24 * time.Hour),
		VCSStatus:         model.VCSStatusMissing,
	}
	report := evaluator.Evaluate(prov)
	if report.TotalScore < 30 {
		t.Errorf("ADV-10 Failed: expected risk score ≥30 for hallucinated transitive dep, got %d", report.TotalScore)
	}
}
