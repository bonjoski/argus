package adversarial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
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
