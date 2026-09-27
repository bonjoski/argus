package heuristics

import (
	"testing"
	"time"

	"bonjoski/argus/internal/model"
)

func TestEngine_ScenarioA_DayOneLegitimatePackage(t *testing.T) {
	authorCreated := time.Now().Add(-400 * 24 * time.Hour) // > 1 year
	yesterday := time.Now().Add(-24 * time.Hour)

	prov := &model.PackageProvenance{
		Name:                   "pytest-tempo",
		Ecosystem:              model.EcosystemPyPI,
		ResolvedVersion:        "0.1.0",
		FirstReleaseDate:       yesterday,
		LatestReleaseDate:      yesterday,
		TotalReleases:          1,
		HasBinaryWheels:        true,
		HasPEP740Attestation:   true,
		RepositoryURL:          "https://github.com/established-author/pytest-tempo",
		VCSStatus:              model.VCSStatusVerified,
		RepositoryManifestName: "pytest-tempo",
		RepositoryAgeMonths:    12,
		AuthorName:             "established-author",
		AuthorCreatedAt:        &authorCreated,
		AuthorTotalPackages:    5,
	}

	engine := DefaultEngine()
	report := engine.Evaluate(prov)

	if report.TotalScore > 20 {
		t.Fatalf("expected legitimate day-one package score <= 20, got %d (penalties=%d, offsets=%d)",
			report.TotalScore, report.TotalPenalties, report.TotalOffsets)
	}

	if report.RiskLevel != model.RiskLevelLow {
		t.Errorf("expected RiskLevelLow, got %s", report.RiskLevel)
	}
}

func TestEngine_ScenarioB_The31DaySleeper(t *testing.T) {
	created := time.Now().Add(-35 * 24 * time.Hour) // 35 days ago
	updated := time.Now().Add(-2 * 24 * time.Hour)  // 2 days ago

	prov := &model.PackageProvenance{
		Name:              "hallucinated-sleeper-auth",
		Ecosystem:         model.EcosystemNPM,
		ResolvedVersion:   "0.0.2",
		FirstReleaseDate:  created,
		LatestReleaseDate: updated,
		TotalReleases:     2,
		WeeklyDownloads:   12,
		HasInstallScripts: true,
		VCSStatus:         model.VCSStatusNone,
	}

	engine := DefaultEngine()
	report := engine.Evaluate(prov)

	// Negligible (+15) + Sudden Sleeper (+25) + Install Hooks (+15) + Detached VCS (+20) = 75
	if report.TotalScore < 60 {
		t.Fatalf("expected sleeper attack score >= 60, got %d", report.TotalScore)
	}
}

func TestEngine_ScenarioC_FakeVCSImpersonation(t *testing.T) {
	yesterday := time.Now().Add(-24 * time.Hour)

	prov := &model.PackageProvenance{
		Name:                   "react-ai-auth-utils",
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

	engine := DefaultEngine()
	report := engine.Evaluate(prov)

	// HR-01 (+35) + HR-03 (+15) + HR-04 (+15) + HR-05B (+35) = 100
	if report.TotalScore < 80 {
		t.Fatalf("expected spoofed VCS package score >= 80, got %d", report.TotalScore)
	}

	if report.RiskLevel != model.RiskLevelCritical {
		t.Errorf("expected RiskLevelCritical, got %s", report.RiskLevel)
	}
}

func TestEngine_HR06_LexicalConflation(t *testing.T) {
	engine := DefaultEngine()

	// Package "express-auth-helpers" blends express + auth + helpers
	prov := &model.PackageProvenance{
		Name:      "express-auth-helpers",
		Ecosystem: model.EcosystemNPM,
	}

	report := engine.Evaluate(prov)
	var foundHR06 bool
	for _, p := range report.Penalties {
		if p.RuleID == "HR-06" && p.Triggered {
			foundHR06 = true
			break
		}
	}
	if !foundHR06 {
		t.Errorf("expected HR-06 (Lexical Conflation) to trigger for express-auth-helpers")
	}
}

func TestEngine_MO04_ApprovedNamespace(t *testing.T) {
	engine := DefaultEngine()

	prov := &model.PackageProvenance{
		Name:      "pytest-fastapi-deps",
		Ecosystem: model.EcosystemPyPI,
	}

	report := engine.Evaluate(prov)
	var foundMO04 bool
	for _, o := range report.Offsets {
		if o.OffsetID == "MO-04" && o.Triggered {
			foundMO04 = true
			break
		}
	}
	if !foundMO04 {
		t.Errorf("expected MO-04 (Approved Namespace) to trigger for pytest-fastapi-deps")
	}

	// Verify that HR-06 was NOT triggered due to exemption
	for _, p := range report.Penalties {
		if p.RuleID == "HR-06" && p.Triggered {
			t.Errorf("expected HR-06 to be suppressed for approved namespace plugin")
		}
	}
}
