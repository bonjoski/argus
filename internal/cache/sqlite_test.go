package cache

import (
	"context"
	"testing"
	"time"

	"bonjoski/argus/internal/model"
)

func TestSQLiteStore_ProvenanceAndReport(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	defer store.Close()

	prov := &model.PackageProvenance{
		Name:            "test-pkg",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		IntegrityHash:   "sha512-abc123xyz",
		WeeklyDownloads: 5000,
		TotalReleases:   3,
	}

	// 1. Set Provenance with 1 hour TTL
	if err := store.SetProvenance(ctx, prov, "etag-1", time.Hour); err != nil {
		t.Fatalf("failed to set provenance: %v", err)
	}

	// 2. Get Provenance (Cache Hit)
	gotProv, etag, hit, err := store.GetProvenance(ctx, model.EcosystemNPM, "test-pkg", "1.0.0", "sha512-abc123xyz")
	if err != nil {
		t.Fatalf("failed to get provenance: %v", err)
	}
	if !hit {
		t.Fatalf("expected cache hit, got miss")
	}
	if gotProv.Name != "test-pkg" || gotProv.WeeklyDownloads != 5000 || etag != "etag-1" {
		t.Errorf("unexpected provenance data: %+v, etag: %s", gotProv, etag)
	}

	// 3. Set Report with short TTL and test expiry
	report := &model.RiskReport{
		Package:         "test-pkg",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		TotalScore:      15,
		RiskLevel:       model.RiskLevelLow,
	}
	if err := store.SetReport(ctx, report, "etag-2", 10*time.Millisecond); err != nil {
		t.Fatalf("failed to set report: %v", err)
	}

	time.Sleep(25 * time.Millisecond)

	// Report should be expired now
	_, gotEtag, hit, err := store.GetReport(ctx, model.EcosystemNPM, "test-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error getting report: %v", err)
	}
	if hit {
		t.Errorf("expected expired report to not be a hit")
	}
	if gotEtag != "etag-2" {
		t.Errorf("expected etag 'etag-2', got %s", gotEtag)
	}

	// 4. Test Prune
	pruned, err := store.Prune(ctx)
	if err != nil {
		t.Fatalf("failed to prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("expected 1 pruned entry, got %d", pruned)
	}

	// 5. Test Stats
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.TotalEntries != 1 {
		t.Errorf("expected 1 remaining total entry, got %d", stats.TotalEntries)
	}
}
