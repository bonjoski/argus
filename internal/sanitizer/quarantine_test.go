package sanitizer_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/sanitizer"
)

func TestQuarantineStore_BasicLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := sanitizer.NewQuarantineStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create quarantine store: %v", err)
	}

	rawTarball := []byte("malicious-tarball-payload-data")
	mockReport := &model.RiskReport{
		Package:         "@evil/dropper",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.2.3",
		TotalScore:      95,
		RiskLevel:       model.RiskLevelCritical,
		Penalties: []model.HeuristicFinding{
			{
				RuleID:    "HR-01",
				Name:      "Severe Risk Rule",
				Points:    50,
				Triggered: true,
			},
			{
				RuleID:    "HR-10",
				Name:      "Suspicious AST",
				Points:    45,
				Triggered: true,
			},
		},
		Provenance: model.PackageProvenance{
			Name:               "@evil/dropper",
			Ecosystem:          model.EcosystemNPM,
			ResolvedVersion:    "1.2.3",
			TarballURL:         "https://registry.npmjs.org/@evil/dropper/-/dropper-1.2.3.tgz",
			HasSuspiciousAST:   true,
			SuspiciousFindings: []string{"install.js:2: [PROCESS_EXECUTION] execSync('rm -rf /')"},
		},
	}

	// 1. Quarantine package
	rec, err := store.Quarantine(model.EcosystemNPM, "@evil/dropper", "1.2.3", rawTarball, mockReport, "")
	if err != nil {
		t.Fatalf("Quarantine failed: %v", err)
	}

	if rec.Package != "@evil/dropper" || rec.Version != "1.2.3" || rec.RiskScore != 95 {
		t.Errorf("Quarantine record mismatch: %+v", rec)
	}
	if len(rec.TriggeredRules) != 2 {
		t.Errorf("expected 2 triggered rules, got %d", len(rec.TriggeredRules))
	}
	if len(rec.ASTFindings) != 1 {
		t.Errorf("expected 1 AST finding, got %d", len(rec.ASTFindings))
	}
	if rec.SourceURL != mockReport.Provenance.TarballURL {
		t.Errorf("expected source URL %s, got %s", mockReport.Provenance.TarballURL, rec.SourceURL)
	}

	// Verify files on disk
	if _, err := os.Stat(rec.TarballPath); err != nil {
		t.Errorf("quarantined tarball not found on disk at %s: %v", rec.TarballPath, err)
	}
	if _, err := os.Stat(rec.MetadataPath); err != nil {
		t.Errorf("quarantine metadata file not found on disk at %s: %v", rec.MetadataPath, err)
	}

	// Verify metadata file contents
	metaBytes, err := os.ReadFile(rec.MetadataPath)
	if err != nil {
		t.Fatalf("failed to read metadata file: %v", err)
	}
	var loadedMeta sanitizer.QuarantineRecord
	if err := json.Unmarshal(metaBytes, &loadedMeta); err != nil {
		t.Fatalf("failed to parse metadata JSON: %v", err)
	}
	if loadedMeta.Package != "@evil/dropper" || loadedMeta.SHA256 != rec.SHA256 {
		t.Errorf("loaded meta mismatch: %+v", loadedMeta)
	}

	// 2. List items
	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 item in list, got %d", len(list))
	}
	if list[0].ID != rec.ID {
		t.Errorf("list[0] ID = %s, want %s", list[0].ID, rec.ID)
	}

	// 3. Inspect by ID
	inspected, err := store.Inspect(rec.ID)
	if err != nil {
		t.Fatalf("Inspect by ID failed: %v", err)
	}
	if inspected.Package != "@evil/dropper" {
		t.Errorf("inspected package mismatch: %s", inspected.Package)
	}

	// Inspect by package name
	inspectedPkg, err := store.Inspect("@evil/dropper")
	if err != nil {
		t.Fatalf("Inspect by package name failed: %v", err)
	}
	if inspectedPkg.ID != rec.ID {
		t.Errorf("inspected by pkg mismatch: %+v", inspectedPkg)
	}

	// 4. Get Tarball bytes
	tbBytes, err := store.GetTarball(rec.ID)
	if err != nil {
		t.Fatalf("GetTarball failed: %v", err)
	}
	if !bytes.Equal(tbBytes, rawTarball) {
		t.Errorf("GetTarball returned bytes do not match original tarball")
	}

	// 5. Purge
	purgedCount, err := store.Purge()
	if err != nil {
		t.Fatalf("Purge failed: %v", err)
	}
	if purgedCount != 1 {
		t.Errorf("expected 1 purged item, got %d", purgedCount)
	}

	// Check that store is empty
	remaining, err := store.List()
	if err != nil {
		t.Fatalf("List after purge failed: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining items after purge, got %d", len(remaining))
	}
}

func TestQuarantineStore_MultipleEcosystemsAndOrdering(t *testing.T) {
	tempDir := t.TempDir()
	store, err := sanitizer.NewQuarantineStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create quarantine store: %v", err)
	}

	// Add 3 packages across npm and pypi with slight time delays
	rec1, err := store.Quarantine(model.EcosystemNPM, "pkg-one", "1.0.0", []byte("tar1"), nil, "")
	if err != nil {
		t.Fatalf("Quarantine 1 failed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	rec2, err := store.Quarantine(model.EcosystemPyPI, "pkg-two", "2.0.0", []byte("tar2"), nil, "")
	if err != nil {
		t.Fatalf("Quarantine 2 failed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	rec3, err := store.Quarantine(model.EcosystemNPM, "pkg-three", "3.0.0", []byte("tar3"), nil, "")
	if err != nil {
		t.Fatalf("Quarantine 3 failed: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}

	// Verify descending timestamp order (rec3 newest, rec1 oldest)
	if list[0].Package != rec3.Package {
		t.Errorf("expected newest package pkg-three first, got %s", list[0].Package)
	}
	if list[1].Package != rec2.Package {
		t.Errorf("expected middle package pkg-two second, got %s", list[1].Package)
	}
	if list[2].Package != rec1.Package {
		t.Errorf("expected oldest package pkg-one last, got %s", list[2].Package)
	}
}

func TestQuarantineStore_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	store, err := sanitizer.NewQuarantineStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	var wg sync.WaitGroup
	numWorkers := 10

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkgName := fmt.Sprintf("pkg-concurrency-%d", id)
			payload := []byte(fmt.Sprintf("payload-%d", id))
			_, err := store.Quarantine(model.EcosystemNPM, pkgName, "1.0.0", payload, nil, "")
			if err != nil {
				t.Errorf("worker %d quarantine failed: %v", id, err)
			}
			_, _ = store.List()
		}(i)
	}

	wg.Wait()

	list, err := store.List()
	if err != nil {
		t.Fatalf("List after concurrency failed: %v", err)
	}
	if len(list) != numWorkers {
		t.Errorf("expected %d items after concurrency, got %d", numWorkers, len(list))
	}
}

func TestQuarantineStore_DefaultDirectory(t *testing.T) {
	defaultDir := sanitizer.DefaultQuarantineDir()
	if defaultDir == "" || !filepath.IsAbs(defaultDir) {
		t.Errorf("invalid default quarantine dir: %s", defaultDir)
	}
}
