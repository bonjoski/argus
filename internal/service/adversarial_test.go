package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/vcs"
)

type stubAdapter struct {
	calls atomic.Int64
	prov  *model.PackageProvenance
	delay time.Duration
}

func (a *stubAdapter) Ecosystem() model.Ecosystem { return model.EcosystemNPM }
func (a *stubAdapter) FetchProvenance(_ context.Context, _, _ string) (*model.PackageProvenance, string, error) {
	a.calls.Add(1)
	if a.delay > 0 {
		time.Sleep(a.delay)
	}
	cp := *a.prov
	return &cp, "etag-stub", nil
}

type failingVCSVerifier struct{}

func (failingVCSVerifier) Verify(_ context.Context, _ model.Ecosystem, _, _ string) (*vcs.VCSResult, error) {
	return nil, errors.New("simulated VCS timeout")
}

// ARG-04 & ARG-07: Never cache degraded sub-probe ALLOW verdicts, enforce 0600 IntegrityHash-bound cache,
// and deduplicate N=8 concurrent identical Vet requests via singleflight.
func TestAdversarial_ARG04_DegradedSubProbeNotCachedAndIntegrityBound(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cache.db")

	store, err := cache.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	fi, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions on cache.db, got %04o", perm)
	}

	adapter := &stubAdapter{
		prov: &model.PackageProvenance{
			Name:              "established-lib",
			Ecosystem:         model.EcosystemNPM,
			ResolvedVersion:   "2.0.0",
			FirstReleaseDate:  time.Now().Add(-400 * 24 * time.Hour),
			LatestReleaseDate: time.Now().Add(-30 * 24 * time.Hour),
			TotalReleases:     12,
			WeeklyDownloads:   100000,
			IntegrityHash:     "sha512-authentic-v200",
			RepositoryURL:     "https://github.com/org/established-lib",
		},
		delay: 25 * time.Millisecond,
	}

	// 1. With failing VCS sub-probe, ALLOW report MUST NOT be cached for 24h
	degradedSvc := NewVettingService(store, []registry.Adapter{adapter}, failingVCSVerifier{}, heuristics.DefaultEngine(), 24*time.Hour)
	rep, err := degradedSvc.Vet(context.Background(), model.EcosystemNPM, "established-lib", "2.0.0")
	if err != nil {
		t.Fatalf("Vet failed: %v", err)
	}
	if rep.TotalScore >= 50 {
		t.Fatalf("expected low score, got %d", rep.TotalScore)
	}
	if _, _, hit, _ := store.GetReport(context.Background(), model.EcosystemNPM, "established-lib", "2.0.0"); hit {
		t.Fatalf("SECURITY BYPASS: degraded sub-probe ALLOW verdict was cached in SQLite!")
	}

	// 2. Healthy Vet under N=8 concurrency coalesces via singleflight and binds cache to IntegrityHash
	adapter.calls.Store(0)
	healthySvc := NewVettingService(store, []registry.Adapter{adapter}, nil, heuristics.DefaultEngine(), 24*time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, vErr := healthySvc.Vet(context.Background(), model.EcosystemNPM, "established-lib", "2.0.0")
			if vErr != nil || r == nil {
				t.Errorf("concurrent Vet failed: %v", vErr)
			}
		}()
	}
	wg.Wait()

	if calls := adapter.calls.Load(); calls != 1 {
		t.Errorf("expected singleflight to coalesce N=8 concurrent requests into 1 registry fetch, got %d", calls)
	}

	// Mismatched expected IntegrityHash MUST miss cache and fail closed against upstream mismatch
	if _, _, hit, _ := store.GetReportWithIntegrity(context.Background(), model.EcosystemNPM, "established-lib", "2.0.0", "sha512-tampered"); hit {
		t.Fatalf("SECURITY BYPASS: GetReportWithIntegrity returned cache hit on tampered integrity hash!")
	}
	if _, err := healthySvc.VetWithIntegrity(context.Background(), model.EcosystemNPM, "established-lib", "2.0.0", "sha512-tampered"); err == nil {
		t.Fatalf("SECURITY BYPASS: VetWithIntegrity allowed mismatched registry integrity hash!")
	}
}
