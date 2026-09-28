package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
)

type mockAdapter struct {
	eco model.Ecosystem
}

func (m *mockAdapter) Ecosystem() model.Ecosystem {
	return m.eco
}

func (m *mockAdapter) FetchProvenance(ctx context.Context, name, version string) (*model.PackageProvenance, string, error) {
	if name == "not-found" {
		return nil, "", fmt.Errorf("package not found: %s", name)
	}
	return &model.PackageProvenance{
		Name:              name,
		Ecosystem:         m.eco,
		ResolvedVersion:   "1.0.0",
		FirstReleaseDate:  time.Now().Add(-180 * 24 * time.Hour),
		LatestReleaseDate: time.Now().Add(-30 * 24 * time.Hour),
		TotalReleases:     5,
		WeeklyDownloads:   50000,
	}, "etag-123", nil
}

func setupTestDaemon(t *testing.T) (*Server, *Client, string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "argus-daemon-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("dtest_%d.sock", time.Now().UnixNano()))
	pidPath := filepath.Join(os.TempDir(), fmt.Sprintf("dtest_%d.pid", time.Now().UnixNano()))
	dbPath := filepath.Join(tmpDir, "cache.db")

	store, err := cache.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite cache: %v", err)
	}

	adapters := []registry.Adapter{
		&mockAdapter{eco: model.EcosystemNPM},
		&mockAdapter{eco: model.EcosystemPyPI},
	}

	evaluator := heuristics.DefaultEngine()
	vetService := service.NewVettingService(store, adapters, nil, evaluator, 24*time.Hour)

	server := NewServer(sockPath, pidPath, vetService)
	serverCtx, serverCancel := context.WithCancel(context.Background())

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(serverCtx)
	}()

	client := NewClient(sockPath).WithTimeout(1 * time.Second)

	// Wait for daemon to become ready
	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if client.Ping(context.Background()) == nil {
			ready = true
			break
		}
	}

	if !ready {
		t.Fatalf("daemon failed to start listening within timeout")
	}

	cleanup := func() {
		serverCancel()
		_ = server.Close()
		_ = store.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return server, client, sockPath, cleanup
}

func TestDaemon_PingAndStats(t *testing.T) {
	_, client, _, cleanup := setupTestDaemon(t)
	defer cleanup()

	ctx := context.Background()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	stats, err := client.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats.PID <= 0 {
		t.Errorf("expected positive PID, got %d", stats.PID)
	}
	if stats.TotalRequests < 1 {
		t.Errorf("expected TotalRequests >= 1, got %d", stats.TotalRequests)
	}
}

func TestDaemon_VetAndCache(t *testing.T) {
	_, client, _, cleanup := setupTestDaemon(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Initial Vet (Cache Miss)
	report, err := client.Vet(ctx, model.EcosystemNPM, "express", "1.0.0", false)
	if err != nil {
		t.Fatalf("Vet failed: %v", err)
	}

	if report.Package != "express" {
		t.Errorf("expected package express, got %s", report.Package)
	}
	if report.RiskLevel != model.RiskLevelLow {
		t.Errorf("expected RiskLevelLow, got %s", report.RiskLevel)
	}

	// 2. Second Vet (Cache Hit - Sub-millisecond IPC)
	start := time.Now()
	cachedReport, err := client.Vet(ctx, model.EcosystemNPM, "express", "1.0.0", false)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Cached vet failed: %v", err)
	}
	if !cachedReport.Cached {
		t.Errorf("expected cachedReport.Cached == true")
	}
	t.Logf("Daemon cached IPC latency: %v", duration)

	// 3. Vet Not Found
	_, err = client.Vet(ctx, model.EcosystemNPM, "not-found", "1.0.0", false)
	if err == nil {
		t.Fatalf("expected error for not-found package, got nil")
	}
}

func TestDaemon_ConcurrentRequests(t *testing.T) {
	_, client, _, cleanup := setupTestDaemon(t)
	defer cleanup()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkgName := fmt.Sprintf("pkg-%d", id%5)
			_, err := client.Vet(context.Background(), model.EcosystemPyPI, pkgName, "1.0.0", false)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent request failed: %v", err)
	}

	stats, err := client.Stats(context.Background())
	if err != nil {
		t.Fatalf("stats check failed: %v", err)
	}
	if stats.TotalRequests < 20 {
		t.Errorf("expected at least 20 requests recorded, got %d", stats.TotalRequests)
	}
}

func TestDaemon_GracefulShutdown(t *testing.T) {
	_, client, sockPath, cleanup := setupTestDaemon(t)
	defer cleanup()

	ctx := context.Background()
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// Verify that client ping now fails
	time.Sleep(200 * time.Millisecond)
	if client.Ping(context.Background()) == nil {
		t.Errorf("expected ping to fail after shutdown")
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file to be deleted on shutdown")
	}
}
