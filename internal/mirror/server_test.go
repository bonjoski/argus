package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/policy"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
)

func TestParser_NPM(t *testing.T) {
	tests := []struct {
		path        string
		wantName    string
		wantVersion string
		wantTarget  bool
	}{
		{"/express", "express", "", true},
		{"/express/4.18.2", "express", "4.18.2", true},
		{"/@angular/core", "@angular/core", "", true},
		{"/@angular%2fcore", "@angular/core", "", true},
		{"/@angular/core/15.0.0", "@angular/core", "15.0.0", true},
		{"/@angular%2fcore/15.0.0", "@angular/core", "15.0.0", true},
		{"/express/-/express-4.18.2.tgz", "express", "4.18.2", true},
		{"/@angular/core/-/core-15.0.0.tgz", "@angular/core", "15.0.0", true},
		{"/@angular%2fcore/-/core-15.0.0.tgz", "@angular/core", "15.0.0", true},
		{"/-/v1/search", "", "", false},
		{"/-/ping", "", "", false},
		{"/", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			name, ver, isTarget := ParseNPMPath(tc.path)
			if isTarget != tc.wantTarget {
				t.Fatalf("ParseNPMPath(%q) isTarget = %v, want %v", tc.path, isTarget, tc.wantTarget)
			}
			if isTarget {
				if name != tc.wantName {
					t.Errorf("ParseNPMPath(%q) name = %q, want %q", tc.path, name, tc.wantName)
				}
				if ver != tc.wantVersion {
					t.Errorf("ParseNPMPath(%q) version = %q, want %q", tc.path, ver, tc.wantVersion)
				}
			}
		})
	}
}

func TestParser_PyPI(t *testing.T) {
	tests := []struct {
		path        string
		wantName    string
		wantVersion string
		wantTarget  bool
	}{
		{"/simple/requests/", "requests", "", true},
		{"/simple/requests", "requests", "", true},
		{"/simple/", "", "", false},
		{"/packages/ab/cd/123/requests-2.28.1-py3-none-any.whl", "requests", "2.28.1", true},
		{"/packages/ab/cd/123/requests-2.28.1.tar.gz", "requests", "2.28.1", true},
		{"/pypi/requests/json", "requests", "", true},
		{"/pypi/requests/2.28.1/json", "requests", "2.28.1", true},
		{"/requests/json", "requests", "", true},
		{"/requests/2.28.1/json", "requests", "2.28.1", true},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			name, ver, isTarget := ParsePyPIPath(tc.path)
			if isTarget != tc.wantTarget {
				t.Fatalf("ParsePyPIPath(%q) isTarget = %v, want %v", tc.path, isTarget, tc.wantTarget)
			}
			if isTarget {
				if name != tc.wantName {
					t.Errorf("ParsePyPIPath(%q) name = %q, want %q", tc.path, name, tc.wantName)
				}
				if ver != tc.wantVersion {
					t.Errorf("ParsePyPIPath(%q) version = %q, want %q", tc.path, ver, tc.wantVersion)
				}
			}
		})
	}
}

func TestParser_Generic(t *testing.T) {
	// Crates
	name, ver, ok := ParseGenericEcosystemPath(model.EcosystemCargo, "/api/v1/crates/serde/1.0.180/download")
	if !ok || name != "serde" || ver != "1.0.180" {
		t.Errorf("Cargo parse failed: got (%q, %q, %v)", name, ver, ok)
	}

	// RubyGems
	name, ver, ok = ParseGenericEcosystemPath(model.EcosystemRubyGems, "/gems/rails-7.0.4.gem")
	if !ok || name != "rails" || ver != "7.0.4" {
		t.Errorf("RubyGems parse failed: got (%q, %q, %v)", name, ver, ok)
	}

	// Go
	name, ver, ok = ParseGenericEcosystemPath(model.EcosystemGo, "/github.com/gin-gonic/gin/@v/v1.9.0.zip")
	if !ok || name != "github.com/gin-gonic/gin" || ver != "v1.9.0" {
		t.Errorf("Go parse failed: got (%q, %q, %v)", name, ver, ok)
	}
}

func setupTestMirror(t *testing.T) (*httptest.Server, *Server, *int64, *int64) {
	var cleanServed int64
	var malTarballServed int64

	// Mock Upstream Registry
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/clean-pkg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "clean-pkg",
				"dist-tags": {"latest": "1.0.0"},
				"time": {
					"created": "2020-01-01T00:00:00Z",
					"modified": "2024-01-01T00:00:00Z",
					"1.0.0": "2020-01-01T00:00:00Z",
					"1.1.0": "2021-01-01T00:00:00Z",
					"2.0.0": "2024-01-01T00:00:00Z"
				},
				"versions": {
					"1.0.0": {
						"name": "clean-pkg",
						"version": "1.0.0",
						"dist": {"tarball": "http://upstream/clean-pkg/-/clean-pkg-1.0.0.tgz"}
					},
					"1.1.0": {
						"name": "clean-pkg",
						"version": "1.1.0"
					},
					"2.0.0": {
						"name": "clean-pkg",
						"version": "2.0.0"
					}
				},
				"repository": {
					"type": "git",
					"url": "https://github.com/clean-pkg/clean-pkg.git"
				}
			}`))
		case r.URL.Path == "/downloads/point/last-week/clean-pkg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"downloads": 50000}`))
		case r.URL.Path == "/clean-pkg/-/clean-pkg-1.0.0.tgz":
			atomic.AddInt64(&cleanServed, 1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("CLEAN_TARBALL_BYTES"))
		case r.URL.Path == "/malicious-pkg":
			yesterday := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"name": "malicious-pkg",
				"dist-tags": {"latest": "0.0.1"},
				"time": {
					"created": "%s",
					"modified": "%s",
					"0.0.1": "%s"
				},
				"versions": {
					"0.0.1": {
						"name": "malicious-pkg",
						"version": "0.0.1",
						"scripts": {"postinstall": "malicious.sh"},
						"dist": {"tarball": "http://upstream/malicious-pkg/-/malicious-pkg-0.0.1.tgz"}
					}
				}
			}`, yesterday, yesterday, yesterday)
		case r.URL.Path == "/malicious-pkg/-/malicious-pkg-0.0.1.tgz":
			atomic.AddInt64(&malTarballServed, 1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("EXPLOIT_PAYLOAD_DO_NOT_SEND"))
		default:
			http.NotFound(w, r)
		}
	}))

	// Vetting Service
	adapter := registry.NewNPMAdapter(upstream.Client())
	adapter.SetRegistryURL(upstream.URL)
	adapter.SetDownloadURL(upstream.URL + "/downloads")

	evaluator := heuristics.DefaultEngine()
	vetService := service.NewVettingService(nil, []registry.Adapter{adapter}, nil, evaluator, 24*time.Hour)

	cfg := Config{
		Host:           "127.0.0.1",
		Port:           0, // auto-select free port
		UpstreamNPM:    upstream.URL,
		UpstreamPyPI:   upstream.URL + "/pypi",
		VettingService: vetService,
		Threshold:      50,
	}

	server := NewServer(cfg)
	server.SetTransport(upstream.Client().Transport)

	return upstream, server, &cleanServed, &malTarballServed
}

func TestMirrorServer_CleanPackageProxied(t *testing.T) {
	upstream, server, cleanServed, _ := setupTestMirror(t)
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to bind port
	for i := 0; i < 50; i++ {
		if server.Port() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mirrorURL := fmt.Sprintf("http://127.0.0.1:%d", server.Port())

	// 1. Fetch metadata for clean package
	resp, err := http.Get(mirrorURL + "/npm/clean-pkg")
	if err != nil {
		t.Fatalf("failed to query mirror for clean package metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clean package metadata, got %d", resp.StatusCode)
	}

	// 2. Fetch clean tarball
	tbResp, err := http.Get(mirrorURL + "/npm/clean-pkg/-/clean-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("failed to download clean tarball: %v", err)
	}
	defer tbResp.Body.Close()

	if tbResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clean tarball, got %d", tbResp.StatusCode)
	}

	body, _ := io.ReadAll(tbResp.Body)
	if string(body) != "CLEAN_TARBALL_BYTES" {
		t.Fatalf("expected CLEAN_TARBALL_BYTES, got %s", string(body))
	}

	if atomic.LoadInt64(cleanServed) != 1 {
		t.Errorf("expected 1 upstream clean tarball request, got %d", atomic.LoadInt64(cleanServed))
	}

	cancel()
	_ = server.Close()
}

func TestMirrorServer_MaliciousPackageBlocked(t *testing.T) {
	upstream, server, _, malTarballServed := setupTestMirror(t)
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if server.Port() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mirrorURL := fmt.Sprintf("http://127.0.0.1:%d", server.Port())

	// Request malicious tarball
	tbResp, err := http.Get(mirrorURL + "/npm/malicious-pkg/-/malicious-pkg-0.0.1.tgz")
	if err != nil {
		t.Fatalf("failed to query mirror: %v", err)
	}
	defer tbResp.Body.Close()

	if tbResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for malicious tarball, got %d", tbResp.StatusCode)
	}

	var blockedResp BlockedResponse
	if err := json.NewDecoder(tbResp.Body).Decode(&blockedResp); err != nil {
		t.Fatalf("failed to decode blocked JSON response: %v", err)
	}

	if blockedResp.Error != "Blocked by Argus" {
		t.Errorf("expected error 'Blocked by Argus', got %q", blockedResp.Error)
	}
	if blockedResp.Package != "malicious-pkg" {
		t.Errorf("expected package 'malicious-pkg', got %q", blockedResp.Package)
	}
	if blockedResp.RiskScore < 50 {
		t.Errorf("expected risk score >= 50, got %d", blockedResp.RiskScore)
	}
	if len(blockedResp.Reasons) == 0 {
		t.Errorf("expected non-empty reasons in blocked response")
	}

	// CRITICAL INVARIANT: Upstream malicious tarball must NOT have been served/proxied
	if atomic.LoadInt64(malTarballServed) != 0 {
		t.Fatalf("CRITICAL SECURITY LEAK: Upstream malicious tarball was proxied to client!")
	}

	cancel()
	_ = server.Close()
}

func TestMirrorServer_EnterprisePolicy(t *testing.T) {
	upstream, server, _, _ := setupTestMirror(t)
	defer upstream.Close()

	server.cfg.Policy = &policy.Policy{
		Version: 1,
		Blocklist: policy.BlocklistConfig{
			Packages: []string{"blocked-by-policy"},
		},
		Allowlist: policy.AllowlistConfig{
			Packages: []string{"malicious-pkg"}, // Exemption
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if server.Port() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mirrorURL := fmt.Sprintf("http://127.0.0.1:%d", server.Port())

	// 1. Policy Blocklist: immediate 403
	resp, err := http.Get(mirrorURL + "/npm/blocked-by-policy")
	if err != nil {
		t.Fatalf("failed request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for blocklisted package, got %d", resp.StatusCode)
	}

	// 2. Policy Allowlist: exempted package bypasses high score
	resp2, err := http.Get(mirrorURL + "/npm/malicious-pkg")
	if err != nil {
		t.Fatalf("failed request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for allowlisted package, got %d", resp2.StatusCode)
	}

	cancel()
	_ = server.Close()
}

func TestMirrorServer_StatusAndHealth(t *testing.T) {
	upstream, server, _, _ := setupTestMirror(t)
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if server.Port() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mirrorURL := fmt.Sprintf("http://127.0.0.1:%d", server.Port())

	// 1. Health check
	hResp, err := http.Get(mirrorURL + "/_argus/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from health, got %d", hResp.StatusCode)
	}

	// 2. Status check
	sResp, err := http.Get(mirrorURL + "/_argus/status")
	if err != nil {
		t.Fatalf("status check failed: %v", err)
	}
	defer sResp.Body.Close()
	if sResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from status, got %d", sResp.StatusCode)
	}

	var stats ServerStats
	if err := json.NewDecoder(sResp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if !stats.Running {
		t.Errorf("expected stats.Running = true")
	}
	if stats.Port != server.Port() {
		t.Errorf("expected port %d, got %d", server.Port(), stats.Port)
	}

	cancel()
	_ = server.Close()
}

func TestMirror_BackgroundManagerLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "mirror.pid")
	logFile := filepath.Join(tempDir, "mirror.log")

	// Verify StopMirror on non-existent PID cleans gracefully
	if err := StopMirror(pidFile, 12345); err != nil {
		t.Errorf("unexpected error stopping non-existent mirror: %v", err)
	}

	// Create fake PID file
	_ = os.WriteFile(pidFile, []byte("99999999"), 0600)
	_ = StopMirror(pidFile, 12345)
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("expected PID file to be removed after StopMirror")
	}

	_ = logFile
}
