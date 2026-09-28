package adversarial

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/mirror"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
)

// ADV-17: Inline Registry Mirror Pre-Flight Interception
// Verifies that the HTTP mirror proxy intercepts package queries before they reach
// developer package managers or autonomous agents. Clean packages are streamed with
// full integrity, while malicious or hallucinated packages receive an immediate
// HTTP 403 Forbidden with diagnostic JSON, preventing any byte of untrusted tarballs
// from being served.
func TestADV17_InlineRegistryMirrorPreFlightInterception(t *testing.T) {
	var (
		upstreamCleanMetaCount    int64
		upstreamCleanTarballCount int64
		upstreamMalMetaCount      int64
		upstreamMalTarballCount   int64
	)

	// 1. Setup Mock Upstream Registry
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/trusted-framework":
			atomic.AddInt64(&upstreamCleanMetaCount, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "trusted-framework",
				"dist-tags": {"latest": "3.2.0"},
				"time": {
					"created": "2021-01-01T00:00:00Z",
					"modified": "2024-01-01T00:00:00Z",
					"3.2.0": "2024-01-01T00:00:00Z"
				},
				"versions": {
					"3.2.0": {
						"name": "trusted-framework",
						"version": "3.2.0",
						"dist": {
							"integrity": "sha512-legit-hash-clean",
							"tarball": "http://upstream/trusted-framework/-/trusted-framework-3.2.0.tgz"
						}
					}
				}
			}`))

		case "/trusted-framework/-/trusted-framework-3.2.0.tgz":
			atomic.AddInt64(&upstreamCleanTarballCount, 1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("VERIFIED_CLEAN_FRAMEWORK_BINARY_PAYLOAD"))

		case "/hallucinated-stealer":
			atomic.AddInt64(&upstreamMalMetaCount, 1)
			yesterday := time.Now().Add(-12 * time.Hour).Format(time.RFC3339)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"name": "hallucinated-stealer",
				"dist-tags": {"latest": "0.0.1"},
				"time": {
					"created": "%s",
					"modified": "%s",
					"0.0.1": "%s"
				},
				"versions": {
					"0.0.1": {
						"name": "hallucinated-stealer",
						"version": "0.0.1",
						"scripts": {"preinstall": "node dropper.js"},
						"dist": {
							"integrity": "sha512-malicious-exploit-hash",
							"tarball": "http://upstream/hallucinated-stealer/-/hallucinated-stealer-0.0.1.tgz"
						}
					}
				}
			}`, yesterday, yesterday, yesterday)

		case "/hallucinated-stealer/-/hallucinated-stealer-0.0.1.tgz":
			atomic.AddInt64(&upstreamMalTarballCount, 1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("EXPLOIT_DROPPER_CRITICAL_MALWARE"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	// 2. Setup Vetting Service pointing to mock upstream
	npmAdapter := registry.NewNPMAdapter(upstream.Client())
	npmAdapter.SetRegistryURL(upstream.URL)
	npmAdapter.SetDownloadURL(upstream.URL + "/downloads")

	evaluator := heuristics.DefaultEngine()
	vetService := service.NewVettingService(nil, []registry.Adapter{npmAdapter}, nil, evaluator, 24*time.Hour)

	// 3. Initialize and Start Mirror Proxy
	cfg := mirror.Config{
		Host:           "127.0.0.1",
		Port:           0, // Dynamically assigned port
		UpstreamNPM:    upstream.URL,
		UpstreamPyPI:   upstream.URL + "/pypi",
		VettingService: vetService,
		Threshold:      50,
	}

	server := mirror.NewServer(cfg)
	server.SetTransport(upstream.Client().Transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for mirror server readiness
	for i := 0; i < 50; i++ {
		if server.Port() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mirrorURL := fmt.Sprintf("http://127.0.0.1:%d", server.Port())
	client := &http.Client{Timeout: 2 * time.Second}

	// 4. Client Action A: Query & Download Clean Package
	cleanMetaResp, err := client.Get(mirrorURL + "/npm/trusted-framework")
	if err != nil {
		t.Fatalf("ADV-17 Failed: clean metadata request failed: %v", err)
	}
	defer cleanMetaResp.Body.Close()

	if cleanMetaResp.StatusCode != http.StatusOK {
		t.Fatalf("ADV-17 Failed: expected HTTP 200 for clean package, got %d", cleanMetaResp.StatusCode)
	}

	cleanTarballResp, err := client.Get(mirrorURL + "/npm/trusted-framework/-/trusted-framework-3.2.0.tgz")
	if err != nil {
		t.Fatalf("ADV-17 Failed: clean tarball download failed: %v", err)
	}
	defer cleanTarballResp.Body.Close()

	if cleanTarballResp.StatusCode != http.StatusOK {
		t.Fatalf("ADV-17 Failed: expected HTTP 200 for clean tarball, got %d", cleanTarballResp.StatusCode)
	}

	cleanBytes, _ := io.ReadAll(cleanTarballResp.Body)
	if string(cleanBytes) != "VERIFIED_CLEAN_FRAMEWORK_BINARY_PAYLOAD" {
		t.Fatalf("ADV-17 Failed: expected clean tarball contents, got %q", string(cleanBytes))
	}

	if atomic.LoadInt64(&upstreamCleanTarballCount) != 1 {
		t.Errorf("ADV-17 Failed: expected upstream clean tarball served once, got %d", upstreamCleanTarballCount)
	}

	// 5. Client Action B: Attempt to Download Malicious / Hallucinated Package
	malTarballResp, err := client.Get(mirrorURL + "/npm/hallucinated-stealer/-/hallucinated-stealer-0.0.1.tgz")
	if err != nil {
		t.Fatalf("ADV-17 Failed: malicious tarball request failed: %v", err)
	}
	defer malTarballResp.Body.Close()

	// MUST be blocked with HTTP 403 Forbidden
	if malTarballResp.StatusCode != http.StatusForbidden {
		t.Fatalf("ADV-17 Failed: expected HTTP 403 Forbidden for untrusted package, got %d", malTarballResp.StatusCode)
	}

	var blockDiag mirror.BlockedResponse
	if err := json.NewDecoder(malTarballResp.Body).Decode(&blockDiag); err != nil {
		t.Fatalf("ADV-17 Failed: response was not valid diagnostic JSON: %v", err)
	}

	if blockDiag.Error != "Blocked by Argus" {
		t.Errorf("ADV-17 Failed: expected error message 'Blocked by Argus', got %q", blockDiag.Error)
	}
	if blockDiag.Package != "hallucinated-stealer" {
		t.Errorf("ADV-17 Failed: expected package 'hallucinated-stealer', got %q", blockDiag.Package)
	}
	if blockDiag.Ecosystem != model.EcosystemNPM {
		t.Errorf("ADV-17 Failed: expected ecosystem 'npm', got %q", blockDiag.Ecosystem)
	}
	if blockDiag.RiskScore < 50 {
		t.Errorf("ADV-17 Failed: expected risk score >= 50, got %d", blockDiag.RiskScore)
	}
	if len(blockDiag.Reasons) == 0 {
		t.Errorf("ADV-17 Failed: expected threat penalty reasons in diagnostic response")
	}

	// 6. VERIFY CRITICAL ZERO-LEAK INVARIANT:
	// The upstream malicious tarball endpoint MUST NEVER have been requested or proxied to the client.
	if atomic.LoadInt64(&upstreamMalTarballCount) != 0 {
		t.Fatalf("ADV-17 SECURITY VIOLATION: Malicious tarball was fetched from upstream registry! Count = %d", upstreamMalTarballCount)
	}

	t.Logf("ADV-17 Interception Success: Blocked risk score %d/100 (%s), reasons: %v",
		blockDiag.RiskScore, blockDiag.RiskLevel, blockDiag.Reasons)

	// 7. Graceful Server Teardown
	cancel()
	_ = server.Close()
}
