package mirror

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
)

// ARG-04: Mirror proxy MUST fail closed (HTTP 403) when VettingService is nil or Vet returns an error.
func TestAdversarial_ARG04_MirrorFailsClosedOnVetErrorAndNilService(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phantom-pkg/-/phantom-pkg-1.0.0.tgz" {
			upstreamHits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("UNVETTED_PAYLOAD"))
			return
		}
		// Metadata endpoint simulates 503 outage -> Vet returns error!
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	adapter := registry.NewNPMAdapter(upstream.Client())
	adapter.SetRegistryURL(upstream.URL)
	vetSvc := service.NewVettingService(nil, []registry.Adapter{adapter}, nil, heuristics.DefaultEngine(), time.Hour)

	srv := NewServer(Config{
		Host:           "127.0.0.1",
		Port:           0,
		UpstreamNPM:    upstream.URL,
		VettingService: vetSvc,
		Threshold:      50,
	})
	srv.SetTransport(upstream.Client().Transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	for i := 0; i < 50 && srv.Port() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	defer srv.Close()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/npm/phantom-pkg/-/phantom-pkg-1.0.0.tgz", srv.Port()))
	if err != nil {
		t.Fatalf("mirror request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("FAIL-OPEN: expected HTTP 403 Forbidden when Vet fails, got %d", resp.StatusCode)
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("FAIL-OPEN: upstream tarball was proxied despite Vet failure!")
	}
}
