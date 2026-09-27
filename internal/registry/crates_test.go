package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"

	"bonjoski/argus/internal/model"
)

const sampleCratesPayload = `{
  "crate": {
    "id": "tokio",
    "name": "tokio",
    "created_at": "2016-06-24T18:23:44.250495+00:00",
    "updated_at": "2024-03-01T12:00:00.000000+00:00",
    "downloads": 120000000,
    "recent_downloads": 12000000,
    "max_version": "1.36.0",
    "repository": "https://github.com/tokio-rs/tokio",
    "homepage": "https://tokio.rs"
  },
  "versions": [
    {
      "id": 101,
      "num": "1.36.0",
      "created_at": "2024-03-01T12:00:00.000000+00:00",
      "updated_at": "2024-03-01T12:00:00.000000+00:00",
      "downloads": 500000,
      "checksum": "d16c9053075b5b0373fe49265f24ecb94a9629b307ec326e47d158f96409fe69",
      "dl_path": "/api/v1/crates/tokio/1.36.0/download",
      "yanked": false,
      "license": "MIT"
    },
    {
      "id": 100,
      "num": "1.35.0",
      "created_at": "2024-01-15T10:00:00.000000+00:00",
      "updated_at": "2024-01-15T10:00:00.000000+00:00",
      "downloads": 1200000,
      "checksum": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "dl_path": "/api/v1/crates/tokio/1.35.0/download",
      "yanked": false,
      "license": "MIT"
    }
  ]
}`

func TestCratesAdapter_FetchProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("missing User-Agent header")
		}
		if r.URL.Path != "/tokio" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", "W/\"etag-crates-tokio\"")
		w.Write([]byte(sampleCratesPayload))
	}))
	defer server.Close()

	adapter := NewCratesAdapter(server.Client())
	adapter.SetBaseURL(server.URL)
	adapter.SetLimiter(rate.NewLimiter(rate.Inf, 1)) // fast for tests

	ctx := context.Background()
	prov, etag, err := adapter.FetchProvenance(ctx, "tokio", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if etag != "W/\"etag-crates-tokio\"" {
		t.Errorf("expected etag W/\"etag-crates-tokio\", got %q", etag)
	}
	if prov.Name != "tokio" {
		t.Errorf("expected name tokio, got %s", prov.Name)
	}
	if prov.Ecosystem != model.EcosystemCargo {
		t.Errorf("expected ecosystem cargo, got %s", prov.Ecosystem)
	}
	if prov.ResolvedVersion != "1.36.0" {
		t.Errorf("expected version 1.36.0, got %s", prov.ResolvedVersion)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected total releases 2, got %d", prov.TotalReleases)
	}
	if prov.WeeklyDownloads != 1000000 {
		t.Errorf("expected weekly downloads 1000000, got %d", prov.WeeklyDownloads)
	}
	expectedHash := "sha256-d16c9053075b5b0373fe49265f24ecb94a9629b307ec326e47d158f96409fe69"
	if prov.IntegrityHash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, prov.IntegrityHash)
	}
	if prov.RepositoryURL != "https://github.com/tokio-rs/tokio" {
		t.Errorf("expected repo https://github.com/tokio-rs/tokio, got %s", prov.RepositoryURL)
	}
	if prov.FirstReleaseDate.IsZero() {
		t.Errorf("expected non-zero FirstReleaseDate")
	}
}

func TestCratesAdapter_SpecificVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(sampleCratesPayload))
	}))
	defer server.Close()

	adapter := NewCratesAdapter(server.Client())
	adapter.SetBaseURL(server.URL)
	adapter.SetLimiter(rate.NewLimiter(rate.Inf, 1))

	ctx := context.Background()
	prov, _, err := adapter.FetchProvenance(ctx, "tokio", "1.35.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.ResolvedVersion != "1.35.0" {
		t.Errorf("expected resolved version 1.35.0, got %s", prov.ResolvedVersion)
	}
	expectedHash := "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	if prov.IntegrityHash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, prov.IntegrityHash)
	}
}

func TestCratesAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := NewCratesAdapter(server.Client())
	adapter.SetBaseURL(server.URL)
	adapter.SetLimiter(rate.NewLimiter(rate.Inf, 1))

	ctx := context.Background()
	_, _, err := adapter.FetchProvenance(ctx, "nonexistent-crate", "")
	if err == nil {
		t.Fatalf("expected error for nonexistent crate, got nil")
	}
}
