package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestHexAdapter_FetchProvenance(t *testing.T) {
	hexPackageJSON := `{
		"name": "phoenix",
		"meta": {
			"description": "Peace of mind from prototype to production",
			"licenses": ["MIT"],
			"links": {
				"GitHub": "https://github.com/phoenixframework/phoenix",
				"Docs": "https://hexdocs.pm/phoenix"
			},
			"maintainers": ["Chris McCord", "Jose Valim"]
		},
		"downloads": {
			"all": 5000000,
			"recent": 50000,
			"week": 12500,
			"day": 2000
		},
		"releases": [
			{
				"version": "1.7.10",
				"url": "https://hex.pm/api/packages/phoenix/releases/1.7.10",
				"checksum": "c345164bc1f26771d6f272a8cfaebbf1797c277ee76e312a831eecba585b2e9e",
				"inserted_at": "2023-11-01T12:00:00Z",
				"updated_at": "2023-11-01T12:00:00Z"
			},
			{
				"version": "1.0.0",
				"url": "https://hex.pm/api/packages/phoenix/releases/1.0.0",
				"checksum": "1111111111111111111111111111111111111111111111111111111111111111",
				"inserted_at": "2015-09-01T12:00:00Z",
				"updated_at": "2015-09-01T12:00:00Z"
			}
		],
		"inserted_at": "2015-09-01T12:00:00Z",
		"updated_at": "2023-11-01T12:00:00Z"
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/phoenix") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "\"hex-etag-88\"")
			w.Write([]byte(hexPackageJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewHexAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemHex {
		t.Fatalf("expected ecosystem hex, got %s", adapter.Ecosystem())
	}

	// 1. Fetch latest version by default
	prov, etag, err := adapter.FetchProvenance(context.Background(), "phoenix", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "phoenix" {
		t.Errorf("expected name phoenix, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "1.7.10" {
		t.Errorf("expected version 1.7.10, got %s", prov.ResolvedVersion)
	}
	if prov.AuthorName != "Chris McCord" {
		t.Errorf("expected maintainer Chris McCord, got %s", prov.AuthorName)
	}
	if prov.RepositoryURL != "https://github.com/phoenixframework/phoenix" {
		t.Errorf("expected repo URL, got %s", prov.RepositoryURL)
	}
	if prov.WeeklyDownloads != 12500 {
		t.Errorf("expected 12500 weekly downloads, got %d", prov.WeeklyDownloads)
	}
	if prov.IntegrityHash != "sha256-c345164bc1f26771d6f272a8cfaebbf1797c277ee76e312a831eecba585b2e9e" {
		t.Errorf("expected integrity hash, got %s", prov.IntegrityHash)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.FirstReleaseDate.Year() != 2015 {
		t.Errorf("expected first release 2015, got %v", prov.FirstReleaseDate)
	}
	if prov.LatestReleaseDate.Year() != 2023 {
		t.Errorf("expected latest release 2023, got %v", prov.LatestReleaseDate)
	}
	if etag != "\"hex-etag-88\"" {
		t.Errorf("expected etag \"hex-etag-88\", got %s", etag)
	}

	// 2. Fetch specific version 1.0.0
	prov1, _, err := adapter.FetchProvenance(context.Background(), "phoenix", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error for version 1.0.0: %v", err)
	}
	if prov1.ResolvedVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", prov1.ResolvedVersion)
	}
	if prov1.IntegrityHash != "sha256-1111111111111111111111111111111111111111111111111111111111111111" {
		t.Errorf("expected hash for 1.0.0, got %s", prov1.IntegrityHash)
	}
}

func TestHexAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewHexAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	_, _, err := adapter.FetchProvenance(context.Background(), "non_existent_hex", "")
	if err == nil {
		t.Fatalf("expected error for non-existent package, got nil")
	}
}
