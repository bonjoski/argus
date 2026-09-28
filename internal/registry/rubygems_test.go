package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bonjoski/argus/internal/model"
)

func TestRubyGemsAdapter_FetchProvenance(t *testing.T) {
	gemJSON := `{
		"name": "rails",
		"downloads": 52000000,
		"version": "7.1.3",
		"version_downloads": 1000000,
		"authors": "David Heinemeier Hansson",
		"info": "Ruby on Rails",
		"sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"gem_uri": "https://rubygems.org/downloads/rails-7.1.3.gem",
		"source_code_uri": "https://github.com/rails/rails",
		"version_created_at": "2024-01-16T12:00:00.000Z"
	}`

	versionsJSON := `[
		{
			"number": "7.1.3",
			"created_at": "2024-01-16T12:00:00.000Z",
			"sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"downloads_count": 1000000
		},
		{
			"number": "0.1.0",
			"created_at": "2004-07-25T00:00:00.000Z",
			"sha": "11223344",
			"downloads_count": 500
		}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/gems/rails.json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"gem-etag-123"`)
			fmt.Fprint(w, gemJSON)
		case "/api/v1/versions/rails.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, versionsJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	adapter := NewRubyGemsAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemRubyGems {
		t.Fatalf("expected ecosystem %v, got %v", model.EcosystemRubyGems, adapter.Ecosystem())
	}

	ctx := context.Background()
	prov, etag, err := adapter.FetchProvenance(ctx, "rails", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if etag != `"gem-etag-123"` {
		t.Errorf("expected etag %q, got %q", `"gem-etag-123"`, etag)
	}
	if prov.Name != "rails" {
		t.Errorf("expected name rails, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "7.1.3" {
		t.Errorf("expected version 7.1.3, got %s", prov.ResolvedVersion)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.IntegrityHash != "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("unexpected hash: %s", prov.IntegrityHash)
	}
	if prov.RepositoryURL != "https://github.com/rails/rails" {
		t.Errorf("unexpected repo URL: %s", prov.RepositoryURL)
	}
	if prov.WeeklyDownloads != 1000000 {
		t.Errorf("expected 1000000 weekly downloads, got %d", prov.WeeklyDownloads)
	}
	if prov.FirstReleaseDate.Year() != 2004 {
		t.Errorf("expected first release 2004, got %v", prov.FirstReleaseDate)
	}
}

func TestRubyGemsAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewRubyGemsAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := adapter.FetchProvenance(ctx, "nonexistent-gem", "")
	if err == nil {
		t.Fatal("expected 404 error, got nil")
	}
}
