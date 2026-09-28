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

func TestPackagistAdapter_FetchProvenance(t *testing.T) {
	packagistJSON := `{
		"packages": {
			"guzzlehttp/guzzle": [
				{
					"name": "guzzlehttp/guzzle",
					"version": "7.8.1",
					"time": "2023-12-03T18:00:00+00:00",
					"source": {
						"type": "git",
						"url": "https://github.com/guzzle/guzzle.git",
						"reference": "4de0563baaa2f102ee471642e04f218614055d7c"
					},
					"dist": {
						"type": "zip",
						"url": "https://api.github.com/repos/guzzle/guzzle/zipball/4de0563baaa2f102ee471642e04f218614055d7c",
						"shasum": "abcdef123456"
					},
					"authors": [
						{
							"name": "Michael Dowling",
							"email": "mtdowling@gmail.com"
						}
					]
				},
				{
					"name": "guzzlehttp/guzzle",
					"version": "1.0.0",
					"time": "2011-08-01T00:00:00+00:00",
					"source": {
						"type": "git",
						"url": "https://github.com/guzzle/guzzle.git",
						"reference": "v1.0.0"
					}
				}
			]
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"packagist-etag-789"`)
		fmt.Fprint(w, packagistJSON)
	}))
	defer server.Close()

	adapter := NewPackagistAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemPackagist {
		t.Fatalf("expected ecosystem %v, got %v", model.EcosystemPackagist, adapter.Ecosystem())
	}

	ctx := context.Background()
	prov, etag, err := adapter.FetchProvenance(ctx, "guzzlehttp/guzzle", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if etag != `"packagist-etag-789"` {
		t.Errorf("expected etag %q, got %q", `"packagist-etag-789"`, etag)
	}
	if prov.Name != "guzzlehttp/guzzle" {
		t.Errorf("expected name guzzlehttp/guzzle, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "7.8.1" {
		t.Errorf("expected version 7.8.1, got %s", prov.ResolvedVersion)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.IntegrityHash != "sha1-abcdef123456" {
		t.Errorf("unexpected hash: %s", prov.IntegrityHash)
	}
	if prov.RepositoryURL != "https://github.com/guzzle/guzzle.git" {
		t.Errorf("unexpected repo URL: %s", prov.RepositoryURL)
	}
	if prov.AuthorName != "Michael Dowling" {
		t.Errorf("unexpected author: %s", prov.AuthorName)
	}
	if prov.FirstReleaseDate.Year() != 2011 {
		t.Errorf("expected first release in 2011, got %v", prov.FirstReleaseDate)
	}
}

func TestPackagistAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewPackagistAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := adapter.FetchProvenance(ctx, "vendor/notfound", "")
	if err == nil {
		t.Fatal("expected error for non-existent package, got nil")
	}
}
