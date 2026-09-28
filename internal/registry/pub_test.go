package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestPubAdapter_FetchProvenance(t *testing.T) {
	pubPackageJSON := `{
		"name": "http",
		"latest": {
			"version": "1.2.0",
			"pubspec": {
				"name": "http",
				"version": "1.2.0",
				"author": "Dart Team",
				"repository": "https://github.com/dart-lang/http",
				"homepage": "https://dart.dev"
			},
			"archive_url": "https://pub.dev/packages/http/versions/1.2.0.tar.gz",
			"archive_sha256": "abcdef1234567890",
			"published": "2024-02-15T12:00:00.000Z"
		},
		"versions": [
			{
				"version": "1.0.0",
				"pubspec": {
					"name": "http",
					"version": "1.0.0",
					"author": "Dart Team",
					"repository": "https://github.com/dart-lang/http"
				},
				"archive_url": "https://pub.dev/packages/http/versions/1.0.0.tar.gz",
				"archive_sha256": "1111111111111111",
				"published": "2023-01-10T12:00:00.000Z"
			},
			{
				"version": "1.2.0",
				"pubspec": {
					"name": "http",
					"version": "1.2.0",
					"author": "Dart Team",
					"repository": "https://github.com/dart-lang/http"
				},
				"archive_url": "https://pub.dev/packages/http/versions/1.2.0.tar.gz",
				"archive_sha256": "abcdef1234567890",
				"published": "2024-02-15T12:00:00.000Z"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/http") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "\"pub-etag-99\"")
			w.Write([]byte(pubPackageJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewPubAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemPub {
		t.Fatalf("expected ecosystem pub, got %s", adapter.Ecosystem())
	}

	// 1. Fetch latest version by default
	prov, etag, err := adapter.FetchProvenance(context.Background(), "http", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "http" {
		t.Errorf("expected name http, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "1.2.0" {
		t.Errorf("expected version 1.2.0, got %s", prov.ResolvedVersion)
	}
	if prov.AuthorName != "Dart Team" {
		t.Errorf("expected author Dart Team, got %s", prov.AuthorName)
	}
	if prov.RepositoryURL != "https://github.com/dart-lang/http" {
		t.Errorf("expected repo URL, got %s", prov.RepositoryURL)
	}
	if prov.IntegrityHash != "sha256-abcdef1234567890" {
		t.Errorf("expected hash sha256-abcdef1234567890, got %s", prov.IntegrityHash)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.FirstReleaseDate.Year() != 2023 {
		t.Errorf("expected first release 2023, got %v", prov.FirstReleaseDate)
	}
	if prov.LatestReleaseDate.Year() != 2024 {
		t.Errorf("expected latest release 2024, got %v", prov.LatestReleaseDate)
	}
	if etag != "\"pub-etag-99\"" {
		t.Errorf("expected etag \"pub-etag-99\", got %s", etag)
	}

	// 2. Fetch specific version 1.0.0
	prov1, _, err := adapter.FetchProvenance(context.Background(), "http", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error for version 1.0.0: %v", err)
	}
	if prov1.ResolvedVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", prov1.ResolvedVersion)
	}
	if prov1.IntegrityHash != "sha256-1111111111111111" {
		t.Errorf("expected hash sha256-1111111111111111, got %s", prov1.IntegrityHash)
	}
}

func TestPubAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewPubAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	_, _, err := adapter.FetchProvenance(context.Background(), "non_existent_pkg", "")
	if err == nil {
		t.Fatalf("expected error for non-existent package, got nil")
	}
}
