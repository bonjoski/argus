package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestSwiftAdapter_FetchProvenance(t *testing.T) {
	swiftDocJSON := `{
		"title": "swift-algorithms",
		"owner": "apple",
		"repositoryName": "swift-algorithms",
		"url": "https://github.com/apple/swift-algorithms",
		"summary": "Standard suite of sequence and collection algorithms",
		"license": "Apache-2.0",
		"history": {
			"firstCommit": "2020-10-01T00:00:00Z",
			"latestCommit": "2024-01-01T00:00:00Z",
			"firstRelease": "2020-10-07T00:00:00Z",
			"latestRelease": "2024-01-10T00:00:00Z",
			"releaseCount": 2
		},
		"releases": [
			{
				"version": "1.2.0",
				"date": "2024-01-10T00:00:00Z",
				"url": "https://github.com/apple/swift-algorithms/releases/tag/1.2.0",
				"checksum": "algo-checksum-120"
			},
			{
				"version": "1.0.0",
				"date": "2020-10-07T00:00:00Z",
				"url": "https://github.com/apple/swift-algorithms/releases/tag/1.0.0",
				"checksum": "algo-checksum-100"
			}
		],
		"authors": [
			{"name": "Apple Inc."}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/apple/swift-algorithms") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "\"swift-etag-77\"")
			w.Write([]byte(swiftDocJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewSwiftAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemSwift {
		t.Fatalf("expected ecosystem swift, got %s", adapter.Ecosystem())
	}

	// 1. Fetch latest version by default
	prov, etag, err := adapter.FetchProvenance(context.Background(), "apple/swift-algorithms", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "apple/swift-algorithms" {
		t.Errorf("expected name apple/swift-algorithms, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "1.2.0" {
		t.Errorf("expected version 1.2.0, got %s", prov.ResolvedVersion)
	}
	if prov.AuthorName != "Apple Inc." {
		t.Errorf("expected author Apple Inc., got %s", prov.AuthorName)
	}
	if prov.RepositoryURL != "https://github.com/apple/swift-algorithms" {
		t.Errorf("expected repo URL, got %s", prov.RepositoryURL)
	}
	if prov.IntegrityHash != "sha256-algo-checksum-120" {
		t.Errorf("expected integrity hash sha256-algo-checksum-120, got %s", prov.IntegrityHash)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.FirstReleaseDate.Year() != 2020 {
		t.Errorf("expected first release 2020, got %v", prov.FirstReleaseDate)
	}
	if prov.LatestReleaseDate.Year() != 2024 {
		t.Errorf("expected latest release 2024, got %v", prov.LatestReleaseDate)
	}
	if etag != "\"swift-etag-77\"" {
		t.Errorf("expected etag \"swift-etag-77\", got %s", etag)
	}
	if !prov.IsScoped {
		t.Errorf("expected apple/swift-algorithms to be scoped")
	}

	// 2. Fetch specific version 1.0.0
	prov1, _, err := adapter.FetchProvenance(context.Background(), "apple/swift-algorithms", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error for version 1.0.0: %v", err)
	}
	if prov1.ResolvedVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", prov1.ResolvedVersion)
	}
	if prov1.IntegrityHash != "sha256-algo-checksum-100" {
		t.Errorf("expected integrity hash sha256-algo-checksum-100, got %s", prov1.IntegrityHash)
	}
}

func TestSwiftAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewSwiftAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	_, _, err := adapter.FetchProvenance(context.Background(), "apple/non-existent-swift-pkg", "")
	if err == nil {
		t.Fatalf("expected error for non-existent package, got nil")
	}
}
