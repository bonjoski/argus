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

func TestMavenAdapter_FetchProvenance(t *testing.T) {
	solrJSON := `{
		"response": {
			"numFound": 12,
			"start": 0,
			"docs": [
				{
					"id": "com.google.guava:guava:33.0.0-jre",
					"g": "com.google.guava",
					"a": "guava",
					"v": "33.0.0-jre",
					"timestamp": 1705600000000,
					"ec": [".jar", ".pom", "-sources.jar", ".asc"]
				},
				{
					"id": "com.google.guava:guava:10.0",
					"g": "com.google.guava",
					"a": "guava",
					"v": "10.0",
					"timestamp": 1318000000000,
					"ec": [".jar", ".pom"]
				}
			]
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"solr-etag-456"`)
		fmt.Fprint(w, solrJSON)
	}))
	defer server.Close()

	adapter := NewMavenAdapter(server.Client())
	adapter.SetSearchURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemMaven {
		t.Fatalf("expected ecosystem %v, got %v", model.EcosystemMaven, adapter.Ecosystem())
	}

	ctx := context.Background()
	prov, etag, err := adapter.FetchProvenance(ctx, "com.google.guava:guava", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if etag != `"solr-etag-456"` {
		t.Errorf("expected etag %q, got %q", `"solr-etag-456"`, etag)
	}
	if prov.Name != "com.google.guava:guava" {
		t.Errorf("expected name com.google.guava:guava, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "33.0.0-jre" {
		t.Errorf("expected version 33.0.0-jre, got %s", prov.ResolvedVersion)
	}
	if prov.TotalReleases != 12 {
		t.Errorf("expected 12 releases, got %d", prov.TotalReleases)
	}
	if !prov.HasSigstoreProvenance {
		t.Error("expected cryptographic signature (.asc) to be detected")
	}
	if !prov.IsScoped {
		t.Error("expected com.google.guava to be marked as scoped")
	}
	if prov.FirstReleaseDate.IsZero() {
		t.Error("expected first release date to be populated")
	}
}

func TestMavenAdapter_NotFound(t *testing.T) {
	solrEmptyJSON := `{
		"response": {
			"numFound": 0,
			"start": 0,
			"docs": []
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, solrEmptyJSON)
	}))
	defer server.Close()

	adapter := NewMavenAdapter(server.Client())
	adapter.SetSearchURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := adapter.FetchProvenance(ctx, "com.example:notfound", "")
	if err == nil {
		t.Fatal("expected error for non-existent artifact, got nil")
	}
}
