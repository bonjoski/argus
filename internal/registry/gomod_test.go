package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestGoModAdapter_LatestVersion(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github.com/gin-gonic/gin/@latest":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Version":"v1.9.1","Time":"2023-06-01T10:00:00Z"}`))
		case "/github.com/gin-gonic/gin/@v/list":
			w.Write([]byte("v1.8.0\nv1.9.0\nv1.9.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxyServer.Close()

	sumServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lookup/github.com/gin-gonic/gin@v1.9.1" {
			w.Write([]byte("github.com/gin-gonic/gin v1.9.1 h1:4+TMb2Wus253d8C2D8o6y6...\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:O5yW...\n"))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer sumServer.Close()

	adapter := NewGoModAdapter(proxyServer.Client())
	adapter.SetProxyURL(proxyServer.URL)
	adapter.SetSumURL(sumServer.URL)

	ctx := context.Background()
	prov, _, err := adapter.FetchProvenance(ctx, "github.com/gin-gonic/gin", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected module name github.com/gin-gonic/gin, got %s", prov.Name)
	}
	if prov.Ecosystem != model.EcosystemGo {
		t.Errorf("expected ecosystem go, got %s", prov.Ecosystem)
	}
	if prov.ResolvedVersion != "v1.9.1" {
		t.Errorf("expected version v1.9.1, got %s", prov.ResolvedVersion)
	}
	if prov.TotalReleases != 3 {
		t.Errorf("expected total releases 3, got %d", prov.TotalReleases)
	}
	if !prov.InGoChecksumDB {
		t.Errorf("expected InGoChecksumDB to be true")
	}
	if prov.IntegrityHash != "h1:4+TMb2Wus253d8C2D8o6y6..." {
		t.Errorf("expected integrity hash h1:4+TMb2Wus253d8C2D8o6y6..., got %s", prov.IntegrityHash)
	}
	if prov.RepositoryURL != "https://github.com/gin-gonic/gin" {
		t.Errorf("expected repo https://github.com/gin-gonic/gin, got %s", prov.RepositoryURL)
	}
	if prov.AuthorName != "gin-gonic" {
		t.Errorf("expected author gin-gonic, got %s", prov.AuthorName)
	}
}

func TestGoModAdapter_ChecksumMissing(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Version":"v0.1.0","Time":"2024-01-01T00:00:00Z"}`))
	}))
	defer proxyServer.Close()

	sumServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer sumServer.Close()

	adapter := NewGoModAdapter(proxyServer.Client())
	adapter.SetProxyURL(proxyServer.URL)
	adapter.SetSumURL(sumServer.URL)

	ctx := context.Background()
	prov, _, err := adapter.FetchProvenance(ctx, "github.com/unknown/pkg", "v0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.InGoChecksumDB {
		t.Errorf("expected InGoChecksumDB to be false on 404")
	}
	if prov.IntegrityHash != "" {
		t.Errorf("expected empty integrity hash on 404, got %s", prov.IntegrityHash)
	}
}

func TestGoModAdapter_NotFound(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer proxyServer.Close()

	adapter := NewGoModAdapter(proxyServer.Client())
	adapter.SetProxyURL(proxyServer.URL)

	ctx := context.Background()
	_, _, err := adapter.FetchProvenance(ctx, "github.com/missing/module", "")
	if err == nil {
		t.Fatalf("expected error for nonexistent module, got nil")
	}
}

func TestEscapeModulePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/Azure/azure-sdk-for-go", "github.com/!azure/azure-sdk-for-go"},
		{"golang.org/x/sync", "golang.org/x/sync"},
	}

	for _, tc := range tests {
		actual := escapeModulePath(tc.input)
		if actual != tc.expected {
			t.Errorf("escapeModulePath(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}
