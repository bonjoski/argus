package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestNuGetAdapter_FetchProvenance(t *testing.T) {
	nugetRegistrationJSON := `{
		"count": 1,
		"items": [
			{
				"@id": "https://api.nuget.org/v3/registration5-gz-semver/newtonsoft.json/index.json#page/1.0.0/13.0.3",
				"count": 2,
				"items": [
					{
						"@id": "https://api.nuget.org/v3/registration5-gz-semver/newtonsoft.json/1.0.0.json",
						"catalogEntry": {
							"id": "Newtonsoft.Json",
							"version": "1.0.0",
							"authors": "James Newton-King",
							"published": "2010-01-01T12:00:00Z",
							"projectUrl": "https://github.com/JamesNK/Newtonsoft.Json",
							"packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/1.0.0/newtonsoft.json.1.0.0.nupkg",
							"packageHash": "hash100",
							"packageHashAlgorithm": "SHA512",
							"listed": true
						},
						"packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/1.0.0/newtonsoft.json.1.0.0.nupkg"
					},
					{
						"@id": "https://api.nuget.org/v3/registration5-gz-semver/newtonsoft.json/13.0.3.json",
						"catalogEntry": {
							"id": "Newtonsoft.Json",
							"version": "13.0.3",
							"authors": "James Newton-King",
							"published": "2023-03-08T06:01:03Z",
							"projectUrl": "https://github.com/JamesNK/Newtonsoft.Json",
							"packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
							"packageHash": "4839hash==",
							"packageHashAlgorithm": "SHA512",
							"listed": true
						},
						"packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
					}
				]
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/newtonsoft.json/index.json") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "\"nuget-etag-123\"")
			w.Write([]byte(nugetRegistrationJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewNuGetAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	if adapter.Ecosystem() != model.EcosystemNuGet {
		t.Fatalf("expected ecosystem nuget, got %s", adapter.Ecosystem())
	}

	prov, etag, err := adapter.FetchProvenance(context.Background(), "Newtonsoft.Json", "13.0.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "Newtonsoft.Json" {
		t.Errorf("expected name Newtonsoft.Json, got %s", prov.Name)
	}
	if prov.ResolvedVersion != "13.0.3" {
		t.Errorf("expected version 13.0.3, got %s", prov.ResolvedVersion)
	}
	if prov.AuthorName != "James Newton-King" {
		t.Errorf("expected author James Newton-King, got %s", prov.AuthorName)
	}
	if prov.RepositoryURL != "https://github.com/JamesNK/Newtonsoft.Json" {
		t.Errorf("expected repository URL, got %s", prov.RepositoryURL)
	}
	if prov.IntegrityHash != "sha512-4839hash==" {
		t.Errorf("expected integrity hash sha512-4839hash==, got %s", prov.IntegrityHash)
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if prov.FirstReleaseDate.Year() != 2010 {
		t.Errorf("expected first release 2010, got %v", prov.FirstReleaseDate)
	}
	if prov.LatestReleaseDate.Year() != 2023 {
		t.Errorf("expected latest release 2023, got %v", prov.LatestReleaseDate)
	}
	if etag != "\"nuget-etag-123\"" {
		t.Errorf("expected etag \"nuget-etag-123\", got %s", etag)
	}
	if !prov.IsScoped {
		t.Errorf("expected Newtonsoft.Json to be scoped (dotted)")
	}
}

func TestNuGetAdapter_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewNuGetAdapter(server.Client())
	adapter.SetRegistryURL(server.URL)

	_, _, err := adapter.FetchProvenance(context.Background(), "NonExistentPackage", "")
	if err == nil {
		t.Fatalf("expected error for non-existent package, got nil")
	}
}
