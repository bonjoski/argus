package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNPMAdapter_FetchProvenance(t *testing.T) {
	npmDocJSON := `{
		"name": "sample-pkg",
		"dist-tags": {"latest": "1.0.0"},
		"time": {
			"created": "2024-01-01T00:00:00.000Z",
			"modified": "2024-02-01T00:00:00.000Z"
		},
		"versions": {
			"1.0.0": {
				"name": "sample-pkg",
				"version": "1.0.0",
				"scripts": {
					"postinstall": "node setup.js"
				},
				"dist": {
					"integrity": "sha512-test-hash",
					"tarball": "https://registry.npmjs.org/sample-pkg/-/sample-pkg-1.0.0.tgz",
					"signatures": [{"keyid": "sig-1"}]
				}
			}
		},
		"repository": {
			"type": "git",
			"url": "git+https://github.com/sample/sample-pkg.git"
		}
	}`

	downloadsJSON := `{"downloads": 1250}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downloads/sample-pkg" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(downloadsJSON))
			return
		}
		if r.URL.Path == "/sample-pkg" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "W/\"sample-etag\"")
			w.Write([]byte(npmDocJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	adapter := NewNPMAdapter(server.Client())
	adapter.registryURL = server.URL
	adapter.downloadURL = server.URL + "/downloads"

	prov, etag, err := adapter.FetchProvenance(context.Background(), "sample-pkg", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "sample-pkg" || prov.ResolvedVersion != "1.0.0" {
		t.Errorf("unexpected name/version: %s@%s", prov.Name, prov.ResolvedVersion)
	}
	if !prov.HasInstallScripts {
		t.Errorf("expected HasInstallScripts to be true")
	}
	if !prov.HasSigstoreProvenance {
		t.Errorf("expected HasSigstoreProvenance to be true")
	}
	if prov.WeeklyDownloads != 1250 {
		t.Errorf("expected 1250 downloads, got %d", prov.WeeklyDownloads)
	}
	if etag != "W/\"sample-etag\"" {
		t.Errorf("expected etag W/\"sample-etag\", got %s", etag)
	}
}

func TestPyPIAdapter_FetchProvenance(t *testing.T) {
	pypiDocJSON := `{
		"info": {
			"name": "demo-pkg",
			"version": "0.5.0",
			"author": "Alice",
			"project_urls": {
				"Source": "https://github.com/alice/demo-pkg"
			}
		},
		"releases": {
			"0.1.0": [
				{"filename": "demo_pkg-0.1.0-py3-none-any.whl", "upload_time_iso_8601": "2024-01-01T12:00:00Z"}
			],
			"0.5.0": [
				{
					"filename": "demo_pkg-0.5.0-py3-none-any.whl",
					"packagetype": "bdist_wheel",
					"upload_time_iso_8601": "2024-03-01T12:00:00Z",
					"has_sigstore": true,
					"digests": {"sha256": "sha256-demo-digest"}
				}
			]
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", "\"pypi-etag\"")
		w.Write([]byte(pypiDocJSON))
	}))
	defer server.Close()

	adapter := NewPyPIAdapter(server.Client())
	adapter.baseURL = server.URL

	prov, etag, err := adapter.FetchProvenance(context.Background(), "demo-pkg", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.Name != "demo-pkg" || prov.ResolvedVersion != "0.5.0" {
		t.Errorf("unexpected name/version: %s@%s", prov.Name, prov.ResolvedVersion)
	}
	if !prov.HasBinaryWheels {
		t.Errorf("expected HasBinaryWheels to be true")
	}
	if !prov.HasPEP740Attestation {
		t.Errorf("expected HasPEP740Attestation to be true")
	}
	if prov.TotalReleases != 2 {
		t.Errorf("expected 2 releases, got %d", prov.TotalReleases)
	}
	if etag != "\"pypi-etag\"" {
		t.Errorf("expected etag \"pypi-etag\", got %s", etag)
	}
	if prov.FirstReleaseDate.Year() != 2024 {
		t.Errorf("expected 2024 release year, got %v", prov.FirstReleaseDate)
	}
}
