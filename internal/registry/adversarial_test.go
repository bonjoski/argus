package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ARG-01: Verify dist-tags (latest, canary) and semver ranges (^, ~, >=, *, empty)
// resolve against doc.Versions so HasInstallScripts and TarballURL NEVER silently skip.
func TestAdversarial_ARG01_NPMDistTagsAndSemverRangesExtractInstallScripts(t *testing.T) {
	npmDoc := `{
		"name": "stealth-hook-pkg",
		"dist-tags": {
			"latest": "1.2.0",
			"canary": "2.0.0-canary.1"
		},
		"time": {
			"created": "2024-01-01T00:00:00Z",
			"modified": "2025-01-01T00:00:00Z"
		},
		"versions": {
			"1.0.0": {
				"name": "stealth-hook-pkg",
				"version": "1.0.0",
				"dist": {
					"integrity": "sha512-clean100",
					"tarball": "https://registry.npmjs.org/stealth-hook-pkg/-/stealth-hook-pkg-1.0.0.tgz"
				}
			},
			"1.2.3": {
				"name": "stealth-hook-pkg",
				"version": "1.2.3",
				"scripts": {
					"postinstall": "node exfil.js"
				},
				"dist": {
					"integrity": "sha512-hook123",
					"tarball": "https://registry.npmjs.org/stealth-hook-pkg/-/stealth-hook-pkg-1.2.3.tgz"
				}
			},
			"1.2.0": {
				"name": "stealth-hook-pkg",
				"version": "1.2.0",
				"scripts": {
					"preinstall": "sh payload.sh"
				},
				"dist": {
					"integrity": "sha512-hook120",
					"tarball": "https://registry.npmjs.org/stealth-hook-pkg/-/stealth-hook-pkg-1.2.0.tgz"
				}
			},
			"2.0.0-canary.1": {
				"name": "stealth-hook-pkg",
				"version": "2.0.0-canary.1",
				"scripts": {
					"install": "node canary-hook.js"
				},
				"dist": {
					"integrity": "sha512-canary",
					"tarball": "https://registry.npmjs.org/stealth-hook-pkg/-/stealth-hook-pkg-2.0.0-canary.1.tgz"
				}
			}
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stealth-hook-pkg" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(npmDoc))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	adapter := NewNPMAdapter(srv.Client())
	adapter.SetRegistryURL(srv.URL)
	adapter.SetDownloadURL(srv.URL + "/downloads")

	cases := []struct {
		spec        string
		wantVersion string
		wantHash    string
	}{
		{"", "1.2.0", "sha512-hook120"},
		{"latest", "1.2.0", "sha512-hook120"},
		{"canary", "2.0.0-canary.1", "sha512-canary"},
		{"^1.0.0", "1.2.3", "sha512-hook123"},
		{"~1.2.0", "1.2.3", "sha512-hook123"},
		{">=1.1.0 <2.0.0", "1.2.3", "sha512-hook123"},
		{"*", "1.2.3", "sha512-hook123"},
	}

	for _, tc := range cases {
		prov, _, err := adapter.FetchProvenance(context.Background(), "stealth-hook-pkg", tc.spec)
		if err != nil {
			t.Fatalf("FetchProvenance(%q) unexpected error: %v", tc.spec, err)
		}
		if prov.ResolvedVersion != tc.wantVersion {
			t.Errorf("spec %q resolved to %q, want %q", tc.spec, prov.ResolvedVersion, tc.wantVersion)
		}
		if !prov.HasInstallScripts {
			t.Errorf("SECURITY BYPASS: spec %q failed to detect HasInstallScripts on resolved version %s", tc.spec, prov.ResolvedVersion)
		}
		if prov.TarballURL == "" {
			t.Errorf("SECURITY BYPASS: spec %q left TarballURL empty, skipping AST inspection", tc.spec)
		}
		if prov.IntegrityHash != tc.wantHash {
			t.Errorf("spec %q IntegrityHash = %q, want %q", tc.spec, prov.IntegrityHash, tc.wantHash)
		}
	}
}

// ARG-01: Fail closed when requested version/range/dist-tag cannot be resolved against doc.Versions.
func TestAdversarial_ARG01_NPMUnresolvableVersionFailsClosed(t *testing.T) {
	npmDoc := `{
		"name": "strict-pkg",
		"dist-tags": {"latest": "1.0.0", "broken": "9.9.9"},
		"versions": {
			"1.0.0": {
				"name": "strict-pkg",
				"version": "1.0.0",
				"dist": {"integrity": "sha512-ok"}
			}
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(npmDoc))
	}))
	defer srv.Close()

	adapter := NewNPMAdapter(srv.Client())
	adapter.SetRegistryURL(srv.URL)
	adapter.SetDownloadURL(srv.URL + "/downloads")

	for _, badSpec := range []string{"^2.0.0", "9.9.9", "broken", "not-a-semver-range"} {
		if _, _, err := adapter.FetchProvenance(context.Background(), "strict-pkg", badSpec); err == nil {
			t.Errorf("FAIL-OPEN: expected FetchProvenance(%q) to fail closed with error, got nil", badSpec)
		}
	}
}
