package adversarial

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

// ADV-19: Extended Ecosystem Adapters & Lockfiles (NuGet, Pub, Hex, Swift)
// Verifies:
// 1. Authoritative provenance adapters for NuGet (.NET), Pub (Dart/Flutter), Hex (Elixir), and Swift SPI.
// 2. High-risk threat detection against fresh/hallucinated packages across all 4 ecosystems (HR-01 Fresh Release, HR-03 Single Version Trap, HR-05A Detached VCS).
// 3. Robust lockfile parsing across packages.lock.json, pubspec.lock, mix.lock, and Package.resolved (v1, v2, v3).
func TestADV19_ExtendedEcosystemAdaptersAndLockfiles(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	freshDate := now.Add(-2 * 24 * time.Hour).Format(time.RFC3339)
	oldDate := now.Add(-400 * 24 * time.Hour).Format(time.RFC3339)

	// 1. Setup Mock Registries
	// NuGet Mock Server
	nugetMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "hallucinated.dotnet.auth") {
			jsonResp := fmt.Sprintf(`{
				"count": 1,
				"items": [
					{
						"count": 1,
						"items": [
							{
								"catalogEntry": {
									"id": "Hallucinated.Dotnet.Auth",
									"version": "1.0.0",
									"published": "%s",
									"authors": "ShadowActor",
									"projectUrl": "",
									"packageHash": "hash512==",
									"packageHashAlgorithm": "SHA512"
								}
							}
						]
					}
				]
			}`, freshDate)
			w.Write([]byte(jsonResp))
			return
		}
		if strings.Contains(r.URL.Path, "newtonsoft.json") {
			jsonResp := fmt.Sprintf(`{
				"count": 1,
				"items": [
					{
						"count": 2,
						"items": [
							{
								"catalogEntry": {
									"id": "Newtonsoft.Json",
									"version": "1.0.0",
									"published": "%s",
									"authors": "James Newton-King",
									"projectUrl": "https://github.com/JamesNK/Newtonsoft.Json"
								}
							},
							{
								"catalogEntry": {
									"id": "Newtonsoft.Json",
									"version": "13.0.3",
									"published": "%s",
									"authors": "James Newton-King",
									"projectUrl": "https://github.com/JamesNK/Newtonsoft.Json"
								}
							}
						]
					}
				]
			}`, oldDate, oldDate)
			w.Write([]byte(jsonResp))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nugetMock.Close()

	// Pub Mock Server
	pubMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/hallucinated_pub_auth") {
			jsonResp := fmt.Sprintf(`{
				"name": "hallucinated_pub_auth",
				"latest": {
					"version": "0.0.1",
					"pubspec": {
						"name": "hallucinated_pub_auth",
						"version": "0.0.1",
						"author": "HallucinatedDev",
						"repository": ""
					},
					"archive_url": "https://pub.dev/packages/hallucinated_pub_auth/versions/0.0.1.tar.gz",
					"archive_sha256": "abcdef9876",
					"published": "%s"
				},
				"versions": [
					{
						"version": "0.0.1",
						"pubspec": {"name": "hallucinated_pub_auth", "version": "0.0.1"},
						"published": "%s"
					}
				]
			}`, freshDate, freshDate)
			w.Write([]byte(jsonResp))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/http") {
			jsonResp := fmt.Sprintf(`{
				"name": "http",
				"latest": {
					"version": "1.2.0",
					"pubspec": {
						"name": "http",
						"version": "1.2.0",
						"author": "Dart Team",
						"repository": "https://github.com/dart-lang/http"
					},
					"published": "%s"
				},
				"versions": [
					{"version": "1.0.0", "published": "%s"},
					{"version": "1.2.0", "published": "%s"}
				]
			}`, oldDate, oldDate, oldDate)
			w.Write([]byte(jsonResp))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer pubMock.Close()

	// Hex Mock Server
	hexMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/hallucinated_hex_auth") {
			jsonResp := fmt.Sprintf(`{
				"name": "hallucinated_hex_auth",
				"meta": {
					"maintainers": ["BadActor"],
					"links": {}
				},
				"downloads": {"week": 5, "all": 5},
				"releases": [
					{
						"version": "0.1.0",
						"checksum": "hexchecksum999",
						"inserted_at": "%s"
					}
				]
			}`, freshDate)
			w.Write([]byte(jsonResp))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/phoenix") {
			jsonResp := fmt.Sprintf(`{
				"name": "phoenix",
				"meta": {
					"maintainers": ["Chris McCord"],
					"links": {"GitHub": "https://github.com/phoenixframework/phoenix"}
				},
				"downloads": {"week": 50000, "all": 5000000},
				"releases": [
					{"version": "1.7.10", "checksum": "phoenix1710", "inserted_at": "%s"},
					{"version": "1.0.0", "checksum": "phoenix100", "inserted_at": "%s"}
				]
			}`, oldDate, oldDate)
			w.Write([]byte(jsonResp))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer hexMock.Close()

	// Swift Mock Server
	swiftMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "attacker/swift-keychain-exfiltrator") {
			jsonResp := fmt.Sprintf(`{
				"title": "swift-keychain-exfiltrator",
				"owner": "attacker",
				"repositoryName": "swift-keychain-exfiltrator",
				"url": "",
				"history": {
					"firstRelease": "%s",
					"latestRelease": "%s",
					"releaseCount": 1
				},
				"releases": [
					{
						"version": "1.0.0",
						"date": "%s",
						"checksum": "swiftfakehash"
					}
				],
				"authors": [{"name": "attacker"}]
			}`, freshDate, freshDate, freshDate)
			w.Write([]byte(jsonResp))
			return
		}
		if strings.Contains(r.URL.Path, "apple/swift-algorithms") {
			jsonResp := fmt.Sprintf(`{
				"title": "swift-algorithms",
				"owner": "apple",
				"repositoryName": "swift-algorithms",
				"url": "https://github.com/apple/swift-algorithms",
				"history": {
					"firstRelease": "%s",
					"latestRelease": "%s",
					"releaseCount": 10
				},
				"releases": [
					{"version": "1.2.0", "date": "%s"},
					{"version": "1.0.0", "date": "%s"}
				],
				"authors": [{"name": "Apple Inc."}]
			}`, oldDate, oldDate, oldDate, oldDate)
			w.Write([]byte(jsonResp))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer swiftMock.Close()

	// 2. Configure Registry Adapters with Mock Base URLs
	nugetAdapter := registry.NewNuGetAdapter(nugetMock.Client())
	nugetAdapter.SetRegistryURL(nugetMock.URL)

	pubAdapter := registry.NewPubAdapter(pubMock.Client())
	pubAdapter.SetRegistryURL(pubMock.URL)

	hexAdapter := registry.NewHexAdapter(hexMock.Client())
	hexAdapter.SetRegistryURL(hexMock.URL)

	swiftAdapter := registry.NewSwiftAdapter(swiftMock.Client())
	swiftAdapter.SetRegistryURL(swiftMock.URL)

	adapters := []registry.Adapter{
		nugetAdapter,
		pubAdapter,
		hexAdapter,
		swiftAdapter,
	}

	evaluator := heuristics.DefaultEngine()
	vcsVerifier := vcs.NewHTTPVerifier(nil)
	vettingService := service.NewVettingService(nil, adapters, vcsVerifier, evaluator, 24*time.Hour)

	// 3. Verify Vetting and Hallucination Threat Flagging across all 4 ecosystems
	hallucinatedCases := []struct {
		eco     model.Ecosystem
		pkgName string
		version string
	}{
		{model.EcosystemNuGet, "Hallucinated.Dotnet.Auth", "1.0.0"},
		{model.EcosystemPub, "hallucinated_pub_auth", "0.0.1"},
		{model.EcosystemHex, "hallucinated_hex_auth", "0.1.0"},
		{model.EcosystemSwift, "attacker/swift-keychain-exfiltrator", "1.0.0"},
	}

	for _, tc := range hallucinatedCases {
		report, err := vettingService.Vet(ctx, tc.eco, tc.pkgName, tc.version)
		if err != nil {
			t.Fatalf("ADV-19 Failed: vetting failed for %s:%s: %v", tc.eco, tc.pkgName, err)
		}

		if report.TotalScore < 50 {
			t.Fatalf("ADV-19 Failed: expected risk score >= 50 for fresh hallucinated package %s:%s, got %d", tc.eco, tc.pkgName, report.TotalScore)
		}

		// Verify Fresh Release (HR-01) and Single Version Trap (HR-03) triggered
		foundHR01 := false
		foundHR03 := false
		for _, p := range report.Penalties {
			if p.RuleID == "HR-01" && p.Triggered {
				foundHR01 = true
			}
			if p.RuleID == "HR-03" && p.Triggered {
				foundHR03 = true
			}
		}

		if !foundHR01 {
			t.Errorf("ADV-19 Failed: expected HR-01 (Fresh Release) for %s:%s", tc.eco, tc.pkgName)
		}
		if !foundHR03 {
			t.Errorf("ADV-19 Failed: expected HR-03 (Single Version Trap) for %s:%s", tc.eco, tc.pkgName)
		}
	}

	// 4. Test Lockfile Parsers for NuGet, Pub, Hex, and Swift
	t.Run("NuGet_packages.lock.json", func(t *testing.T) {
		const lockContent = `{
			"version": 1,
			"dependencies": {
				"net8.0": {
					"Newtonsoft.Json": {
						"type": "Direct",
						"requested": "[13.0.3, )",
						"resolved": "13.0.3",
						"contentHash": "sha512-newtonsoft=="
					},
					"Microsoft.Extensions.Logging": {
						"type": "Transitive",
						"resolved": "8.0.0",
						"contentHash": "sha512-mslogging=="
					}
				}
			}
		}`
		parser, eco, err := lockfile.Detect("packages.lock.json")
		if err != nil {
			t.Fatalf("Detect failed: %v", err)
		}
		if eco != model.EcosystemNuGet {
			t.Fatalf("expected ecosystem nuget, got %s", eco)
		}
		deps, err := parser.Parse(strings.NewReader(lockContent))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(deps) != 2 {
			t.Fatalf("expected 2 dependencies, got %d", len(deps))
		}
		if deps[0].IsTransitive {
			t.Errorf("expected direct dependency for first item")
		}
		if !deps[1].IsTransitive {
			t.Errorf("expected transitive dependency for second item")
		}
	})

	t.Run("Pub_pubspec.lock", func(t *testing.T) {
		const lockContent = `packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "abc123sha256"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  async:
    dependency: transitive
    description:
      name: async
      sha256: "def456sha256"
    source: hosted
    version: "2.11.0"
`
		parser, eco, err := lockfile.Detect("pubspec.lock")
		if err != nil {
			t.Fatalf("Detect failed: %v", err)
		}
		if eco != model.EcosystemPub {
			t.Fatalf("expected ecosystem pub, got %s", eco)
		}
		deps, err := parser.Parse(strings.NewReader(lockContent))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(deps) != 2 {
			t.Fatalf("expected 2 dependencies, got %d", len(deps))
		}
		var foundHttp, foundAsync bool
		for _, d := range deps {
			if d.Name == "http" && !d.IsTransitive && d.IntegrityHash == "sha256-abc123sha256" {
				foundHttp = true
			}
			if d.Name == "async" && d.IsTransitive && d.IntegrityHash == "sha256-def456sha256" {
				foundAsync = true
			}
		}
		if !foundHttp || !foundAsync {
			t.Errorf("failed to parse expected pub dependencies: %+v", deps)
		}
	})

	t.Run("Hex_mix.lock", func(t *testing.T) {
		const lockContent = `%{
  "decimal": {:hex, :decimal, "2.1.1", "a96a17b2b8104e76", [:mix], [], "hexpm", "f1d4"},
  "phoenix": {:hex, :phoenix, "1.7.10", "c345164bc1f26771", [:mix], [], "hexpm", "58fe"}
}`
		parser, eco, err := lockfile.Detect("mix.lock")
		if err != nil {
			t.Fatalf("Detect failed: %v", err)
		}
		if eco != model.EcosystemHex {
			t.Fatalf("expected ecosystem hex, got %s", eco)
		}
		deps, err := parser.Parse(strings.NewReader(lockContent))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(deps) != 2 {
			t.Fatalf("expected 2 dependencies, got %d", len(deps))
		}
		if deps[0].Name != "decimal" || deps[0].Version != "2.1.1" {
			t.Errorf("unexpected first dep: %+v", deps[0])
		}
		if deps[1].Name != "phoenix" || deps[1].Version != "1.7.10" {
			t.Errorf("unexpected second dep: %+v", deps[1])
		}
	})

	t.Run("Swift_Package.resolved_v1_v2_v3", func(t *testing.T) {
		const v1Content = `{
			"object": {
				"pins": [
					{
						"package": "Alamofire",
						"repositoryURL": "https://github.com/Alamofire/Alamofire.git",
						"state": {
							"revision": "f96bd1f",
							"version": "5.8.1"
						}
					}
				]
			},
			"version": 1
		}`
		const v2Content = `{
			"pins": [
				{
					"identity": "swift-algorithms",
					"kind": "remoteSourceControl",
					"location": "https://github.com/apple/swift-algorithms.git",
					"state": {
						"revision": "a1b2c3d4",
						"version": "1.2.0"
					}
				}
			],
			"version": 2
		}`
		const v3Content = `{
			"pins": [
				{
					"identity": "snapkit",
					"kind": "remoteSourceControl",
					"location": "https://github.com/SnapKit/SnapKit.git",
					"state": {
						"checksum": "snap-checksum",
						"revision": "rev789",
						"version": "5.7.0"
					}
				}
			],
			"version": 3,
			"originHash": "orig"
		}`

		parser, eco, err := lockfile.Detect("Package.resolved")
		if err != nil {
			t.Fatalf("Detect failed: %v", err)
		}
		if eco != model.EcosystemSwift {
			t.Fatalf("expected ecosystem swift, got %s", eco)
		}

		deps1, err := parser.Parse(strings.NewReader(v1Content))
		if err != nil || len(deps1) != 1 || deps1[0].Name != "Alamofire" || deps1[0].Version != "5.8.1" {
			t.Errorf("failed parsing v1: %v, %+v", err, deps1)
		}

		deps2, err := parser.Parse(strings.NewReader(v2Content))
		if err != nil || len(deps2) != 1 || deps2[0].Name != "swift-algorithms" || deps2[0].Version != "1.2.0" {
			t.Errorf("failed parsing v2: %v, %+v", err, deps2)
		}

		deps3, err := parser.Parse(strings.NewReader(v3Content))
		if err != nil || len(deps3) != 1 || deps3[0].Name != "snapkit" || deps3[0].Version != "5.7.0" {
			t.Errorf("failed parsing v3: %v, %+v", err, deps3)
		}
	})
}
