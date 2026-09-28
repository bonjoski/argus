package lockfile

import (
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		path        string
		expectedEco model.Ecosystem
	}{
		{"package-lock.json", model.EcosystemNPM},
		{"sub/dir/package-lock.json", model.EcosystemNPM},
		{"Cargo.lock", model.EcosystemCargo},
		{"poetry.lock", model.EcosystemPyPI},
		{"go.sum", model.EcosystemGo},
		{"packages.lock.json", model.EcosystemNuGet},
		{"sub/dir/packages.lock.json", model.EcosystemNuGet},
		{"pubspec.lock", model.EcosystemPub},
		{"mix.lock", model.EcosystemHex},
		{"Package.resolved", model.EcosystemSwift},
	}

	for _, tc := range tests {
		parser, eco, err := Detect(tc.path)
		if err != nil {
			t.Fatalf("unexpected error detecting %s: %v", tc.path, err)
		}
		if parser == nil {
			t.Fatalf("expected non-nil parser for %s", tc.path)
		}
		if eco != tc.expectedEco {
			t.Errorf("Detect(%s) = %s, expected %s", tc.path, eco, tc.expectedEco)
		}
	}
}

func TestNPMLockParser_V3(t *testing.T) {
	v3JSON := `{
		"name": "my-app",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "my-app"
			},
			"node_modules/express": {
				"version": "4.18.2",
				"integrity": "sha512-express-hash"
			},
			"node_modules/express/node_modules/debug": {
				"version": "2.6.9",
				"integrity": "sha512-debug-hash"
			}
		}
	}`

	parser := &NPMLockParser{}
	deps, err := parser.Parse(strings.NewReader(v3JSON))
	if err != nil {
		t.Fatalf("unexpected error parsing npm lock v3: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	for _, d := range deps {
		if d.Name == "express" {
			if d.IsTransitive {
				t.Errorf("expected express to not be transitive")
			}
			if d.IntegrityHash != "sha512-express-hash" {
				t.Errorf("unexpected hash for express: %s", d.IntegrityHash)
			}
		}
		if d.Name == "debug" {
			if !d.IsTransitive {
				t.Errorf("expected nested debug to be transitive")
			}
		}
	}
}

func TestCargoLockParser(t *testing.T) {
	cargoLock := `version = 3

[[package]]
name = "my-crate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
dependencies = [
 "serde_derive",
]
`

	parser := &CargoLockParser{}
	deps, err := parser.Parse(strings.NewReader(cargoLock))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 crates, got %d", len(deps))
	}

	if deps[1].Name != "serde" || deps[1].Version != "1.0.197" {
		t.Errorf("unexpected crate: %+v", deps[1])
	}
	if !strings.HasPrefix(deps[1].IntegrityHash, "sha256-") {
		t.Errorf("expected sha256 prefix in integrity hash, got %s", deps[1].IntegrityHash)
	}
}

func TestPoetryLockParser(t *testing.T) {
	poetryLock := `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.8"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:92d60375398d6d005c6b68e870abedd0d60d46ecd879d1a373cb80f8ab5ed742"},
]
`

	parser := &PoetryLockParser{}
	deps, err := parser.Parse(strings.NewReader(poetryLock))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 package, got %d", len(deps))
	}

	if deps[0].Name != "requests" || deps[0].Version != "2.31.0" {
		t.Errorf("unexpected package: %+v", deps[0])
	}
	if !strings.HasPrefix(deps[0].IntegrityHash, "sha256-") {
		t.Errorf("expected sha256 prefix in integrity hash, got %s", deps[0].IntegrityHash)
	}
}

func TestGoSumParser(t *testing.T) {
	goSum := `github.com/gin-gonic/gin v1.9.1 h1:4+TMb2Wus253d8C2D8o6y6...=
github.com/gin-gonic/gin v1.9.1/go.mod h1:O5yW...=
golang.org/x/sync v0.3.0 h1:ft/tqQ1s12yT...=
golang.org/x/sync v0.3.0/go.mod h1:FEe...=
`

	parser := &GoSumParser{}
	deps, err := parser.Parse(strings.NewReader(goSum))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 unique modules, got %d", len(deps))
	}

	if deps[0].Name != "github.com/gin-gonic/gin" || deps[0].Version != "v1.9.1" {
		t.Errorf("unexpected module: %+v", deps[0])
	}
	if deps[0].IntegrityHash != "h1:4+TMb2Wus253d8C2D8o6y6...=" {
		t.Errorf("expected module code hash, got %s", deps[0].IntegrityHash)
	}
}

func TestNuGetLockParser(t *testing.T) {
	nugetLockJSON := `{
		"version": 1,
		"dependencies": {
			"net8.0": {
				"Newtonsoft.Json": {
					"type": "Direct",
					"requested": "[13.0.3, )",
					"resolved": "13.0.3",
					"contentHash": "260c=="
				},
				"Microsoft.Extensions.Logging": {
					"type": "Transitive",
					"resolved": "8.0.0",
					"contentHash": "800c==",
					"dependencies": {
						"Microsoft.Extensions.DependencyInjection.Abstractions": "8.0.0"
					}
				}
			}
		}
	}`

	parser := &NuGetLockParser{}
	deps, err := parser.Parse(strings.NewReader(nugetLockJSON))
	if err != nil {
		t.Fatalf("unexpected error parsing nuget lock: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	for _, d := range deps {
		if d.Name == "Newtonsoft.Json" {
			if d.Version != "13.0.3" {
				t.Errorf("expected 13.0.3, got %s", d.Version)
			}
			if d.IsTransitive {
				t.Errorf("expected direct dependency for Newtonsoft.Json")
			}
			if d.IntegrityHash != "sha512-260c==" {
				t.Errorf("expected sha512-260c==, got %s", d.IntegrityHash)
			}
			if d.Ecosystem != model.EcosystemNuGet {
				t.Errorf("expected nuget ecosystem, got %s", d.Ecosystem)
			}
		}
		if d.Name == "Microsoft.Extensions.Logging" {
			if !d.IsTransitive {
				t.Errorf("expected transitive dependency for Microsoft.Extensions.Logging")
			}
		}
	}
}

func TestPubLockParser(t *testing.T) {
	pubLockYAML := `packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "abcdef123456"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  async:
    dependency: transitive
    description:
      name: async
      sha256: "9876543210"
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
`

	parser := &PubLockParser{}
	deps, err := parser.Parse(strings.NewReader(pubLockYAML))
	if err != nil {
		t.Fatalf("unexpected error parsing pub lock: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	for _, d := range deps {
		if d.Name == "http" {
			if d.Version != "1.2.0" {
				t.Errorf("expected 1.2.0, got %s", d.Version)
			}
			if d.IsTransitive {
				t.Errorf("expected direct dependency for http")
			}
			if d.IntegrityHash != "sha256-abcdef123456" {
				t.Errorf("expected hash sha256-abcdef123456, got %s", d.IntegrityHash)
			}
			if d.Ecosystem != model.EcosystemPub {
				t.Errorf("expected pub ecosystem, got %s", d.Ecosystem)
			}
		}
		if d.Name == "async" {
			if !d.IsTransitive {
				t.Errorf("expected transitive dependency for async")
			}
		}
	}
}

func TestHexLockParser(t *testing.T) {
	mixLockElixir := `%{
  "decimal": {:hex, :decimal, "2.1.1", "a96a17b2b8104e76", [:mix], [], "hexpm", "f1d4"},
  "phoenix": {:hex, :phoenix, "1.7.10", "c345164bc1f26771", [:mix], [], "hexpm", "58fe"},
  "custom_git": {:git, "https://github.com/org/custom.git", "gitrev1234", []}
}`

	parser := &HexLockParser{}
	deps, err := parser.Parse(strings.NewReader(mixLockElixir))
	if err != nil {
		t.Fatalf("unexpected error parsing mix lock: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	for _, d := range deps {
		if d.Name == "decimal" {
			if d.Version != "2.1.1" {
				t.Errorf("expected version 2.1.1, got %s", d.Version)
			}
			if d.IntegrityHash != "sha256-a96a17b2b8104e76" {
				t.Errorf("expected hash sha256-a96a17b2b8104e76, got %s", d.IntegrityHash)
			}
			if d.Ecosystem != model.EcosystemHex {
				t.Errorf("expected hex ecosystem, got %s", d.Ecosystem)
			}
		}
		if d.Name == "custom_git" {
			if d.Version != "gitrev1234" {
				t.Errorf("expected version gitrev1234, got %s", d.Version)
			}
		}
	}
}

func TestSwiftLockParser(t *testing.T) {
	v1JSON := `{
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

	v2JSON := `{
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

	v3JSON := `{
		"pins": [
			{
				"identity": "snapkit",
				"kind": "remoteSourceControl",
				"location": "https://github.com/SnapKit/SnapKit.git",
				"state": {
					"checksum": "snap-checksum-123",
					"revision": "snaprev789",
					"version": "5.7.0"
				}
			}
		],
		"version": 3,
		"originHash": "orig-hash"
	}`

	parser := &SwiftLockParser{}

	// Test V1
	deps1, err := parser.Parse(strings.NewReader(v1JSON))
	if err != nil {
		t.Fatalf("unexpected error parsing Swift V1: %v", err)
	}
	if len(deps1) != 1 || deps1[0].Name != "Alamofire" || deps1[0].Version != "5.8.1" {
		t.Errorf("unexpected v1 dep: %+v", deps1)
	}
	if deps1[0].Ecosystem != model.EcosystemSwift {
		t.Errorf("expected swift ecosystem, got %s", deps1[0].Ecosystem)
	}

	// Test V2
	deps2, err := parser.Parse(strings.NewReader(v2JSON))
	if err != nil {
		t.Fatalf("unexpected error parsing Swift V2: %v", err)
	}
	if len(deps2) != 1 || deps2[0].Name != "swift-algorithms" || deps2[0].Version != "1.2.0" {
		t.Errorf("unexpected v2 dep: %+v", deps2)
	}

	// Test V3
	deps3, err := parser.Parse(strings.NewReader(v3JSON))
	if err != nil {
		t.Fatalf("unexpected error parsing Swift V3: %v", err)
	}
	if len(deps3) != 1 || deps3[0].Name != "snapkit" || deps3[0].Version != "5.7.0" {
		t.Errorf("unexpected v3 dep: %+v", deps3)
	}
	if deps3[0].IntegrityHash != "snap-checksum-123" {
		t.Errorf("expected checksum snap-checksum-123, got %s", deps3[0].IntegrityHash)
	}
}
