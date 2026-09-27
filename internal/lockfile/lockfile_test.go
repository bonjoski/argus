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
