package lockfile

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseNpmLock(t *testing.T) {
	pkgLockJSON := []byte(`{
		"name": "sample-project",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "sample-project",
				"version": "1.0.0"
			},
			"node_modules/express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				"integrity": "sha512-5/psL6iVEkiGu9pe45X5CMWRRE3cRfx2z3cdfG3t5FupqiUcC5pRztzsxF11bED3GuSmvyETFambDn6Fqm5DQg=="
			},
			"node_modules/lodash": {
				"version": "4.17.21",
				"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
			}
		}
	}`)

	deps, err := ParseNpmLock(pkgLockJSON)
	if err != nil {
		t.Fatalf("failed to parse npm lock: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	foundExpress := false
	for _, dep := range deps {
		if dep.Ref.Name == "express" && dep.Ref.Version == "4.18.2" {
			foundExpress = true
			if !strings.HasPrefix(dep.Integrity, "sha512-") {
				t.Errorf("unexpected integrity for express: %s", dep.Integrity)
			}
		}
	}

	if !foundExpress {
		t.Errorf("did not find express in parsed dependencies")
	}
}

func TestParseCargoLock(t *testing.T) {
	cargoLock := []byte(`
version = 3

[[package]]
name = "anyhow"
version = "1.0.75"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a4668dc1446613a5f8b7dfd9e1bc21b1ac5e1be09c90832759da75251f094947"

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cf9e0fcba69a370eed61bcf2b728575f726b50b55cba78064753d708ddc7549e"
`)

	deps, err := ParseCargoLock(cargoLock)
	if err != nil {
		t.Fatalf("failed to parse Cargo.lock: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(deps))
	}

	if deps[0].Ref.Name != "anyhow" || deps[0].Ref.Version != "1.0.75" {
		t.Errorf("unexpected package: %+v", deps[0])
	}
	if deps[0].Integrity != "a4668dc1446613a5f8b7dfd9e1bc21b1ac5e1be09c90832759da75251f094947" {
		t.Errorf("unexpected checksum: %s", deps[0].Integrity)
	}
}

func TestParseGoSum(t *testing.T) {
	goSum := []byte(`
github.com/gin-gonic/gin v1.9.1 h1:4+fr/ElT2pkfZLW8b9Wdewx5EotHAe5lM4QUMTXx5bM=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7YrpYKXt5YId3A/Tnip5wdbE1dslASNJstL8tqo=
golang.org/x/sys v0.6.0 h1:MVltknQI5T45cq8QTP3qL03LU1YVo65UtlicKGjKBq0=
`)

	deps, err := ParseGoSum(goSum)
	if err != nil {
		t.Fatalf("failed to parse go.sum: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 unique modules, got %d", len(deps))
	}
}

func TestLockfileTamper(t *testing.T) {
	// Baseline known good hashes
	trusted := map[string]string{
		"cargo:anyhow:1.0.75": "a4668dc1446613a5f8b7dfd9e1bc21b1ac5e1be09c90832759da75251f094947",
		"cargo:serde:1.0.188": "cf9e0fcba69a370eed61bcf2b728575f726b50b55cba78064753d708ddc7549e",
	}

	validator := NewLockfileValidator(trusted)

	// Tampered lockfile where serde has a modified hash
	tamperedCargoLock := []byte(`
version = 3

[[package]]
name = "anyhow"
version = "1.0.75"
checksum = "a4668dc1446613a5f8b7dfd9e1bc21b1ac5e1be09c90832759da75251f094947"

[[package]]
name = "serde"
version = "1.0.188"
checksum = "TAMPERED_CHECKSUM_0000000000000000000000000000000000000000000000000"

[[package]]
name = "unpinned-pkg"
version = "0.1.0"
`)

	deps, err := ParseCargoLock(tamperedCargoLock)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	report := validator.AuditDependencies(deps)
	if report.Allowed {
		t.Fatalf("expected tampered lockfile to be REJECTED, but was allowed")
	}

	if report.TamperedCount != 1 {
		t.Errorf("expected 1 tampered dep, got %d", report.TamperedCount)
	}

	if report.MissingHashes != 1 {
		t.Errorf("expected 1 missing hash dep, got %d", report.MissingHashes)
	}

	// Verify SBOM-enricher integration check
	licenses := map[string]string{
		"anyhow":     "MIT",
		"serde":      "GPL-3.0-only", // Assume GPL not allowed in proprietary build
		"unlicensed": "UNKNOWN",
	}
	validator.EnrichWithCycloneDX(report, licenses, []string{"MIT", "Apache-2.0"})

	if report.EnrichmentData == nil || !report.EnrichmentData.EnrichedWithCycloneDX {
		t.Errorf("expected enrichment data to be populated")
	}

	if len(report.EnrichmentData.NonCompliantLicenses) == 0 {
		t.Errorf("expected non-compliant license finding for GPL-3.0-only")
	}
}

func TestVerifyFileDigest(t *testing.T) {
	content := []byte("hello world")
	// SHA256 of "hello world" = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	validHex := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	ok, err := VerifyFileDigest(bytes.NewReader(content), validHex)
	if err != nil || !ok {
		t.Errorf("expected hex digest match, got ok=%v, err=%v", ok, err)
	}

	invalidHex := "0000000000000000000000000000000000000000000000000000000000000000"
	ok, _ = VerifyFileDigest(bytes.NewReader(content), invalidHex)
	if ok {
		t.Errorf("expected hex digest mismatch for invalid hash")
	}
}

func TestParseHelmChartLock(t *testing.T) {
	yamlContent := []byte(`
dependencies:
  - name: ingress-nginx
    version: 4.8.3
    repository: https://kubernetes.github.io/ingress-nginx
    digest: sha256:1122334455667788990011223344556677889900112233445566778899001122
digest: sha256:overall
generated: "2026-10-28T00:00:00Z"
`)

	deps, err := ParseHelmChartLock(yamlContent)
	if err != nil {
		t.Fatalf("ParseHelmChartLock failed: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Ref.Name != "ingress-nginx" || deps[0].Ref.Ecosystem != "helm" {
		t.Errorf("unexpected ref: %+v", deps[0].Ref)
	}
	if deps[0].Integrity != "sha256:1122334455667788990011223344556677889900112233445566778899001122" {
		t.Errorf("unexpected integrity: %s", deps[0].Integrity)
	}
}
