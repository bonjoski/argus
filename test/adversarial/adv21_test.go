package adversarial

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
	"bonjoski/argus/internal/registry"
)

// ADV-21: Attestation Laundering, Typosquat Offsetting, and Impersonation Veto Resistance
// Validates defenses against the class of vulnerabilities identified in GHSA-v6ph-v6gg-5hmm:
//  1. MO-01 Attestation Fabrication Defense: Standard npm registry signatures must never be
//     confused for cryptographic provenance attestations.
//  2. Impersonation Veto: Reputational offsets must never cancel out identity-impersonation
//     threats (HR-06 Lexical Conflation, HR-05B Spoofed VCS).
//  3. Terminal Security Tombstones: npm 0.0.1-security placeholders must evaluate to hard CRITICAL blocks.
//  4. Clean Provenance Laundering Defense: Single-version droppers and detached VCS cannot claim MO-05.
//  5. Decision Coherence: Output recommendations and exit statuses must never contradict each other.

// Scenario 1: Standard registry signature present without Sigstore attestations.
// Attacker expectation: Argus awards -40 pts (MO-01) due to dist.signatures presence.
// Defense requirement: MO-01 must evaluate to false; HasSigstoreProvenance must be false.
func TestADV21_AttestationFabricationDefense(t *testing.T) {
	fakeNPM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "expresss",
			"dist-tags": map[string]string{"latest": "0.0.0"},
			"time": map[string]string{
				"created":  "2016-08-15T00:00:00Z",
				"modified": "2016-08-15T00:00:00Z",
			},
			"versions": map[string]any{
				"0.0.0": map[string]any{
					"name":    "expresss",
					"version": "0.0.0",
					"dist": map[string]any{
						"integrity": "sha512-fakehash",
						"tarball":   "https://registry.npmjs.org/expresss/-/expresss-0.0.0.tgz",
						// Standard npm registry signature (attached automatically to all npm packages)
						"signatures": []map[string]string{
							{
								"keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
								"sig":   "MEUCIQDDywb1hZYJ4NOVXnh2ZykRSgTVF3wW3Eouy4xM2bVF3wIgEHA9BgRT4fZWrtmMZeyfE8otEgv0XS/2ukdhX2vIQaA=",
							},
						},
						// Note: attestations field is absent
					},
				},
			},
		})
	}))
	defer fakeNPM.Close()

	adapter := registry.NewNPMAdapter(fakeNPM.Client())
	adapter.SetRegistryURL(fakeNPM.URL)
	adapter.SetDownloadURL(fakeNPM.URL + "/downloads")

	prov, _, err := adapter.FetchProvenance(context.Background(), "expresss", "latest")
	if err != nil {
		t.Fatalf("ADV-21 Failed: npm metadata fetch failed: %v", err)
	}

	if prov.HasSigstoreProvenance {
		t.Fatalf("ADV-21 Vulnerability: HasSigstoreProvenance asserted true based solely on npm registry signature")
	}

	engine := heuristics.DefaultEngine()
	report := engine.Evaluate(prov)

	for _, o := range report.Offsets {
		if o.OffsetID == "MO-01" && o.Triggered {
			t.Fatalf("ADV-21 Vulnerability: MO-01 Cryptographic Attestation awarded to package without attestations")
		}
	}
}

// Scenario 2: Attacker crafts a typosquat and signs it with real Sigstore keys.
// Attacker expectation: -40 pts (MO-01) + -30 pts (MO-02) neutralizes the +25 pt HR-06 penalty,
// allowing a malicious typosquat to score 0/100 LOW and report "Safe to install".
// Defense requirement: Impersonation Veto must ensure identity impersonation penalties
// cannot be washed away by hygiene offsets.
func TestADV21_ImpersonationVeto_SigstoreSignedTyposquat(t *testing.T) {
	authorCreated := time.Now().Add(-500 * 24 * time.Hour)

	prov := &model.PackageProvenance{
		Name:                  "expresss", // Typosquat of express
		Ecosystem:             model.EcosystemNPM,
		ResolvedVersion:       "1.0.0",
		FirstReleaseDate:      time.Now().Add(-400 * 24 * time.Hour),
		LatestReleaseDate:     time.Now().Add(-10 * 24 * time.Hour),
		TotalReleases:         10,
		WeeklyDownloads:       5000,
		HasSigstoreProvenance: true, // Signed with Sigstore!
		AuthorName:            "adversary-signer",
		AuthorCreatedAt:       &authorCreated,
		AuthorTotalPackages:   10,
		VCSStatus:             model.VCSStatusVerified,
		RepositoryURL:         "https://github.com/adversary/expresss",
	}

	engine := heuristics.DefaultEngine()
	report := engine.Evaluate(prov)

	var hr06Triggered bool
	for _, p := range report.Penalties {
		if p.RuleID == "HR-06" && p.Triggered {
			hr06Triggered = true
			break
		}
	}
	if !hr06Triggered {
		t.Fatalf("ADV-21 Expected HR-06 (Lexical Conflation) to trigger for expresss")
	}

	// Impersonation Veto: Even with -40 (MO-01) and -30 (MO-02), score cannot drop below the veto penalty
	if report.TotalScore < 25 {
		t.Fatalf("ADV-21 Vulnerability: Impersonation Veto failed. Score washed down to %d despite typosquatting", report.TotalScore)
	}

	if report.Safe {
		t.Fatalf("ADV-21 Vulnerability: Typosquat marked as Safe to install")
	}

	if report.Verdict == model.VerdictAllow {
		t.Fatalf("ADV-21 Vulnerability: Verdict was ALLOW for typosquatted package")
	}
}

// Scenario 3: Revoked security tombstone placeholder (0.0.1-security).
// Defense requirement: Immediate terminal verdict, CRITICAL (100 pts), zero offsets awarded, BLOCK.
func TestADV21_SecurityTombstoneTerminalVerdict(t *testing.T) {
	prov := &model.PackageProvenance{
		Name:                "lodahs",
		Ecosystem:           model.EcosystemNPM,
		ResolvedVersion:     "0.0.1-security",
		IsSecurityTombstone: true,
		TotalReleases:       1,
		FirstReleaseDate:    time.Now().Add(-500 * 24 * time.Hour),
		RepositoryURL:       "https://github.com/npm/security-holder",
		VCSStatus:           model.VCSStatusMismatch,
		IntegrityHash:       "sha512-test",
	}

	engine := heuristics.DefaultEngine()
	report := engine.Evaluate(prov)

	if report.TotalScore != 100 {
		t.Fatalf("ADV-21 Expected security tombstone score 100, got %d", report.TotalScore)
	}
	if report.RiskLevel != model.RiskLevelCritical {
		t.Fatalf("ADV-21 Expected RiskLevelCritical, got %s", report.RiskLevel)
	}
	if report.TotalOffsets != 0 {
		t.Fatalf("ADV-21 Expected 0 offsets awarded to security tombstone, got %d", report.TotalOffsets)
	}
	if !report.Blocked {
		t.Fatalf("ADV-21 Expected security tombstone to be blocked")
	}
	if report.Verdict != model.VerdictBlock {
		t.Fatalf("ADV-21 Expected verdict BLOCK, got %s", report.Verdict)
	}
}

// Scenario 4: Clean Provenance Credit Laundering (MO-05).
// An attacker creates a detached or single-version package and tries to claim MO-05.
// Defense requirement: MO-05 must strictly refuse packages with Detached/Missing/Mismatch VCS or TotalReleases <= 1.
func TestADV21_DirtyProvenanceCreditLaunderingDefense(t *testing.T) {
	oldDate := time.Now().Add(-300 * 24 * time.Hour)

	// Case A: Detached VCS (VCSStatusNone)
	provDetached := &model.PackageProvenance{
		Name:              "detached-dropper",
		Ecosystem:         model.EcosystemNPM,
		ResolvedVersion:   "1.0.0",
		TotalReleases:     5,
		FirstReleaseDate:  oldDate,
		IntegrityHash:     "sha512-hash",
		HasInstallScripts: false,
		VCSStatus:         model.VCSStatusNone,
	}

	// Case B: Single Version Trap (TotalReleases == 1)
	provSingleVersion := &model.PackageProvenance{
		Name:              "single-version-trap",
		Ecosystem:         model.EcosystemNPM,
		ResolvedVersion:   "0.0.1",
		TotalReleases:     1,
		FirstReleaseDate:  oldDate,
		IntegrityHash:     "sha512-hash",
		HasInstallScripts: false,
		VCSStatus:         model.VCSStatusVerified,
	}

	engine := heuristics.DefaultEngine()

	reportA := engine.Evaluate(provDetached)
	for _, o := range reportA.Offsets {
		if o.OffsetID == "MO-05" && o.Triggered {
			t.Fatalf("ADV-21 Vulnerability: MO-05 awarded to package with detached VCS")
		}
	}

	reportB := engine.Evaluate(provSingleVersion)
	for _, o := range reportB.Offsets {
		if o.OffsetID == "MO-05" && o.Triggered {
			t.Fatalf("ADV-21 Vulnerability: MO-05 awarded to package with single release lifetime")
		}
	}
}

// Scenario 5: Output Coherence & Decision Integrity.
// Defense requirement: When a package is blocked by policy or threshold, TTY output must
// NEVER print "Safe to install", and JSON output must carry blocked/verdict fields.
func TestADV21_OutputCoherenceAndVerdictFields(t *testing.T) {
	report := &model.RiskReport{
		Package:         "malicious-squat",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		TotalScore:      75,
		RiskLevel:       model.RiskLevelHigh,
		Blocked:         true,
		Safe:            false,
		Verdict:         model.VerdictBlock,
		Action:          "block",
	}

	var buf bytes.Buffer
	reporter := output.TTYReporter{}
	if err := reporter.Render(&buf, report); err != nil {
		t.Fatalf("ADV-21 TTY render error: %v", err)
	}

	outStr := buf.String()
	if strings.Contains(outStr, "Safe to install") {
		t.Fatalf("ADV-21 Vulnerability: TTY output contained 'Safe to install' on blocked report")
	}
	if !strings.Contains(outStr, "BLOCKED") {
		t.Fatalf("ADV-21 Expected TTY output to contain 'BLOCKED'")
	}

	// Verify JSON output serialization includes verdict and blocked fields
	var jsonBuf bytes.Buffer
	jsonReporter := output.JSONReporter{}
	if err := jsonReporter.Render(&jsonBuf, report); err != nil {
		t.Fatalf("ADV-21 JSON render error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("ADV-21 Failed to parse JSON report: %v", err)
	}

	if parsed["verdict"] != "BLOCK" {
		t.Errorf("ADV-21 Expected JSON verdict BLOCK, got %v", parsed["verdict"])
	}
	if parsed["blocked"] != true {
		t.Errorf("ADV-21 Expected JSON blocked true, got %v", parsed["blocked"])
	}
	if parsed["safe"] != false {
		t.Errorf("ADV-21 Expected JSON safe false, got %v", parsed["safe"])
	}
	if parsed["action"] != "block" {
		t.Errorf("ADV-21 Expected JSON action block, got %v", parsed["action"])
	}
}
