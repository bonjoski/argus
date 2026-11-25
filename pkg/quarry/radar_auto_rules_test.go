package quarry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type radarAutoManifestEntry struct {
	GHSAID           string `json:"ghsa_id"`
	CVEID            string `json:"cve_id"`
	RuleName         string `json:"rule_name"`
	RuleFile         string `json:"rule_file"`
	Ecosystem        string `json:"ecosystem"`
	PackageName      string `json:"package_name"`
	Constraint       string `json:"vulnerable_versions"`
	VulnerableSample string `json:"vulnerable_sample"`
	PatchedSample    string `json:"patched_sample"`
	CommandSample    string `json:"command_sample"`
}

type radarAutoManifest struct {
	SchemaVersion string                   `json:"schema_version"`
	Entries       []radarAutoManifestEntry `json:"entries"`
}

// TestRadarAutoAdvisoryRules validates every Quarry rule synthesized by Spanreed's
// automated daily threat radar (RFC-2026-11-25-59). Every auto-generated rule must:
//  1. Parse and compile cleanly with zero errors.
//  2. Block a concrete vulnerable SemVer with action="kill".
//  3. Fail closed (action="kill") when the version is omitted/unpinned or "latest".
//  4. Allow the first patched version with zero false positives.
//  5. Never interfere with unrelated benign packages.
func TestRadarAutoAdvisoryRules(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules", "quarry")
	manifestPath := filepath.Join(rulesDir, "radar_auto_manifest.json")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("radar_auto_manifest.json not present yet")
		}
		t.Fatalf("failed reading %s: %v", manifestPath, err)
	}

	var manifest radarAutoManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("FAIL-CLOSED: invalid radar_auto_manifest.json: %v", err)
	}

	// Strictly parse every radar_*.yaml file individually so malformed rules never silently skip.
	matches, err := filepath.Glob(filepath.Join(rulesDir, "radar_*.yaml"))
	if err != nil {
		t.Fatalf("glob radar_*.yaml failed: %v", err)
	}

	correlator := NewCorrelator(CorrelatorOptions{MultiTierWindow: true})
	for _, rf := range matches {
		parsed, err := ParseRulesFromFile(rf)
		if err != nil {
			t.Fatalf("FAIL-CLOSED: radar rule %s failed parse/validation: %v", rf, err)
		}
		for _, r := range parsed {
			if err := correlator.RegisterRule(r); err != nil {
				t.Fatalf("FAIL-CLOSED: RegisterRule(%q) from %s failed: %v", r.Name, rf, err)
			}
		}
	}

	if len(manifest.Entries) == 0 {
		return
	}

	for idx, entry := range manifest.Entries {
		entry := entry
		t.Run(entry.GHSAID+"_"+entry.RuleName, func(t *testing.T) {
			// Verify rule file exists and is confined inside rules/quarry
			if strings.Contains(entry.RuleFile, "..") || strings.ContainsAny(entry.RuleFile, `/\`) {
				t.Fatalf("FAIL-CLOSED: unsafe rule_file path %q", entry.RuleFile)
			}
			if _, err := os.Stat(filepath.Join(rulesDir, entry.RuleFile)); err != nil {
				t.Fatalf("FAIL-CLOSED: missing rule file %q: %v", entry.RuleFile, err)
			}

			// 1. Concrete vulnerable version MUST be blocked
			if entry.VulnerableSample != "" {
				ev := &Event{
					AgentPID:  20000 + idx*10 + 1,
					Layer:     LayerSupplyChain,
					Action:    "package_install",
					Timestamp: time.Now(),
					Args: map[string]any{
						"package": entry.PackageName,
						"version": entry.VulnerableSample,
					},
				}
				alerts, err := correlator.Ingest(ev)
				if err != nil {
					t.Fatalf("Ingest vulnerable sample failed: %v", err)
				}
				if !hasKillAlertForRule(alerts, entry.RuleName) {
					t.Fatalf("FAIL-OPEN: expected kill alert from %q for vulnerable %s@%s (constraint %q), got alerts=%+v",
						entry.RuleName, entry.PackageName, entry.VulnerableSample, entry.Constraint, alerts)
				}
			}

			// 2. Unpinned / empty version MUST fail closed
			evUnpinned := &Event{
				AgentPID:  20000 + idx*10 + 2,
				Layer:     LayerSupplyChain,
				Action:    "package_install",
				Command:   entry.CommandSample,
				Timestamp: time.Now(),
				Args: map[string]any{
					"package": entry.PackageName,
				},
			}
			alertsUnpinned, err := correlator.Ingest(evUnpinned)
			if err != nil {
				t.Fatalf("Ingest unpinned sample failed: %v", err)
			}
			if !hasKillAlertForRule(alertsUnpinned, entry.RuleName) {
				t.Fatalf("FAIL-OPEN: unpinned %s bypassed rule %q", entry.PackageName, entry.RuleName)
			}

			// 3. Floating "latest" version MUST fail closed
			evLatest := &Event{
				AgentPID:  20000 + idx*10 + 3,
				Layer:     LayerSupplyChain,
				Action:    "package_install",
				Timestamp: time.Now(),
				Args: map[string]any{
					"package": entry.PackageName,
					"version": "latest",
				},
			}
			alertsLatest, err := correlator.Ingest(evLatest)
			if err != nil {
				t.Fatalf("Ingest latest sample failed: %v", err)
			}
			if !hasKillAlertForRule(alertsLatest, entry.RuleName) {
				t.Fatalf("FAIL-OPEN: floating latest %s bypassed rule %q", entry.PackageName, entry.RuleName)
			}

			// 4. First patched version MUST be allowed (zero false positives)
			if entry.PatchedSample != "" {
				evPatched := &Event{
					AgentPID:  20000 + idx*10 + 4,
					Layer:     LayerSupplyChain,
					Action:    "package_install",
					Timestamp: time.Now(),
					Args: map[string]any{
						"package": entry.PackageName,
						"version": entry.PatchedSample,
					},
				}
				alertsPatched, err := correlator.Ingest(evPatched)
				if err != nil {
					t.Fatalf("Ingest patched sample failed: %v", err)
				}
				if hasAnyAlertForRule(alertsPatched, entry.RuleName) {
					t.Fatalf("FALSE POSITIVE: patched %s@%s triggered rule %q: %+v",
						entry.PackageName, entry.PatchedSample, entry.RuleName, alertsPatched)
				}
			}

			// 5. Unrelated benign package MUST never trigger this rule
			evBenign := &Event{
				AgentPID:  20000 + idx*10 + 5,
				Layer:     LayerSupplyChain,
				Action:    "package_install",
				Timestamp: time.Now(),
				Args: map[string]any{
					"package": "github.com/stretchr/testify",
					"version": "v1.9.0",
				},
			}
			alertsBenign, err := correlator.Ingest(evBenign)
			if err != nil {
				t.Fatalf("Ingest benign sample failed: %v", err)
			}
			if hasAnyAlertForRule(alertsBenign, entry.RuleName) {
				t.Fatalf("FALSE POSITIVE: benign package triggered rule %q: %+v", entry.RuleName, alertsBenign)
			}
		})
	}
}

func hasKillAlertForRule(alerts []*Alert, ruleName string) bool {
	for _, a := range alerts {
		if a.RuleName == ruleName && a.Action == "kill" {
			return true
		}
	}
	return false
}

func hasAnyAlertForRule(alerts []*Alert, ruleName string) bool {
	for _, a := range alerts {
		if a.RuleName == ruleName {
			return true
		}
	}
	return false
}
