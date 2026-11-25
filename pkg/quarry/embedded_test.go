package quarry

import (
	"testing"
)

func TestEmbeddedQuarryRules_EnforceAdvisoriesAtRuntime(t *testing.T) {
	rules, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatalf("LoadEmbeddedRules failed: %v", err)
	}
	if len(rules) < 8 {
		t.Fatalf("expected >= 8 embedded quarry rules, got %d", len(rules))
	}
	digest := EmbeddedRulesDigest()
	if len(digest) != 64 {
		t.Fatalf("expected 64-char SHA-256 embedded digest, got %q", digest)
	}

	cases := []struct {
		name      string
		pkg       string
		ver       string
		wantBlock bool
		wantRule  string
	}{
		{"GHCLI_Vulnerable", "github.com/cli/cli/v2", "v2.95.0", true, "radar_ghsa_8cg3_r6g9_fpg2"},
		{"GHCLI_UnpinnedFailClosed", "github.com/cli/cli/v2", "", true, "radar_ghsa_8cg3_r6g9_fpg2"},
		{"GHCLI_Patched", "github.com/cli/cli/v2", "v2.96.0", false, ""},
		{"Etcd_Vulnerable35", "go.etcd.io/etcd/v3", "3.5.31", true, "radar_ghsa_3wh4_j44w_pg92"},
		{"Etcd_Vulnerable36", "go.etcd.io/etcd/v3", "3.6.12", true, "radar_ghsa_3wh4_j44w_pg92"},
		{"Etcd_Patched3613", "go.etcd.io/etcd/v3", "3.6.13", false, ""},
		{"SevenZRust2_Vulnerable", "sevenz-rust2", "0.20.4", true, "sevenz_rust2_zip_slip"},
		{"SevenZRust2_Patched", "sevenz-rust2", "0.21.1", false, ""},
		{"BenignPackage", "github.com/stretchr/testify", "v1.9.0", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alerts, err := EvaluateEmbeddedPackageAdvisory(tc.pkg, tc.ver, "")
			if err != nil {
				t.Fatalf("EvaluateEmbeddedPackageAdvisory error: %v", err)
			}
			if tc.wantBlock {
				if len(alerts) == 0 || alerts[0].RuleName != tc.wantRule {
					t.Fatalf("FAIL-OPEN: expected embedded rule %q for %s@%s, got %+v", tc.wantRule, tc.pkg, tc.ver, alerts)
				}
			} else if len(alerts) != 0 {
				t.Fatalf("FALSE POSITIVE: expected 0 alerts for %s@%s, got %+v", tc.pkg, tc.ver, alerts)
			}
		})
	}
}
