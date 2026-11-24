package quarry

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAndEvaluateUpstreamAdvisoryRules(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules", "quarry")
	rules, err := LoadRulesFromDir(rulesDir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir(%s) failed: %v", rulesDir, err)
	}
	if len(rules) < 6 {
		t.Fatalf("expected at least 6 rules in %s, got %d", rulesDir, len(rules))
	}

	correlator := NewCorrelator(CorrelatorOptions{MultiTierWindow: true})
	for _, r := range rules {
		if err := correlator.RegisterRule(r); err != nil {
			t.Fatalf("RegisterRule(%q) failed: %v", r.Name, err)
		}
	}

	testCases := []struct {
		name        string
		pkg         string
		ver         string
		command     string
		wantRule    string
		shouldBlock bool
	}{
		// GHSA-qh76-45cr-8xrc: sevenz-rust2 < 0.21.1
		{"SevenZRust2_Vulnerable", "sevenz-rust2", "0.20.4", "", "sevenz_rust2_zip_slip", true},
		{"SevenZRust2_UnpinnedFailClosed", "sevenz-rust2", "", "cargo add sevenz-rust2", "sevenz_rust2_zip_slip", true},
		{"SevenZRust2_Patched", "sevenz-rust2", "0.21.1", "", "", false},

		// GHSA-f9h7-4mmq-vgcq: klever-go < 1.7.20
		{"KleverGo_Vulnerable", "github.com/klever-io/klever-go", "v1.7.19", "", "klever_go_bls_quorum_bypass", true},
		{"KleverGo_InlineSpec", "", "", "go get github.com/klever-io/klever-go@v1.7.18", "klever_go_bls_quorum_bypass", true},
		{"KleverGo_Patched", "github.com/klever-io/klever-go", "v1.7.20", "", "", false},

		// GHSA-p3j5-5hrq-p75h: nats-server < 2.12.8 || >= 2.14.0-RC.1, < 2.14.3
		{"NatsLeaf_Vulnerable212", "github.com/nats-io/nats-server/v2", "2.12.7", "", "nats_leaf_trace_bypass", true},
		{"NatsLeaf_Vulnerable214RC", "github.com/nats-io/nats-server/v2", "2.14.0-RC.1", "", "nats_leaf_trace_bypass", true},
		{"NatsLeaf_Vulnerable2142", "github.com/nats-io/nats-server/v2", "2.14.2", "", "nats_leaf_trace_bypass", true},
		{"NatsLeaf_Patched2128", "github.com/nats-io/nats-server/v2", "2.12.8", "", "", false},
		{"NatsLeaf_Patched2143", "github.com/nats-io/nats-server/v2", "2.14.3", "", "", false},

		// GHSA-x72p-hmqp-46hw: git-lfs >= 1.3.0, <= 2.13.3 || >= 3.0.0, < 3.8.1
		{"GitLFS_VulnerableV2", "github.com/git-lfs/git-lfs", "2.13.3", "", "git_lfs_config_rce", true},
		{"GitLFS_VulnerableV3", "github.com/git-lfs/git-lfs/v3", "v3.8.0", "", "git_lfs_config_rce", true},
		{"GitLFS_PatchedV381", "github.com/git-lfs/git-lfs/v3", "v3.8.1", "", "", false},

		// Benign unrelated package
		{"BenignPackage", "github.com/stretchr/testify", "v1.9.0", "", "", false},
	}

	for idx, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &Event{
				AgentPID:  9000 + idx,
				Layer:     LayerSupplyChain,
				Action:    "package_install",
				Command:   tc.command,
				Timestamp: time.Now(),
				Args:      map[string]any{},
			}
			if tc.pkg != "" {
				ev.Args["package"] = tc.pkg
			}
			if tc.ver != "" {
				ev.Args["version"] = tc.ver
			}

			alerts, err := correlator.Ingest(ev)
			if err != nil {
				t.Fatalf("Ingest error: %v", err)
			}

			if tc.shouldBlock {
				found := false
				for _, a := range alerts {
					if a.RuleName == tc.wantRule && a.Action == "kill" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("FAIL-OPEN: expected kill alert from rule %q for %s@%s, got alerts=%+v", tc.wantRule, tc.pkg, tc.ver, alerts)
				}
			} else {
				if len(alerts) != 0 {
					t.Fatalf("FALSE POSITIVE: expected 0 alerts for patched/benign %s@%s, got %+v", tc.pkg, tc.ver, alerts)
				}
			}
		})
	}
}

func TestAdversarial_VersionConstraintBypassAttempts(t *testing.T) {
	vcs, err := ParseVersionConstraintSet("<2.12.8 || >=2.14.0-RC.1, <2.14.3")
	if err != nil {
		t.Fatalf("ParseVersionConstraintSet failed: %v", err)
	}

	// Unpinned, floating, or malformed versions must fail closed (return true)
	failClosedInputs := []string{"", "latest", "main", "HEAD", "v2.12.x", "not-a-version", "2.14.0-RC.2+evil"}
	for _, v := range failClosedInputs {
		if !vcs.Matches(v) {
			t.Errorf("FAIL-OPEN: version %q bypassed vulnerable_versions constraint", v)
		}
	}

	// Invalid rule syntax must fail at compile time
	if _, err := ParseVersionConstraintSet("<=not_semver"); err == nil {
		t.Fatalf("FAIL-OPEN: ParseVersionConstraintSet accepted invalid semver syntax")
	}
	if _, err := ParseVersionConstraintSet("|| <1.0.0"); err == nil {
		t.Fatalf("FAIL-OPEN: ParseVersionConstraintSet accepted empty OR clause")
	}
}
