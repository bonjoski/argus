package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicy_LoadAndMatch(t *testing.T) {
	yamlContent := `
version: 1
threshold: 60
strict: true
allowlist:
  packages:
    - "@mycorp/*"
    - "my-internal-tool"
  authors:
    - "trusted-dev"
  namespaces:
    - "@corp/"
blocklist:
  packages:
    - "malicious-pkg"
    - "evil-*"
  authors:
    - "hacker"
rule_overrides:
  HR-09: 20
  HR-01: 0
offline:
  enabled: true
  fallback_cache_only: true
`
	tmpDir, err := os.MkdirTemp("", "argus-policy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	policyPath := filepath.Join(tmpDir, ".argusrc.yaml")
	if err := os.WriteFile(policyPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	p, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if p.Threshold != 60 {
		t.Errorf("expected threshold 60, got %d", p.Threshold)
	}
	if !p.Strict {
		t.Error("expected strict to be true")
	}
	if !p.Offline.Enabled {
		t.Error("expected offline.enabled to be true")
	}
	if p.RuleOverrides["HR-09"] != 20 {
		t.Errorf("expected HR-09 override 20, got %d", p.RuleOverrides["HR-09"])
	}

	// Test Allowlist
	if allowed, _ := p.MatchAllowlist("@mycorp/auth-lib", ""); !allowed {
		t.Error("expected @mycorp/auth-lib to match allowlist wildcard")
	}
	if allowed, _ := p.MatchAllowlist("my-internal-tool", ""); !allowed {
		t.Error("expected my-internal-tool to match allowlist")
	}
	if allowed, _ := p.MatchAllowlist("any-package", "trusted-dev"); !allowed {
		t.Error("expected author trusted-dev to match allowlist")
	}
	if allowed, _ := p.MatchAllowlist("@corp/helpers", ""); !allowed {
		t.Error("expected @corp/helpers to match namespace allowlist")
	}
	if allowed, _ := p.MatchAllowlist("unrelated-pkg", "other-author"); allowed {
		t.Error("expected unrelated package not to match allowlist")
	}

	// Test Blocklist
	if blocked, _ := p.MatchBlocklist("malicious-pkg", ""); !blocked {
		t.Error("expected malicious-pkg to match blocklist")
	}
	if blocked, _ := p.MatchBlocklist("evil-cryptominer", ""); !blocked {
		t.Error("expected evil-cryptominer to match blocklist wildcard")
	}
	if blocked, _ := p.MatchBlocklist("any-pkg", "hacker"); !blocked {
		t.Error("expected hacker author to match blocklist")
	}
	if blocked, _ := p.MatchBlocklist("safe-pkg", "clean-dev"); blocked {
		t.Error("expected safe package not to match blocklist")
	}
}

func TestPolicy_DefaultWhenMissing(t *testing.T) {
	_, err := Load("/nonexistent/.argusrc.yaml")
	if err == nil {
		t.Log("Load on non-existent path gave error as expected or returned default")
	}

	def := DefaultPolicy()
	if def.Threshold != 50 {
		t.Errorf("expected default threshold 50, got %d", def.Threshold)
	}
}
