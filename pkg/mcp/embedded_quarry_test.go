package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAdversarial_ArgusVetMCPEnforcesEmbeddedQuarryAdvisories(t *testing.T) {
	h := NewDefaultToolHandler()

	blockedCases := []struct {
		name     string
		command  string
		wantRule string
	}{
		{"GHCLI_Vulnerable", "go get github.com/cli/cli/v2@v2.95.0", "radar_ghsa_8cg3_r6g9_fpg2"},
		{"GHCLI_Unpinned", "go get github.com/cli/cli/v2", "radar_ghsa_8cg3_r6g9_fpg2"},
		{"Etcd_Vulnerable", "go get go.etcd.io/etcd/v3@v3.5.31", "radar_ghsa_3wh4_j44w_pg92"},
		{"SevenZRust2_Vulnerable", "cargo add sevenz-rust2@0.20.4", "sevenz_rust2_zip_slip"},
	}

	for _, tc := range blockedCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"command": tc.command})
			res, err := h.HandleVet(context.Background(), raw)
			if err != nil {
				t.Fatalf("HandleVet error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("FAIL-OPEN: argus_vet allowed vulnerable command %q (expected rule %s)", tc.command, tc.wantRule)
			}
			if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, tc.wantRule) {
				t.Fatalf("expected rule %q in response, got %+v", tc.wantRule, res.Content)
			}
		})
	}

	allowedCases := []string{
		"go get github.com/cli/cli/v2@v2.96.0",
		"go get go.etcd.io/etcd/v3@v3.6.13",
		"cargo add sevenz-rust2@0.21.1",
	}
	for _, cmd := range allowedCases {
		t.Run("Allow_"+cmd, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"command": cmd})
			res, err := h.HandleVet(context.Background(), raw)
			if err != nil {
				t.Fatalf("HandleVet error: %v", err)
			}
			if res.IsError {
				t.Fatalf("FALSE POSITIVE: argus_vet blocked patched command %q: %+v", cmd, res.Content)
			}
		})
	}
}
