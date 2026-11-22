package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestMCPCommand_HelpAndStdioPing(t *testing.T) {
	// 1. Verify `argus mcp --help`
	cmd := newMCPCmd()
	var helpOut bytes.Buffer
	cmd.SetOut(&helpOut)
	cmd.SetErr(&helpOut)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("argus mcp --help failed: %v", err)
	}
	if !strings.Contains(helpOut.String(), "argus_vet") {
		t.Fatalf("expected argus mcp --help output to mention argus_vet, got:\n%s", helpOut.String())
	}

	// 2. Verify `argus mcp` STDIO JSON-RPC ping round-trip
	cmd2 := newMCPCmd()
	var out bytes.Buffer
	cmd2.SetIn(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"))
	cmd2.SetOut(&out)
	cmd2.SetErr(&out)
	cmd2.SetArgs([]string{})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("argus mcp stdio ping failed: %v", err)
	}
	if !strings.Contains(out.String(), `"jsonrpc":"2.0"`) || !strings.Contains(out.String(), `"id":1`) {
		t.Fatalf("unexpected STDIO ping output: %s", out.String())
	}
}
