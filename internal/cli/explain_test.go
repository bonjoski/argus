package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplainCmd_Heuristic(t *testing.T) {
	buf := new(bytes.Buffer)
	cmd := newExplainCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"reqeusts", "--ecosystem", "pypi"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected explain to succeed, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "HIGH RISK") {
		t.Errorf("expected high risk heuristic for reqeusts, got: %s", out)
	}
	if !strings.Contains(out, "requests") {
		t.Errorf("expected canonical alternative 'requests', got: %s", out)
	}
}

func TestExplainCmd_WithAI(t *testing.T) {
	buf := new(bytes.Buffer)
	cmd := newExplainCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"express-js", "--ai", "--ecosystem", "npm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected explain --ai to succeed, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[Shield Protected AI Advisory]") {
		t.Errorf("expected Shield AI Advisory in output, got: %s", out)
	}
}
