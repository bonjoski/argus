package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestExplainCmd_WithAI_AdversarialWireSecretRedaction(t *testing.T) {
	var outboundPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		outboundPayload = string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message":       map[string]any{"content": "Suspicious package name; do not install."},
					"finish_reason": "stop",
				},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "test-dummy-key")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("OLLAMA_HOST", "")

	for _, tc := range []struct {
		name      string
		arg       string
		forbidden string
	}{
		{"unicode_smuggled_aws_key", "AKIA\u200bIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"high_entropy_token", "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ", "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outboundPayload = ""
			buf := new(bytes.Buffer)
			cmd := newExplainCmd()
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{tc.arg, "--ai", "--ecosystem", "npm"})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("expected explain --ai to succeed, got: %v", err)
			}
			if strings.Contains(outboundPayload, tc.forbidden) {
				t.Fatalf("outbound AI payload leaked %s: %s", tc.name, outboundPayload)
			}
			if !strings.Contains(outboundPayload, "[SECRET_REF_") {
				t.Fatalf("expected redacted placeholder in outbound AI payload: %s", outboundPayload)
			}
		})
	}
}
