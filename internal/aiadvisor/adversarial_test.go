package aiadvisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAdversarial_SecretRedactionPatternsAndEntropy(t *testing.T) {
	cfg := DefaultRedactorConfig()
	cfg.CustomVaultKeys["MY_DB_PASS"] = "SuperSecretPassword999!"
	redactor := NewRedactor(cfg)

	secrets := []struct {
		name  string
		value string
		input string
	}{
		{"aws_key", "AKIA" + "IOSFODNN7EXAMPLE", "aws_access_key = AKIA" + "IOSFODNN7EXAMPLE"},
		{"anthropic_key", "sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz1234567890_test", "key: sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz1234567890_test"},
		{"openai_key", "sk-" + "proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "OPENAI=sk-" + "proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"},
		{"google_key", "AIza" + "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", "google=AIza" + "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"},
		{"github_pat", "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz", "token ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"},
		{"slack_token", "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx", "slack xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx"},
		{"db_uri_password", "SuperSecretPassword999!", "postgres://admin:SuperSecretPassword999!@db.prod.internal:5432/main"},
		{"generic_assignment", "my_super_secret_token_99", `api_key = "my_super_secret_token_99"`},
		{"pem_private_key", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj", "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END RSA PRIVATE KEY-----"},
		{"high_entropy_raw", "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ", "bearer k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"},
	}

	for _, tc := range secrets {
		t.Run(tc.name, func(t *testing.T) {
			redacted, tm, err := redactor.Redact(tc.input)
			if err != nil {
				t.Fatalf("Redact failed: %v", err)
			}
			defer tm.Zeroize()

			if strings.Contains(redacted, tc.value) {
				t.Fatalf("secret %s leaked in redacted output: %q", tc.name, redacted)
			}
			if !strings.Contains(redacted, "[SECRET_REF_") {
				t.Fatalf("expected placeholder token for %s, got: %q", tc.name, redacted)
			}
			if err := redactor.FailClosedWireGuard([]byte(redacted)); err != nil {
				t.Fatalf("FailClosedWireGuard rejected redacted output for %s: %v", tc.name, err)
			}
			if err := redactor.FailClosedWireGuard([]byte(tc.input)); !errors.Is(err, ErrSecretLeakageDetected) {
				t.Fatalf("FailClosedWireGuard failed to block raw %s; got err=%v", tc.name, err)
			}

			restored := redactor.Restore(redacted, tm)
			if !strings.Contains(restored, tc.value) {
				t.Fatalf("Restore failed to recover original secret for %s", tc.name)
			}
		})
	}
}

func TestAdversarial_UnicodeSmugglingBypassDefeated(t *testing.T) {
	redactor := NewRedactor(DefaultRedactorConfig())

	attacks := []struct {
		name   string
		raw    string
		secret string
	}{
		{
			name:   "zwsp_inside_aws_key",
			raw:    "leak: AKIA\u200bIOSF\u200cODNN\u200d7EXA\ufeffMPLE",
			secret: "AKIA" + "IOSFODNN7EXAMPLE",
		},
		{
			name:   "bidi_override_inside_github_pat",
			raw:    "pat: ghp_\u202e1234567890\u2066abcdefghijklmnopqrstuvwxyz",
			secret: "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:   "unicode_tag_block_inside_high_entropy",
			raw:    "tok: k9J2m!xQ8$\U000E0041vP4zL7*wR1tY6#bN3cV5mZ",
			secret: "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ",
		},
		{
			name:   "word_joiner_and_soft_hyphen_inside_openai_key",
			raw:    "key: sk-\u2060proj-\u00adAbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
			secret: "sk-" + "proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			if err := redactor.FailClosedWireGuard([]byte(tc.raw)); !errors.Is(err, ErrSecretLeakageDetected) {
				t.Fatalf("FailClosedWireGuard failed to block Unicode-smuggled payload %s: err=%v", tc.name, err)
			}

			redacted, tm, err := redactor.Redact(tc.raw)
			if err != nil {
				t.Fatalf("Redact failed: %v", err)
			}
			defer tm.Zeroize()

			if strings.Contains(redacted, tc.secret) {
				t.Fatalf("Unicode-smuggled secret %s escaped redaction: %q", tc.name, redacted)
			}
			if err := redactor.FailClosedWireGuard([]byte(redacted)); err != nil {
				t.Fatalf("FailClosedWireGuard rejected redacted payload: %v", err)
			}
		})
	}
}

func TestAdversarial_SpoofedPlaceholderPrefixBlocked(t *testing.T) {
	redactor := NewRedactor(DefaultRedactorConfig())

	spoofedAssignment := `api_key = "[SECRET_REF_fake]super_secret_leaked_key"`
	if err := redactor.FailClosedWireGuard([]byte(spoofedAssignment)); !errors.Is(err, ErrSecretLeakageDetected) {
		t.Fatalf("expected FailClosedWireGuard to block spoofed placeholder assignment, got: %v", err)
	}

	gluedHighEntropy := "[SECRET_REF_0123456789abcdef]k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	if err := redactor.FailClosedWireGuard([]byte(gluedHighEntropy)); !errors.Is(err, ErrSecretLeakageDetected) {
		t.Fatalf("expected FailClosedWireGuard to block high-entropy token glued to placeholder, got: %v", err)
	}
}

func TestAdversarial_TokenMapZeroizationAndConcurrency(t *testing.T) {
	tm := NewTokenMap()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref := tm.Add("AKIA" + "IOSFODNN7EXAMPLE", "aws")
			if !validPlaceholderRe.MatchString(ref) {
				t.Errorf("invalid placeholder format: %q", ref)
			}
			if sec, ok := tm.GetSecret(ref); !ok || sec != "AKIA" + "IOSFODNN7EXAMPLE" {
				t.Errorf("unexpected secret lookup: %q, %v", sec, ok)
			}
		}()
	}
	wg.Wait()

	if tm.Count() != 1 {
		t.Fatalf("expected deduplicated count 1, got %d", tm.Count())
	}
	tm.Zeroize()
	if tm.Count() != 0 {
		t.Fatalf("expected count 0 after Zeroize, got %d", tm.Count())
	}
}

func TestAdversarial_OpenAIWirePayloadHasZeroSecretLeakage(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message":       map[string]any{"content": "Advisory: verify canonical package."},
					"finish_reason": "stop",
				},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "test-only-dummy-key")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("OPENAI_MODEL", "gpt-4o-mini")
	t.Setenv("OLLAMA_HOST", "")

	redactor := NewRedactor(DefaultRedactorConfig())
	rawPrompt := "Inspect package AKIA\u200bIOSFODNN7EXAMPLE with token k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	redacted, tm, err := redactor.Redact(rawPrompt)
	if err != nil {
		t.Fatalf("Redact failed: %v", err)
	}
	defer tm.Zeroize()

	if err := redactor.FailClosedWireGuard([]byte(redacted)); err != nil {
		t.Fatalf("FailClosedWireGuard failed on redacted prompt: %v", err)
	}

	prov := NewProviderFromEnv()
	if prov.Name() != "openai-compatible" {
		t.Fatalf("expected openai-compatible provider, got %s", prov.Name())
	}
	resp, err := prov.Complete(context.Background(), Request{
		Model:    "auto",
		Messages: []Message{{Role: RoleUser, Content: redacted}},
	})
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if resp.Model != "gpt-4o-mini" {
		t.Fatalf("expected auto model to resolve to gpt-4o-mini, got %q", resp.Model)
	}
	if strings.Contains(capturedBody, "AKIA" + "IOSFODNN7EXAMPLE") || strings.Contains(capturedBody, "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ") {
		t.Fatalf("wire body leaked unredacted credential: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, "[SECRET_REF_") {
		t.Fatalf("expected redacted placeholder in wire body: %s", capturedBody)
	}
}
