package daemon_test

import (
	"strings"
	"testing"
	"time"

	"bonjoski/argus/internal/daemon"
)

// ADV-06: Attacker attempts to forge CEF log entries via newline and pipe injection.
func TestAdversarial_CEFLogInjection(t *testing.T) {
	maliciousEvent := &daemon.AuditEvent{
		TraceID:   "trace-001\nCEF:0|hacked|fake|1.0|spoofed|event|10|injected=true",
		SpanID:    "span-001\r\nCEF:0|injected",
		Timestamp: time.Now(),
		Source:    "airlock|malicious|pipe",
		EventType: "syscall.violation\nattack",
		Severity:  daemon.SeverityCritical,
		Details:   map[string]any{"key": "value"},
	}

	cefOut := maliciousEvent.CEF()

	// 1. Verify no raw newlines or carriage returns exist in the generated CEF line
	if strings.Contains(cefOut, "\n") {
		t.Fatalf("FAIL: CEF output contains raw newline injection: %q", cefOut)
	}
	if strings.Contains(cefOut, "\r") {
		t.Fatalf("FAIL: CEF output contains raw carriage return injection: %q", cefOut)
	}

	// 2. Verify that pipe characters in fields are escaped as \|
	if strings.Contains(cefOut, "airlock|malicious") {
		t.Fatalf("FAIL: CEF output contains unescaped pipe in Source field: %q", cefOut)
	}
	if !strings.Contains(cefOut, "airlock\\|malicious\\|pipe") {
		t.Fatalf("FAIL: Pipe was not properly escaped in CEF output: %q", cefOut)
	}

	t.Logf("PASS: CEF log injection attempt neutralized cleanly: %s", cefOut)
}
