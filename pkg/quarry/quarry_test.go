package quarry

import (
	"fmt"
	"testing"
	"time"
)

const sampleQuarryRuleYAML = `
name: agent_exfiltration_via_curl
version: 1.0
severity: CRITICAL
action: kill
window: 60s
causal_sequence:
  - step: reconnaissance
    events:
      - layer: l7_mcp
        action: list_directory
        path_matches: "\\.env|secrets"
  - step: payload_assembly
    events:
      - layer: l7_mcp
        action: read_file
  - step: egress_execution
    events:
      - layer: l3_kernel
        action: syscall_connect
        dest_not_in: ["internal.lan", "github.com"]
`

func TestRuleParsingAndCompilation(t *testing.T) {
	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse YAML rule: %v", err)
	}

	if rule.Name != "agent_exfiltration_via_curl" {
		t.Errorf("Expected rule name 'agent_exfiltration_via_curl', got %q", rule.Name)
	}
	if rule.Window != 60*time.Second {
		t.Errorf("Expected window 60s, got %v", rule.Window)
	}
	if rule.Action != "kill" {
		t.Errorf("Expected action 'kill', got %q", rule.Action)
	}
	if len(rule.CausalSequence) != 3 {
		t.Fatalf("Expected 3 causal sequence steps, got %d", len(rule.CausalSequence))
	}

	cr, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}

	if len(cr.Steps) != 3 {
		t.Fatalf("Expected 3 compiled steps, got %d", len(cr.Steps))
	}
}

func TestCausalSequenceEvaluation(t *testing.T) {
	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	correlator := NewCorrelator(CorrelatorOptions{
		MultiTierWindow: true,
	})
	if err := correlator.RegisterRule(rule); err != nil {
		t.Fatalf("Failed to register rule: %v", err)
	}

	now := time.Now()
	agentPID := 4242
	sessionTicket := "st-audit-token-9988"

	// Step 1: Reconnaissance (L7 MCP list_directory looking for secrets)
	e1 := &Event{
		AgentPID:      agentPID,
		SessionTicket: sessionTicket,
		Layer:         LayerL7MCP,
		Action:        "list_directory",
		Path:          "/workspace/.env",
		Timestamp:     now,
	}
	alerts, err := correlator.Ingest(e1)
	if err != nil {
		t.Fatalf("Ingest e1 error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("Expected 0 alerts after step 1, got %d", len(alerts))
	}

	// Step 2: Payload assembly (L7 MCP read_file)
	e2 := &Event{
		AgentPID:      agentPID,
		SessionTicket: sessionTicket,
		Layer:         LayerL7MCP,
		Action:        "read_file",
		Path:          "/workspace/.env",
		Timestamp:     now.Add(2 * time.Second),
	}
	alerts, err = correlator.Ingest(e2)
	if err != nil {
		t.Fatalf("Ingest e2 error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("Expected 0 alerts after step 2, got %d", len(alerts))
	}

	// Step 3: Egress execution (L3 Kernel connect to untrusted host)
	e3 := &Event{
		AgentPID:      agentPID,
		SessionTicket: sessionTicket,
		Layer:         LayerL3Kernel,
		Action:        "syscall_connect",
		Destination:   "evil-c2-server.com:443",
		Timestamp:     now.Add(4 * time.Second),
	}
	alerts, err = correlator.Ingest(e3)
	if err != nil {
		t.Fatalf("Ingest e3 error: %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("Expected exactly 1 alert after step 3, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.RuleName != "agent_exfiltration_via_curl" {
		t.Errorf("Expected alert rule name 'agent_exfiltration_via_curl', got %q", alert.RuleName)
	}
	if alert.AgentPID != agentPID {
		t.Errorf("Expected alert PID %d, got %d", agentPID, alert.AgentPID)
	}
	if alert.Action != "kill" {
		t.Errorf("Expected alert action 'kill', got %q", alert.Action)
	}
	if len(alert.MatchedEvents) != 3 {
		t.Errorf("Expected 3 matched events in alert, got %d", len(alert.MatchedEvents))
	}
}

func TestLegitimateTrafficDoesNotTrigger(t *testing.T) {
	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	correlator := NewCorrelator()
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	// Step 1: Recon on .env
	_, _ = correlator.Ingest(&Event{
		AgentPID:  5001,
		Layer:     LayerL7MCP,
		Action:    "list_directory",
		Path:      "/workspace/.env",
		Timestamp: now,
	})

	// Step 2: Read file
	_, _ = correlator.Ingest(&Event{
		AgentPID:  5001,
		Layer:     LayerL7MCP,
		Action:    "read_file",
		Path:      "/workspace/.env",
		Timestamp: now.Add(1 * time.Second),
	})

	// Step 3: Connect to ALLOWED destination (github.com)
	alerts, err := correlator.Ingest(&Event{
		AgentPID:    5001,
		Layer:       LayerL3Kernel,
		Action:      "syscall_connect",
		Destination: "api.github.com:443",
		Timestamp:   now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("Unexpected ingest error: %v", err)
	}

	if len(alerts) != 0 {
		t.Fatalf("Expected 0 alerts for traffic to allowed destination, got %d", len(alerts))
	}
}

func TestSlidingWindowExpirationWithoutMultiTier(t *testing.T) {
	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	// Disable multi-tier so only strict 60s window applies
	correlator := NewCorrelator(CorrelatorOptions{
		MultiTierWindow: false,
	})
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	agentPID := 7777

	// Step 1: Recon at T = 0
	_, _ = correlator.Ingest(&Event{
		AgentPID:  agentPID,
		Layer:     LayerL7MCP,
		Action:    "list_directory",
		Path:      "/workspace/.env",
		Timestamp: now,
	})

	// Step 2: Read at T = 30s
	_, _ = correlator.Ingest(&Event{
		AgentPID:  agentPID,
		Layer:     LayerL7MCP,
		Action:    "read_file",
		Path:      "/workspace/.env",
		Timestamp: now.Add(30 * time.Second),
	})

	// Step 3: Egress at T = 90s (>60s window expiration)
	alerts, err := correlator.Ingest(&Event{
		AgentPID:    agentPID,
		Layer:       LayerL3Kernel,
		Action:      "syscall_connect",
		Destination: "exfiltration.host.net:8080",
		Timestamp:   now.Add(90 * time.Second),
	})
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	if len(alerts) != 0 {
		t.Fatalf("Expected 0 alerts because 60s sliding window expired, got %d", len(alerts))
	}
}

// Adversarial Test 1: Window Evasion Attacks
// An adversary spaces out actions by 70s to evade a 60s window.
// With MultiTierWindow enabled, the session window preserves suspicion.
func TestAdversarialWindowEvasionMitigation(t *testing.T) {
	ruleYAML := `
name: evasion_test_rule
version: 1.0
action: kill
window: 60s
session_window: 10m
causal_sequence:
  - step: step1
    events:
      - layer: l7_mcp
        action: list_directory
        path_matches: "\\.env"
  - step: step2
    events:
      - layer: l3_kernel
        action: syscall_connect
        dest_not_in: ["internal.lan"]
`
	rule, err := ParseRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	correlator := NewCorrelator(CorrelatorOptions{
		MultiTierWindow: true,
	})
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	agentPID := 8888

	_, _ = correlator.Ingest(&Event{
		AgentPID:  agentPID,
		Layer:     LayerL7MCP,
		Action:    "list_directory",
		Path:      "/workspace/.env",
		Timestamp: now,
	})

	// Egress at T = 75s (exceeds 60s window, but within 10m session window)
	alerts, err := correlator.Ingest(&Event{
		AgentPID:    agentPID,
		Layer:       LayerL3Kernel,
		Action:      "syscall_connect",
		Destination: "attacker-dropzone.org:443",
		Timestamp:   now.Add(75 * time.Second),
	})
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("Multi-tier windowing should have caught window evasion attack, got %d alerts", len(alerts))
	}
}

// Adversarial Test 2: Interleaving Benign Events (Buffer Exhaustion & Noise Injection)
// An adversary injects 1,000 benign `ls` commands between recon and exfiltration.
func TestAdversarialInterleavingBenignEvents(t *testing.T) {
	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	correlator := NewCorrelator(CorrelatorOptions{
		MaxEventsPerAgent: 100, // Small buffer to test ring buffer rotation
		MultiTierWindow:   true,
	})
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	agentPID := 9999

	// Step 1: Recon
	_, _ = correlator.Ingest(&Event{
		AgentPID:  agentPID,
		Layer:     LayerL7MCP,
		Action:    "list_directory",
		Path:      "/workspace/.env",
		Timestamp: now,
	})

	// Step 2: Payload assembly
	_, _ = correlator.Ingest(&Event{
		AgentPID:  agentPID,
		Layer:     LayerL7MCP,
		Action:    "read_file",
		Path:      "/workspace/.env",
		Timestamp: now.Add(1 * time.Second),
	})

	// Inject 1,000 benign events to try to wash out state
	for i := 0; i < 1000; i++ {
		_, _ = correlator.Ingest(&Event{
			AgentPID:  agentPID,
			Layer:     LayerL7MCP,
			Action:    "format_code",
			Path:      fmt.Sprintf("/workspace/file_%d.go", i),
			Timestamp: now.Add(2*time.Second + time.Duration(i)*time.Millisecond),
		})
	}

	// Step 3: Egress
	alerts, err := correlator.Ingest(&Event{
		AgentPID:    agentPID,
		Layer:       LayerL3Kernel,
		Action:      "syscall_connect",
		Destination: "198.51.100.25:443",
		Timestamp:   now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("Interleaved benign noise should NOT clear pending FSM state, expected 1 alert, got %d", len(alerts))
	}
}

// Adversarial Test 3: Tool Obfuscation Bypass Defeated by Kernel Cross-Check
// An agent executes a benign-sounding tool (e.g. "code_formatter") with base64 payload,
// but the underlying kernel syscall connects to an untrusted external server.
func TestAdversarialToolObfuscationCrossCheck(t *testing.T) {
	ruleYAML := `
name: obfuscated_egress_detection
version: 1.0
action: kill
window: 30s
causal_sequence:
  - step: suspicious_read
    events:
      - layer: l7_mcp
        action: read_file
        path_matches: "credentials\\.json"
  - step: kernel_egress
    events:
      - layer: l3_kernel
        action: syscall_connect
        dest_not_in: ["localhost", "127.0.0.1"]
`
	rule, err := ParseRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	correlator := NewCorrelator()
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	pid := 31337

	// Step 1: Read credentials
	_, _ = correlator.Ingest(&Event{
		AgentPID:  pid,
		Layer:     LayerL7MCP,
		Action:    "read_file",
		Path:      "/etc/credentials.json",
		Timestamp: now,
	})

	// Even though the agent claims at L7 it is running "prettier",
	// the L3 kernel event reports an outbound network socket connect.
	alerts, err := correlator.Ingest(&Event{
		AgentPID:    pid,
		Layer:       LayerL3Kernel,
		Action:      "syscall_connect",
		Destination: "c2.malicious.io:8443",
		Timestamp:   now.Add(1 * time.Second),
		Metadata: map[string]string{
			"claimed_l7_tool": "prettier",
		},
	})
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("Expected L3 kernel cross-check to catch obfuscated egress, got %d alerts", len(alerts))
	}
}

// Adversarial Test 4: Event Bus High-Throughput Flooding (DoS Resilience)
func TestAdversarialEventBusFlooding(t *testing.T) {
	correlator := NewCorrelator(CorrelatorOptions{
		MaxEventsPerAgent: 500,
	})

	rule, err := ParseRule([]byte(sampleQuarryRuleYAML))
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}
	_ = correlator.RegisterRule(rule)

	now := time.Now()
	// Ingest 20,000 events rapidly across multiple PIDs
	for i := 0; i < 20000; i++ {
		pid := 1000 + (i % 20)
		_, err := correlator.Ingest(&Event{
			AgentPID:  pid,
			Layer:     LayerL7MCP,
			Action:    "ping",
			Timestamp: now.Add(time.Duration(i) * time.Microsecond),
		})
		if err != nil {
			t.Fatalf("Correlator failed during flood at event %d: %v", i, err)
		}
	}

	if correlator.TotalIngested() != 20000 {
		t.Errorf("Expected 20,000 total ingested, got %d", correlator.TotalIngested())
	}
}
