package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/stoneward/pkg/client"
)

func TestTelemetryBus_BasicIngest(t *testing.T) {
	tmpDir := t.TempDir()
	sinkPath := filepath.Join(tmpDir, "telemetry.log")

	bus := NewTelemetryBus(TelemetryBusOptions{
		Capacity:    100,
		LogSinkPath: sinkPath,
	})
	defer bus.Close()

	ev := &AuditEvent{
		TraceID:   "trace-12345",
		SpanID:    "span-67890",
		Timestamp: time.Now(),
		Source:    "airlock",
		EventType: "execution.completed",
		Severity:  SeverityInfo,
		Details:   map[string]any{"command": "pytest"},
	}

	if err := bus.Ingest(ev); err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// Give worker time to drain to file
	time.Sleep(50 * time.Millisecond)

	data, err := os.ReadFile(sinkPath)
	if err != nil {
		t.Fatalf("failed to read sink file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "CEF:0|bonjoski|airlock|1.0|execution.completed") {
		t.Fatalf("expected CEF record in sink log, got: %s", content)
	}
	if !strings.Contains(content, "trace-12345") {
		t.Fatalf("expected trace-12345 in sink log, got: %s", content)
	}
}

// VAL-04: Telemetry Backpressure Deadlock Prevention
// Flooding the ring buffer with low-priority events must NEVER block or deadlock.
// Non-critical events are dropped with an atomic counter.
func TestTelemetryBus_RingBufferBackpressure(t *testing.T) {
	// Tiny buffer capacity of 5 events
	bus := NewTelemetryBus(TelemetryBusOptions{
		Capacity: 5,
	})
	defer bus.Close()

	// Rapidly inject 500 events
	for i := 0; i < 500; i++ {
		ev := &AuditEvent{
			TraceID:   "flood-trace",
			SpanID:    "flood-span",
			Timestamp: time.Now(),
			Source:    "airlock",
			EventType: "log.info",
			Severity:  SeverityInfo,
		}
		if err := bus.Ingest(ev); err != nil {
			t.Fatalf("Ingest returned error during flood: %v", err)
		}
	}

	ingested, dropped, _, _ := bus.Stats()
	if ingested != 500 {
		t.Fatalf("expected totalIngested=500, got %d", ingested)
	}
	if dropped == 0 {
		t.Fatal("expected non-zero dropped events under buffer flood, got 0")
	}
	t.Logf("PASS: Ingested %d events, safely dropped %d low-priority events without blocking", ingested, dropped)
}

func TestTelemetryBus_CriticalEventPriority(t *testing.T) {
	// Tiny buffer capacity of 2 events
	bus := NewTelemetryBus(TelemetryBusOptions{
		Capacity: 2,
	})
	defer bus.Close()

	// Fill buffer
	for i := 0; i < 5; i++ {
		_ = bus.Ingest(&AuditEvent{
			TraceID:   "fill",
			EventType: "fill",
			Severity:  SeverityInfo,
		})
	}

	// Spawn and register a real managed child process so killswitch containment is authorized
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if err := bus.Killswitch().RegisterAgentPID(cmd.Process.Pid); err != nil {
		t.Fatalf("failed to register child PID: %v", err)
	}

	// Ingest CRITICAL event: must succeed, terminate registered child, and not be dropped
	critEv := &AuditEvent{
		TraceID:   "crit-1",
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: cmd.Process.Pid,
	}

	if err := bus.Ingest(critEv); err != nil {
		t.Fatalf("critical event ingestion failed: %v", err)
	}

	_, _, kills, _ := bus.Stats()
	if kills != 1 {
		t.Fatalf("expected killswitch to be triggered once for critical event, got %d", kills)
	}
}

func TestTelemetryBus_CloudStreamingConditionedOnFabrialAuth(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	t.Setenv("FABRIAL_AUTH_FILE", authFile)
	t.Setenv("FABRIAL_AUTH_TOKEN", "")
	t.Setenv("STONEWARD_TOKEN", "")

	var receivedEvents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/telemetry" {
			var batch []map[string]any
			_ = json.NewDecoder(r.Body).Decode(&batch)
			for _, item := range batch {
				if tool, ok := item["tool_name"].(string); ok {
					receivedEvents = append(receivedEvents, tool)
				}
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// 1. UNAUTHENTICATED: Cloud forwarder must be inactive and send 0 events to cloud
	busUnauth := NewTelemetryBus(TelemetryBusOptions{Capacity: 10})
	if busUnauth.CloudForwarder() != nil && busUnauth.CloudForwarder().IsActive() {
		t.Fatal("expected cloud forwarder to be inactive when Fabrial is unauthenticated")
	}

	_ = busUnauth.Ingest(&AuditEvent{
		TraceID:   "unauth-trace",
		Source:    "airlock",
		EventType: "command.exec",
		Severity:  SeverityInfo,
	})
	time.Sleep(50 * time.Millisecond)
	_ = busUnauth.Close()

	if len(receivedEvents) != 0 {
		t.Fatalf("expected 0 events sent to cloud when unauthenticated, got %d", len(receivedEvents))
	}

	// 2. AUTHENTICATED: Save valid Fabrial auth pointing to mock cloud server
	validAuth := &client.FabrialAuthContext{
		Token:     "stnw_live_argus_cloud_token",
		TenantID:  "tenant-argus-test",
		ServerURL: srv.URL,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(12 * time.Hour),
	}
	if err := client.SaveFabrialAuth(validAuth); err != nil {
		t.Fatalf("failed to save fabrial auth: %v", err)
	}

	busAuth := NewTelemetryBus(TelemetryBusOptions{Capacity: 10})
	if busAuth.CloudForwarder() == nil || !busAuth.CloudForwarder().IsActive() {
		t.Fatal("expected cloud forwarder to be active when Fabrial is authenticated")
	}

	_ = busAuth.Ingest(&AuditEvent{
		TraceID:   "auth-trace-1",
		Source:    "locksmith",
		EventType: "secret.lease.granted",
		Severity:  SeverityInfo,
		Details:   map[string]any{"secret": "AWS_SECRET_KEY"},
	})

	time.Sleep(100 * time.Millisecond)
	_ = busAuth.Close()

	if len(receivedEvents) != 1 || receivedEvents[0] != "locksmith" {
		t.Fatalf("expected 1 locksmith event delivered to cloud control plane, got: %v", receivedEvents)
	}
}
