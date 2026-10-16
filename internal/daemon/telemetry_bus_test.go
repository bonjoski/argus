package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// Ingest CRITICAL event: must succeed and not be dropped
	critEv := &AuditEvent{
		TraceID:   "crit-1",
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: 999999,
	}

	if err := bus.Ingest(critEv); err != nil {
		t.Fatalf("critical event ingestion failed: %v", err)
	}

	_, _, kills, _ := bus.Stats()
	if kills != 1 {
		t.Fatalf("expected killswitch to be triggered once for critical event, got %d", kills)
	}
}
