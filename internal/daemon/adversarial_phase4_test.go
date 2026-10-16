package daemon_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"bonjoski/argus/internal/daemon"
)

// ADV-P4-01: Real-Time Killswitch Process Termination
func TestAdversarial_KillswitchImmediateProcessTermination(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to spawn victim process: %v", err)
	}
	targetPID := cmd.Process.Pid

	kc := daemon.NewKillswitchCoordinator("")

	tripwireEvent := &daemon.AuditEvent{
		TraceID:   "tripwire-01",
		EventType: "canary.tripwire.hit",
		Severity:  daemon.SeverityCritical,
		TargetPID: targetPID,
	}

	if err := kc.Intercept(tripwireEvent); err != nil {
		t.Fatalf("Killswitch intercept failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Logf("PASS: Rogue agent PID %d terminated immediately by Argus Killswitch", targetPID)
	case <-time.After(1 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("CRITICAL: Rogue process %d survived killswitch!", targetPID)
	}
}

// ADV-P4-02: Cascading Locksmith Credential Invalidation
func TestAdversarial_CascadingCredentialRevocation(t *testing.T) {
	fakeSocket := fmt.Sprintf("/tmp/fake-ls-adv-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(fakeSocket)

	l, err := net.Listen("unix", fakeSocket)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer l.Close()

	revocationReceived := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req struct {
			Action   string `json:"action"`
			TicketID string `json:"ticket_id"`
		}
		if err := json.NewDecoder(conn).Decode(&req); err == nil {
			revocationReceived <- req.TicketID
		}
	}()

	kc := daemon.NewKillswitchCoordinator(fakeSocket)

	crit := &daemon.AuditEvent{
		TraceID:       "trace-attack",
		EventType:     "landlock.violation",
		Severity:      daemon.SeverityCritical,
		SessionTicket: "sess-compromised-agent-999",
	}

	if err := kc.Intercept(crit); err != nil {
		t.Fatalf("Intercept failed: %v", err)
	}

	select {
	case ticket := <-revocationReceived:
		if ticket != "sess-compromised-agent-999" {
			t.Fatalf("unexpected ticket: %s", ticket)
		}
		t.Log("PASS: Locksmith credential session invalidated instantly upon critical violation")
	case <-time.After(1 * time.Second):
		t.Fatal("CRITICAL: Locksmith session revocation was not received!")
	}
}

// ADV-P4-03: Telemetry Flooding & Anti-Deadlock Resilience (VAL-04)
func TestAdversarial_TelemetryFloodingAntiDeadlock(t *testing.T) {
	bus := daemon.NewTelemetryBus(daemon.TelemetryBusOptions{
		Capacity: 10,
	})
	defer bus.Close()

	start := time.Now()
	// Rapidly inject 2,000 events into small buffer
	for i := 0; i < 2000; i++ {
		_ = bus.Ingest(&daemon.AuditEvent{
			TraceID:   "flood",
			EventType: "info",
			Severity:  daemon.SeverityInfo,
		})
	}
	dur := time.Since(start)

	ingested, dropped, _, _ := bus.Stats()
	if ingested != 2000 {
		t.Fatalf("expected 2000 ingested, got %d", ingested)
	}
	if dropped == 0 {
		t.Fatal("expected events to be dropped under flood, got 0")
	}
	if dur > 500*time.Millisecond {
		t.Fatalf("CRITICAL: Flooding caused caller to block! Took %v", dur)
	}
	t.Logf("PASS: 2,000 events processed in %v with %d dropped; zero execution deadlock", dur, dropped)
}
