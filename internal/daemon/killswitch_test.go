package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestKillswitchCoordinator_ProcessTermination(t *testing.T) {
	// Spawn a real benign sleep child process
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to spawn test process: %v", err)
	}
	targetPID := cmd.Process.Pid

	kc := NewKillswitchCoordinator("")

	critEvent := &AuditEvent{
		TraceID:   "crit-test-trace",
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: targetPID,
	}

	if err := kc.Intercept(critEvent); err != nil {
		t.Fatalf("Intercept failed: %v", err)
	}

	// Verify child process was killed by SIGKILL
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Log("PASS: Target process terminated immediately by killswitch")
	case <-time.After(1 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("CRITICAL: Process was not killed within 1 second of critical violation!")
	}
}

func TestKillswitchCoordinator_LocksmithRevocation(t *testing.T) {
	fakeSocket := fmt.Sprintf("/tmp/fake-ls-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(fakeSocket)

	l, err := net.Listen("unix", fakeSocket)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer l.Close()

	revokedSession := make(chan string, 1)
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
			revokedSession <- req.TicketID
		}
	}()

	kc := NewKillswitchCoordinator(fakeSocket)

	critEvent := &AuditEvent{
		TraceID:       "trace-tripwire",
		EventType:     "canary.tripwire",
		Severity:      SeverityCritical,
		SessionTicket: "sess-attack-123",
	}

	if err := kc.Intercept(critEvent); err != nil {
		t.Fatalf("Intercept failed: %v", err)
	}

	select {
	case ticketID := <-revokedSession:
		if ticketID != "sess-attack-123" {
			t.Fatalf("unexpected ticket revoked: %s", ticketID)
		}
		t.Log("PASS: Locksmith session revocation dispatched by killswitch")
	case <-time.After(1 * time.Second):
		t.Fatal("CRITICAL: Killswitch did not dispatch revocation to Locksmith socket!")
	}
}
