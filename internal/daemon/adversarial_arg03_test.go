package daemon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ARG-03: Verify 0600 socket permissions, symlink refusal, and 1 MiB LimitReader DoS defense.
func TestAdversarial_ARG03_SocketSecurityAndBoundedFrameReads(t *testing.T) {
	// Use concise path under os.TempDir() so Unix sockaddr_un (104 bytes on Darwin) never overflows
	tmpDir, err := os.MkdirTemp("", "arg03-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	victimFile := filepath.Join(tmpDir, "victim.txt")
	if err := os.WriteFile(victimFile, []byte("precious"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkSock := filepath.Join(tmpDir, "s.sock")
	if err := os.Symlink(victimFile, symlinkSock); err != nil {
		t.Fatal(err)
	}

	// 1. Server MUST refuse to unlink a symlink at socketPath
	symSrv := NewServer(symlinkSock, "", nil)
	if err := symSrv.Start(context.Background()); err == nil {
		_ = symSrv.Close()
		t.Fatalf("SECURITY BYPASS: Server.Start unlinked symlinked socket path!")
	}
	if _, err := os.Stat(victimFile); err != nil {
		t.Fatalf("victim file destroyed via symlink attack: %v", err)
	}

	// 2. Real socket must have 0600 permissions and bound line reads to 1 MiB
	sockPath := filepath.Join(tmpDir, "d.sock")
	srv := NewServer(sockPath, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if fi, sErr := os.Lstat(sockPath); sErr == nil {
			if perm := fi.Mode().Perm(); perm != 0600 {
				t.Fatalf("expected 0600 socket permissions, got %04o", perm)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer srv.Close()

	// Send a >1 MiB line without newline -> daemon must reject cleanly via LimitReader
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		t.Fatalf("failed to dial daemon socket: %v", err)
	}
	defer conn.Close()

	oversized := bytes.Repeat([]byte("A"), MaxDaemonFrameBytes+4096)
	_, _ = conn.Write(oversized)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respLine, rErr := bufio.NewReader(conn).ReadString('\n')
	if rErr != nil {
		t.Fatalf("expected structured error response on oversized frame, got err: %v", rErr)
	}
	if !strings.Contains(respLine, "exceeds maximum allowed size") {
		t.Fatalf("unexpected oversized frame response: %s", respLine)
	}
}

// ARG-03: Verify KillswitchCoordinator refuses unregistered PIDs and recycled PIDs (mismatched startTimeNs).
func TestAdversarial_ARG03_KillswitchRefusesUnregisteredAndRecycledPIDs(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start benign victim process: %v", err)
	}
	victimPID := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	kc := NewKillswitchCoordinator("")

	// 1. Unregistered PID MUST NOT be killed
	_ = kc.Intercept(&AuditEvent{
		TraceID:   "spoof-unregistered",
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: victimPID,
	})
	if kc.KillsCount() != 0 {
		t.Fatalf("SECURITY BYPASS: killswitch signaled unregistered PID %d!", victimPID)
	}
	if err := syscall.Kill(victimPID, 0); err != nil {
		t.Fatalf("unregistered victim process %d was killed!", victimPID)
	}

	// 2. Registered PID with mismatched startTimeNs (simulated PID recycling) MUST NOT be killed
	if err := kc.RegisterAgentPIDWithStartTime(victimPID, 12345); err != nil {
		t.Fatal(err)
	}
	_ = kc.Intercept(&AuditEvent{
		TraceID:   "recycled-pid",
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: victimPID,
	})
	if kc.KillsCount() != 0 {
		t.Fatalf("SECURITY BYPASS: killswitch signaled PID %d despite mismatched start time!", victimPID)
	}
	if err := syscall.Kill(victimPID, 0); err != nil {
		t.Fatalf("recycled victim process %d was killed!", victimPID)
	}

	// 3. Registered PID with authentic kernel startTimeNs MUST be terminated
	if err := kc.RegisterAgentPID(victimPID); err != nil {
		t.Fatalf("failed to register authentic PID: %v", err)
	}
	_ = kc.Intercept(&AuditEvent{
		TraceID:   fmt.Sprintf("auth-%d", victimPID),
		EventType: "syscall.violation",
		Severity:  SeverityCritical,
		TargetPID: victimPID,
	})

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("registered rogue child PID %d survived killswitch", victimPID)
	}
}
