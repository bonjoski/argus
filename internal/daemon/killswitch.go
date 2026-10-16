package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// KillswitchCoordinator handles real-time containment actions when critical
// violations or tripwires are detected by Airlock, Locksmith, or Aegisbox.
type KillswitchCoordinator struct {
	locksmithSocket string
	killsTriggered  atomic.Int64
	leasesRevoked   atomic.Int64
}

// NewKillswitchCoordinator initializes a coordinator targeting the specified or default Locksmith socket.
func NewKillswitchCoordinator(locksmithSocket string) *KillswitchCoordinator {
	if locksmithSocket == "" {
		locksmithSocket = resolveDefaultLocksmithSocket()
	}
	return &KillswitchCoordinator{
		locksmithSocket: locksmithSocket,
	}
}

func resolveDefaultLocksmithSocket() string {
	if s := os.Getenv("LOCKSMITH_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := filepath.Join(home, ".locksmith", "locksmith.sock")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "locksmith.sock")
}

// Intercept evaluates an incoming audit event and executes immediate containment if critical.
func (kc *KillswitchCoordinator) Intercept(event *AuditEvent) error {
	if event == nil || event.Severity != SeverityCritical {
		return nil
	}

	// 1. Process Group / PID Termination (SIGKILL)
	if event.TargetPID > 1 {
		// Attempt to kill process group first (-PID), fallback to single PID
		_ = syscall.Kill(-event.TargetPID, syscall.SIGKILL)
		_ = syscall.Kill(event.TargetPID, syscall.SIGKILL)
		kc.killsTriggered.Add(1)
	}

	// 2. Locksmith Lease & Session Revocation
	if event.SessionTicket != "" || event.Details != nil {
		sessionTicket := event.SessionTicket
		leaseID := ""
		if event.Details != nil {
			if l, ok := event.Details["lease_id"].(string); ok {
				leaseID = l
			}
			if s, ok := event.Details["session_ticket"].(string); ok && sessionTicket == "" {
				sessionTicket = s
			}
		}

		if sessionTicket != "" || leaseID != "" {
			go kc.revokeLocksmithCredentials(sessionTicket, leaseID)
		}
	}

	return nil
}

func (kc *KillswitchCoordinator) revokeLocksmithCredentials(sessionTicket, leaseID string) {
	conn, err := net.DialTimeout("unix", kc.locksmithSocket, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	if sessionTicket != "" {
		payload := map[string]any{
			"action":    "revoke_session",
			"ticket_id": sessionTicket,
		}
		_ = json.NewEncoder(conn).Encode(payload)
		kc.leasesRevoked.Add(1)
	}

	if leaseID != "" {
		rPayload := map[string]any{
			"action":     "revoke_lease",
			"lease_id":   leaseID,
			"client_pid": os.Getpid(),
		}
		_ = json.NewEncoder(conn).Encode(rPayload)
		kc.leasesRevoked.Add(1)
	}
}

// KillsCount returns the total number of processes terminated by the killswitch.
func (kc *KillswitchCoordinator) KillsCount() int64 {
	return kc.killsTriggered.Load()
}

// RevocationsCount returns the total number of secret revocations dispatched.
func (kc *KillswitchCoordinator) RevocationsCount() int64 {
	return kc.leasesRevoked.Load()
}
