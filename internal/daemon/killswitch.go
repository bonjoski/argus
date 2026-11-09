package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"bonjoski/argus/internal/procident"
)

// KillswitchCoordinator handles real-time containment actions when critical
// violations or tripwires are detected by Airlock, Locksmith, or Aegisbox.
// Process termination is strictly scoped to registered child/agent PIDs verified
// by kernel process start time to prevent arbitrary host-PID assassination or PID recycling kills.
type KillswitchCoordinator struct {
	locksmithSocket string
	killsTriggered  atomic.Int64
	leasesRevoked   atomic.Int64

	mu             sync.RWMutex
	registeredPIDs map[int]int64 // pid -> startTimeNs
}

// NewKillswitchCoordinator initializes a coordinator targeting the specified or default Locksmith socket.
func NewKillswitchCoordinator(locksmithSocket string) *KillswitchCoordinator {
	if locksmithSocket == "" {
		locksmithSocket = resolveDefaultLocksmithSocket()
	}
	return &KillswitchCoordinator{
		locksmithSocket: locksmithSocket,
		registeredPIDs:  make(map[int]int64),
	}
}

// resolveDefaultLocksmithSocket locates a user-owned ~/.locksmith/locksmith.sock (never world-writable /tmp).
func resolveDefaultLocksmithSocket() string {
	if s := os.Getenv("LOCKSMITH_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "locksmith.sock")
	}
	return ""
}

// RegisterAgentPID records a managed child/agent PID and captures its kernel start time.
func (kc *KillswitchCoordinator) RegisterAgentPID(pid int) error {
	if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return fmt.Errorf("refusing to register protected or invalid PID %d", pid)
	}
	startTimeNs, err := procident.GetProcessStartTimeNs(pid)
	if err != nil {
		return fmt.Errorf("failed to inspect process %d start time: %w", pid, err)
	}
	kc.mu.Lock()
	kc.registeredPIDs[pid] = startTimeNs
	kc.mu.Unlock()
	return nil
}

// RegisterAgentPIDWithStartTime records a managed PID with an explicit pre-captured start time.
func (kc *KillswitchCoordinator) RegisterAgentPIDWithStartTime(pid int, startTimeNs int64) error {
	if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return fmt.Errorf("refusing to register protected or invalid PID %d", pid)
	}
	kc.mu.Lock()
	kc.registeredPIDs[pid] = startTimeNs
	kc.mu.Unlock()
	return nil
}

// UnregisterAgentPID removes a PID from the killswitch registration table.
func (kc *KillswitchCoordinator) UnregisterAgentPID(pid int) {
	kc.mu.Lock()
	delete(kc.registeredPIDs, pid)
	kc.mu.Unlock()
}

// IsRegisteredAgentPID reports whether pid is currently registered for killswitch containment.
func (kc *KillswitchCoordinator) IsRegisteredAgentPID(pid int) bool {
	kc.mu.RLock()
	_, ok := kc.registeredPIDs[pid]
	kc.mu.RUnlock()
	return ok
}

// Intercept evaluates an incoming audit event and executes immediate containment if critical.
func (kc *KillswitchCoordinator) Intercept(event *AuditEvent) error {
	if event == nil || event.Severity != SeverityCritical {
		return nil
	}

	// 1. Registered Process Group / PID Termination (SIGKILL) with start-time verification
	if event.TargetPID > 1 {
		kc.mu.RLock()
		expectedStartNs, registered := kc.registeredPIDs[event.TargetPID]
		kc.mu.RUnlock()

		if registered {
			if terminateVerifiedPID(event.TargetPID, expectedStartNs) {
				kc.killsTriggered.Add(1)
			}
			kc.UnregisterAgentPID(event.TargetPID)
		}
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
	if kc.locksmithSocket == "" {
		return
	}
	if err := procident.VerifyFileOwnerAndNotSymlink(kc.locksmithSocket); err != nil {
		return
	}

	conn, err := net.DialTimeout("unix", kc.locksmithSocket, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	if err := procident.VerifyUnixPeerUID(conn); err != nil {
		return
	}

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
