package graph

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAdversarial_IMDSExfiltrationAttempt(t *testing.T) {
	killCount := 0
	mockKill := func(pid int, jti string, reason string) error {
		killCount++
		return nil
	}

	graph := NewMemoryActivityGraph(mockKill)
	ctx := context.Background()

	node := AgentIdentityNode{
		JTI:           "agent-imds-attacker",
		AllowedScopes: []string{"repo:read"},
		ActivePID:     7777,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Second),
	}
	_ = graph.RegisterSession(ctx, node)

	// Attempt connecting or reading AWS IMDS
	event := ActivityEvent{
		JTI:       "agent-imds-attacker",
		PID:       7777,
		Syscall:   "connect",
		Target:    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		Timestamp: time.Now(),
	}

	eval, err := graph.RecordActivity(ctx, event)
	if err != nil {
		t.Fatal(err)
	}

	if !eval.DriftDetected {
		t.Fatal("expected IMDS access to trigger behavioral drift")
	}
	if eval.ViolationType != "UNAUTHORIZED_CREDENTIAL_ACCESS" {
		t.Errorf("expected UNAUTHORIZED_CREDENTIAL_ACCESS, got %s", eval.ViolationType)
	}
	if killCount != 1 {
		t.Errorf("expected killswitch called once, got %d", killCount)
	}
}

func TestAdversarial_Concurrency_N8_ParallelSubagents(t *testing.T) {
	graph := NewMemoryActivityGraph(nil)
	ctx := context.Background()

	// Register 8 parallel subagents
	for i := 1; i <= 8; i++ {
		node := AgentIdentityNode{
			JTI:           fmt.Sprintf("subagent-jti-%d", i),
			AgentID:       fmt.Sprintf("subagent-%d", i),
			AllowedScopes: []string{"repo:read", "repo:write"},
			ActivePID:     8000 + i,
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(60 * time.Second),
		}
		if err := graph.RegisterSession(ctx, node); err != nil {
			t.Fatalf("RegisterSession failed for subagent %d: %v", i, err)
		}
	}

	// Hammer the graph concurrently across 8 goroutines
	var wg sync.WaitGroup
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			jti := fmt.Sprintf("subagent-jti-%d", id)
			for j := 0; j < 100; j++ {
				event := ActivityEvent{
					JTI:       jti,
					PID:       8000 + id,
					Syscall:   "read",
					Target:    fmt.Sprintf("file_%d.txt", j),
					Timestamp: time.Now(),
				}
				eval, err := graph.RecordActivity(ctx, event)
				if err != nil || eval.DriftDetected {
					t.Errorf("subagent %d failed legitimate activity: err=%v, eval=%+v", id, err, eval)
				}
			}
		}(i)
	}

	wg.Wait()

	if graph.ActiveSessionsCount() != 8 {
		t.Errorf("expected 8 active sessions, got %d", graph.ActiveSessionsCount())
	}
}

func TestAdversarial_RevokedTokenReplay(t *testing.T) {
	graph := NewMemoryActivityGraph(nil)
	ctx := context.Background()

	node := AgentIdentityNode{
		JTI:           "replayed-jti",
		AllowedScopes: []string{"repo:read"},
		ActivePID:     5555,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Second),
	}
	_ = graph.RegisterSession(ctx, node)

	// Revoke the token
	_, _ = graph.RevokeLineage(ctx, "replayed-jti", "Compromise detected")

	// Attempt replaying tool action with revoked token
	event := ActivityEvent{
		JTI:       "replayed-jti",
		PID:       5555,
		Syscall:   "openat",
		Target:    "data.json",
		Timestamp: time.Now(),
	}

	eval, err := graph.RecordActivity(ctx, event)
	if err != nil {
		t.Fatal(err)
	}

	if !eval.DriftDetected || eval.ViolationType != "REVOKED_TOKEN_USE" {
		t.Errorf("expected REVOKED_TOKEN_USE rejection on replay, got: %+v", eval)
	}
}
