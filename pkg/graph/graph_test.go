package graph

import (
	"context"
	"testing"
	"time"
)

func TestSessionRegistrationAndLookup(t *testing.T) {
	graph := NewMemoryActivityGraph(nil)
	ctx := context.Background()

	rootNode := AgentIdentityNode{
		JTI:           "root-jti-001",
		AgentID:       "orchestrator",
		AllowedScopes: []string{"repo:read", "repo:write"},
		ActivePID:     1234,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	if err := graph.RegisterSession(ctx, rootNode); err != nil {
		t.Fatalf("RegisterSession root failed: %v", err)
	}

	childNode := AgentIdentityNode{
		JTI:           "child-jti-002",
		ParentJTI:     "root-jti-001",
		AgentID:       "doc-writer",
		AllowedScopes: []string{"repo:read"},
		ActivePID:     1235,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Second),
	}

	if err := graph.RegisterSession(ctx, childNode); err != nil {
		t.Fatalf("RegisterSession child failed: %v", err)
	}

	if graph.ActiveSessionsCount() != 2 {
		t.Errorf("expected 2 active sessions, got %d", graph.ActiveSessionsCount())
	}

	fetched, ok := graph.GetSession(ctx, "child-jti-002")
	if !ok || fetched.AgentID != "doc-writer" {
		t.Errorf("failed fetching child session, got %+v", fetched)
	}
}

func TestShadowAgentDetection(t *testing.T) {
	killswitchCalled := false
	var killedPID int

	mockKill := func(pid int, jti string, reason string) error {
		killswitchCalled = true
		killedPID = pid
		return nil
	}

	graph := NewMemoryActivityGraph(mockKill)
	ctx := context.Background()

	// Event from unregistered PID (shadow agent)
	event := ActivityEvent{
		PID:       9999,
		Syscall:   "openat",
		Target:    "main.go",
		Timestamp: time.Now(),
	}

	eval, err := graph.RecordActivity(ctx, event)
	if err != nil {
		t.Fatal(err)
	}

	if !eval.DriftDetected {
		t.Error("expected drift detected for untracked shadow agent")
	}
	if eval.ViolationType != "UNTRACKED_SHADOW_AGENT" {
		t.Errorf("expected UNTRACKED_SHADOW_AGENT, got %s", eval.ViolationType)
	}
	if !killswitchCalled || killedPID != 9999 {
		t.Errorf("killswitch not triggered properly for PID 9999")
	}
}

func TestBehavioralDrift_ShellSpawn(t *testing.T) {
	killswitchCalled := false
	mockKill := func(pid int, jti string, reason string) error {
		killswitchCalled = true
		return nil
	}

	graph := NewMemoryActivityGraph(mockKill)
	ctx := context.Background()

	node := AgentIdentityNode{
		JTI:           "doc-agent-jti",
		AllowedScopes: []string{"repo:read"},
		ActivePID:     4001,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Second),
	}
	_ = graph.RegisterSession(ctx, node)

	// Attempt execve /bin/sh
	event := ActivityEvent{
		JTI:       "doc-agent-jti",
		PID:       4001,
		Syscall:   "execve",
		Target:    "/bin/sh",
		Timestamp: time.Now(),
	}

	eval, err := graph.RecordActivity(ctx, event)
	if err != nil {
		t.Fatal(err)
	}

	if !eval.DriftDetected {
		t.Error("expected drift detected for shell spawn attempt")
	}
	if eval.ViolationType != "UNAUTHORIZED_SHELL_SPAWN" {
		t.Errorf("expected UNAUTHORIZED_SHELL_SPAWN, got %s", eval.ViolationType)
	}
	if !killswitchCalled {
		t.Error("expected killswitch to be invoked")
	}
	if !graph.IsRevoked(ctx, "doc-agent-jti") {
		t.Error("expected token to be revoked in graph")
	}
}

func TestCascadingLineageRevocation(t *testing.T) {
	graph := NewMemoryActivityGraph(nil)
	ctx := context.Background()

	// Root -> Child -> Grandchild
	_ = graph.RegisterSession(ctx, AgentIdentityNode{JTI: "root-1"})
	_ = graph.RegisterSession(ctx, AgentIdentityNode{JTI: "child-1", ParentJTI: "root-1"})
	_ = graph.RegisterSession(ctx, AgentIdentityNode{JTI: "grandchild-1", ParentJTI: "child-1"})

	revoked, err := graph.RevokeLineage(ctx, "root-1", "Security breach on coordinator")
	if err != nil {
		t.Fatal(err)
	}

	if len(revoked) != 3 {
		t.Errorf("expected 3 revoked JTIs, got %d (%v)", len(revoked), revoked)
	}

	for _, id := range []string{"root-1", "child-1", "grandchild-1"} {
		if !graph.IsRevoked(ctx, id) {
			t.Errorf("expected %s to be marked revoked", id)
		}
	}
}
