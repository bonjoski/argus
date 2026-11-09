package quarry

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ARG-07: Verify bounded LRU + TTL eviction in Correlator.agents and self-dial guard in Dispatcher.
func TestAdversarial_ARG07_CorrelatorLRUEvictionTTLAndDispatcherSelfDialGuard(t *testing.T) {
	corr := NewCorrelator(CorrelatorOptions{
		MaxEventsPerAgent: 16,
		MaxTrackedAgents:  32,
		AgentIdleTTL:      100 * time.Millisecond,
		SessionWindow:     time.Minute,
	})

	base := time.Now()
	// Flood 500 distinct session IDs -> TrackedAgentsCount MUST never exceed 32!
	for i := 0; i < 500; i++ {
		_, err := corr.Ingest(&Event{
			SessionID: fmt.Sprintf("sess-flood-%d", i),
			Timestamp: base.Add(time.Duration(i) * time.Microsecond),
			Layer:     LayerL7MCP,
			Tool:      "bash",
		})
		if err != nil {
			t.Fatalf("Ingest failed: %v", err)
		}
		if got := corr.TrackedAgentsCount(); got > 32 {
			t.Fatalf("MEMORY EXHAUSTION: TrackedAgentsCount = %d, exceeded MaxTrackedAgents = 32", got)
		}
	}

	// Advance timestamp past AgentIdleTTL (100ms) -> stale sessions must be evicted
	_, err := corr.Ingest(&Event{
		SessionID: "fresh-session",
		Timestamp: base.Add(5 * time.Second),
		Layer:     LayerL7MCP,
		Tool:      "bash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := corr.TrackedAgentsCount(); got != 1 {
		t.Fatalf("expected stale sessions to be TTL-evicted leaving 1 active session, got %d", got)
	}

	// Verify in-process Dispatcher NEVER dials its own socket when len(subscribers) == 0
	tmpDir, err := os.MkdirTemp("", "arg07-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "q.sock")
	disp := NewDispatcher(sockPath)
	if err := disp.Start(); err != nil {
		t.Fatalf("Dispatcher.Start failed: %v", err)
	}
	defer disp.Stop()

	for i := 0; i < 10; i++ {
		if err := disp.Broadcast(&Alert{RuleName: "test-rule", AgentPID: 42}); err != nil {
			t.Fatalf("Broadcast failed: %v", err)
		}
	}
	time.Sleep(80 * time.Millisecond)

	if subs := disp.SubscribersCount(); subs != 0 {
		t.Fatalf("SELF-DIAL BUG: in-process Dispatcher connected to its own socket (%d phantom subscribers)!", subs)
	}
}
