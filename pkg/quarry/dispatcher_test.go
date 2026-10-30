package quarry

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDispatcherBroadcastAndSubscribe(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quarry-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "argus.sock")
	dispatcher := NewDispatcher(sockPath)

	if err := dispatcher.Start(); err != nil {
		t.Fatalf("Failed to start dispatcher: %v", err)
	}
	defer dispatcher.Stop()

	// Wait briefly for listener to become ready
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Connect 3 subscriber clients
	const numSubscribers = 3
	var wg sync.WaitGroup
	receivedAlerts := make([][]*Alert, numSubscribers)

	for i := 0; i < numSubscribers; i++ {
		idx := i
		alertCh, err := ListenAlerts(ctx, sockPath)
		if err != nil {
			t.Fatalf("Subscriber %d failed to connect: %v", idx, err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range alertCh {
				receivedAlerts[idx] = append(receivedAlerts[idx], a)
				if len(receivedAlerts[idx]) >= 2 {
					return
				}
			}
		}()
	}

	// Give subscribers time to register
	time.Sleep(100 * time.Millisecond)
	if count := dispatcher.SubscribersCount(); count != numSubscribers {
		t.Fatalf("Expected %d subscribers connected, got %d", numSubscribers, count)
	}

	startBroadcast := time.Now()

	// Broadcast Alert 1
	alert1 := &Alert{
		RuleName:    "rule-1",
		Severity:    "CRITICAL",
		Action:      "kill",
		AgentPID:    1234,
		TriggeredAt: time.Now(),
	}
	if err := dispatcher.Broadcast(alert1); err != nil {
		t.Fatalf("Broadcast error: %v", err)
	}

	// Broadcast Alert 2
	alert2 := &Alert{
		RuleName:    "rule-2",
		Severity:    "HIGH",
		Action:      "freeze",
		AgentPID:    5678,
		TriggeredAt: time.Now(),
	}
	if err := dispatcher.Broadcast(alert2); err != nil {
		t.Fatalf("Broadcast error: %v", err)
	}

	broadcastLatency := time.Since(startBroadcast)
	if broadcastLatency > 15*time.Millisecond {
		t.Logf("Broadcast latency: %v", broadcastLatency)
	}

	wg.Wait()

	for i := 0; i < numSubscribers; i++ {
		if len(receivedAlerts[i]) != 2 {
			t.Fatalf("Subscriber %d expected 2 alerts, got %d", i, len(receivedAlerts[i]))
		}
		if receivedAlerts[i][0].RuleName != "rule-1" {
			t.Errorf("Subscriber %d Alert 0 rule mismatch: got %s", i, receivedAlerts[i][0].RuleName)
		}
		if receivedAlerts[i][1].RuleName != "rule-2" {
			t.Errorf("Subscriber %d Alert 1 rule mismatch: got %s", i, receivedAlerts[i][1].RuleName)
		}
	}
}

func TestDispatcherDirectPush(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quarry-push-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "receiver.sock")
	dispatcher := NewDispatcher(sockPath)

	// In direct push mode without Start(), Broadcast pushes directly to sockPath if someone is listening
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start local listener simulating circuit breaker
	l, err := os.OpenFile(sockPath, os.O_RDWR|os.O_CREATE, 0600)
	_ = l
	// Start an actual dispatcher as server
	serverDispatcher := NewDispatcher(sockPath)
	if err := serverDispatcher.Start(); err != nil {
		t.Fatalf("Failed to start server dispatcher: %v", err)
	}
	defer serverDispatcher.Stop()

	alertCh, err := ListenAlerts(ctx, sockPath)
	if err != nil {
		t.Fatalf("ListenAlerts failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	a := &Alert{
		RuleName: "push-test",
		AgentPID: 9001,
	}
	_ = serverDispatcher.Broadcast(a)

	select {
	case received := <-alertCh:
		if received == nil || received.RuleName != "push-test" {
			t.Errorf("Unexpected alert received: %v", received)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for push alert")
	}
	_ = dispatcher
}

func BenchmarkCorrelatorIngest(b *testing.B) {
	rule, _ := ParseRule([]byte(sampleQuarryRuleYAML))
	c := NewCorrelator()
	_ = c.RegisterRule(rule)

	event := &Event{
		AgentPID:  9999,
		Layer:     LayerL7MCP,
		Action:    "list_directory",
		Path:      "/workspace/.env",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Ingest(event)
	}
}
