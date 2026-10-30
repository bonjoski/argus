package quarry

import (
	"sync"
	"time"
)

// SequenceBranch represents a single active causal progression candidate for a rule.
type SequenceBranch struct {
	State          int
	MatchedEvents  []Event
	StepTimestamps []time.Time
	CreatedAt      time.Time
	LastMatchedAt  time.Time
}

// FSM evaluates events against a CompiledRule for a single agent or session.
// It supports multiple concurrent sequence branches to prevent window evasion
// and interleaving attacks.
type FSM struct {
	mu           sync.Mutex
	rule         *CompiledRule
	branches     []*SequenceBranch
	maxBranches  int
	failClosed   bool
	multiTier    bool
	alertHistory []*Alert
}

// NewFSM creates a new state machine tracker for a compiled rule.
func NewFSM(rule *CompiledRule, multiTier bool) *FSM {
	return &FSM{
		rule:        rule,
		branches:    make([]*SequenceBranch, 0, 8),
		maxBranches: 16,
		multiTier:   multiTier,
	}
}

// Step processes an incoming event and returns an Alert if the rule's sequence completes.
func (fsm *FSM) Step(event *Event) *Alert {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	if event == nil || fsm.rule == nil {
		return nil
	}

	eventTime := event.Timestamp
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	steps := fsm.rule.Steps
	totalSteps := len(steps)
	if totalSteps == 0 {
		return nil
	}

	// 1. Clean expired branches
	fsm.pruneExpiredBranches(eventTime)

	var triggeredBranch *SequenceBranch
	newBranches := make([]*SequenceBranch, 0, len(fsm.branches)+1)

	// 2. Evaluate existing branches
	for _, b := range fsm.branches {
		if b.State < totalSteps && steps[b.State].Matches(event) {
			// Advance branch
			b.State++
			b.MatchedEvents = append(b.MatchedEvents, *event.Clone())
			b.StepTimestamps = append(b.StepTimestamps, eventTime)
			b.LastMatchedAt = eventTime

			// Check if complete
			if b.State == totalSteps {
				triggeredBranch = b
				// Once triggered, do not re-add
				continue
			}
		}
		newBranches = append(newBranches, b)
	}

	// 3. Check if event matches Step 0 to initiate a new branch
	if steps[0].Matches(event) && len(newBranches) < fsm.maxBranches {
		newB := &SequenceBranch{
			State:          1,
			MatchedEvents:  []Event{*event.Clone()},
			StepTimestamps: []time.Time{eventTime},
			CreatedAt:      eventTime,
			LastMatchedAt:  eventTime,
		}

		if totalSteps == 1 {
			triggeredBranch = newB
		} else {
			newBranches = append(newBranches, newB)
		}
	}

	fsm.branches = newBranches

	// 4. If branch completed, construct Alert
	if triggeredBranch != nil {
		stepNames := make([]string, len(steps))
		for i, s := range steps {
			stepNames[i] = s.Name
		}

		startT := triggeredBranch.StepTimestamps[0]
		latency := eventTime.Sub(startT)

		alert := &Alert{
			RuleName:      fsm.rule.Rule.Name,
			RuleVersion:   fsm.rule.Rule.Version,
			Severity:      fsm.rule.Rule.Severity,
			Action:        fsm.rule.Rule.Action,
			AgentPID:      event.AgentPID,
			SessionID:     event.SessionID,
			SessionTicket: event.SessionTicket,
			TriggeredAt:   eventTime,
			SequenceSteps: stepNames,
			MatchedEvents: triggeredBranch.MatchedEvents,
			LatencyNs:     latency.Nanoseconds(),
			Details: map[string]any{
				"window_configured": fsm.rule.Rule.Window.String(),
				"sequence_duration": latency.String(),
				"branches_tracked":  len(fsm.branches),
			},
		}

		fsm.alertHistory = append(fsm.alertHistory, alert)
		return alert
	}

	return nil
}

// pruneExpiredBranches evicts branches exceeding the sliding window or session window.
func (fsm *FSM) pruneExpiredBranches(now time.Time) {
	window := fsm.rule.Rule.Window
	sessionWindow := fsm.rule.Rule.SessionWindow

	active := fsm.branches[:0]
	for _, b := range fsm.branches {
		if len(b.StepTimestamps) == 0 {
			continue
		}
		startTime := b.StepTimestamps[0]
		elapsed := now.Sub(startTime)

		// Real-time window check
		if elapsed <= window {
			active = append(active, b)
			continue
		}

		// Multi-tier session window check: if enabled and intermediate suspicion exists, allow session window
		if fsm.multiTier && elapsed <= sessionWindow {
			active = append(active, b)
			continue
		}
	}
	fsm.branches = active
}

// Reset clears all active branches.
func (fsm *FSM) Reset() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.branches = fsm.branches[:0]
}

// ActiveBranchesCount returns the number of active candidate sequence paths.
func (fsm *FSM) ActiveBranchesCount() int {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return len(fsm.branches)
}
