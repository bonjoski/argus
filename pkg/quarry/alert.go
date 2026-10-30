package quarry

import (
	"encoding/json"
	"time"
)

// Alert represents an alert dispatched when a Quarry causal rule triggers.
type Alert struct {
	RuleName      string         `json:"rule_name"`
	RuleVersion   string         `json:"rule_version,omitempty"`
	Severity      string         `json:"severity"`
	Action        string         `json:"action"` // "kill", "freeze", "alert"
	AgentPID      int            `json:"agent_pid"`
	SessionID     string         `json:"session_id,omitempty"`
	SessionTicket string         `json:"session_ticket,omitempty"`
	TriggeredAt   time.Time      `json:"triggered_at"`
	SequenceSteps []string       `json:"sequence_steps"`
	MatchedEvents []Event        `json:"matched_events"`
	Details       map[string]any `json:"details,omitempty"`
	LatencyNs     int64          `json:"latency_ns,omitempty"`
}

// JSON returns the serialized JSON byte slice of the Alert.
func (a *Alert) JSON() ([]byte, error) {
	return json.Marshal(a)
}

// String returns the JSON representation.
func (a *Alert) String() string {
	b, err := a.JSON()
	if err != nil {
		return "{}"
	}
	return string(b)
}
