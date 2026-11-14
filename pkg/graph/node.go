package graph

import (
	"time"
)

// AgentIdentityNode models an active DPoP token session in the runtime activity graph.
type AgentIdentityNode struct {
	JTI           string            `json:"jti"`
	ParentJTI     string            `json:"parent_jti,omitempty"`
	AgentID       string            `json:"agent_id"`
	IssuedAt      time.Time         `json:"issued_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	AllowedScopes []string          `json:"allowed_scopes"`
	ActivePID     int               `json:"active_pid"`
	ChildrenJTIs  []string          `json:"children_jtis,omitempty"`
	IsRevoked     bool              `json:"is_revoked"`
	RevokedReason string            `json:"revoked_reason,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ActivityEvent captures runtime operations bound to a JTI.
type ActivityEvent struct {
	JTI       string    `json:"jti"`
	PID       int       `json:"pid"`
	Syscall   string    `json:"syscall"`
	Target    string    `json:"target"` // file path, socket address, or tool name
	Timestamp time.Time `json:"timestamp"`
}

// DriftEvaluation represents the verdict of checking an activity against an agent's mandate.
type DriftEvaluation struct {
	JTI           string `json:"jti"`
	DriftDetected bool   `json:"drift_detected"`
	ViolationType string `json:"violation_type,omitempty"`
	ActionTaken   string `json:"action_taken"` // "ALLOW", "KILL_SESSION", "REVOKE_TOKEN"
	Reason        string `json:"reason,omitempty"`
}
