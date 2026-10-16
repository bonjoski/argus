package daemon

import (
	"fmt"
	"strings"
	"time"

	"bonjoski/argus/internal/model"
)

// Action represents an IPC daemon command.
type Action string

const (
	ActionPing            Action = "ping"
	ActionVet             Action = "vet"
	ActionStats           Action = "stats"
	ActionShutdown        Action = "shutdown"
	ActionTelemetryIngest Action = "telemetry_ingest"
)

// Request is the IPC payload sent from clients to the Argus daemon.
type Request struct {
	Action    Action          `json:"action"`
	Ecosystem model.Ecosystem `json:"ecosystem,omitempty"`
	Package   string          `json:"package,omitempty"`
	Version   string          `json:"version,omitempty"`
	NoCache   bool            `json:"no_cache,omitempty"`
	Telemetry *AuditEvent     `json:"telemetry,omitempty"`
}

// AuditSeverity represents the risk level of a telemetry event.
type AuditSeverity string

const (
	SeverityInfo     AuditSeverity = "INFO"
	SeverityWarn     AuditSeverity = "WARN"
	SeverityCritical AuditSeverity = "CRITICAL"
)

// AgentContext captures the AI agent runtime context for audit correlation.
type AgentContext struct {
	Orchestrator string `json:"orchestrator,omitempty"` // e.g. "claude-code", "cursor", "gemini-cli"
	SessionID    string `json:"session_id,omitempty"`
	Profile      string `json:"profile,omitempty"` // e.g. "agent"
	CommandAST   string `json:"command_ast,omitempty"`
}

// AuditEvent represents a normalized telemetry event from Airlock, Locksmith, or Aegisbox.
type AuditEvent struct {
	TraceID       string         `json:"trace_id"`
	SpanID        string         `json:"span_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Source        string         `json:"source"`     // "airlock", "locksmith", "aegisbox"
	EventType     string         `json:"event_type"` // e.g. "syscall.violation", "secret.lease.granted", "canary.tripwire"
	Severity      AuditSeverity  `json:"severity"`
	TargetPID     int            `json:"target_pid,omitempty"`
	SessionTicket string         `json:"session_ticket,omitempty"`
	AgentContext  *AgentContext  `json:"agent_context,omitempty"`
	Details       map[string]any `json:"details"`
}

// CEF returns the Common Event Format (CEF) representation for SIEM ingestion.
// Sanitizes pipe and newline characters to prevent CEF log injection attacks.
func (ae *AuditEvent) CEF() string {
	sevNum := 1
	switch ae.Severity {
	case SeverityWarn:
		sevNum = 6
	case SeverityCritical:
		sevNum = 10
	}
	clean := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", " ")
		s = strings.ReplaceAll(s, "|", "\\|")
		return s
	}
	return fmt.Sprintf("CEF:0|bonjoski|%s|1.0|%s|%s|%d|traceId=%s spanId=%s",
		clean(ae.Source), clean(ae.EventType), clean(ae.EventType), sevNum, clean(ae.TraceID), clean(ae.SpanID))
}

// OTelMap formats the audit event as an OpenTelemetry compliant resource span dictionary.
func (ae *AuditEvent) OTelMap() map[string]any {
	attributes := map[string]any{
		"service.name":    "bonjoski-" + ae.Source,
		"event.name":      ae.EventType,
		"event.severity":  string(ae.Severity),
		"event.timestamp": ae.Timestamp.Format(time.RFC3339Nano),
		"security.source": ae.Source,
	}
	if ae.TargetPID > 0 {
		attributes["process.pid"] = ae.TargetPID
	}
	if ae.SessionTicket != "" {
		attributes["session.ticket"] = ae.SessionTicket
	}
	if ae.AgentContext != nil {
		if ae.AgentContext.Orchestrator != "" {
			attributes["agent.orchestrator"] = ae.AgentContext.Orchestrator
		}
		if ae.AgentContext.Profile != "" {
			attributes["agent.profile"] = ae.AgentContext.Profile
		}
		if ae.AgentContext.SessionID != "" {
			attributes["agent.session_id"] = ae.AgentContext.SessionID
		}
	}
	for k, v := range ae.Details {
		attributes["details."+k] = v
	}

	return map[string]any{
		"trace_id":   ae.TraceID,
		"span_id":    ae.SpanID,
		"name":       ae.EventType,
		"attributes": attributes,
	}
}

// Response is the IPC payload returned by the Argus daemon.
type Response struct {
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
	Report    *model.RiskReport `json:"report,omitempty"`
	Stats     *DaemonStats      `json:"stats,omitempty"`
	LatencyMs int64             `json:"latency_ms,omitempty"`
}

// DaemonStats provides operational metrics of the resident daemon process.
type DaemonStats struct {
	PID           int       `json:"pid"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	StartTime     time.Time `json:"start_time"`
	TotalRequests int64     `json:"total_requests"`
	CacheHits     int64     `json:"cache_hits"`
	CacheMisses   int64     `json:"cache_misses"`
	MemoryAllocMB float64   `json:"memory_alloc_mb"`
	SocketPath    string    `json:"socket_path"`
}
