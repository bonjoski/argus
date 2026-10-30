package quarry

import (
	"encoding/json"
	"strings"
	"time"
)

// Layer represents the layer of telemetry (Layer-7 MCP tool or Layer-3 Kernel syscall).
type Layer string

const (
	LayerL7MCP    Layer = "l7_mcp"
	LayerL3Kernel Layer = "l3_kernel"
)

// NormalizeLayer maps common aliases to standardized Layer values.
func NormalizeLayer(s string) Layer {
	clean := strings.ToLower(strings.TrimSpace(s))
	switch clean {
	case "l7_mcp", "l7", "mcp", "tool", "mcp_tool":
		return LayerL7MCP
	case "l3_kernel", "l3", "kernel", "syscall", "os":
		return LayerL3Kernel
	default:
		return Layer(clean)
	}
}

// Event represents an atomic telemetry event observed by Argus or Airlock.
type Event struct {
	ID            string            `json:"id,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	AgentPID      int               `json:"agent_pid"`
	SessionID     string            `json:"session_id,omitempty"`
	SessionTicket string            `json:"session_ticket,omitempty"`
	Layer         Layer             `json:"layer"`
	Action        string            `json:"action"` // e.g. "list_directory", "read_file", "syscall_connect"
	Path          string            `json:"path,omitempty"`
	Destination   string            `json:"destination,omitempty"` // host, ip, or host:port
	Tool          string            `json:"tool,omitempty"`
	Command       string            `json:"command,omitempty"`
	Args          map[string]any    `json:"args,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Clone creates a deep copy of the Event.
func (e *Event) Clone() *Event {
	if e == nil {
		return nil
	}
	cp := *e
	if e.Args != nil {
		cp.Args = make(map[string]any, len(e.Args))
		for k, v := range e.Args {
			cp.Args[k] = v
		}
	}
	if e.Metadata != nil {
		cp.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

// String returns a compact JSON representation of the Event.
func (e *Event) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
