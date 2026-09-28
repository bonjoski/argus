package daemon

import (
	"time"

	"bonjoski/argus/internal/model"
)

// Action represents an IPC daemon command.
type Action string

const (
	ActionPing     Action = "ping"
	ActionVet      Action = "vet"
	ActionStats    Action = "stats"
	ActionShutdown Action = "shutdown"
)

// Request is the IPC payload sent from clients to the Argus daemon.
type Request struct {
	Action    Action          `json:"action"`
	Ecosystem model.Ecosystem `json:"ecosystem,omitempty"`
	Package   string          `json:"package,omitempty"`
	Version   string          `json:"version,omitempty"`
	NoCache   bool            `json:"no_cache,omitempty"`
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
