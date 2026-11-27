package quarry

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Layer represents the layer of telemetry (Layer-7 MCP tool, Layer-3 Kernel syscall, or Layer Supply Chain).
type Layer string

const (
	LayerL7MCP       Layer = "l7_mcp"
	LayerL3Kernel    Layer = "l3_kernel"
	LayerSupplyChain Layer = "supply_chain"
)

// NormalizeLayer maps common aliases to standardized Layer values.
func NormalizeLayer(s string) Layer {
	clean := strings.ToLower(strings.TrimSpace(s))
	switch clean {
	case "l7_mcp", "l7", "mcp", "tool", "mcp_tool":
		return LayerL7MCP
	case "l3_kernel", "l3", "kernel", "syscall", "os":
		return LayerL3Kernel
	case "supply_chain", "supplychain", "package", "dependency", "pkg":
		return LayerSupplyChain
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

// splitPackageAndVersion separates an inline package specifier (e.g. "pkg@1.2.3",
// "github.com/nats-io/nats-server/v2@v2.12.7", "@scope/pkg@1.0.0", "pkg==0.20.0",
// "pkg>=1.0.0", "pkg[dev]~=1.2") into its clean package name and version string.
func splitPackageAndVersion(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	// Strip inline environment markers (e.g. "pkg==1.0; python_version<'3.12'")
	if semi := strings.IndexByte(s, ';'); semi > 0 {
		s = strings.TrimSpace(s[:semi])
	}
	// Check PEP 440 / pip / uv comparison operators in longest-first order
	for _, op := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(s, op); idx > 0 {
			name := stripPackageExtras(strings.TrimSpace(s[:idx]))
			ver := strings.TrimSpace(s[idx+len(op):])
			return name, ver
		}
	}
	// Find '@' after any scoped prefix (e.g., "@scope/pkg@1.2.3")
	searchStart := 0
	if strings.HasPrefix(s, "@") {
		if slash := strings.IndexByte(s, '/'); slash != -1 {
			searchStart = slash + 1
		} else {
			return s, ""
		}
	}
	if relIdx := strings.LastIndexByte(s[searchStart:], '@'); relIdx > 0 {
		idx := searchStart + relIdx
		name := stripPackageExtras(strings.TrimSpace(s[:idx]))
		ver := strings.TrimSpace(s[idx+1:])
		return name, ver
	}
	return stripPackageExtras(s), ""
}

// stripPackageExtras removes PEP 508 extras brackets (e.g. "suki-zov[dev]" -> "suki-zov").
func stripPackageExtras(name string) string {
	if idx := strings.IndexByte(name, '['); idx > 0 && strings.HasSuffix(name, "]") {
		return strings.TrimSpace(name[:idx])
	}
	return name
}

// GetEcosystem extracts the package ecosystem (e.g. "pypi", "npm", "go", "cargo") if provided.
func (e *Event) GetEcosystem() string {
	if e == nil {
		return ""
	}
	if e.Args != nil {
		if eco, ok := e.Args["ecosystem"].(string); ok && strings.TrimSpace(eco) != "" {
			return strings.ToLower(strings.TrimSpace(eco))
		}
	}
	if e.Metadata != nil {
		if eco, ok := e.Metadata["ecosystem"]; ok && strings.TrimSpace(eco) != "" {
			return strings.ToLower(strings.TrimSpace(eco))
		}
	}
	return ""
}

// getRawPackageSpec extracts the raw package token (potentially including @version or ==version).
func (e *Event) getRawPackageSpec() string {
	if e == nil {
		return ""
	}
	if e.Args != nil {
		for _, key := range []string{"package", "package_name", "pkg", "pkg_name", "name", "dependency"} {
			if pkg, ok := e.Args[key].(string); ok && strings.TrimSpace(pkg) != "" {
				return strings.TrimSpace(pkg)
			}
		}
	}
	if e.Metadata != nil {
		for _, key := range []string{"package", "package_name", "pkg", "name", "dependency"} {
			if pkg, ok := e.Metadata[key]; ok && strings.TrimSpace(pkg) != "" {
				return strings.TrimSpace(pkg)
			}
		}
	}
	// Fall back to Path if it represents a package name (not an absolute, relative, or directory path)
	if e.Path != "" && !strings.HasPrefix(e.Path, "/") && !strings.HasPrefix(e.Path, ".") && !strings.Contains(e.Path, "/") {
		return strings.TrimSpace(e.Path)
	}
	// Extract from Command if simple install syntax (e.g. "npm install <pkg>", "go get <pkg>@<ver>", "cargo add <pkg>@<ver>")
	if e.Command != "" {
		parts := strings.Fields(e.Command)
		for i, part := range parts {
			cleanPart := strings.ToLower(part)
			if (cleanPart == "install" || cleanPart == "add" || cleanPart == "i" || cleanPart == "get") && i+1 < len(parts) {
				next := parts[i+1]
				if !strings.HasPrefix(next, "-") {
					return next
				}
			}
		}
	}
	return ""
}

// GetPackageName extracts the target dependency/package name from Args, Metadata, Path, or Command,
// stripping any inline @version or ==version suffix.
func (e *Event) GetPackageName() string {
	name, _ := splitPackageAndVersion(e.getRawPackageSpec())
	return name
}

// GetPackageVersion extracts the target package version from Args, Metadata, or inline package specifiers.
func (e *Event) GetPackageVersion() string {
	if e == nil {
		return ""
	}
	if e.Args != nil {
		for _, key := range []string{"version", "package_version", "pkg_version", "ver"} {
			if v, ok := e.Args[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	if e.Metadata != nil {
		for _, key := range []string{"version", "package_version", "pkg_version", "ver"} {
			if v, ok := e.Metadata[key]; ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	_, ver := splitPackageAndVersion(e.getRawPackageSpec())
	return ver
}

// GetPackageAgeHours returns the age of the package in hours, if known.
func (e *Event) GetPackageAgeHours() (float64, bool) {
	if e == nil {
		return 0, false
	}
	if e.Args != nil {
		for _, key := range []string{"age_hours", "package_age_hours", "age"} {
			if val, ok := e.Args[key]; ok {
				switch v := val.(type) {
				case float64:
					return v, true
				case int:
					return float64(v), true
				case int64:
					return float64(v), true
				case string:
					if f, err := strconv.ParseFloat(v, 64); err == nil {
						return f, true
					}
				}
			}
		}
		if tVal, ok := e.Args["published_at"].(time.Time); ok && !tVal.IsZero() {
			ref := e.Timestamp
			if ref.IsZero() {
				ref = time.Now()
			}
			return ref.Sub(tVal).Hours(), true
		}
		if tStr, ok := e.Args["published_at"].(string); ok && tStr != "" {
			if parsed, err := time.Parse(time.RFC3339, tStr); err == nil {
				ref := e.Timestamp
				if ref.IsZero() {
					ref = time.Now()
				}
				return ref.Sub(parsed).Hours(), true
			}
		}
	}
	if e.Metadata != nil {
		for _, key := range []string{"age_hours", "package_age_hours", "age"} {
			if s, ok := e.Metadata[key]; ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					return f, true
				}
			}
		}
	}
	return 0, false
}

// GetDownloads returns the download count (weekly or total), if present.
func (e *Event) GetDownloads() (int64, bool) {
	if e == nil {
		return 0, false
	}
	if e.Args != nil {
		for _, key := range []string{"downloads", "weekly_downloads", "monthly_downloads", "download_count"} {
			if val, ok := e.Args[key]; ok {
				switch v := val.(type) {
				case int64:
					return v, true
				case int:
					return int64(v), true
				case float64:
					return int64(v), true
				case string:
					if d, err := strconv.ParseInt(v, 10, 64); err == nil {
						return d, true
					}
				}
			}
		}
	}
	if e.Metadata != nil {
		for _, key := range []string{"downloads", "weekly_downloads", "monthly_downloads"} {
			if s, ok := e.Metadata[key]; ok {
				if d, err := strconv.ParseInt(s, 10, 64); err == nil {
					return d, true
				}
			}
		}
	}
	return 0, false
}

// GetHookScript returns the script code, shell command, or path associated with a lifecycle hook.
func (e *Event) GetHookScript() string {
	if e == nil {
		return ""
	}
	if e.Args != nil {
		for _, key := range []string{"script", "hook_script", "command", "hook_command", "script_content"} {
			if s, ok := e.Args[key].(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	if e.Command != "" {
		return e.Command
	}
	if e.Path != "" {
		return e.Path
	}
	return ""
}

// IsLifecycleHook returns true if the event represents an install lifecycle script hook.
func (e *Event) IsLifecycleHook() bool {
	if e == nil {
		return false
	}
	act := strings.ToLower(e.Action)
	if act == "preinstall" || act == "install" || act == "postinstall" ||
		act == "preuninstall" || act == "postuninstall" || act == "lifecycle_script" ||
		act == "install_hook" || act == "run_hook" {
		return true
	}
	if e.Args != nil {
		if _, ok := e.Args["hook"]; ok {
			return true
		}
	}
	if e.Metadata != nil {
		if _, ok := e.Metadata["hook_type"]; ok {
			return true
		}
	}
	return false
}
