package mcp

import (
	"encoding/json"
)

// JSON-RPC 2.0 Standard Types

// Request represents a JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 Error Codes
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Deterministic UB-CLI-v2 / UB-MCP-v1 Exit Code Contract
const (
	ExitOK               = 0
	ExitRuntimeErr       = 1
	ExitPolicyDeny       = 10
	ExitSupplyChainBlock = 20
)

// Canonical UB-MCP-v1 error codes emitted by Argus
const (
	CodeSlopsquatSuspect = "ARGUS_SLOPSQUAT_SUSPECT"
	CodeMaliciousAST     = "ARGUS_MALICIOUS_AST"
	CodePolicyDeny       = "ARGUS_POLICY_DENY"
)

// MCP Protocol Types

// ServerInfo contains metadata about the MCP server implementation.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerCapabilities describes capabilities supported by the server.
type ServerCapabilities struct {
	Tools   *ToolsCapability   `json:"tools,omitempty"`
	Logging *LoggingCapability `json:"logging,omitempty"`
}

// ToolsCapability indicates support for tools.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability indicates support for logging.
type LoggingCapability struct{}

// InitializeResult is the response payload for the "initialize" method.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Tool represents an MCP Tool definition.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema represents the JSON schema for tool arguments.
type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]PropertyDef `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

// PropertyDef represents a single property in a JSON schema.
type PropertyDef struct {
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Items       map[string]any `json:"items,omitempty"`
	Default     any            `json:"default,omitempty"`
}

// ListToolsResult is the response payload for "tools/list".
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is the parameters payload for "tools/call".
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ContentItem represents a content piece in an MCP Tool result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is the response payload for "tools/call".
type CallToolResult struct {
	Content           []ContentItem `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError,omitempty"`
}

// SelfHeal conforms to ub-mcp-v1-error.schema.json#properties/self_heal.
// SuggestedArgs must ONLY be populated from strictly allowlisted canonical identifiers.
type SelfHeal struct {
	SuggestedTool         string         `json:"suggested_tool"`
	SuggestedArgs         map[string]any `json:"suggested_args"`
	RequiresHumanApproval bool           `json:"requires_human_approval"`
}

// StructuredError strictly conforms to ub-mcp-v1-error.schema.json.
type StructuredError struct {
	SchemaVersion  string    `json:"schema_version"`
	Tool           string    `json:"tool"`
	Code           string    `json:"code"`
	ExitCode       int       `json:"exit_code"`
	Retryable      bool      `json:"retryable"`
	Summary        string    `json:"summary"`
	RemediationCmd string    `json:"remediation_cmd"`
	Why            string    `json:"why"`
	DeepWhy        string    `json:"deep_why,omitempty"`
	SelfHeal       *SelfHeal `json:"self_heal,omitempty"`
	ReceiptID      string    `json:"receipt_id,omitempty"`
	References     []string  `json:"references,omitempty"`
}
