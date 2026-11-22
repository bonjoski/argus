package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"bonjoski/argus/internal/version"
)

// Server implements a zero-external-dependency MCP JSON-RPC 2.0 STDIO server for Argus.
type Server struct {
	in          io.Reader
	out         io.Writer
	toolHandler ToolHandler
	outMu       sync.Mutex
	version     string
}

// ServerOption configures the MCP server.
type ServerOption func(*Server)

// WithToolHandler customizes the tool handler.
func WithToolHandler(handler ToolHandler) ServerOption {
	return func(s *Server) {
		if handler != nil {
			s.toolHandler = handler
		}
	}
}

// WithVersion sets the server version string.
func WithVersion(v string) ServerOption {
	return func(s *Server) {
		if v != "" {
			s.version = v
		}
	}
}

// NewServer creates a new Argus MCP STDIO server instance.
func NewServer(in io.Reader, out io.Writer, opts ...ServerOption) *Server {
	s := &Server{
		in:          in,
		out:         out,
		toolHandler: NewDefaultToolHandler(),
		version:     version.Version,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Serve reads JSON-RPC 2.0 requests from the input stream and writes responses until EOF or context cancellation.
func (s *Server) Serve(ctx context.Context) error {
	scanner := bufio.NewScanner(s.in)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(nil, CodeParseError, fmt.Sprintf("invalid JSON payload: %v", err))
			continue
		}

		s.handleRequest(ctx, &req)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("scanner error: %w", err)
	}
	return nil
}

// HandleMessage handles a single raw JSON-RPC message synchronously (useful for testing or direct piping).
func (s *Server) HandleMessage(ctx context.Context, msg []byte) (*Response, error) {
	var req Request
	if err := json.Unmarshal(msg, &req); err != nil {
		return &Response{
			JSONRPC: "2.0",
			Error: &RPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("invalid JSON payload: %v", err),
			},
		}, nil
	}
	return s.processRequest(ctx, &req)
}

func (s *Server) handleRequest(ctx context.Context, req *Request) {
	resp, err := s.processRequest(ctx, req)
	if err != nil {
		s.writeError(req.ID, CodeInternalError, err.Error())
		return
	}
	if resp != nil {
		s.writeResponse(resp)
	}
}

func (s *Server) processRequest(ctx context.Context, req *Request) (*Response, error) {
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("unsupported jsonrpc version: %s", req.JSONRPC),
			},
		}, nil
	}

	switch req.Method {
	case "initialize":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities: ServerCapabilities{
					Tools:   &ToolsCapability{ListChanged: false},
					Logging: &LoggingCapability{},
				},
				ServerInfo: ServerInfo{
					Name:    "argus-mcp",
					Version: s.version,
				},
			},
		}, nil

	case "notifications/initialized", "initialized":
		// Notification - no response required
		return nil, nil

	case "ping":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}, nil

	case "tools/list":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ListToolsResult{
				Tools: SupportedTools(),
			},
		}, nil

	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &RPCError{
					Code:    CodeInvalidParams,
					Message: fmt.Sprintf("invalid tools/call params: %v", err),
				},
			}, nil
		}

		var result *CallToolResult
		var callErr error

		switch params.Name {
		case "argus_vet":
			result, callErr = s.toolHandler.HandleVet(ctx, params.Arguments)
		default:
			return &Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &RPCError{
					Code:    CodeMethodNotFound,
					Message: fmt.Sprintf("unknown tool: %s", params.Name),
				},
			}, nil
		}

		if callErr != nil {
			return &Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: buildRuntimeErrorResult(
					fmt.Sprintf("argus_vet execution error: %v", callErr),
				),
			}, nil
		}

		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}, nil

	case "logging/setLevel":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}, nil

	default:
		if len(req.ID) == 0 {
			return nil, nil
		}
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("unsupported method: %s", req.Method),
			},
		}, nil
	}
}

func (s *Server) writeResponse(resp *Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_, _ = s.out.Write(data)
	_, _ = s.out.Write([]byte("\n"))
}

func (s *Server) writeError(id json.RawMessage, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	s.writeResponse(&resp)
}
