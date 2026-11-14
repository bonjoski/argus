package graph

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ActivityGraphManager defines operations on the runtime agent activity graph.
type ActivityGraphManager interface {
	RegisterSession(ctx context.Context, node AgentIdentityNode) error
	RecordActivity(ctx context.Context, event ActivityEvent) (*DriftEvaluation, error)
	RevokeLineage(ctx context.Context, rootJTI string, reason string) ([]string, error)
	IsRevoked(ctx context.Context, jti string) bool
	GetSession(ctx context.Context, jti string) (*AgentIdentityNode, bool)
	ActiveSessionsCount() int
}

// MemoryActivityGraph implements ActivityGraphManager using an in-memory sharded graph.
type MemoryActivityGraph struct {
	mu           sync.RWMutex
	nodes        map[string]*AgentIdentityNode
	pidToJTI     map[int]string
	childIndex   map[string][]string // parentJTI -> []childJTI
	killswitchFn func(pid int, jti string, reason string) error
}

// NewMemoryActivityGraph initializes an activity graph engine.
func NewMemoryActivityGraph(killswitchFn func(pid int, jti string, reason string) error) *MemoryActivityGraph {
	return &MemoryActivityGraph{
		nodes:        make(map[string]*AgentIdentityNode),
		pidToJTI:     make(map[int]string),
		childIndex:   make(map[string][]string),
		killswitchFn: killswitchFn,
	}
}

// RegisterSession adds an agent token identity node to the active graph.
func (g *MemoryActivityGraph) RegisterSession(ctx context.Context, node AgentIdentityNode) error {
	if node.JTI == "" {
		return fmt.Errorf("cannot register session with empty JTI")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// If parent JTI is specified, check if parent exists and is not revoked
	if node.ParentJTI != "" {
		parent, exists := g.nodes[node.ParentJTI]
		if !exists {
			return fmt.Errorf("parent JTI %s does not exist in graph", node.ParentJTI)
		}
		if parent.IsRevoked {
			return fmt.Errorf("parent JTI %s is revoked; cannot spawn child session", node.ParentJTI)
		}
		g.childIndex[node.ParentJTI] = append(g.childIndex[node.ParentJTI], node.JTI)
	}

	nodeCopy := node
	nodeCopy.ChildrenJTIs = make([]string, 0)
	g.nodes[node.JTI] = &nodeCopy

	if node.ActivePID > 0 {
		g.pidToJTI[node.ActivePID] = node.JTI
	}

	return nil
}

// RecordActivity checks an incoming runtime event against the session mandate.
func (g *MemoryActivityGraph) RecordActivity(ctx context.Context, event ActivityEvent) (*DriftEvaluation, error) {
	g.mu.RLock()
	jti := event.JTI
	if jti == "" && event.PID > 0 {
		jti = g.pidToJTI[event.PID]
	}

	node, exists := g.nodes[jti]
	g.mu.RUnlock()

	if !exists {
		// Unregistered agent process executing actions is an untracked shadow agent!
		eval := &DriftEvaluation{
			JTI:           jti,
			DriftDetected: true,
			ViolationType: "UNTRACKED_SHADOW_AGENT",
			ActionTaken:   "KILL_SESSION",
			Reason:        fmt.Sprintf("Process %d has no registered Conjoiner token identity (shadow agent)", event.PID),
		}
		if g.killswitchFn != nil && event.PID > 0 {
			_ = g.killswitchFn(event.PID, jti, eval.Reason)
		}
		return eval, nil
	}

	// 1. Check if token is already revoked
	if node.IsRevoked {
		eval := &DriftEvaluation{
			JTI:           node.JTI,
			DriftDetected: true,
			ViolationType: "REVOKED_TOKEN_USE",
			ActionTaken:   "KILL_SESSION",
			Reason:        fmt.Sprintf("Attempted tool execution with revoked JTI %s (%s)", node.JTI, node.RevokedReason),
		}
		if g.killswitchFn != nil && event.PID > 0 {
			_ = g.killswitchFn(event.PID, node.JTI, eval.Reason)
		}
		return eval, nil
	}

	// 2. Check if token has expired
	if !node.ExpiresAt.IsZero() && time.Now().After(node.ExpiresAt) {
		eval := &DriftEvaluation{
			JTI:           node.JTI,
			DriftDetected: true,
			ViolationType: "EXPIRED_TOKEN_USE",
			ActionTaken:   "KILL_SESSION",
			Reason:        fmt.Sprintf("Token expired at %s", node.ExpiresAt.Format(time.RFC3339)),
		}
		if g.killswitchFn != nil && event.PID > 0 {
			_ = g.killswitchFn(event.PID, node.JTI, eval.Reason)
		}
		return eval, nil
	}

	// 3. Behavioral Mandate Drift Detection: Syscall and Target inspection
	lowerTarget := strings.ToLower(event.Target)
	lowerSyscall := strings.ToLower(event.Syscall)

	// Check 3a: Shell spawn attempt without execution scope
	if (lowerSyscall == "execve" || lowerSyscall == "execveat") && !hasScope(node.AllowedScopes, "exec:shell", "admin:*") {
		if strings.Contains(lowerTarget, "sh") || strings.Contains(lowerTarget, "bash") || strings.Contains(lowerTarget, "zsh") || strings.Contains(lowerTarget, "cmd") {
			eval := &DriftEvaluation{
				JTI:           node.JTI,
				DriftDetected: true,
				ViolationType: "UNAUTHORIZED_SHELL_SPAWN",
				ActionTaken:   "KILL_SESSION",
				Reason:        fmt.Sprintf("Agent mandate lacks shell execution scope for %s", event.Target),
			}
			_, _ = g.RevokeLineage(ctx, node.JTI, eval.Reason)
			if g.killswitchFn != nil && event.PID > 0 {
				_ = g.killswitchFn(event.PID, node.JTI, eval.Reason)
			}
			return eval, nil
		}
	}

	// Check 3b: Sensitive credential theft attempt
	sensitivePaths := []string{
		".aws/credentials",
		".ssh/id_",
		"/etc/shadow",
		"/etc/passwd",
		".env",
		"169.254.169.254", // IMDS exfiltration
	}
	for _, sens := range sensitivePaths {
		if strings.Contains(lowerTarget, sens) && !hasScope(node.AllowedScopes, "credentials:*", "admin:*") {
			eval := &DriftEvaluation{
				JTI:           node.JTI,
				DriftDetected: true,
				ViolationType: "UNAUTHORIZED_CREDENTIAL_ACCESS",
				ActionTaken:   "KILL_SESSION",
				Reason:        fmt.Sprintf("Agent attempted out-of-mandate access to sensitive resource '%s'", event.Target),
			}
			_, _ = g.RevokeLineage(ctx, node.JTI, eval.Reason)
			if g.killswitchFn != nil && event.PID > 0 {
				_ = g.killswitchFn(event.PID, node.JTI, eval.Reason)
			}
			return eval, nil
		}
	}

	// Authorized activity within bounds
	return &DriftEvaluation{
		JTI:           node.JTI,
		DriftDetected: false,
		ActionTaken:   "ALLOW",
	}, nil
}

// RevokeLineage cascades revocation down the token identity tree, invalidating
// the root token and all subagent child tokens derived from it.
func (g *MemoryActivityGraph) RevokeLineage(ctx context.Context, rootJTI string, reason string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	var revoked []string
	queue := []string{rootJTI}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if node, exists := g.nodes[curr]; exists {
			if !node.IsRevoked {
				node.IsRevoked = true
				node.RevokedReason = reason
				revoked = append(revoked, curr)
			}
		}

		// Enqueue children
		if children, exists := g.childIndex[curr]; exists {
			queue = append(queue, children...)
		}
	}

	return revoked, nil
}

func (g *MemoryActivityGraph) IsRevoked(ctx context.Context, jti string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if node, exists := g.nodes[jti]; exists {
		return node.IsRevoked
	}
	return false
}

func (g *MemoryActivityGraph) GetSession(ctx context.Context, jti string) (*AgentIdentityNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, exists := g.nodes[jti]
	if !exists {
		return nil, false
	}
	copyNode := *node
	return &copyNode, true
}

func (g *MemoryActivityGraph) ActiveSessionsCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, n := range g.nodes {
		if !n.IsRevoked {
			count++
		}
	}
	return count
}

func hasScope(scopes []string, matches ...string) bool {
	for _, s := range scopes {
		for _, m := range matches {
			if s == m || s == "*" {
				return true
			}
		}
	}
	return false
}
