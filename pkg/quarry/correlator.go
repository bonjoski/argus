package quarry

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxTrackedAgents bounds total distinct agent/session contexts retained concurrently in RAM.
const DefaultMaxTrackedAgents = 4096

// CorrelatorOptions configures the causal sliding window correlator.
type CorrelatorOptions struct {
	MaxEventsPerAgent int
	MaxTrackedAgents  int
	AgentIdleTTL      time.Duration
	MultiTierWindow   bool
	SessionWindow     time.Duration
	FailClosed        bool
	Dispatcher        *Dispatcher
}

// AgentContext tracks sliding-window telemetry and rule FSMs for a specific agent PID/Session.
type AgentContext struct {
	PID           int
	SessionID     string
	mu            sync.Mutex
	fsms          map[string]*FSM
	eventBuffer   []*Event
	bufferCap     int
	lastSeen      time.Time
	droppedEvents atomic.Int64
}

type lruAgentEntry struct {
	key string
	ctx *AgentContext
}

// Correlator evaluates Layer-7 MCP tool events and Layer-3 kernel syscall events
// against compiled Quarry rules in causal order with bounded LRU + idle TTL agent state.
type Correlator struct {
	mu            sync.RWMutex
	rules         map[string]*CompiledRule
	agents        map[string]*list.Element
	agentLRU      *list.List
	opts          CorrelatorOptions
	dispatcher    *Dispatcher
	totalIngested atomic.Int64
	totalAlerts   atomic.Int64
}

// NewCorrelator initializes a causal sliding-window correlator.
func NewCorrelator(opts ...CorrelatorOptions) *Correlator {
	opt := CorrelatorOptions{
		MaxEventsPerAgent: 1000,
		MaxTrackedAgents:  DefaultMaxTrackedAgents,
		MultiTierWindow:   true,
		SessionWindow:     1 * time.Hour,
		FailClosed:        true,
	}
	if len(opts) > 0 {
		if opts[0].MaxEventsPerAgent > 0 {
			opt.MaxEventsPerAgent = opts[0].MaxEventsPerAgent
		}
		if opts[0].MaxTrackedAgents > 0 {
			opt.MaxTrackedAgents = opts[0].MaxTrackedAgents
		}
		opt.MultiTierWindow = opts[0].MultiTierWindow
		if opts[0].SessionWindow > 0 {
			opt.SessionWindow = opts[0].SessionWindow
		}
		if opts[0].AgentIdleTTL > 0 {
			opt.AgentIdleTTL = opts[0].AgentIdleTTL
		}
		opt.FailClosed = opts[0].FailClosed
		opt.Dispatcher = opts[0].Dispatcher
	}
	if opt.AgentIdleTTL <= 0 {
		opt.AgentIdleTTL = opt.SessionWindow
	}

	return &Correlator{
		rules:      make(map[string]*CompiledRule),
		agents:     make(map[string]*list.Element),
		agentLRU:   list.New(),
		opts:       opt,
		dispatcher: opt.Dispatcher,
	}
}

// SetDispatcher attaches an alert dispatcher to automatically broadcast alerts.
func (c *Correlator) SetDispatcher(d *Dispatcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dispatcher = d
}

// RegisterRule compiles and adds a Quarry rule to the active correlation set.
func (c *Correlator) RegisterRule(r *Rule) error {
	cr, err := CompileRule(r)
	if err != nil {
		return err
	}
	return c.RegisterCompiledRule(cr)
}

// RegisterCompiledRule adds a precompiled rule.
func (c *Correlator) RegisterCompiledRule(cr *CompiledRule) error {
	if cr == nil || cr.Rule == nil {
		return errors.New("cannot register nil compiled rule")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.rules[cr.Rule.Name] = cr

	// Update any existing agent contexts with this rule FSM
	for _, elem := range c.agents {
		entry := elem.Value.(*lruAgentEntry)
		ac := entry.ctx
		ac.mu.Lock()
		if _, exists := ac.fsms[cr.Rule.Name]; !exists {
			ac.fsms[cr.Rule.Name] = NewFSM(cr, c.opts.MultiTierWindow)
		}
		ac.mu.Unlock()
	}

	return nil
}

// Ingest receives a telemetry event, tracks it in the agent context ring buffer,
// and evaluates all compiled rule state machines.
func (c *Correlator) Ingest(e *Event) ([]*Alert, error) {
	if e == nil {
		return nil, errors.New("cannot ingest nil event")
	}

	c.totalIngested.Add(1)

	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}

	agentKey := c.resolveAgentKey(e)
	ac := c.getOrCreateAgentContext(agentKey, e)

	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.lastSeen = e.Timestamp

	// Add event to bounded ring buffer (preventing unbounded memory growth)
	if len(ac.eventBuffer) >= ac.bufferCap {
		copy(ac.eventBuffer[0:], ac.eventBuffer[1:])
		ac.eventBuffer[len(ac.eventBuffer)-1] = e
	} else {
		ac.eventBuffer = append(ac.eventBuffer, e)
	}

	var alerts []*Alert

	// Evaluate event across all rule state machines for this agent
	for _, fsm := range ac.fsms {
		if alert := fsm.Step(e); alert != nil {
			c.totalAlerts.Add(1)
			alerts = append(alerts, alert)

			c.mu.RLock()
			d := c.dispatcher
			c.mu.RUnlock()
			if d != nil {
				_ = d.Broadcast(alert)
			}
		}
	}

	return alerts, nil
}

func (c *Correlator) resolveAgentKey(e *Event) string {
	if e.SessionID != "" {
		return fmt.Sprintf("session:%s", e.SessionID)
	}
	if e.AgentPID > 0 {
		return fmt.Sprintf("pid:%d", e.AgentPID)
	}
	return "global"
}

func (c *Correlator) getOrCreateAgentContext(key string, e *Event) *AgentContext {
	c.mu.Lock()
	defer c.mu.Unlock()

	refTime := e.Timestamp
	if refTime.IsZero() {
		refTime = time.Now()
	}

	// 1. Opportunistically evict idle expired contexts from LRU tail
	c.evictExpiredLocked(refTime)

	// 2. Promote existing context on hit
	if elem, exists := c.agents[key]; exists {
		c.agentLRU.MoveToFront(elem)
		return elem.Value.(*lruAgentEntry).ctx
	}

	// 3. Enforce strict upper bound via LRU eviction before inserting new agent context
	for c.opts.MaxTrackedAgents > 0 && len(c.agents) >= c.opts.MaxTrackedAgents {
		back := c.agentLRU.Back()
		if back == nil {
			break
		}
		c.removeElementLocked(back)
	}

	ac := &AgentContext{
		PID:         e.AgentPID,
		SessionID:   e.SessionID,
		fsms:        make(map[string]*FSM, len(c.rules)),
		eventBuffer: make([]*Event, 0, minInt(128, c.opts.MaxEventsPerAgent)),
		bufferCap:   c.opts.MaxEventsPerAgent,
		lastSeen:    refTime,
	}

	for name, cr := range c.rules {
		ac.fsms[name] = NewFSM(cr, c.opts.MultiTierWindow)
	}

	elem := c.agentLRU.PushFront(&lruAgentEntry{key: key, ctx: ac})
	c.agents[key] = elem
	return ac
}

func (c *Correlator) evictExpiredLocked(now time.Time) {
	if c.opts.AgentIdleTTL <= 0 {
		return
	}
	for {
		back := c.agentLRU.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*lruAgentEntry)
		entry.ctx.mu.Lock()
		idle := now.Sub(entry.ctx.lastSeen)
		entry.ctx.mu.Unlock()
		if idle <= c.opts.AgentIdleTTL {
			return
		}
		c.removeElementLocked(back)
	}
}

func (c *Correlator) removeElementLocked(elem *list.Element) {
	entry := elem.Value.(*lruAgentEntry)
	entry.ctx.mu.Lock()
	for _, fsm := range entry.ctx.fsms {
		fsm.Reset()
	}
	entry.ctx.eventBuffer = nil
	entry.ctx.mu.Unlock()

	c.agentLRU.Remove(elem)
	delete(c.agents, entry.key)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TrackedAgentsCount returns the current number of active agent/session contexts in memory.
func (c *Correlator) TrackedAgentsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.agents)
}

// RulesCount returns the count of active Quarry rules loaded in memory.
func (c *Correlator) RulesCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

// TotalIngested returns the total count of events processed.
func (c *Correlator) TotalIngested() int64 {
	return c.totalIngested.Load()
}

// TotalAlerts returns the total count of alerts generated.
func (c *Correlator) TotalAlerts() int64 {
	return c.totalAlerts.Load()
}

// ResetAgent clears the state and history for a specific agent PID or session key.
func (c *Correlator) ResetAgent(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.agents[key]; exists {
		c.removeElementLocked(elem)
	}
}
