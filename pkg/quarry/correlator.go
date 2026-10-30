package quarry

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CorrelatorOptions configures the causal sliding window correlator.
type CorrelatorOptions struct {
	MaxEventsPerAgent int
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

// Correlator evaluates Layer-7 MCP tool events and Layer-3 kernel syscall events
// against compiled Quarry rules in causal order.
type Correlator struct {
	mu            sync.RWMutex
	rules         map[string]*CompiledRule
	agents        map[string]*AgentContext
	opts          CorrelatorOptions
	dispatcher    *Dispatcher
	totalIngested atomic.Int64
	totalAlerts   atomic.Int64
}

// NewCorrelator initializes a causal sliding-window correlator.
func NewCorrelator(opts ...CorrelatorOptions) *Correlator {
	opt := CorrelatorOptions{
		MaxEventsPerAgent: 1000,
		MultiTierWindow:   true,
		SessionWindow:     1 * time.Hour,
		FailClosed:        true,
	}
	if len(opts) > 0 {
		if opts[0].MaxEventsPerAgent > 0 {
			opt.MaxEventsPerAgent = opts[0].MaxEventsPerAgent
		}
		opt.MultiTierWindow = opts[0].MultiTierWindow
		if opts[0].SessionWindow > 0 {
			opt.SessionWindow = opts[0].SessionWindow
		}
		opt.FailClosed = opts[0].FailClosed
		opt.Dispatcher = opts[0].Dispatcher
	}

	return &Correlator{
		rules:      make(map[string]*CompiledRule),
		agents:     make(map[string]*AgentContext),
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
	for _, ac := range c.agents {
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
		// Evict oldest benign event
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

			// Dispatch alert immediately if dispatcher is active
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

	if ac, exists := c.agents[key]; exists {
		return ac
	}

	ac := &AgentContext{
		PID:         e.AgentPID,
		SessionID:   e.SessionID,
		fsms:        make(map[string]*FSM, len(c.rules)),
		eventBuffer: make([]*Event, 0, 128),
		bufferCap:   c.opts.MaxEventsPerAgent,
		lastSeen:    e.Timestamp,
	}

	for name, cr := range c.rules {
		ac.fsms[name] = NewFSM(cr, c.opts.MultiTierWindow)
	}

	c.agents[key] = ac
	return ac
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

	if ac, exists := c.agents[key]; exists {
		ac.mu.Lock()
		for _, fsm := range ac.fsms {
			fsm.Reset()
		}
		ac.eventBuffer = ac.eventBuffer[:0]
		ac.mu.Unlock()
		delete(c.agents, key)
	}
}
