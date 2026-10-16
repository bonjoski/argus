package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// TelemetryBusOptions configures the in-memory telemetry ring buffer.
type TelemetryBusOptions struct {
	Capacity       int
	LogSinkPath    string
	LocksmithSock  string
	FlushInterval  time.Duration
}

// TelemetryBus provides non-blocking, lock-free ingestion for high-throughput
// security and operational telemetry streams from Airlock, Locksmith, and Aegisbox.
type TelemetryBus struct {
	mu             sync.Mutex
	opts           TelemetryBusOptions
	ch             chan *AuditEvent
	killswitch     *KillswitchCoordinator
	totalIngested  atomic.Int64
	droppedEvents  atomic.Int64
	logFile        io.WriteCloser
	stopCh         chan struct{}
	workerDone     chan struct{}
	closed         bool
}

// NewTelemetryBus initializes an ingestion bus and starts the background sink drainer.
func NewTelemetryBus(opts ...TelemetryBusOptions) *TelemetryBus {
	opt := TelemetryBusOptions{
		Capacity:      10000,
		FlushInterval: 100 * time.Millisecond,
	}
	if len(opts) > 0 {
		if opts[0].Capacity > 0 {
			opt.Capacity = opts[0].Capacity
		}
		if opts[0].LogSinkPath != "" {
			opt.LogSinkPath = opts[0].LogSinkPath
		}
		opt.LocksmithSock = opts[0].LocksmithSock
		if opts[0].FlushInterval > 0 {
			opt.FlushInterval = opts[0].FlushInterval
		}
	}

	bus := &TelemetryBus{
		opts:       opt,
		ch:         make(chan *AuditEvent, opt.Capacity),
		killswitch: NewKillswitchCoordinator(opt.LocksmithSock),
		stopCh:     make(chan struct{}),
		workerDone: make(chan struct{}),
	}

	// Open local telemetry log sink if path provided
	if opt.LogSinkPath != "" {
		_ = os.MkdirAll(filepath.Dir(opt.LogSinkPath), 0700)
		f, err := os.OpenFile(opt.LogSinkPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			bus.logFile = f
		}
	}

	go bus.drainWorker()

	return bus
}

// Ingest receives an audit event without blocking execution.
// If the buffer is full, low-severity events are safely dropped with an atomic counter (VAL-04).
// Critical events trigger immediate killswitch containment and are guaranteed priority.
func (b *TelemetryBus) Ingest(event *AuditEvent) error {
	if event == nil {
		return errors.New("cannot ingest nil audit event")
	}

	b.totalIngested.Add(1)

	// Critical severity trigger immediate killswitch intervention
	if event.Severity == SeverityCritical {
		_ = b.killswitch.Intercept(event)
	}

	// Non-blocking ring buffer delivery
	select {
	case b.ch <- event:
		return nil
	default:
		// Ring buffer full
		if event.Severity == SeverityCritical {
			// For critical events, pop an older event to make room
			select {
			case <-b.ch:
				b.droppedEvents.Add(1)
			default:
			}
			b.ch <- event
			return nil
		}
		// For Info / Warn events: drop gracefully to prevent backpressure deadlock
		b.droppedEvents.Add(1)
		return nil
	}
}

func (b *TelemetryBus) drainWorker() {
	defer close(b.workerDone)

	for {
		select {
		case <-b.stopCh:
			// Drain remaining events
			for {
				select {
				case ev := <-b.ch:
					b.writeEvent(ev)
				default:
					return
				}
			}
		case ev := <-b.ch:
			b.writeEvent(ev)
		}
	}
}

func (b *TelemetryBus) writeEvent(ev *AuditEvent) {
	if ev == nil || b.logFile == nil {
		return
	}
	// Write CEF formatted record
	cef := ev.CEF()
	_, _ = fmt.Fprintln(b.logFile, cef)

	// Also write OTel JSON record
	otelData, err := json.Marshal(ev.OTelMap())
	if err == nil {
		_, _ = fmt.Fprintln(b.logFile, string(otelData))
	}
}

// Stats returns current operational metrics of the telemetry bus.
func (b *TelemetryBus) Stats() (ingested int64, dropped int64, kills int64, revocations int64) {
	return b.totalIngested.Load(), b.droppedEvents.Load(), b.killswitch.KillsCount(), b.killswitch.RevocationsCount()
}

// Close gracefully flushes the bus and releases file handles.
func (b *TelemetryBus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()

	close(b.stopCh)
	<-b.workerDone

	if b.logFile != nil {
		_ = b.logFile.Close()
	}
	return nil
}
