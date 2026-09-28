package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"bonjoski/argus/internal/service"
)

// Server represents the resident Argus IPC daemon server.
type Server struct {
	socketPath    string
	pidPath       string
	service       *service.VettingService
	listener      net.Listener
	startTime     time.Time
	totalRequests atomic.Int64
	cacheHits     atomic.Int64
	cacheMisses   atomic.Int64

	shutdownOnce sync.Once
	shutdownCh   chan struct{}
	wg           sync.WaitGroup
}

// NewServer initializes a new resident daemon server.
func NewServer(socketPath, pidPath string, vettingService *service.VettingService) *Server {
	return &Server{
		socketPath: socketPath,
		pidPath:    pidPath,
		service:    vettingService,
		startTime:  time.Now(),
		shutdownCh: make(chan struct{}),
	}
}

// Start begins listening on the Unix domain socket and serving connections.
func (s *Server) Start(ctx context.Context) error {
	// Clean up stale socket file if it exists
	if _, err := os.Stat(s.socketPath); err == nil {
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing socket file: %w", err)
		}
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", s.socketPath, err)
	}
	s.listener = l

	// Enforce 0600 permissions so only owner user can access the socket
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = l.Close()
		return fmt.Errorf("failed to set socket permissions on %s: %w", s.socketPath, err)
	}

	// Write PID file
	if s.pidPath != "" {
		pidContent := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(s.pidPath, []byte(pidContent), 0600); err != nil {
			_ = l.Close()
			return fmt.Errorf("failed to write pid file %s: %w", s.pidPath, err)
		}
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.shutdownCh:
			_ = s.Close()
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("daemon socket accept error: %w", err)
			}
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(c)
		}(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				// Non-EOF error
			}
			return
		}

		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			resp := Response{
				Success: false,
				Error:   fmt.Sprintf("malformed request payload: %v", err),
			}
			_ = s.sendResponse(writer, resp)
			return
		}

		s.totalRequests.Add(1)
		resp := s.processRequest(req)
		if err := s.sendResponse(writer, resp); err != nil {
			return
		}

		if req.Action == ActionShutdown {
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = s.Close()
			}()
			return
		}
	}
}

func (s *Server) processRequest(req Request) Response {
	start := time.Now()

	switch req.Action {
	case ActionPing:
		return Response{
			Success:   true,
			LatencyMs: time.Since(start).Milliseconds(),
		}

	case ActionStats:
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		stats := &DaemonStats{
			PID:           os.Getpid(),
			UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
			StartTime:     s.startTime,
			TotalRequests: s.totalRequests.Load(),
			CacheHits:     s.cacheHits.Load(),
			CacheMisses:   s.cacheMisses.Load(),
			MemoryAllocMB: float64(m.Alloc) / (1024 * 1024),
			SocketPath:    s.socketPath,
		}

		return Response{
			Success:   true,
			Stats:     stats,
			LatencyMs: time.Since(start).Milliseconds(),
		}

	case ActionVet:
		if s.service == nil {
			return Response{
				Success: false,
				Error:   "vetting service is uninitialized in daemon",
			}
		}

		if req.Ecosystem == "" || req.Package == "" {
			return Response{
				Success: false,
				Error:   "ecosystem and package are required for vet action",
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		report, err := s.service.Vet(ctx, req.Ecosystem, req.Package, req.Version)
		if err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}

		if report.Cached {
			s.cacheHits.Add(1)
		} else {
			s.cacheMisses.Add(1)
		}

		return Response{
			Success:   true,
			Report:    report,
			LatencyMs: time.Since(start).Milliseconds(),
		}

	case ActionShutdown:
		return Response{
			Success:   true,
			LatencyMs: time.Since(start).Milliseconds(),
		}

	default:
		return Response{
			Success: false,
			Error:   fmt.Sprintf("unknown action: %s", req.Action),
		}
	}
}

func (s *Server) sendResponse(w *bufio.Writer, resp Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return w.Flush()
}

// Close gracefully stops the listener, waits for connections, and cleans up artifacts.
func (s *Server) Close() error {
	var closeErr error
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
		if s.listener != nil {
			closeErr = s.listener.Close()
		}

		// Wait for active connections with a 2-second timeout
		waitCh := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(waitCh)
		}()

		select {
		case <-waitCh:
		case <-time.After(2 * time.Second):
		}

		// Remove socket file
		if s.socketPath != "" {
			if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) && closeErr == nil {
				closeErr = err
			}
		}

		// Remove PID file
		if s.pidPath != "" {
			if err := os.Remove(s.pidPath); err != nil && !os.IsNotExist(err) && closeErr == nil {
				closeErr = err
			}
		}
	})

	return closeErr
}
