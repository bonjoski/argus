package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bonjoski/argus/internal/model"
)

// BlockedResponse represents the structured JSON diagnostic payload returned on 403 Forbidden.
type BlockedResponse struct {
	Error     string          `json:"error"`
	Package   string          `json:"package"`
	Ecosystem model.Ecosystem `json:"ecosystem,omitempty"`
	Version   string          `json:"version,omitempty"`
	RiskScore int             `json:"risk_score"`
	RiskLevel model.RiskLevel `json:"risk_level,omitempty"`
	Reasons   []string        `json:"reasons"`
}

// ServerStats captures telemetry and operational metrics for the mirror proxy.
type ServerStats struct {
	Running         bool      `json:"running"`
	PID             int       `json:"pid"`
	Port            int       `json:"port"`
	Address         string    `json:"address"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	BytesProxied    int64     `json:"bytes_proxied"`
	UpstreamNPM     string    `json:"upstream_npm"`
	UpstreamPyPI    string    `json:"upstream_pypi"`
	Threshold       int       `json:"threshold"`
	Strict          bool      `json:"strict"`
	StartTime       time.Time `json:"start_time"`
}

// Server is the HTTP forward & mirror proxy server with pre-flight threat interception.
type Server struct {
	cfg        Config
	httpServer *http.Server
	listener   net.Listener
	addr       string
	port       int
	startTime  time.Time
	transport  http.RoundTripper

	mu              sync.RWMutex
	totalRequests   int64
	blockedRequests int64
	allowedRequests int64
	bytesProxied    int64
	closed          bool
}

// NewServer creates a new instance of the mirror proxy server.
func NewServer(cfg Config) *Server {
	def := DefaultConfig()
	if cfg.Host == "" {
		cfg.Host = def.Host
	}
	if cfg.UpstreamNPM == "" {
		cfg.UpstreamNPM = def.UpstreamNPM
	}
	if cfg.UpstreamPyPI == "" {
		cfg.UpstreamPyPI = def.UpstreamPyPI
	}
	if cfg.UpstreamProxies == nil {
		cfg.UpstreamProxies = make(map[model.Ecosystem]string)
		for k, v := range def.UpstreamProxies {
			cfg.UpstreamProxies[k] = v
		}
	}
	cfg.UpstreamProxies[model.EcosystemNPM] = cfg.UpstreamNPM
	cfg.UpstreamProxies[model.EcosystemPyPI] = cfg.UpstreamPyPI

	if cfg.Threshold <= 0 {
		cfg.Threshold = def.Threshold
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = def.ReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = def.WriteTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = def.IdleTimeout
	}

	return &Server{
		cfg:       cfg,
		transport: http.DefaultTransport,
	}
}

// SetTransport configures a custom HTTP RoundTripper for upstream queries.
func (s *Server) SetTransport(t http.RoundTripper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transport = t
}

// Addr returns the bound address of the server.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

// Port returns the bound TCP port of the server.
func (s *Server) Port() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.port
}

// Stats returns a snapshot of runtime metrics and state.
func (s *Server) Stats() ServerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var uptime int64
	if !s.startTime.IsZero() {
		uptime = int64(time.Since(s.startTime).Seconds())
	}

	return ServerStats{
		Running:         !s.closed && !s.startTime.IsZero(),
		PID:             os.Getpid(),
		Port:            s.port,
		Address:         s.addr,
		UptimeSeconds:   uptime,
		TotalRequests:   atomic.LoadInt64(&s.totalRequests),
		BlockedRequests: atomic.LoadInt64(&s.blockedRequests),
		AllowedRequests: atomic.LoadInt64(&s.allowedRequests),
		BytesProxied:    atomic.LoadInt64(&s.bytesProxied),
		UpstreamNPM:     s.cfg.UpstreamNPM,
		UpstreamPyPI:    s.cfg.UpstreamPyPI,
		Threshold:       s.cfg.Threshold,
		Strict:          s.cfg.Strict,
		StartTime:       s.startTime,
	}
}

// Start binds to the configured host:port and begins serving mirror proxy traffic.
func (s *Server) Start(ctx context.Context) error {
	bindAddr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", bindAddr, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.addr = listener.Addr().String()
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}
	s.startTime = time.Now()
	s.closed = false
	s.mu.Unlock()

	// Write PID file if configured
	if s.cfg.PIDFile != "" {
		_ = os.WriteFile(s.cfg.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0600)
		defer os.Remove(s.cfg.PIDFile)
	}

	// Write state file if configured
	if s.cfg.StateFile != "" {
		stateData, _ := json.MarshalIndent(s.Stats(), "", "  ")
		_ = os.WriteFile(s.cfg.StateFile, stateData, 0600)
		defer os.Remove(s.cfg.StateFile)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_argus/status", s.handleStatus)
	mux.HandleFunc("/_argus/health", s.handleHealth)
	mux.HandleFunc("/npm", s.handleNPM)
	mux.HandleFunc("/npm/", s.handleNPM)
	mux.HandleFunc("/pypi", s.handlePyPI)
	mux.HandleFunc("/pypi/", s.handlePyPI)
	mux.HandleFunc("/proxy/", s.handleUniversalProxy)
	mux.HandleFunc("/", s.handleRoot)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}

	// Watch context for cancellation to gracefully stop
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdownCtx)
	}()

	err = s.httpServer.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("mirror server terminated unexpectedly: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the proxy server without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Close immediately closes listener and stops the proxy server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleStatus returns runtime telemetry and stats in JSON format.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.Stats())
}

// handleHealth returns a 200 OK health check payload.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleNPM intercepts and proxies npm registry requests.
func (s *Server) handleNPM(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.totalRequests, 1)

	strippedPath := strings.TrimPrefix(r.URL.Path, "/npm")
	if strippedPath == "" || !strings.HasPrefix(strippedPath, "/") {
		strippedPath = "/" + strippedPath
	}

	name, version, isTarget := ParseNPMPath(strippedPath)
	if isTarget && name != "" {
		if s.shouldBlock(r.Context(), model.EcosystemNPM, name, version, w, r) {
			return
		}
	}

	s.proxyRequest(w, r, s.cfg.UpstreamNPM, strippedPath)
}

// handlePyPI intercepts and proxies PyPI registry requests.
func (s *Server) handlePyPI(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.totalRequests, 1)

	strippedPath := strings.TrimPrefix(r.URL.Path, "/pypi")
	if strippedPath == "" || !strings.HasPrefix(strippedPath, "/") {
		strippedPath = "/" + strippedPath
	}

	name, version, isTarget := ParsePyPIPath(strippedPath)
	if isTarget && name != "" {
		if s.shouldBlock(r.Context(), model.EcosystemPyPI, name, version, w, r) {
			return
		}
	}

	s.proxyRequest(w, r, s.cfg.UpstreamPyPI, strippedPath)
}

// handleUniversalProxy intercepts requests formatted as /proxy/:ecosystem/*
func (s *Server) handleUniversalProxy(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.totalRequests, 1)

	// Format: /proxy/{ecosystem}/{rest...}
	rest := strings.TrimPrefix(r.URL.Path, "/proxy/")
	segments := splitPathSegments(rest)
	if len(segments) == 0 {
		http.Error(w, "missing ecosystem in proxy path", http.StatusBadRequest)
		return
	}

	ecoStr := segments[0]
	eco, ok := ParseEcosystem(ecoStr)
	if !ok {
		http.Error(w, fmt.Sprintf("unsupported ecosystem: %s", ecoStr), http.StatusBadRequest)
		return
	}

	remainder := strings.TrimPrefix(rest, ecoStr)
	if !strings.HasPrefix(remainder, "/") {
		remainder = "/" + remainder
	}

	upstreamBase, ok := s.cfg.UpstreamProxies[eco]
	if !ok || upstreamBase == "" {
		http.Error(w, fmt.Sprintf("no upstream configured for ecosystem %s", eco), http.StatusBadGateway)
		return
	}

	name, version, isTarget := ParseGenericEcosystemPath(eco, remainder)
	if isTarget && name != "" {
		if s.shouldBlock(r.Context(), eco, name, version, w, r) {
			return
		}
	}

	s.proxyRequest(w, r, upstreamBase, remainder)
}

// handleRoot catches unmapped root endpoints.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    "Argus Inline Registry Mirror Proxy",
			"status":  "active",
			"routes":  []string{"/npm/*", "/pypi/*", "/proxy/:ecosystem/*", "/_argus/status", "/_argus/health"},
			"version": "1.0.0",
		})
		return
	}
	http.NotFound(w, r)
}

// shouldBlock evaluates enterprise policy and VettingService for the target package.
// If blocked, it writes HTTP 403 Forbidden with diagnostic JSON and returns true.
func (s *Server) shouldBlock(ctx context.Context, eco model.Ecosystem, pkgName, version string, w http.ResponseWriter, r *http.Request) bool {
	// 1. Enterprise Blocklist Rule Check
	if s.cfg.Policy != nil {
		if blocked, reason := s.cfg.Policy.MatchBlocklist(pkgName, ""); blocked {
			s.blockRequest(w, eco, pkgName, version, 100, model.RiskLevelCritical, []string{reason})
			return true
		}
	}

	// 2. Enterprise Allowlist Rule Check
	if s.cfg.Policy != nil {
		if allowed, _ := s.cfg.Policy.MatchAllowlist(pkgName, ""); allowed {
			return false
		}
	}

	// 3. Pre-Flight Vetting Service
	if s.cfg.VettingService == nil {
		return false
	}

	report, err := s.cfg.VettingService.Vet(ctx, eco, pkgName, version)
	if err != nil {
		// If vetting resolution failed due to missing package, allow request to pass through
		// so upstream returns authentic 404
		return false
	}

	// Check author against allowlist
	if s.cfg.Policy != nil && report.Provenance.AuthorName != "" {
		if allowed, _ := s.cfg.Policy.MatchAllowlist(pkgName, report.Provenance.AuthorName); allowed {
			return false
		}
	}

	threshold := s.cfg.Threshold
	if threshold <= 0 {
		threshold = 50
	}

	isBlocked := report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical
	if s.cfg.Strict && (report.TotalScore >= 60 || report.RiskLevel == model.RiskLevelHigh) {
		isBlocked = true
	}

	if isBlocked {
		reasons := make([]string, 0, len(report.Penalties))
		for _, p := range report.Penalties {
			if p.Triggered {
				reasons = append(reasons, fmt.Sprintf("%s: %s", p.RuleID, p.Name))
			}
		}
		if len(reasons) == 0 {
			reasons = append(reasons, fmt.Sprintf("Risk score %d exceeds threshold %d", report.TotalScore, threshold))
		}

		s.blockRequest(w, eco, pkgName, version, report.TotalScore, report.RiskLevel, reasons)
		return true
	}

	return false
}

// blockRequest records metrics and sends structured 403 Forbidden diagnostic payload.
func (s *Server) blockRequest(w http.ResponseWriter, eco model.Ecosystem, pkgName, version string, score int, level model.RiskLevel, reasons []string) {
	atomic.AddInt64(&s.blockedRequests, 1)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	resp := BlockedResponse{
		Error:     "Blocked by Argus",
		Package:   pkgName,
		Ecosystem: eco,
		Version:   version,
		RiskScore: score,
		RiskLevel: level,
		Reasons:   reasons,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// proxyRequest transparently streams the HTTP request to upstream registry.
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, upstreamBase, strippedPath string) {
	targetURL := strings.TrimRight(upstreamBase, "/") + strippedPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to construct upstream request: %v", err), http.StatusBadGateway)
		return
	}

	// Copy incoming headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Strip hop-by-hop headers
	outReq.Header.Del("Connection")
	outReq.Header.Del("Keep-Alive")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Te")
	outReq.Header.Del("Trailers")
	outReq.Header.Del("Transfer-Encoding")
	outReq.Header.Del("Upgrade")

	if u, err := url.Parse(upstreamBase); err == nil {
		outReq.Host = u.Host
	}

	s.mu.RLock()
	transport := s.transport
	s.mu.RUnlock()

	if transport == nil {
		transport = http.DefaultTransport
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream registry connection error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy upstream response headers to client
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	atomic.AddInt64(&s.allowedRequests, 1)

	n, _ := io.Copy(w, resp.Body)
	atomic.AddInt64(&s.bytesProxied, n)
}
