package mirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultMirrorPaths returns standard pid, log, and state paths for the mirror proxy.
func DefaultMirrorPaths() (pidPath, logPath, statePath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	baseDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", "", "", fmt.Errorf("failed to create argus directory: %w", err)
	}

	pidPath = filepath.Join(baseDir, "mirror.pid")
	logPath = filepath.Join(baseDir, "mirror.log")
	statePath = filepath.Join(baseDir, "mirror.json")
	return pidPath, logPath, statePath, nil
}

// StartBackgroundMirror spawns the mirror proxy server in the background and waits for it to become healthy.
func StartBackgroundMirror(execPath string, port int, upstreamNPM, upstreamPyPI string, threshold int, strict bool, pidPath, logPath string) error {
	if port <= 0 {
		port = 8080
	}

	// Check if already running on port
	if stats, err := GetMirrorStatus(pidPath, port); err == nil && stats != nil && stats.Running {
		return errors.New("mirror proxy is already running")
	}

	if execPath == "" {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed to determine executable path: %w", err)
		}
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open mirror log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	args := []string{
		"mirror", "run",
		"--port", strconv.Itoa(port),
		"--pid-file", pidPath,
	}
	if upstreamNPM != "" {
		args = append(args, "--upstream-npm", upstreamNPM)
	}
	if upstreamPyPI != "" {
		args = append(args, "--upstream-pypi", upstreamPyPI)
	}
	if threshold > 0 {
		args = append(args, "--threshold", strconv.Itoa(threshold))
	}
	if strict {
		args = append(args, "--strict")
	}

	cmd := exec.Command(execPath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = sysProcAttrBackground()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background mirror process: %w", err)
	}

	// Poll health endpoint for up to 3 seconds until ready
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/_argus/health", port)
	client := &http.Client{Timeout: 200 * time.Millisecond}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		req, _ := http.NewRequestWithContext(context.Background(), "GET", healthURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}

	return fmt.Errorf("mirror proxy failed to start within timeout (check logs at %s)", logPath)
}

// StopMirror shuts down the mirror proxy process gracefully or terminates it.
func StopMirror(pidPath string, port int) error {
	var pid int
	if pidPath != "" {
		if pidBytes, err := os.ReadFile(pidPath); err == nil {
			pidStr := strings.TrimSpace(string(pidBytes))
			if parsedPID, err := strconv.Atoi(pidStr); err == nil && parsedPID > 0 {
				pid = parsedPID
			}
		}
	}

	if pid > 0 {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(syscall.SIGTERM)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if err := proc.Signal(syscall.Signal(0)); err != nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			// Force kill if still alive
			_ = proc.Kill()
		}
	}

	if pidPath != "" {
		if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
			// Best-effort cleanup
		}
	}

	_, _, statePath, err := DefaultMirrorPaths()
	if err == nil {
		if rmErr := os.Remove(statePath); rmErr != nil && !os.IsNotExist(rmErr) {
			// Best-effort cleanup
		}
	}

	return nil
}

// GetMirrorStatus queries the status of the mirror proxy server.
func GetMirrorStatus(pidPath string, port int) (*ServerStats, error) {
	if port <= 0 {
		port = 8080
	}

	statusURL := fmt.Sprintf("http://127.0.0.1:%d/_argus/status", port)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	req, err := http.NewRequestWithContext(context.Background(), "GET", statusURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mirror proxy is not reachable on port %d: %w", port, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mirror proxy returned HTTP %d", resp.StatusCode)
	}

	var stats ServerStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode mirror stats: %w", err)
	}

	return &stats, nil
}
