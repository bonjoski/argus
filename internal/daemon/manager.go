package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultPaths returns the standard socket path, pid path, and log path for the daemon.
func DefaultPaths() (socketPath, pidPath, logPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	baseDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", "", "", fmt.Errorf("failed to create argus directory: %w", err)
	}

	socketPath = filepath.Join(baseDir, "argus.sock")
	pidPath = filepath.Join(baseDir, "argus.pid")
	logPath = filepath.Join(baseDir, "daemon.log")
	return socketPath, pidPath, logPath, nil
}

// StartBackgroundDaemon spawns the daemon in background and waits for it to become ready.
func StartBackgroundDaemon(execPath, socketPath, pidPath, logPath string) error {
	client := NewClient(socketPath)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if client.IsRunning(ctx) {
		return errors.New("daemon is already running")
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
		return fmt.Errorf("failed to open daemon log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.Command(execPath, "daemon", "run", "--socket", socketPath, "--pid-file", pidPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background daemon process: %w", err)
	}

	// Poll client ping for up to 3 seconds until ready
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		if client.Ping(checkCtx) == nil {
			checkCancel()
			return nil
		}
		checkCancel()
	}

	return fmt.Errorf("daemon failed to start within timeout (check logs at %s)", logPath)
}

// StopDaemon requests daemon shutdown or terminates the process if unresponsive.
func StopDaemon(socketPath, pidPath string) error {
	client := NewClient(socketPath)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Try graceful IPC shutdown
	if err := client.Shutdown(ctx); err == nil {
		// Wait for socket to disappear
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(socketPath); os.IsNotExist(err) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Fallback to PID termination if PID file exists
	if pidPath != "" {
		if pidBytes, err := os.ReadFile(pidPath); err == nil {
			pidStr := strings.TrimSpace(string(pidBytes))
			if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
				proc, err := os.FindProcess(pid)
				if err == nil {
					_ = proc.Signal(syscall.SIGTERM)
					time.Sleep(200 * time.Millisecond)
					_ = proc.Kill()
				}
			}
		}
		if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
			// Best-effort cleanup
		}
	}

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		// Best-effort cleanup
	}
	return nil
}
