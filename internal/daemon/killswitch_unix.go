//go:build !windows
// +build !windows

package daemon

import (
	"os"
	"syscall"

	"bonjoski/argus/internal/procident"
)

func terminateVerifiedPID(pid int, expectedStartNs int64) bool {
	if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return false
	}

	actualStartNs, err := procident.GetProcessStartTimeNs(pid)
	if err != nil {
		return false
	}
	if expectedStartNs > 0 && actualStartNs > 0 && actualStartNs != expectedStartNs {
		// PID has been recycled to an unrelated process; refuse to signal!
		return false
	}

	// Signal process group ONLY if target PID is an isolated process group leader distinct from daemon's group
	if pgid, pgErr := syscall.Getpgid(pid); pgErr == nil && pgid == pid && pgid != syscall.Getpgrp() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return false
	}
	return true
}
