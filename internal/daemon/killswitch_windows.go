//go:build windows
// +build windows

package daemon

import (
	"os"

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
		return false
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := p.Kill(); err != nil {
		return false
	}
	return true
}
