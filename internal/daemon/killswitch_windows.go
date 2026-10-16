//go:build windows
// +build windows

package daemon

import "os"

func terminatePID(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
