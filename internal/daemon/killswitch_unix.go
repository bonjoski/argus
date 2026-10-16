//go:build !windows
// +build !windows

package daemon

import "syscall"

func terminatePID(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
