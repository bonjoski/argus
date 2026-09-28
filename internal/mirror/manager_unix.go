//go:build !windows

package mirror

import "syscall"

func sysProcAttrBackground() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}
