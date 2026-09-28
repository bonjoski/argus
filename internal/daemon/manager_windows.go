//go:build windows

package daemon

import "syscall"

func sysProcAttrBackground() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
