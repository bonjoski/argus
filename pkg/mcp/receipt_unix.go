//go:build !windows

package mcp

import "syscall"

const openNoFollowFlag = syscall.O_NOFOLLOW
