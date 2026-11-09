//go:build linux

package procident

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// VerifyUnixPeerUID verifies via kernel SO_PEERCRED that the peer on a Unix
// domain socket matches the current effective user ID.
func VerifyUnixPeerUID(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to obtain raw conn for peer cred check: %w", err)
	}

	var peerUID uint32
	var credErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = fmt.Errorf("GetsockoptUcred failed: %w", err)
			return
		}
		peerUID = cred.Uid
	})
	if ctrlErr != nil {
		return fmt.Errorf("rawConn.Control failed: %w", ctrlErr)
	}
	if credErr != nil {
		return credErr
	}

	expectedUID := uint32(os.Geteuid())
	if peerUID != expectedUID {
		return fmt.Errorf("unauthorized peer UID %d (expected %d)", peerUID, expectedUID)
	}
	return nil
}

// GetProcessStartTimeNs reads /proc/<pid>/stat field 22 (starttime clock ticks)
// and verifies process ownership via Lstat on /proc/<pid>.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 1 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	procDir := fmt.Sprintf("/proc/%d", pid)
	fi, err := os.Lstat(procDir)
	if err != nil {
		return 0, fmt.Errorf("stat %s failed: %w", procDir, err)
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Geteuid()) && os.Geteuid() != 0 {
			return 0, fmt.Errorf("process %d owned by foreign UID %d", pid, stat.Uid)
		}
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/stat failed: %w", pid, err)
	}
	raw := string(data)
	closeParen := strings.LastIndexByte(raw, ')')
	if closeParen == -1 || closeParen+2 >= len(raw) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(raw[closeParen+2:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("insufficient fields in /proc/%d/stat", pid)
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || ticks <= 0 {
		return 0, fmt.Errorf("invalid starttime ticks in /proc/%d/stat: %w", pid, err)
	}
	return ticks, nil
}

// VerifyFileOwnerAndNotSymlink checks via Lstat that path is not a symlink and is owned by current UID.
func VerifyFileOwnerAndNotSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink at %s", path)
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Geteuid()) && os.Geteuid() != 0 {
			return fmt.Errorf("path %s owned by foreign UID %d", path, stat.Uid)
		}
	}
	return nil
}
