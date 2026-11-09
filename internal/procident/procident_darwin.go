//go:build darwin

package procident

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const darwinXucredVersion = 0

// VerifyUnixPeerUID verifies via kernel LOCAL_PEERCRED that the peer on a Unix
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
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = fmt.Errorf("GetsockoptXucred failed: %w", err)
			return
		}
		if cred.Version != darwinXucredVersion {
			credErr = fmt.Errorf("unexpected xucred version %d", cred.Version)
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

// GetProcessStartTimeNs queries the Darwin kernel for a process's creation
// timestamp in nanoseconds via SysctlKinfoProc, avoiding subprocess Hop Tax and
// argv[0]/ctime spoofing.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 1 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("sysctl kern.proc.pid for %d failed: %w", pid, err)
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, fmt.Errorf("pid %d not found in kernel process table", pid)
	}
	expectedUID := uint32(os.Geteuid())
	if kp.Eproc.Ucred.Uid != expectedUID && os.Geteuid() != 0 {
		return 0, fmt.Errorf("process %d owned by foreign UID %d", pid, kp.Eproc.Ucred.Uid)
	}
	startNs := kp.Proc.P_starttime.Nano()
	if startNs <= 0 {
		return 0, fmt.Errorf("invalid start time %d for pid %d", startNs, pid)
	}
	return startNs, nil
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
