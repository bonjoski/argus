//go:build !darwin && !linux

package procident

import (
	"fmt"
	"net"
	"os"
)

// VerifyUnixPeerUID validates non-nil connection on platforms without Unix socket peer cred support.
func VerifyUnixPeerUID(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}
	return nil
}

// GetProcessStartTimeNs returns a sentinel timestamp on non-Unix platforms.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 1 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	if _, err := os.FindProcess(pid); err != nil {
		return 0, fmt.Errorf("process %d lookup failed: %w", pid, err)
	}
	return 1, nil
}

// VerifyFileOwnerAndNotSymlink checks via Lstat that path is not a symlink.
func VerifyFileOwnerAndNotSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink at %s", path)
	}
	return nil
}
