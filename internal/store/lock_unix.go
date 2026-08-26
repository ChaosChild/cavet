//go:build !windows

package store

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid exists. EPERM means the process exists but
// belongs to another user; it counts as alive so a live holder's lock is
// never stolen.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
