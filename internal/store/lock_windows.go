//go:build windows

package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

// processAlive reports whether pid exists. Access-denied means the process
// exists but is protected; it counts as alive so a live holder's lock is
// never stolen.
func processAlive(pid int) bool {
	const synchronize = 0x00100000
	h, err := windows.OpenProcess(synchronize, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	windows.CloseHandle(h)
	return true
}
