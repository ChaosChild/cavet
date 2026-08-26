package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Lock timing. Vars rather than consts so tests can shorten the contention
// wait; these are the production values of artefacts §7.1.
//
// ponytail: O_EXCL + pid liveness instead of OS-level flock — ~50 lines, zero
// dependencies. Swap for gofrs/flock if stale-takeover misbehaves in practice
// (artefacts §7.1).
var (
	lockWait     = 10 * time.Second
	lockStaleAge = 60 * time.Second
	lockPoll     = 100 * time.Millisecond
)

type lockInfo struct {
	PID int       `json:"pid"`
	TS  time.Time `json:"ts"`
}

// Lock acquires the artefact-directory lock — many readers, one writer, no
// exceptions (artefacts §7.1). The returned function releases it.
func (s *Store) Lock() (func(), error) {
	path := filepath.Join(s.Cavet, "state", "lock")
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			b, werr := json.Marshal(lockInfo{PID: os.Getpid(), TS: time.Now().UTC()})
			if werr == nil {
				_, werr = f.Write(append(b, '\n'))
			}
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				os.Remove(path) // never leave a half-written lock behind
				return nil, werr
			}
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if stale(path) {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			var info lockInfo
			if b, rerr := os.ReadFile(path); rerr == nil {
				_ = json.Unmarshal(b, &info)
			}
			return nil, errStore("another cavet process holds the lock (pid " + strconv.Itoa(info.PID) + ")")
		}
		time.Sleep(lockPoll)
	}
}

// stale reports whether a lock file may be removed: older than lockStaleAge,
// unparseable, or held by a pid that no longer exists (artefacts §7.1).
func stale(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false // vanished underneath us; the create loop retries
	}
	if time.Since(fi.ModTime()) > lockStaleAge {
		return true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var info lockInfo
	if json.Unmarshal(b, &info) != nil {
		return true
	}
	return info.PID != os.Getpid() && !processAlive(info.PID)
}
