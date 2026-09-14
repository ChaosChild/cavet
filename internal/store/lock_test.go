package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

func fastLock(t *testing.T) {
	t.Helper()
	oldWait, oldPoll := lockWait, lockPoll
	lockWait, lockPoll = 200*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { lockWait, lockPoll = oldWait, oldPoll })
}

func TestLockExclusiveAndRelease(t *testing.T) {
	fastLock(t)
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil {
		t.Fatal("second lock must contend while the first is held")
	}
	rel()
	rel2, err := s.Lock()
	if err != nil {
		t.Fatalf("release must free the lock: %v", err)
	}
	rel2()
}

func TestLockStaleTakeover(t *testing.T) {
	fastLock(t)
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, ".cavet", "state", "lock")
	if err := os.WriteFile(lockPath, []byte(`{"pid":999999999,"ts":"2020-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	rel, err := s.Lock()
	if err != nil {
		t.Fatalf("stale lock must be taken over: %v", err)
	}
	rel()
}

func TestLockDeadHolderTakenOverBeforeStaleAge(t *testing.T) {
	fastLock(t)
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, ".cavet", "state", "lock")
	// Fresh mtime, but the holder pid does not exist.
	if err := os.WriteFile(lockPath, []byte(`{"pid":999999999,"ts":"2020-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := s.Lock()
	if err != nil {
		t.Fatalf("dead holder must allow takeover: %v", err)
	}
	rel()
}

// TestFreshCloneWritesWithoutInit pins the dogfood fix (2026-09-14): a
// repository that tracks .cavet/ cloned fresh has config.yaml and maybe log/
// but none of the gitignored dirs, and the advisory pre-commit hook must not
// block on that. Open (not Init) is the fresh-clone entrypoint; every store
// write creates its own directory on demand.
func TestFreshCloneWritesWithoutInit(t *testing.T) {
	fastLock(t)
	root := t.TempDir()
	c := filepath.Join(root, ".cavet")
	if err := os.MkdirAll(c, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c, "config.yaml"), []byte("engine:\n  variant: core\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root) // Init would create the dirs; the clone path is Open
	if err != nil {
		t.Fatal(err)
	}
	rel, err := s.Lock() // used to fail: open .cavet/state/lock with no dir
	if err != nil {
		t.Fatalf("lock must create the missing state dir: %v", err)
	}
	rel()
	ev, err := events.NewRaised(time.Now().UTC(), events.ActorOperator, events.PhaseDesign,
		testEngine, events.RaisedData{Kind: events.ItemDesign, Question: "q?"})
	if err != nil {
		t.Fatal(err)
	}
	// A clone whose log is not tracked has no log/ dir either.
	if err := s.Append(ev); err != nil {
		t.Fatalf("append must create the missing log dir: %v", err)
	}
	if err := AtomicWrite(filepath.Join(c, "reports", "latest.sarif"), []byte("{}")); err != nil {
		t.Fatalf("atomic write must create the missing reports dir: %v", err)
	}
}
