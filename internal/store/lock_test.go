package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
