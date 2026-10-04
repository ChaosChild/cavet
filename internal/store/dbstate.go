package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DBState is state/db.json: advisory database refresh bookkeeping written by
// `cavet engine update-db` and read by version/status surfaces (PR B scans
// join later). Absent file means the baked era: every artifact is whatever
// the engine image shipped.
type DBState struct {
	Artifacts map[string]DBArtifact `json:"artifacts"`
}

// DBArtifact is one refreshed advisory database. Source is "managed" after a
// successful swap (may be absent in hand-written state).
type DBArtifact struct {
	Digest    string    `json:"digest"`
	UpdatedAt time.Time `json:"updatedAt"`
	SwappedAt time.Time `json:"swappedAt"`
	Source    string    `json:"source,omitempty"`
}

// LoadDBState reads state/db.json. A missing file yields empty state; a
// corrupt one fails loud like the other derived state files (load.go).
func (s *Store) LoadDBState() (DBState, error) {
	var st DBState
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "db.json"))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return DBState{}, fmt.Errorf("state/db.json: %w", err)
	}
	return st, nil
}

// WriteDBState persists DBState atomically under .cavet/state/db.json. The
// caller holds the store lock (artefacts §7.1), as for all state writes.
func (s *Store) WriteDBState(st DBState) error {
	if st.Artifacts == nil {
		st.Artifacts = map[string]DBArtifact{}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(s.Cavet, "state", "db.json"), append(b, '\n'))
}
