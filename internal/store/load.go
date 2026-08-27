package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LoadState reads the derived state files. Missing findings/items files yield
// empty state (fresh init); a missing baseline is an empty baseline. Corrupt
// files fail loud — derived files, but silently regenerating them would lose
// baseline membership and open items.
func (s *Store) LoadState() (*State, error) {
	st := &State{
		Findings: []*Finding{},
		Items:    []Item{},
	}
	if b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "findings.json")); err == nil {
		var doc struct {
			RebuiltAt time.Time  `json:"rebuilt_at"`
			Findings  []*Finding `json:"findings"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("state/findings.json: %w", err)
		}
		if doc.Findings != nil {
			st.Findings = doc.Findings
		}
		st.RebuiltAt = doc.RebuiltAt
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "items.json")); err == nil {
		var doc struct {
			Items []Item `json:"items"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("state/items.json: %w", err)
		}
		if doc.Items != nil {
			st.Items = doc.Items
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.loadBaseline(st); err != nil {
		return nil, err
	}
	return st, nil
}
