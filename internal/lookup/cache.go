// Package lookup answers identifier-only queries against allowlisted
// advisory sources (spec §5.3). The command surface takes identifiers and
// nothing else — that constraint is the no-leak guarantee, structural rather
// than instructional. Five thin adapters, no shared interface: a source that
// breaks is a contained repair.
package lookup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/store"
)

const advisoryTTL = 168 // hours — one week (spec §5.3)

// Cache wraps .cavet/cache/advisories: one JSON file per identifier, atomic
// writes, torn files deleted and refetched (artefacts §11).
type Cache struct{ dir string }

func NewCache(dir string) *Cache { return &Cache{dir: dir} }

type entry struct {
	Identifier string          `json:"identifier"`
	FetchedAt  time.Time       `json:"fetched_at"`
	TTLHours   int             `json:"ttl_hours"`
	Payload    json.RawMessage `json:"payload"`
}

// urlsafe matches artefacts §11's example: ':' and '/' both fold to '~1'
// (pkg:npm/lodash@4 → pkg~1npm~1lodash@4).
func urlsafe(id string) string {
	return strings.NewReplacer(":", "~1", "/", "~1").Replace(id)
}

// Read returns the cached payload and its freshness. Missing and torn files
// both read as absent (torn files are deleted — a torn cache entry is
// disposable by design).
func (c *Cache) Read(id string) (payload []byte, fetchedAt time.Time, fresh bool) {
	b, err := os.ReadFile(filepath.Join(c.dir, urlsafe(id)+".json"))
	if err != nil {
		return nil, time.Time{}, false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil || len(e.Payload) == 0 {
		_ = os.Remove(filepath.Join(c.dir, urlsafe(id)+".json"))
		return nil, time.Time{}, false
	}
	fresh = time.Since(e.FetchedAt) < time.Duration(e.TTLHours)*time.Hour
	return e.Payload, e.FetchedAt, fresh
}

// Write stores a payload with the standard one-week TTL, atomically.
func (c *Cache) Write(id string, payload []byte) error {
	return c.WriteTTL(id, payload, advisoryTTL)
}

// WriteTTL stores with a custom TTL (the KEV feed refreshes daily).
func (c *Cache) WriteTTL(id string, payload []byte, ttlHours int) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	e := entry{Identifier: id, FetchedAt: time.Now().UTC(), TTLHours: ttlHours, Payload: payload}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return store.AtomicWrite(filepath.Join(c.dir, urlsafe(id)+".json"), append(b, '\n'))
}
