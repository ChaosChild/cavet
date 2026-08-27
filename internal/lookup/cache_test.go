package lookup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheRoundTrip(t *testing.T) {
	c := NewCache(t.TempDir())
	if p, _, fresh := c.Read("osv:GHSA-x"); p != nil || fresh {
		t.Fatal("absent entry must read as missing")
	}
	if err := c.Write("osv:GHSA-x", []byte(`{"id":"GHSA-x"}`)); err != nil {
		t.Fatal(err)
	}
	p, at, fresh := c.Read("osv:GHSA-x")
	if !fresh || string(p) != `{"id":"GHSA-x"}` || at.IsZero() {
		t.Fatalf("round trip failed: %q %v %v", p, at, fresh)
	}
	// wrapper shape per artefacts §11
	b, _ := os.ReadFile(filepath.Join(c.dir, "osv~1GHSA-x.json"))
	var e entry
	if json.Unmarshal(b, &e) != nil || e.TTLHours != 168 || e.Identifier != "osv:GHSA-x" {
		t.Fatalf("wrapper shape wrong: %s", b)
	}
}

func TestCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	if err := c.WriteTTL("epss:CVE-1", []byte(`{}`), 1); err != nil {
		t.Fatal(err)
	}
	// Age the file past its TTL by rewriting fetched_at.
	p := filepath.Join(dir, "epss~1CVE-1.json")
	var e entry
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &e)
	e.FetchedAt = time.Now().Add(-2 * time.Hour)
	b2, _ := json.Marshal(e)
	os.WriteFile(p, b2, 0o644)
	if _, _, fresh := c.Read("epss:CVE-1"); fresh {
		t.Fatal("expired entry must read stale")
	}
	// Stale payload is still served (the caller decides offline-vs-refetch).
	if payload, _, _ := c.Read("epss:CVE-1"); payload == nil {
		t.Fatal("stale payload must remain readable")
	}
}

func TestCacheTornFileDiscarded(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	p := filepath.Join(dir, "osv~1torn.json")
	os.WriteFile(p, []byte("{not json"), 0o644)
	if payload, _, _ := c.Read("osv:torn"); payload != nil {
		t.Fatal("torn file must read as missing")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("torn file must be deleted")
	}
}
