package engineclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func TestClassifyPrune(t *testing.T) {
	cases := []struct {
		src       string
		exists    bool
		self, all bool
		want      PruneAction
	}{
		{"C:/r", true, true, false, PruneKeptSelf},
		{"C:/r", true, true, true, PruneKeptSelf}, // --all still never touches self
		{"", false, false, false, PruneSkippedNoBind},
		{"", false, false, true, PruneSkippedNoBind}, // ambiguity beats --all
		{"C:/r", true, false, false, PruneKept},
		{"C:/r", false, false, false, PruneRemovedOrphan},
		{"C:/r", false, false, true, PruneRemovedAll},
		{"C:/r", true, false, true, PruneRemovedAll},
	}
	for _, c := range cases {
		if got := classify(c.src, c.exists, c.self, c.all); got != c.want {
			t.Errorf("classify(%q, exists=%v, self=%v, all=%v) = %q want %q",
				c.src, c.exists, c.self, c.all, got, c.want)
		}
	}
}

func TestBindSource(t *testing.T) {
	cases := []struct{ bind, want string }{
		{"C:/repo:/workspace", "C:/repo"},
		{"/srv/repo:/workspace", "/srv/repo"},
		{"C:/repo/.git:/gitmeta:ro", "C:/repo/.git"},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := bindSource(c.bind); got != c.want {
			t.Errorf("bindSource(%q) = %q want %q", c.bind, got, c.want)
		}
	}
}

// TestPruneRemovesOrphanKeepsLive: prune must force-remove the engine
// container whose repository root vanished from the host and keep the one
// whose root still exists. The orphan's container is stopped before its root
// is removed: the running container holds the Windows bind lock.
func TestPruneRemovesOrphanKeepsLive(t *testing.T) {
	goneRoot := filepath.Join(t.TempDir(), "gone")
	if err := os.MkdirAll(goneRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	aliveRoot := t.TempDir()

	orphan := New(devImage, "", goneRoot)
	alive := New(devImage, "", aliveRoot)
	pruner := New(devImage, "", t.TempDir()) // self; container never created
	for _, c := range []*Client{orphan, alive, pruner} {
		t.Cleanup(func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer ccancel()
			_ = c.Remove(cctx)
		})
	}
	requireDaemon(t, orphan)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := orphan.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning orphan: %v", err)
	}
	if err := alive.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning alive: %v", err)
	}
	if _, err := orphan.docker.ContainerStop(ctx, orphan.name, client.ContainerStopOptions{}); err != nil {
		t.Fatalf("stop orphan: %v", err)
	}
	if err := os.RemoveAll(goneRoot); err != nil {
		t.Fatalf("remove orphan root: %v", err)
	}

	entries, err := pruner.Prune(ctx, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	byName := map[string]PruneEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if e := byName[orphan.name]; e.Action != PruneRemovedOrphan {
		t.Fatalf("orphan must be removed: got %+v among %v", e, entries)
	}
	if e := byName[alive.name]; e.Action != PruneKept {
		t.Fatalf("live must be kept: got %+v among %v", e, entries)
	}

	// imageID=="" only on Status's inspect-NotFound path, so this proves the
	// orphan is gone, not merely stopped (see TestRemoveGenuinelyRemoves).
	running, _, imageID, err := orphan.Status(ctx)
	if err != nil || running || imageID != "" {
		t.Fatalf("orphan still present: running=%v imageID=%q err=%v", running, imageID, err)
	}
	running, _, imageID, err = alive.Status(ctx)
	if err != nil || !running || imageID == "" {
		t.Fatalf("live container must survive prune: running=%v imageID=%q err=%v", running, imageID, err)
	}
}
