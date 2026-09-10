package engineclient

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestToContainerPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\scan\image-0.tar`, "C:/scan/image-0.tar"},
		{"/scan/image-0.tar", "/scan/image-0.tar"},
		{`docker\Dockerfile`, "docker/Dockerfile"},
		{`C:\`, "C:/"},
	}
	for _, c := range cases {
		if got := toContainerPath(c.in); got != c.want {
			t.Errorf("toContainerPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildxArgs(t *testing.T) {
	cases := []struct {
		name       string
		dockerfile string
		contextDir string
		tag        string
		target     string
		want       string
	}{
		{
			name:       "no target",
			dockerfile: `/repo/Dockerfile`,
			contextDir: `/repo`,
			tag:        "cavet-scan-x:1",
			want:       "buildx build --load --progress=plain -t cavet-scan-x:1 -f /repo/Dockerfile /repo",
		},
		{
			name:       "with target",
			dockerfile: `/repo/engine/Dockerfile`,
			contextDir: `/repo/engine`,
			tag:        "cavet-scan-x:2",
			target:     "final-core",
			want:       "buildx build --load --progress=plain -t cavet-scan-x:2 -f /repo/engine/Dockerfile --target final-core /repo/engine",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(buildxArgs(c.dockerfile, c.contextDir, c.tag, c.target), " ")
			if got != c.want {
				t.Errorf("buildxArgs = %q, want %q", got, c.want)
			}
		})
	}
}

func TestTailWriter(t *testing.T) {
	var tw tailWriter
	head := strings.Repeat("h", 500)
	if _, err := tw.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("TAIL")); err != nil {
		t.Fatal(err)
	}
	got := tw.String()
	if len(got) > tailLimit {
		t.Fatalf("tail must be capped at %d chars, got %d", tailLimit, len(got))
	}
	if !strings.HasSuffix(got, "TAIL") {
		t.Fatalf("tail must end with the last write: %q", got)
	}
	if len(got) != tailLimit {
		t.Fatalf("tail must keep the last %d chars, got %d", tailLimit, len(got))
	}
	if strings.Count(got, "T") != 1 {
		t.Fatalf("tail must carry the tail, not the head: %q", got[:20])
	}
}

// --- integration: same daemon-unreachable skip pattern as client_test.go ---

func TestImageBuildSaveCopyInRemove(t *testing.T) {
	c := newClient(t)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Network-free by construction: scratch base, one local COPY.
	ctxDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctxDir, "probe.txt"), []byte("probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dockerfile := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY probe.txt /probe.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tag := "cavet-ec-test:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = c.RemoveImage(cctx, tag)
	})

	if err := c.BuildImage(ctx, dockerfile, ctxDir, tag, "", nil); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "nested", "image.tar")
	if err := c.SaveImage(ctx, tag, dest); err != nil {
		t.Fatalf("SaveImage: %v", err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Size() == 0 {
		t.Fatalf("saved tar must exist and be non-empty: %v %v", fi, err)
	}

	// Copy-in runs against a running engine container, as a real scan will.
	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	scanDir := c.NextScanDir()
	if res, err := c.Exec(ctx, []string{"mkdir", "-p", scanDir}); err != nil || res.Code != 0 {
		t.Fatalf("mkdir %s: code=%d err=%v stderr=%s", scanDir, res.Code, err, res.Stderr)
	}
	inContainer := scanDir + "/image.tar"
	if err := c.CopyToContainer(ctx, dest, inContainer); err != nil {
		t.Fatalf("CopyToContainer: %v", err)
	}
	if res, err := c.Exec(ctx, []string{"sh", "-c", "test -s " + inContainer}); err != nil || res.Code != 0 {
		t.Fatalf("copied tar must exist non-empty in container: code=%d err=%v stderr=%s", res.Code, err, res.Stderr)
	}

	if err := c.RemoveImage(ctx, tag); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if err := c.RemoveImage(ctx, "cavet-ec-test:missing-"+strconv.FormatInt(time.Now().UnixNano(), 36)); err != nil {
		t.Fatalf("removing a missing image must not error: %v", err)
	}
}

// A failing build must exit non-zero and surface the output tail, so the
// operator sees why without re-running with output enabled.
func TestImageBuildFailureSurfacesTail(t *testing.T) {
	c := newClient(t)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ctxDir := t.TempDir()
	dockerfile := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY missing.txt /missing.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tag := "cavet-ec-fail:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = c.RemoveImage(cctx, tag)
	})

	err := c.BuildImage(ctx, dockerfile, ctxDir, tag, "", nil)
	if err == nil {
		t.Fatal("a failing build must error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "output:") {
		t.Fatalf("failure must carry the output tail: %v", err)
	}
	if i := strings.Index(msg, "output: "); len(msg[i+8:]) > tailLimit {
		t.Fatalf("output tail must be capped at ~%d chars: %d", tailLimit, len(msg[i+8:]))
	}
	if !strings.Contains(msg, "missing.txt") {
		t.Fatalf("tail must include the failure reason: %v", err)
	}
}
