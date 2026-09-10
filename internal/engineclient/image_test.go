package engineclient

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
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

func TestBuildDockerfileRef(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ dockerfile, want string }{
		{filepath.Join(dir, "Dockerfile"), "Dockerfile"},
		{filepath.Join(dir, "docker", "Dockerfile"), "docker/Dockerfile"},
		{"Dockerfile", "Dockerfile"},
		{`docker\Dockerfile`, "docker/Dockerfile"},
	}
	for _, c := range cases {
		got, err := buildDockerfileRef(c.dockerfile, dir)
		if err != nil || got != c.want {
			t.Errorf("buildDockerfileRef(%q, %q) = %q, %v; want %q", c.dockerfile, dir, got, err, c.want)
		}
	}
	if _, err := buildDockerfileRef(filepath.Join(dir, "..", "Dockerfile"), dir); err == nil {
		t.Error("dockerfile outside the build context must error")
	}
}

func TestTarDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tarDir(dir, &buf); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"b.txt": "beta", "sub/": "", "sub/a.txt": "alpha"}
	tr := tar.NewReader(&buf)
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = string(b)
	}
	if len(got) != len(want) {
		t.Fatalf("entries: got %v want %v", got, want)
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("entry %q: got %q want %q", name, got[name], content)
		}
	}
}

func TestTarDirSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink creation not permitted on this host: %v", err)
	}
	var buf bytes.Buffer
	if err := tarDir(dir, &buf); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "link" {
			t.Fatal("symlinks must be skipped, not archived")
		}
	}
}

func TestTarDirExcludesGitAndCavet(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{".git/config", ".cavet/state/findings.json", "sub/.git", "Dockerfile"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := tarDir(dir, &buf); err != nil {
		t.Fatal(err)
	}
	entries := map[string]bool{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[hdr.Name] = true
	}
	if !entries["Dockerfile"] {
		t.Fatalf("regular files must be archived, got %v", entries)
	}
	for name := range entries {
		// A regular file named .git (a linked worktree's gitfile) must be
		// skipped like the .git directory, at any depth.
		if name == ".git" || strings.HasSuffix(name, "/.git") ||
			strings.HasPrefix(name, ".git/") || strings.HasPrefix(name, ".cavet/") {
			t.Fatalf(".git and .cavet must stay out of the build context, got %v", entries)
		}
	}
}

func TestBuildFailure(t *testing.T) {
	failing := `{"stream":"Step 1/2 : FROM scratch\n"}
{"stream":" --- > faken\n"}
{"errorDetail":{"code":1,"message":"COPY failed"},"error":"COPY failed"}
`
	err := buildFailure(strings.NewReader(failing))
	if err == nil || !strings.Contains(err.Error(), "COPY failed") {
		t.Fatalf("build failure must surface the daemon error, got %v", err)
	}
	if err := buildFailure(strings.NewReader(`{"stream":"Successfully built abc\n"}`)); err != nil {
		t.Fatalf("successful build log must not error: %v", err)
	}
	if err := buildFailure(strings.NewReader("not json")); err == nil {
		t.Fatal("malformed build log must error")
	}
}

func TestBuildFailureBuildKitStream(t *testing.T) {
	// Real BuildKit /build shape: aux trace envelopes (protobuf payloads)
	// then a terminal error event; no classic stream text at all.
	buildkit := `{"id":"moby.buildkit.trace","aux":"Cm8K"}
{"id":"moby.buildkit.trace","aux":"Cn0K"}
{"error":"busybox: failed to resolve source metadata","errorDetail":{"message":"busybox: failed to resolve source metadata"}}
`
	err := buildFailure(strings.NewReader(buildkit))
	if err == nil || !strings.Contains(err.Error(), "failed to resolve source metadata") {
		t.Fatalf("BuildKit failure must surface the error field, got %v", err)
	}
	if strings.Contains(err.Error(), "output:") {
		t.Fatalf("BuildKit failure without stream text must not claim output: %v", err)
	}
	// errorDetail-only stream (no top-level error).
	err = buildFailure(strings.NewReader(`{"errorDetail":{"code":1,"message":"process did not complete successfully: exit code: 7"}}` + "\n"))
	if err == nil || !strings.Contains(err.Error(), "exit code: 7") {
		t.Fatalf("errorDetail-only failure must surface, got %v", err)
	}
	// Successful BuildKit build ends with an image id aux frame, no error.
	ok := `{"id":"moby.buildkit.trace","aux":"Cm8K"}
{"id":"moby.image.id","aux":{"ID":"sha256:3a58ad"}}
`
	if err := buildFailure(strings.NewReader(ok)); err != nil {
		t.Fatalf("successful BuildKit build log must not error: %v", err)
	}
}

func TestBuildFailureTailTruncation(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"stream":"HEAD `)
	for i := 0; i < 100; i++ {
		sb.WriteString("xxxxxxxxxx") // 1000 filler chars after HEAD
	}
	sb.WriteString(` TAIL\n"}
{"errorDetail":{"message":"boom"},"error":"boom"}
`)
	err := buildFailure(strings.NewReader(sb.String()))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failure must surface, got %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "HEAD") {
		t.Fatalf("output must carry the tail, not the head: %q", msg)
	}
	if !strings.Contains(msg, "TAIL") {
		t.Fatalf("output tail must be preserved: %q", msg)
	}
	if i := strings.Index(msg, "output: "); i >= 0 && len(msg[i+len("output: "):]) > 300 {
		t.Fatalf("output must be truncated to ~300 chars: %d", len(msg)-i-len("output: "))
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

	if err := c.BuildImage(ctx, dockerfile, ctxDir, tag, ""); err != nil {
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
	if res, err := c.Exec(ctx, []string{"sh", "-c", "test -s "+inContainer}); err != nil || res.Code != 0 {
		t.Fatalf("copied tar must exist non-empty in container: code=%d err=%v stderr=%s", res.Code, err, res.Stderr)
	}

	if err := c.RemoveImage(ctx, tag); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if err := c.RemoveImage(ctx, "cavet-ec-test:missing-"+strconv.FormatInt(time.Now().UnixNano(), 36)); err != nil {
		t.Fatalf("removing a missing image must not error: %v", err)
	}
}
