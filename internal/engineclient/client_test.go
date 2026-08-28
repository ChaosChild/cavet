package engineclient

import (
	"context"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
)

func TestContainerNameDerivation(t *testing.T) {
	name := ContainerName(`C:\repo\alpha`)
	if !regexp.MustCompile(`^cavet-[0-9a-f]{12}$`).MatchString(name) {
		t.Fatalf("bad container name %q", name)
	}
	if name != ContainerName(`C:\repo\alpha`) {
		t.Fatal("name must be stable for the same root")
	}
	if name == ContainerName(`C:\repo\beta`) {
		t.Fatal("different roots must derive different names")
	}
}

func TestPathTranslation(t *testing.T) {
	root := filepath.Join("repo", "cavet")
	if got := HostToContainer(root, filepath.Join(root, "api", "x.py")); got != "/workspace/api/x.py" {
		t.Fatalf("host->container: %q", got)
	}
	if got := HostToContainer(root, filepath.Join("elsewhere", "x.py")); got != "" {
		t.Fatalf("outside mount must map empty, got %q", got)
	}
	if runtime.GOOS == "windows" { // drive-letter root semantics (plan Task 13)
		if got := HostToContainer(`C:\repo`, `C:\repo\api\x.py`); got != "/workspace/api/x.py" {
			t.Fatalf("windows drive host->container: %q", got)
		}
	}
	cases := []struct{ path, target, want string }{
		{"/scan/1/api/x.py", "/scan/1", "api/x.py"},
		{"/workspace/api/users.py", "/workspace", "api/users.py"},
		{"config.py", "", "config.py"},
		{"/opt/x", "", "opt/x"},
	}
	for _, c := range cases {
		if got := RepoRelative(c.path, c.target); got != c.want {
			t.Errorf("RepoRelative(%q, %q) = %q, want %q", c.path, c.target, got, c.want)
		}
	}
}

// --- integration: skipped unless a daemon and the dev image are available ---

const devImage = "cavet-engine:dev"

func newClient(t *testing.T) *Client {
	t.Helper()
	c := New(devImage, "", t.TempDir())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = c.Remove(ctx)
	})
	return c
}

func requireDaemon(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Skipf("docker daemon unreachable: %v", err)
	}
	if err := c.ImagePresent(ctx); err != nil {
		t.Skipf("dev image not built: %v", err)
	}
}

func TestEnsureRunningExecCopyOut(t *testing.T) {
	c := newClient(t)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if err := c.EnsureRunning(ctx); err != nil { // idempotent
		t.Fatalf("EnsureRunning second call: %v", err)
	}

	res, err := c.Exec(ctx, []string{"cavet-healthcheck"})
	if err != nil || res.Code != 0 {
		t.Fatalf("healthcheck exec: code=%d err=%v stderr=%s", res.Code, err, res.Stderr)
	}

	res, err = c.Exec(ctx, []string{"sh", "-c", "echo hello; echo bad >&2"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 0 || strings.TrimSpace(string(res.Stdout)) != "hello" {
		t.Fatalf("stdout capture wrong: %+v", res)
	}
	if strings.TrimSpace(string(res.Stderr)) != "bad" {
		t.Fatalf("stderr capture wrong: %+v", res)
	}

	if d1, d2 := c.NextScanDir(), c.NextScanDir(); !strings.HasPrefix(d1, "/scan/") || !strings.HasPrefix(d2, "/scan/") || d1 == d2 {
		t.Fatalf("scan dirs must be distinct /scan/* paths: %q %q", d1, d2)
	}

	if _, err := c.Exec(ctx, []string{"sh", "-c", "printf sarif > /reports/x.sarif"}); err != nil {
		t.Fatal(err)
	}
	b, err := c.CopyOut(ctx, "/reports/x.sarif")
	if err != nil || string(b) != "sarif" {
		t.Fatalf("CopyOut: %q %v", b, err)
	}
}

func TestRemoveGenuinelyRemoves(t *testing.T) {
	c := newClient(t)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// imageID=="" only on Status's inspect-NotFound path, so this proves the
	// container is gone, not merely stopped (regression: Remove used to no-op
	// on a nil docker connection and "stop" left the container running).
	running, _, imageID, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status after Remove: %v", err)
	}
	if running || imageID != "" {
		t.Fatalf("container still present after Remove: running=%v imageID=%q", running, imageID)
	}

	// docker SDK: DELETE ?force=1 still 404s an absent container; force only
	// kills a running one first. Idempotency is the caller's job (EnsureRunning
	// treats NotFound as create).
	if err := c.Remove(ctx); !errdefs.IsNotFound(err) {
		t.Fatalf("Remove on absent container: want NotFound, got %v", err)
	}
}

func TestDigestDriftIsHardStop(t *testing.T) {
	c := newClient(t)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}

	drifted := New(devImage, "sha256:0000000000000000000000000000000000000000000000000000000000000000", c.root)
	err := drifted.EnsureRunning(ctx)
	if err == nil {
		t.Fatal("digest drift must hard-stop")
	}
	// Either actionable outcome is correct: a pin that resolves locally but
	// differs says "rebaseline"; one that is not local at all says "engine pull".
	msg := err.Error()
	if !strings.Contains(msg, "rebaseline") && !strings.Contains(msg, "engine pull") {
		t.Fatalf("hard stop must carry an actionable instruction, got %v", err)
	}
}
