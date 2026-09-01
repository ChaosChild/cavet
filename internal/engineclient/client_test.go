package engineclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
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

// makeWorktree builds the linked-worktree layout on disk the way host git
// does: main checkout with a real .git, plus a worktree whose .git is a
// gitfile pointing at the main .git's worktrees area. Returns the worktree
// root and the main .git host path.
func makeWorktree(t *testing.T) (wtRoot, mainGit string) {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "main")
	mainGit = filepath.Join(main, ".git")
	if err := os.MkdirAll(filepath.Join(mainGit, "worktrees", "wt"), 0o755); err != nil {
		t.Fatal(err)
	}
	wtRoot = filepath.Join(dir, "wt")
	if err := os.MkdirAll(wtRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// git writes forward slashes in the gitfile on every host.
	gitdir := filepath.ToSlash(filepath.Join(mainGit, "worktrees", "wt"))
	if err := os.WriteFile(filepath.Join(wtRoot, ".git"), []byte("gitdir: "+gitdir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return wtRoot, mainGit
}

func TestResolveGitMetaWorktree(t *testing.T) {
	wtRoot, mainGit := makeWorktree(t)
	m, ok := resolveGitMeta(wtRoot)
	if !ok {
		t.Fatal("worktree must resolve")
	}
	if m.hostDir != mainGit {
		t.Fatalf("hostDir: got %q want %q", m.hostDir, mainGit)
	}
	wantEnv := map[string]string{
		"GIT_DIR":            "/gitmeta/worktrees/wt",
		"GIT_WORK_TREE":      "/workspace",
		"GIT_CONFIG_COUNT":   "1",
		"GIT_CONFIG_KEY_0":   "safe.directory",
		"GIT_CONFIG_VALUE_0": "/gitmeta",
	}
	got := map[string]string{}
	for _, e := range m.env {
		k, v, _ := strings.Cut(e, "=")
		got[k] = v
	}
	if len(got) != len(wantEnv) {
		t.Fatalf("env: got %v want %v", got, wantEnv)
	}
	for k, w := range wantEnv {
		if got[k] != w {
			t.Fatalf("env %s: got %q want %q", k, got[k], w)
		}
	}
}

func TestResolveGitMetaNonWorktree(t *testing.T) {
	dir := t.TempDir()
	if _, ok := resolveGitMeta(dir); ok { // no .git at all
		t.Fatal("missing .git must not resolve")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolveGitMeta(dir); ok { // normal repo: .git is a directory
		t.Fatal("normal repository must not resolve as worktree")
	}
}

func TestResolveGitMetaMalformedGitfile(t *testing.T) {
	for name, content := range map[string]string{
		"no prefix":  "C:/main/.git/worktrees/wt\n",
		"relative":   "gitdir: ../main/.git/worktrees/wt\n",
		"empty path": "gitdir: \n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok := resolveGitMeta(dir); ok {
			t.Fatalf("%s gitfile must not resolve: %q", name, content)
		}
	}
}

func TestMountsStaleAndBindDest(t *testing.T) {
	cases := []struct {
		bind, dest string
	}{
		{"/srv/repo:/workspace", "/workspace"},
		{"/srv/repo:/gitmeta:ro", "/gitmeta"},
		{"C:/srv/repo:/workspace", "/workspace"},
		{"C:/srv/repo/.git:/gitmeta:ro", "/gitmeta"},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := bindDest(c.bind); got != c.dest {
			t.Errorf("bindDest(%q) = %q want %q", c.bind, got, c.dest)
		}
	}
	stale := []struct {
		wantGitMeta bool
		binds       []string
		stale       bool
	}{
		{true, nil, true}, // worktree, pre-fix container: no /gitmeta
		{true, []string{"C:/r:/workspace"}, true},
		{true, []string{"C:/r:/workspace", "C:/r/.git:/gitmeta:ro"}, false},
		{false, []string{"C:/r:/workspace"}, false}, // normal repo, as created today
		{false, []string{"/r:/workspace", "/r/.git:/gitmeta:ro"}, true},
	}
	for _, c := range stale {
		if got := mountsStale(c.wantGitMeta, c.binds); got != c.stale {
			t.Errorf("mountsStale(%v, %v) = %v want %v", c.wantGitMeta, c.binds, got, c.stale)
		}
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

// TestWorktreeContainerMountAndRecreate: a linked-worktree root's container
// must carry the /gitmeta bind and resolve the worktree index via exec env;
// a pre-fix container created without the mount must be transparently
// recreated, never silently reused.
func TestWorktreeContainerMountAndRecreate(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main")
	wt := filepath.Join(dir, "wt")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"-c", "user.email=cavet@test", "-c", "user.name=cavet", "commit", "--quiet", "--allow-empty", "-m", "seed"},
		{"worktree", "add", wt, "-b", "wt"},
	} {
		if out, err := wtGit(main, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(wt, "staged.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := wtGit(wt, "add", "staged.txt"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	c := New(devImage, "", wt)
	requireDaemon(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = c.Remove(cctx)
	})

	binds := func() []string {
		t.Helper()
		res, err := c.docker.ContainerInspect(ctx, c.name, client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Container.HostConfig == nil {
			return nil
		}
		return res.Container.HostConfig.Binds
	}
	staged := func() string {
		t.Helper()
		res, err := c.Exec(ctx, []string{"git", "diff", "--cached", "--name-only"})
		if err != nil || res.Code != 0 {
			t.Fatalf("git diff --cached: code=%d err=%v stderr=%s", res.Code, err, res.Stderr)
		}
		return strings.TrimSpace(string(res.Stdout))
	}

	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if mountsStale(true, binds()) {
		t.Fatalf("worktree container must mount /gitmeta: %v", binds())
	}
	if got := staged(); got != "staged.txt" {
		t.Fatalf("worktree index must resolve through /gitmeta, got %q", got)
	}

	// Simulate a pre-fix container: same name, workspace bind only, not even
	// started — EnsureRunning must replace it before anything else.
	if _, err := c.docker.ContainerRemove(ctx, c.name, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	oldHost := &container.HostConfig{
		Binds:       []string{strings.ReplaceAll(wt, "\\", "/") + ":/workspace"},
		NetworkMode: "none",
	}
	if _, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     &container.Config{Image: devImage, Cmd: []string{"sleep", "infinity"}},
		HostConfig: oldHost, Name: c.name,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning must recreate the stale container: %v", err)
	}
	if mountsStale(true, binds()) {
		t.Fatalf("recreated container must mount /gitmeta: %v", binds())
	}
	if got := staged(); got != "staged.txt" {
		t.Fatalf("recreated container must resolve the worktree index, got %q", got)
	}
}

func wtGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
