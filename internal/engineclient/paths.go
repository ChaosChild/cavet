package engineclient

import (
	"os"
	"path/filepath"
	"strings"
)

// gitMetaMount is where a linked worktree's main checkout .git is bind-mounted
// inside the engine container (read-only — staging only reads the index and
// objects; checkout-index writes to /scan, never to the git dir).
const gitMetaMount = "/gitmeta"

// gitMeta captures the linked-worktree layout: root/.git is a gitfile pointing
// at the main checkout's .git/worktrees/<name>, a host-absolute path the
// /workspace mount cannot reach, so in-container git cannot resolve the index.
// The main .git dir is mounted at /gitmeta and every exec carries git env
// pointing into that mount. Behavioural deviation from cli-spec §10's single
// mount, recorded in the fix PR ("staged scans from git worktrees").
type gitMeta struct {
	hostDir string   // main checkout's .git dir (host path)
	env     []string // exec env redirecting git into the /gitmeta mount
}

// resolveGitMeta parses the worktree gitfile on the host — host git is never
// invoked (cli-spec §6). ok is false for normal repositories (.git is a
// directory), a missing .git, and malformed gitfiles.
func resolveGitMeta(root string) (gitMeta, bool) {
	b, err := os.ReadFile(filepath.Join(root, ".git"))
	if err != nil {
		return gitMeta{}, false // normal repo (.git dir) or no repo
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "gitdir:") {
		return gitMeta{}, false
	}
	dir := filepath.Clean(strings.TrimSpace(strings.TrimPrefix(s, "gitdir:")))
	if !filepath.IsAbs(dir) {
		return gitMeta{}, false
	}
	// dir is <main>/.git/worktrees/<name>; its grandparent is the whole .git.
	mainGit := filepath.Dir(filepath.Dir(dir))
	if fi, err := os.Stat(mainGit); err != nil || !fi.IsDir() {
		// Stale gitfile (moved/removed main checkout): mounting a dead host
		// path would fail container create and break even --full, which never
		// touches git. Degrade to plain /workspace behaviour instead.
		return gitMeta{}, false
	}
	rel, err := filepath.Rel(mainGit, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return gitMeta{}, false
	}
	gitDir := gitMetaMount + "/" + filepath.ToSlash(rel)
	return gitMeta{
		hostDir: mainGit,
		env: []string{
			"GIT_DIR=" + gitDir,
			"GIT_WORK_TREE=/workspace",
			// The image entrypoint marks /workspace safe for git; /gitmeta
			// needs the same protection, via protected-config env (git ≥2.36)
			// so the engine digest stays unchanged.
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=safe.directory",
			"GIT_CONFIG_VALUE_0=" + gitMetaMount,
		},
	}, true
}

// mountsStale reports whether an existing container's binds disagree with the
// mounts this client requires: /gitmeta must be bound for worktrees and absent
// otherwise. The bind list is per-container-create, so a mismatch means the
// container must be recreated.
func mountsStale(wantGitMeta bool, binds []string) bool {
	for _, b := range binds {
		if bindDest(b) == gitMetaMount {
			return !wantGitMeta
		}
	}
	return wantGitMeta
}

// bindDest extracts a bind's container-side destination from src:dest[:opts].
// Destinations start with "/", which is what separates them from options even
// when the source is a Windows drive-letter path.
func bindDest(b string) string {
	parts := strings.Split(b, ":")
	n := len(parts)
	if n >= 2 && strings.HasPrefix(parts[n-1], "/") {
		return parts[n-1]
	}
	if n >= 3 && strings.HasPrefix(parts[n-2], "/") {
		return parts[n-2]
	}
	return ""
}

// HostToContainer maps a host path under the repository root into the
// container mount. Paths outside the mount map to "".
func HostToContainer(root, hostPath string) string {
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return "/workspace/" + filepath.ToSlash(rel)
}

// ContainerToHost maps a /workspace-relative container path back to the host.
func ContainerToHost(root, containerPath string) string {
	rel := strings.TrimPrefix(containerPath, "/workspace/")
	return filepath.Join(root, filepath.FromSlash(rel))
}

// RepoRelative strips a scan target prefix (/workspace or /scan/<n>) from a
// container path, yielding a repository-relative slash path. Already-relative
// paths pass through with any leading slash trimmed.
func RepoRelative(containerPath, target string) string {
	if target != "" && strings.HasPrefix(containerPath, target+"/") {
		return containerPath[len(target)+1:]
	}
	return strings.TrimPrefix(containerPath, "/")
}
