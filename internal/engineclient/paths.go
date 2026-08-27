package engineclient

import (
	"path/filepath"
	"strings"
)

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
