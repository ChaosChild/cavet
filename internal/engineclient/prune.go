package engineclient

import (
	"context"
	"os"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// workspaceMount is the container-side destination every engine container
// binds its repository root to (cli-spec §10.1).
const workspaceMount = "/workspace"

// PruneAction is prune's decision for one cavet-* container, phrased for the
// report line the CLI prints.
type PruneAction string

const (
	PruneRemovedOrphan PruneAction = "removed as orphan"           // bind source no longer exists on the host
	PruneRemovedAll    PruneAction = "removed (--all)"             // --all, not the calling repository's
	PruneKept          PruneAction = "kept, root exists"           // nothing to do
	PruneKeptSelf      PruneAction = "kept, current repository"    // never touched, --all included
	PruneSkippedNoBind PruneAction = "skipped, no /workspace bind" // conservative on ambiguity
	PruneSkippedStat   PruneAction = "skipped, root stat failed"   // ambiguity is never a removal
)

// PruneEntry is one cavet-* container and what prune decided about it.
type PruneEntry struct {
	Name   string
	Root   string // host path bound at /workspace; "" when there is none
	Action PruneAction
}

// classify is prune's pure decision rule: the calling repository's container
// is never touched; a cavet-* container without a /workspace bind source is
// skipped (conservative on ambiguity); --all removes every other container;
// without it only those whose host root has vanished.
func classify(workspaceSrc string, rootExists, self, all bool) PruneAction {
	switch {
	case self:
		return PruneKeptSelf
	case workspaceSrc == "":
		return PruneSkippedNoBind
	case all:
		return PruneRemovedAll
	case !rootExists:
		return PruneRemovedOrphan
	}
	return PruneKept
}

// bindSource extracts a bind's host-side source from src:dest[:opts], the
// mirror of bindDest ("C:/repo:/workspace" -> "C:/repo").
func bindSource(b string) string {
	dest := bindDest(b)
	if dest == "" {
		return ""
	}
	i := strings.LastIndex(b, ":"+dest)
	if i < 0 {
		return ""
	}
	return b[:i]
}

// Prune classifies every cavet-* container and force-removes the ones the
// classification marks for removal. HostConfig.Binds (not the summary's
// Mounts) is the source of truth: Docker Desktop rewrites mount sources to
// in-VM paths, while Binds keeps the host path as created. Containers outside
// the cavet- prefix are invisible to prune, and the calling repository's own
// container is never touched.
func (c *Client) Prune(ctx context.Context, all bool) ([]PruneEntry, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	res, err := c.docker.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var out []PruneEntry
	for _, s := range res.Items {
		if len(s.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(s.Names[0], "/")
		if !strings.HasPrefix(name, "cavet-") { // list is unfiltered; be exact
			continue
		}
		insp, ierr := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if errdefs.IsNotFound(ierr) {
			continue // removed by a concurrent prune
		}
		if ierr != nil {
			return out, ierr
		}
		e := PruneEntry{Name: name}
		if insp.Container.HostConfig != nil {
			for _, b := range insp.Container.HostConfig.Binds {
				if bindDest(b) == workspaceMount {
					e.Root = bindSource(b)
					break
				}
			}
		}
		var exists bool
		if e.Root != "" {
			if _, serr := os.Stat(e.Root); serr == nil {
				exists = true
			} else if !os.IsNotExist(serr) {
				e.Action = PruneSkippedStat
				out = append(out, e)
				continue
			}
		}
		e.Action = classify(e.Root, exists, name == c.name, all)
		if e.Action == PruneRemovedOrphan || e.Action == PruneRemovedAll {
			if _, err := c.docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true}); err != nil {
				return out, err
			}
		}
		out = append(out, e)
	}
	return out, nil
}
