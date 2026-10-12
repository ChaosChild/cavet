package scan

import (
	"context"
	"fmt"
	"strings"
)

type Scope int

const (
	ScopeStaged Scope = iota
	ScopeDiff
	ScopeFull
	ScopeImage
)

func (s Scope) String() string {
	switch s {
	case ScopeStaged:
		return "staged"
	case ScopeDiff:
		return "diff"
	case ScopeFull:
		return "full"
	case ScopeImage:
		return "image"
	}
	return "unknown"
}

// TierScanners implements the scope→scanner table (cli-spec §6): the fast
// tier is gitleaks+trivy; --full and --deep add opengrep. checkov joins the
// filesystem tier only where the repository opts in (scanners.checkov), on
// every scope it applies to, so coverage claims stay honest (spec §5.2).
// There is no --fast and no --no-deep – --full already asks for everything.
// The image scope has no filesystem tier: its only scanner, trivy-image, is
// run by the image phase itself.
func TierScanners(scope Scope, deep, checkov bool) []string {
	if scope == ScopeImage {
		return nil
	}
	scanners := []string{"gitleaks", "trivy"}
	if checkov {
		scanners = append(scanners, "checkov")
	}
	if scope == ScopeFull || deep {
		scanners = append(scanners, "opengrep")
	}
	return scanners
}

func splitNUL(b []byte) []string {
	var out []string
	for _, p := range strings.Split(string(b), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// stagedPaths lists the index content, deletions excluded: a deleted path is
// not in the index and cannot be staged for scanning. All git runs inside the
// container — the host needs no git (cli-spec §6).
func stagedPaths(ctx context.Context, r Runner) ([]string, error) {
	res, err := r.Exec(ctx, []string{"sh", "-c", "git diff --cached --name-only --diff-filter=ACMRT -z"})
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("git diff --cached: %s", res.Stderr)
	}
	return splitNUL(res.Stdout), nil
}

// checkoutIndex stages exact index blobs so the scan describes what will be
// committed, not the working tree (spec §5.2). Pipeline form: no path list
// crosses the shell, so there is no quoting hazard.
func checkoutIndex(ctx context.Context, r Runner, scanDir string) error {
	cmd := fmt.Sprintf(
		"mkdir -p %[1]s && git diff --cached --name-only --diff-filter=ACMRT -z | git checkout-index -z --prefix=%[1]s/ --stdin",
		scanDir)
	res, err := r.Exec(ctx, []string{"sh", "-c", cmd})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("git checkout-index: %s", res.Stderr)
	}
	return nil
}

func diffPaths(ctx context.Context, r Runner, ref string) ([]string, error) {
	res, err := r.Exec(ctx, []string{"sh", "-c", "git diff --name-only -z "+shQuote(ref)})
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("git diff %s: %s", ref, res.Stderr)
	}
	return splitNUL(res.Stdout), nil
}

// stageWorktree copies current worktree content of changed files into the
// scan dir; deleted files cannot contain findings and are excluded by the
// diff filter (cli-spec §6). The consumer must stay POSIX sh: the engine's
// /bin/sh is dash, where the 0.2.0 read -d '' loop was an illegal option,
// staged nothing, and still exited 0. xargs -0 eats git's NUL-separated
// paths without re-parsing filenames, cp --parents preserves the tree, and
// mkdir -p upfront keeps an empty diff a valid empty target for trivy.
// The pipeline's exit status is xargs's (dash has no pipefail), so a failed
// git diff would mask here; Run execs diffPaths on the same ref first and
// errors loudly, which is the guard.
func stageWorktree(ctx context.Context, r Runner, ref, scanDir string) error {
	cmd := fmt.Sprintf(
		`mkdir -p %[2]s && cd /workspace && git diff --name-only -z --diff-filter=ACMRT %[1]s | xargs -0 -r -I{} cp --parents -- {} %[2]s/`,
		shQuote(ref), scanDir)
	res, err := r.Exec(ctx, []string{"sh", "-c", cmd})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("staging diff content: %s", res.Stderr)
	}
	return nil
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
