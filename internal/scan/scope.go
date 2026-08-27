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
)

func (s Scope) String() string {
	switch s {
	case ScopeStaged:
		return "staged"
	case ScopeDiff:
		return "diff"
	case ScopeFull:
		return "full"
	}
	return "unknown"
}

// TierScanners implements the scope→scanner table (cli-spec §6): the fast
// tier is gitleaks+trivy; --full and --deep add opengrep. There is no --fast
// and no --no-deep — --full already asks for everything (spec §5.2).
func TierScanners(scope Scope, deep bool) []string {
	if scope == ScopeFull || deep {
		return []string{"gitleaks", "trivy", "opengrep"}
	}
	return []string{"gitleaks", "trivy"}
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

// stagedPaths lists the index content. All git runs inside the container —
// the host needs no git (cli-spec §6).
func stagedPaths(ctx context.Context, r Runner) ([]string, error) {
	res, err := r.Exec(ctx, []string{"sh", "-c", "git diff --cached --name-only -z"})
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
		"mkdir -p %[1]s && git diff --cached --name-only -z | git checkout-index -z --prefix=%[1]s/ --stdin",
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
// scan dir; deleted files cannot contain findings and are skipped silently
// (cli-spec §6).
func stageWorktree(ctx context.Context, r Runner, ref, scanDir string) error {
	cmd := fmt.Sprintf(
		`cd /workspace && git diff --name-only -z %[1]s | while IFS= read -r -d '' f; do if [ -f "$f" ]; then mkdir -p %[2]s/$(dirname "$f"); cp "$f" %[2]s/$f; fi; done`,
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
