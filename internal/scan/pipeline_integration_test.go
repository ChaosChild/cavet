package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/store"
)

var _ Runner = (*engineclient.Client)(nil) // engineclient satisfies the seam

// TestRealEngineStagedScan runs the whole pipeline against the real engine
// container: staging via checkout-index, scanner invocation contracts, SARIF
// copy-out, projection, fold, log append. Skipped without a daemon or the dev
// image.
func TestRealEngineStagedScan(t *testing.T) {
	root := t.TempDir()
	seedRepoWithStagedSecret(t, root)

	c := engineclient.New("cavet-engine:dev", "", root)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	t.Cleanup(func() { _ = c.Remove(ctx) })
	if err := c.Ping(ctx); err != nil {
		t.Skipf("docker daemon unreachable: %v", err)
	}
	if err := c.ImagePresent(ctx); err != nil {
		t.Skipf("dev image not built: %v", err)
	}
	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}

	s, err := store.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(ctx, s, c, Options{Scope: ScopeStaged, Engine: "cavet-engine:dev"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.NothingStaged {
		t.Fatal("fixture has staged content")
	}
	var sawSecret bool
	for _, row := range res.Rows {
		if row.Rule == "generic-api-key" && row.Sev == "high" && row.Path == "staged_secret.py" {
			sawSecret = true
		}
	}
	if !sawSecret {
		t.Fatalf("staged secret must surface, rows: %+v", res.Rows)
	}
	for _, row := range res.Rows {
		if strings.HasPrefix(row.Path, "/") || strings.Contains(row.Path, `\`) {
			t.Fatalf("rows must be repo-relative: %+v", row)
		}
	}
}

// seedRepoWithStagedSecret builds a committed repo plus one staged file
// carrying the fixture's planted key: the staged index is exactly what the
// scan must describe.
func seedRepoWithStagedSecret(t *testing.T, root string) {
	t.Helper()
	src := filepath.Join("..", "finding", "testdata", "fixture")
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"add", "-A"},
		{"-c", "user.email=cavet@test", "-c", "user.name=cavet", "commit", "--quiet", "-m", "seed"},
	} {
		if out, err := gitRun(root, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	b, err := os.ReadFile(filepath.Join(src, "config.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "staged_secret.py"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := gitRun(root, "add", "staged_secret.py"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
}

func gitRun(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
