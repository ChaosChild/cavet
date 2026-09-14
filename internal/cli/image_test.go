package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/store"
)

// initImageRepo scaffolds a temp .cavet with the given config body and chdirs
// into the root, the way the installed CLI would see it.
func initImageRepo(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if _, err := store.Init(root); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		if err := os.WriteFile(filepath.Join(root, ".cavet", "config.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	return root
}

func imageConfig(t *testing.T, root string) config.ContainerImages {
	t.Helper()
	cfg, err := config.Load(filepath.Join(root, ".cavet", "config.yaml"))
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	return cfg.Scan.ContainerImages
}

// touchFile creates test Dockerfiles; relative paths land under the cwd,
// which the image tests keep at the scaffolded repo root.
func touchFile(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImageAddCreatesList(t *testing.T) {
	root := initImageRepo(t, `engine:
  variant: core
  digest: sha256:abc
scan:
  container_images: false
`)
	touchFile(t, filepath.Join(root, "engine", "Dockerfile"))
	msg, err := imageAdd("engine/Dockerfile", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "added engine/Dockerfile") {
		t.Fatalf("add must say what it did: %q", msg)
	}
	ci := imageConfig(t, root)
	if ci.Mode() != "list" || len(ci.Entries()) != 1 || ci.Entries()[0].Dockerfile != "engine/Dockerfile" {
		t.Fatalf("config after add: mode %s entries %v", ci.Mode(), ci.Entries())
	}
	// Other keys ride along untouched.
	cfg, err := config.Load(filepath.Join(root, ".cavet", "config.yaml"))
	if err != nil || cfg.Engine.Digest != "sha256:abc" {
		t.Fatalf("digest pin must survive the edit: %v %v", cfg.Engine.Digest, err)
	}
}

func TestImageAddAbsentKeyCreatesList(t *testing.T) {
	root := initImageRepo(t, "")
	touchFile(t, filepath.Join(root, "Dockerfile"))
	if _, err := imageAdd("Dockerfile", ""); err != nil {
		t.Fatal(err)
	}
	if ci := imageConfig(t, root); ci.Mode() != "list" || len(ci.Entries()) != 1 {
		t.Fatalf("absent key must become a list: mode %s entries %v", ci.Mode(), ci.Entries())
	}
}

func TestImageAddTrueConvertsToList(t *testing.T) {
	root := initImageRepo(t, "scan:\n  container_images: true\n")
	touchFile(t,
		filepath.Join(root, "Dockerfile"),
		filepath.Join(root, "Dockerfile.dev"),
		filepath.Join(root, "engine", "Dockerfile"),
	)
	msg, err := imageAdd("engine/Dockerfile", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "converted container_images from true to an explicit list") ||
		!strings.Contains(msg, "no longer be auto-included") {
		t.Fatalf("conversion must say exactly what it did: %q", msg)
	}
	ci := imageConfig(t, root)
	want := []config.ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "Dockerfile.dev"}, {Dockerfile: "engine/Dockerfile"}}
	got := ci.Entries()
	if len(got) != len(want) {
		t.Fatalf("converted list = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("converted list = %v, want %v", got, want)
		}
	}
}

func TestImageAddDuplicateIsNoOp(t *testing.T) {
	root := initImageRepo(t, "scan:\n  container_images:\n    - Dockerfile\n")
	touchFile(t, filepath.Join(root, "Dockerfile"))
	msg, err := imageAdd("Dockerfile", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "already configured") {
		t.Fatalf("duplicate add must say so: %q", msg)
	}
	if ci := imageConfig(t, root); len(ci.Entries()) != 1 {
		t.Fatalf("duplicate add must not append: %v", ci.Entries())
	}
}

func TestImageAddFromNestedCwd(t *testing.T) {
	root := initImageRepo(t, "")
	touchFile(t, filepath.Join(root, "pkg", "Dockerfile"))
	t.Chdir(filepath.Join(root, "pkg"))
	if _, err := imageAdd("Dockerfile", ""); err != nil {
		t.Fatal(err)
	}
	if ci := imageConfig(t, root); len(ci.Entries()) != 1 || ci.Entries()[0].Dockerfile != "pkg/Dockerfile" {
		t.Fatalf("cwd-relative arg must land repo-relative: %v", ci.Entries())
	}
}

// add --target writes the map form; re-add with a new --target updates it
// and says what changed; re-add without --target leaves it alone.
func TestImageAddWithTarget(t *testing.T) {
	root := initImageRepo(t, "")
	touchFile(t, filepath.Join(root, "engine", "Dockerfile"))
	msg, err := imageAdd("engine/Dockerfile", "final-core")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "added engine/Dockerfile (target final-core)") {
		t.Fatalf("add with target must say it: %q", msg)
	}
	ci := imageConfig(t, root)
	want := config.ImageEntry{Dockerfile: "engine/Dockerfile", Target: "final-core"}
	if len(ci.Entries()) != 1 || ci.Entries()[0] != want {
		t.Fatalf("map form after add: %v", ci.Entries())
	}

	msg, err = imageAdd("engine/Dockerfile", "final-slim")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "updated engine/Dockerfile target: final-core -> final-slim") {
		t.Fatalf("target update must say what changed: %q", msg)
	}
	ci = imageConfig(t, root)
	if len(ci.Entries()) != 1 || ci.Entries()[0].Target != "final-slim" {
		t.Fatalf("target must update in place: %v", ci.Entries())
	}

	// No --target on an existing entry: no change, no error.
	msg, err = imageAdd("engine/Dockerfile", "")
	if err != nil || !strings.Contains(msg, "already configured") {
		t.Fatalf("re-add without target must be a no-op: %q %v", msg, err)
	}
	if ci = imageConfig(t, root); ci.Entries()[0].Target != "final-slim" {
		t.Fatalf("re-add without target must keep the target: %v", ci.Entries())
	}
}

func TestImageListShowsTargets(t *testing.T) {
	root := initImageRepo(t, "scan:\n  container_images:\n    - Dockerfile\n    - dockerfile: engine/Dockerfile\n      target: final-core\n")
	touchFile(t, filepath.Join(root, "Dockerfile"))
	msg, err := imageList()
	if err != nil || msg != "container_images: list\nDockerfile\nengine/Dockerfile (target final-core)\n" {
		t.Fatalf("list must show targets when set: %q %v", msg, err)
	}
}

func TestImageAddRejectsBadPaths(t *testing.T) {
	root := initImageRepo(t, "")
	if _, err := imageAdd("missing/Dockerfile", ""); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing file must error: %v", err)
	}
	outside := t.TempDir()
	touchFile(t, filepath.Join(outside, "Dockerfile"))
	if _, err := imageAdd(filepath.Join(outside, "Dockerfile"), ""); err == nil || !strings.Contains(err.Error(), "outside the repository") {
		t.Fatalf("outside file must error: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := imageAdd("engine", ""); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory arg must error: %v", err)
	}
}

func TestImageRemove(t *testing.T) {
	root := initImageRepo(t, "scan:\n  container_images:\n    - Dockerfile\n    - engine/Dockerfile\n")
	msg, err := imageRemove("engine/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "removed engine/Dockerfile") {
		t.Fatalf("remove must say what it did: %q", msg)
	}
	ci := imageConfig(t, root)
	if ci.Mode() != "list" || len(ci.Entries()) != 1 || ci.Entries()[0].Dockerfile != "Dockerfile" {
		t.Fatalf("after remove: mode %s entries %v", ci.Mode(), ci.Entries())
	}
	if _, err := imageRemove("Dockerfile"); err != nil {
		t.Fatal(err)
	}
	// Removing the last entry writes false.
	if ci := imageConfig(t, root); ci.Mode() != "false" || ci.Enabled() {
		t.Fatalf("removing the last entry must write false: mode %s", ci.Mode())
	}
}

func TestImageRemoveUnknownNamesEntries(t *testing.T) {
	initImageRepo(t, "scan:\n  container_images:\n    - Dockerfile\n")
	_, err := imageRemove("engine/Dockerfile")
	if err == nil || !strings.Contains(err.Error(), "Dockerfile") {
		t.Fatalf("unknown path must error naming the current entries: %v", err)
	}
}

func TestImageRemoveWithoutList(t *testing.T) {
	initImageRepo(t, "scan:\n  container_images: true\n")
	if _, err := imageRemove("Dockerfile"); err == nil || !strings.Contains(err.Error(), "true") {
		t.Fatalf("remove under true must explain the mode: %v", err)
	}
	initImageRepo(t, "scan:\n  container_images: false\n")
	if _, err := imageRemove("Dockerfile"); err == nil || !strings.Contains(err.Error(), "false") {
		t.Fatalf("remove under false must explain the mode: %v", err)
	}
}

func TestImageListOutput(t *testing.T) {
	initImageRepo(t, "scan:\n  container_images: false\n")
	msg, err := imageList()
	if err != nil || msg != "container_images: false\n" {
		t.Fatalf("false mode: %q %v", msg, err)
	}

	root := initImageRepo(t, "scan:\n  container_images: true\n")
	touchFile(t, filepath.Join(root, "Dockerfile"))
	msg, err = imageList()
	if err != nil {
		t.Fatal(err)
	}
	if msg != "container_images: true (every Dockerfile at the repository root)\nDockerfile\n" {
		t.Fatalf("true mode must print mode and current entries: %q", msg)
	}

	initImageRepo(t, "scan:\n  container_images:\n    - engine/Dockerfile\n")
	msg, err = imageList()
	if err != nil || msg != "container_images: list\nengine/Dockerfile\n" {
		t.Fatalf("list mode: %q %v", msg, err)
	}
}

func TestScanScopeFlagsExclusive(t *testing.T) {
	cases := [][]string{
		{"--staged", "--full"},
		{"--image", "--staged"},
		{"--image", "--full"},
		{"--image", "--diff", "HEAD~1"},
	}
	for _, args := range cases {
		cmd := newScanCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true // keep test output clean
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "exactly one scope flag") {
			t.Fatalf("args %v: want exclusivity error, got %v", args, err)
		}
	}
}
