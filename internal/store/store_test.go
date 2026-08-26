package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitScaffold(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"log", "state", filepath.Join("cache", "advisories"),
		filepath.Join("design", "decisions"), "reports"} {
		if fi, err := os.Stat(filepath.Join(root, ".cavet", d)); err != nil || !fi.IsDir() {
			t.Errorf("missing dir %s", d)
		}
	}
	for _, f := range []string{"config.yaml", ".gitattributes", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(root, ".cavet", f)); err != nil {
			t.Errorf("missing file %s", f)
		}
	}
	if s == nil {
		t.Fatal("nil store")
	}
}

func TestInitDoesNotOverwriteExistingFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ".cavet", ".gitattributes")
	if err := os.WriteFile(p, []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(root); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "edited\n" {
		t.Fatalf("init must not clobber operator edits, got %q", b)
	}
}

func TestOpenRequiresInit(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected refusal without init")
	}
}

func TestOpenAfterInit(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Root != root || s.Cavet != filepath.Join(root, ".cavet") {
		t.Fatalf("bad paths: %+v", s)
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := AtomicWrite(p, []byte("{\"a\":1}\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\"a\":1}\n" {
		t.Fatalf("got %q", b)
	}
	if err := AtomicWrite(p, []byte("{\"a\":2}\n")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	b, err = os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\"a\":2}\n" {
		t.Fatalf("got %q after overwrite", b)
	}
	if leftover, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(leftover) != 0 {
		t.Fatalf("temp files leaked: %v", leftover)
	}
}
