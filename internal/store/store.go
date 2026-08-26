// Package store owns the .cavet artefact directory: scaffolding, the repo lock,
// log append/read, replay, and atomic state writes (artefacts-spec.md §§1, 6, 7).
package store

import (
	"errors"
	"os"
	"path/filepath"
)

// Store is a handle to one initialised artefact directory.
type Store struct {
	Root  string // repository root (not .cavet)
	Cavet string // <Root>/.cavet
}

// ErrNotInitialised is returned by Open when .cavet/ has not been created.
var ErrNotInitialised = errStore("no .cavet/ directory here; run 'cavet init'")

type errStore string

func (e errStore) Error() string { return string(e) }

func cavetDir(root string) string { return filepath.Join(root, ".cavet") }

// Init scaffolds .cavet/ exactly as artefacts §1.1. Existing files are never
// overwritten — operator edits win (artefacts §1.1).
func Init(root string) (*Store, error) {
	c := cavetDir(root)
	for _, d := range []string{"log", "state", "cache/advisories", "design/decisions", "reports"} {
		if err := os.MkdirAll(filepath.Join(c, d), 0o755); err != nil {
			return nil, err
		}
	}
	files := map[string]string{
		"config.yaml":    defaultConfigYAML,
		".gitattributes": "log/*.jsonl merge=union\n",
		".gitignore":     "state/\ncache/\nreports/\n",
	}
	for name, body := range files {
		p := filepath.Join(c, name)
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				return nil, err
			}
		}
	}
	return &Store{Root: root, Cavet: c}, nil
}

// Open returns a handle to an existing artefact directory, or ErrNotInitialised.
func Open(root string) (*Store, error) {
	s := &Store{Root: root, Cavet: cavetDir(root)}
	if fi, err := os.Stat(filepath.Join(s.Cavet, "config.yaml")); err != nil || fi.IsDir() {
		return nil, ErrNotInitialised
	}
	return s, nil
}

const defaultConfigYAML = `engine:
  variant: core
scan:
  deep_default: false
  container_images: false
  hook_exit_1: false
scanners:
  checkov: false
network:
  proxy: ""
  db_overrides:
    trivy_db: ""
    trivy_java_db: ""
`
