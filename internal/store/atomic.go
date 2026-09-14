package store

import (
	"os"
	"path/filepath"
)

// AtomicWrite writes b to path via temp-file-then-rename, so readers see either
// the old or the new content, never a torn file (artefacts §7.3). The target
// directory is created on demand: the dirs AtomicWrite targets (state/,
// reports/) are derived and gitignored, absent from a fresh clone.
func AtomicWrite(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeded
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
