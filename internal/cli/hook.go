package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// installHook wires the advisory pre-commit trigger via core.hooksPath so it
// survives a fresh clone (spec §9, cli-spec §13). Advisory-only behaviour is
// enforced inside scan --context pre-commit, not in the hook script.
func installHook(root string) error {
	hooks := filepath.Join(root, ".cavet", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		return err
	}
	shim := "#!/bin/sh\nexec cavet scan --staged --context pre-commit\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(shim), 0o755); err != nil {
		return err
	}
	// Windows fallback: Git for Windows runs the POSIX shim through its
	// bundled sh; the .cmd is for setups where sh is not reachable.
	cmdShim := "@echo off\r\ncavet scan --staged --context pre-commit\r\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit.cmd"), []byte(cmdShim), 0o755); err != nil {
		return err
	}
	if out, err := gitConfig(root, "core.hooksPath", ".cavet/hooks"); err != nil {
		return fmt.Errorf("git config core.hooksPath: %v\n%s", err, out)
	}
	return nil
}

func gitConfig(dir, key, value string) (string, error) {
	cmd := exec.Command("git", "config", key, value)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
