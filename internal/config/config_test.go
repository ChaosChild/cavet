package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	c, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if c.Engine.Variant != "core" || c.Scan.DeepDefault || c.Scan.ContainerImages ||
		c.Scanners.Checkov || c.Scan.HookExit1 {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestDefaultsWhenFileMissing(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("missing file must yield defaults: %v", err)
	}
	if c.Engine.Variant != "core" {
		t.Fatalf("bad default variant %q", c.Engine.Variant)
	}
}

func TestUnknownKeyFailsLoud(t *testing.T) {
	_, err := Load(writeConfig(t, "scan:\n  deep_default: true\n  nope: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("want error naming unknown key %q, got %v", "nope", err)
	}
}

func TestVariantValidation(t *testing.T) {
	if _, err := Load(writeConfig(t, "engine:\n  variant: full\n")); err != nil {
		t.Fatalf("full is valid: %v", err)
	}
	if _, err := Load(writeConfig(t, "engine:\n  variant: mega\n")); err == nil {
		t.Fatal("invalid variant must fail")
	}
}

func TestValuesLoad(t *testing.T) {
	c, err := Load(writeConfig(t, `engine:
  variant: full
  digest: sha256:abc
scan:
  deep_default: true
  hook_exit_1: true
scanners:
  checkov: true
network:
  proxy: http://proxy:3128
  db_overrides:
    trivy_db: /db/trivy
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Engine.Variant != "full" || c.Engine.Digest != "sha256:abc" ||
		!c.Scan.DeepDefault || !c.Scan.HookExit1 || !c.Scanners.Checkov ||
		c.Network.Proxy != "http://proxy:3128" || c.Network.DBOverrides.TrivyDB != "/db/trivy" {
		t.Fatalf("values not loaded: %+v", c)
	}
}
