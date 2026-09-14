package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
	if c.Engine.Variant != "core" || c.Scan.DeepDefault || c.Scan.ContainerImages.Enabled() ||
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

func TestContainerImagesForms(t *testing.T) {
	cases := []struct {
		name, body string
		mode       string
		enabled    bool
		entries    []ImageEntry
	}{
		{"absent", "scan:\n  deep_default: false\n", "false", false, nil},
		{"false", "scan:\n  container_images: false\n", "false", false, nil},
		{"true", "scan:\n  container_images: true\n", "true", true, nil},
		{"list with nested paths", "scan:\n  container_images:\n    - Dockerfile\n    - engine/Dockerfile\n",
			"list", true, []ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "engine/Dockerfile"}}},
		{"map entry with target", "scan:\n  container_images:\n    - dockerfile: engine/Dockerfile\n      target: final-core\n",
			"list", true, []ImageEntry{{Dockerfile: "engine/Dockerfile", Target: "final-core"}}},
		{"map entry without target", "scan:\n  container_images:\n    - dockerfile: engine/Dockerfile\n",
			"list", true, []ImageEntry{{Dockerfile: "engine/Dockerfile"}}},
		{"mixed list", "scan:\n  container_images:\n    - Dockerfile\n    - dockerfile: engine/Dockerfile\n      target: final-core\n",
			"list", true, []ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "engine/Dockerfile", Target: "final-core"}}},
		{"empty list", "scan:\n  container_images: []\n", "list", false, []ImageEntry{}},
	}
	for _, c := range cases {
		cfg, err := Load(writeConfig(t, c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := cfg.Scan.ContainerImages
		if got.Mode() != c.mode || got.Enabled() != c.enabled {
			t.Errorf("%s: mode/enabled = %s/%v, want %s/%v", c.name, got.Mode(), got.Enabled(), c.mode, c.enabled)
		}
		if len(got.Entries()) != len(c.entries) {
			t.Errorf("%s: entries %v, want %v", c.name, got.Entries(), c.entries)
			continue
		}
		for i := range c.entries {
			if got.Entries()[i] != c.entries[i] {
				t.Errorf("%s: entries %v, want %v", c.name, got.Entries(), c.entries)
			}
		}
	}
}

// Map entries keep the strict contract: unknown keys and non-string values
// fail loud naming the offender, and a missing dockerfile key is an error.
func TestContainerImagesInvalidEntriesFailLoud(t *testing.T) {
	cases := []struct{ body, want string }{
		{"scan:\n  container_images:\n    - dockerfile: engine/Dockerfile\n      stage: final-core\n", "stage"},
		{"scan:\n  container_images:\n    - dockerfile: 1\n      target: final-core\n", "dockerfile"},
		{"scan:\n  container_images:\n    - target: final-core\n", "dockerfile"},
		{"scan:\n  container_images:\n    - dockerfile: engine/Dockerfile\n      target: [a]\n", "target"},
	}
	for _, c := range cases {
		_, err := Load(writeConfig(t, c.body))
		if err == nil || !strings.Contains(err.Error(), "container_images") || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("body %q: want error naming %q, got %v", c.body, c.want, err)
		}
	}
}

func TestContainerImagesInvalidFailsLoud(t *testing.T) {
	for _, body := range []string{
		"scan:\n  container_images: 3\n",
		"scan:\n  container_images: maybe\n",
		"scan:\n  container_images:\n    trivy: yes\n",
		"scan:\n  container_images:\n    - 1\n",
	} {
		_, err := Load(writeConfig(t, body))
		if err == nil || !strings.Contains(err.Error(), "container_images") {
			t.Fatalf("non-bool non-list value must fail loud naming the key, got: %v", err)
		}
	}
}

func TestContainerImagesGlobResolution(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"Dockerfile", "Dockerfile.prod", "engine/Dockerfile"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := (ContainerImages{auto: true}).Dockerfiles(root)
	// Bool mode globs Dockerfile* at the root only: nested and non-files stay out.
	want := []ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "Dockerfile.prod"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("root glob = %v, want %v", got, want)
	}
	// List mode uses entries verbatim, existing or not, targets riding along.
	l := ImageList([]ImageEntry{{Dockerfile: "engine/Dockerfile", Target: "final-core"}})
	if g := l.Dockerfiles(root); len(g) != 1 || g[0] != (ImageEntry{Dockerfile: "engine/Dockerfile", Target: "final-core"}) {
		t.Fatalf("list verbatim = %v", g)
	}
}

func TestContainerImagesMarshalRoundTrip(t *testing.T) {
	for name, ci := range map[string]ContainerImages{
		"false": {},
		"true":  {auto: true},
		"list":  ImageList([]ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "engine/Dockerfile"}}),
	} {
		cfg := Default()
		cfg.Scan.ContainerImages = ci
		b, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(p)
		if err != nil {
			t.Fatalf("%s: reload: %v", name, err)
		}
		if got.Scan.ContainerImages.Mode() != name {
			t.Errorf("round trip: mode = %s, want %s", got.Scan.ContainerImages.Mode(), name)
		}
		if name == "list" && len(got.Scan.ContainerImages.Entries()) != 2 {
			t.Errorf("round trip: entries = %v", got.Scan.ContainerImages.Entries())
		}
	}
}

// A targeted entry marshals as the map form and a plain one as the string
// form, in one list; reload reproduces both exactly.
func TestContainerImagesMarshalTargetRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Scan.ContainerImages = ImageList([]ImageEntry{
		{Dockerfile: "Dockerfile"},
		{Dockerfile: "engine/Dockerfile", Target: "final-core"},
	})
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "- Dockerfile\n") || !strings.Contains(string(b), "dockerfile: engine/Dockerfile") ||
		!strings.Contains(string(b), "target: final-core") {
		t.Fatalf("mixed list must keep the plain and map forms:\n%s", b)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []ImageEntry{{Dockerfile: "Dockerfile"}, {Dockerfile: "engine/Dockerfile", Target: "final-core"}}
	entries := got.Scan.ContainerImages.Entries()
	if len(entries) != 2 || entries[0] != want[0] || entries[1] != want[1] {
		t.Fatalf("round trip = %v, want %v", entries, want)
	}
}
