// Package config loads and validates .cavet/config.yaml (artefacts-spec.md §4).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Engine struct {
		Variant string `yaml:"variant"`
		Digest  string `yaml:"digest"`
	} `yaml:"engine"`
	Scan struct {
		DeepDefault     bool            `yaml:"deep_default"`
		ContainerImages ContainerImages `yaml:"container_images"`
		HookExit1       bool            `yaml:"hook_exit_1"`
	} `yaml:"scan"`
	Scanners struct {
		Checkov bool `yaml:"checkov"`
	} `yaml:"scanners"`
	Network struct {
		Proxy       string `yaml:"proxy"`
		DBOverrides struct {
			TrivyDB     string `yaml:"trivy_db"`
			TrivyJavaDB string `yaml:"trivy_java_db"`
		} `yaml:"db_overrides"`
	} `yaml:"network"`
}

// Default returns the all-defaults config: core variant, every opt-in off.
func Default() Config {
	var c Config
	c.Engine.Variant = "core"
	return c
}

// ImageEntry is one configured image: a Dockerfile path plus an optional
// build target (empty means the Dockerfile default, i.e. the last stage).
type ImageEntry struct {
	Dockerfile string
	Target     string
}

// ContainerImages is the scan.container_images value: false or absent (off),
// true (every Dockerfile at the repository root), or an explicit list of
// Dockerfile paths (nested allowed), each optionally a dockerfile/target map.
// The cavet image verb is the author of the list form; YAML round-trips
// through the same three shapes.
type ContainerImages struct {
	auto bool
	list []ImageEntry // nil unless the explicit list form
}

// Enabled reports whether any image scanning is configured.
func (c ContainerImages) Enabled() bool { return c.auto || len(c.list) > 0 }

// Mode names the configured form, "true"|"false"|"list" (cavet image list).
func (c ContainerImages) Mode() string {
	switch {
	case c.auto:
		return "true"
	case c.list != nil:
		return "list"
	default:
		return "false"
	}
}

// Entries returns the explicit list verbatim; nil for true/false.
func (c ContainerImages) Entries() []ImageEntry { return c.list }

// ImageList builds the explicit-list form (cavet image add/remove).
func ImageList(entries []ImageEntry) ContainerImages { return ContainerImages{list: entries} }

// Dockerfiles resolves the configured Dockerfiles to repo-relative slash
// paths: the list form verbatim, the true form by globbing Dockerfile* at the
// repository root only (non-recursive, regular files). Targets ride along;
// the glob form never sets one.
func (c ContainerImages) Dockerfiles(root string) []ImageEntry {
	if !c.auto {
		return c.list
	}
	matches, err := filepath.Glob(filepath.Join(root, "Dockerfile*"))
	if err != nil {
		return nil // unreachable: a literal-star pattern cannot be malformed
	}
	var out []ImageEntry
	for _, m := range matches {
		if fi, serr := os.Stat(m); serr == nil && fi.Mode().IsRegular() {
			if rel, rerr := filepath.Rel(root, m); rerr == nil {
				out = append(out, ImageEntry{Dockerfile: filepath.ToSlash(rel)})
			}
		}
	}
	return out
}

// UnmarshalYAML accepts bool or a list whose entries are a plain Dockerfile
// path or a dockerfile/target map (target optional, empty = Dockerfile
// default); any other shape fails loud naming the key, in step with the
// strict unknown-key errors (artefacts §4).
func (c *ContainerImages) UnmarshalYAML(value *yaml.Node) error {
	badKey := fmt.Errorf("container_images: must be true, false, or a list of Dockerfile paths")
	switch value.Kind {
	case yaml.ScalarNode:
		var b bool
		if err := value.Decode(&b); err != nil {
			return badKey
		}
		c.auto, c.list = b, nil
	case yaml.SequenceNode:
		entries := make([]ImageEntry, 0, len(value.Content))
		for _, el := range value.Content {
			switch el.Kind {
			case yaml.ScalarNode:
				// Decode into any first: yaml coerces int scalars into string
				// fields silently, and "1" is not a Dockerfile path.
				var a any
				if err := el.Decode(&a); err != nil {
					return badKey
				}
				s, ok := a.(string)
				if !ok {
					return badKey
				}
				entries = append(entries, ImageEntry{Dockerfile: s})
			case yaml.MappingNode:
				e, err := unmarshalImageEntry(el)
				if err != nil {
					return err
				}
				entries = append(entries, e)
			default:
				return badKey
			}
		}
		c.auto, c.list = false, entries
	default:
		return badKey
	}
	return nil
}

// unmarshalImageEntry decodes one {dockerfile, target} map entry strictly:
// unknown keys and non-string values fail loud naming the offender.
func unmarshalImageEntry(el *yaml.Node) (ImageEntry, error) {
	var m map[string]any
	if err := el.Decode(&m); err != nil {
		return ImageEntry{}, fmt.Errorf("container_images: entry must be a Dockerfile path or a dockerfile/target map")
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic error text
	for _, k := range keys {
		if k != "dockerfile" && k != "target" {
			return ImageEntry{}, fmt.Errorf("container_images: unknown key %q in entry (dockerfile, target)", k)
		}
	}
	var e ImageEntry
	df, ok := m["dockerfile"]
	if !ok {
		return ImageEntry{}, fmt.Errorf("container_images: entry map requires a dockerfile key")
	}
	if e.Dockerfile, ok = df.(string); !ok {
		return ImageEntry{}, fmt.Errorf("container_images: entry dockerfile must be a string")
	}
	if t, present := m["target"]; present {
		if e.Target, ok = t.(string); !ok {
			return ImageEntry{}, fmt.Errorf("container_images: entry target must be a string")
		}
	}
	return e, nil
}

// MarshalYAML round-trips the configured form; the cavet image verb writes it.
// Entries keep the plain string form until they carry a target.
func (c ContainerImages) MarshalYAML() (any, error) {
	if c.auto {
		return true, nil
	}
	if c.list == nil {
		return false, nil
	}
	out := make([]any, 0, len(c.list))
	for _, e := range c.list {
		if e.Target == "" {
			out = append(out, e.Dockerfile)
			continue
		}
		out = append(out, map[string]string{"dockerfile": e.Dockerfile, "target": e.Target})
	}
	return out, nil
}

// Load parses config.yaml strictly: unknown keys fail loud and the error names
// the key (artefacts §4). A missing or empty file yields Default().
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return c, nil // empty file: defaults stand
		}
		return Default(), fmt.Errorf("config.yaml: %w", err)
	}
	switch c.Engine.Variant {
	case "core", "full":
	default:
		return Default(), fmt.Errorf("config.yaml: engine.variant %q (core|full)", c.Engine.Variant)
	}
	return c, nil
}
