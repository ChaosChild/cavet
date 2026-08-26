// Package config loads and validates .cavet/config.yaml (artefacts-spec.md §4).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Engine struct {
		Variant string `yaml:"variant"`
		Digest  string `yaml:"digest"`
	} `yaml:"engine"`
	Scan struct {
		DeepDefault     bool `yaml:"deep_default"`
		ContainerImages bool `yaml:"container_images"`
		HookExit1       bool `yaml:"hook_exit_1"`
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
