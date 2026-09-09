package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/store"
)

// newImageCmd is the scan.container_images editor: the CLI owns this config
// key so operators never hand-edit the list. Bare `cavet image` lists.
func newImageCmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "Print the container_images mode and entries",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			msg, err := imageList()
			if err != nil {
				return fail(err.Error())
			}
			fmt.Print(msg)
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add <path>",
		Short: "Add a Dockerfile to the scanned image list",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			msg, err := imageAdd(args[0])
			if err != nil {
				return fail(err.Error())
			}
			fmt.Print(msg)
			return nil
		},
	}
	remove := &cobra.Command{
		Use:   "remove <path>",
		Short: "Remove a Dockerfile from the scanned image list",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			msg, err := imageRemove(args[0])
			if err != nil {
				return fail(err.Error())
			}
			fmt.Print(msg)
			return nil
		},
	}
	cmd := &cobra.Command{
		Use:   "image (add|remove|list)",
		Short: "Manage the Dockerfiles cavet scans as container images",
		Args:  cobra.NoArgs,
		RunE:  list.RunE,
	}
	cmd.AddCommand(add, remove, list)
	return cmd
}

// imageAdd appends a Dockerfile to the configured list. When the key is true,
// it converts to an explicit list seeded with the root Dockerfiles currently
// present plus the new entry, and says so: future root Dockerfiles stop being
// auto-included.
func imageAdd(arg string) (string, error) {
	root, s, err := imageStore()
	if err != nil {
		return "", err
	}
	cfg, err := config.Load(filepath.Join(s.Cavet, "config.yaml"))
	if err != nil {
		return "", err
	}
	rel, err := resolveImageArg(root, arg)
	if err != nil {
		return "", err
	}
	cur := cfg.Scan.ContainerImages
	if cur.Mode() == "true" {
		entries := cur.Dockerfiles(root)
		if !sliceContains(entries, rel) {
			entries = append(entries, rel)
		}
		cfg.Scan.ContainerImages = config.ImageList(entries)
		if err := writeImageConfig(s, cfg); err != nil {
			return "", err
		}
		var b strings.Builder
		b.WriteString("converted container_images from true to an explicit list:\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "  %s\n", e)
		}
		b.WriteString("future Dockerfiles added at the repository root will no longer be auto-included\n")
		return b.String(), nil
	}
	entries := cur.Entries()
	if sliceContains(entries, rel) {
		return fmt.Sprintf("%s is already configured\n", rel), nil
	}
	entries = append(entries, rel)
	cfg.Scan.ContainerImages = config.ImageList(entries)
	if err := writeImageConfig(s, cfg); err != nil {
		return "", err
	}
	return fmt.Sprintf("added %s\n", rel), nil
}

// imageRemove drops an entry; removing the last one writes false. The path
// need not exist on disk any more, that is a common reason to remove it.
func imageRemove(arg string) (string, error) {
	root, s, err := imageStore()
	if err != nil {
		return "", err
	}
	cfg, err := config.Load(filepath.Join(s.Cavet, "config.yaml"))
	if err != nil {
		return "", err
	}
	rel, err := imageArgRel(root, arg)
	if err != nil {
		return "", err
	}
	cur := cfg.Scan.ContainerImages
	if cur.Mode() != "list" {
		return "", fmt.Errorf("container_images is %s, there is no explicit entry to remove; "+
			"'cavet image add <path>' starts a list", cur.Mode())
	}
	entries := cur.Entries()
	var keep []string
	found := false
	for _, e := range entries {
		if e == rel {
			found = true
			continue
		}
		keep = append(keep, e)
	}
	if !found {
		return "", fmt.Errorf("%s is not configured; entries: %s", rel, orNone(strings.Join(entries, ", ")))
	}
	cfg.Scan.ContainerImages = config.ImageList(keep) // empty list marshals as false
	if err := writeImageConfig(s, cfg); err != nil {
		return "", err
	}
	return fmt.Sprintf("removed %s\n", rel), nil
}

// imageList prints the mode (true/false/list) and the entries.
func imageList() (string, error) {
	root, s, err := imageStore()
	if err != nil {
		return "", err
	}
	cfg, err := config.Load(filepath.Join(s.Cavet, "config.yaml"))
	if err != nil {
		return "", err
	}
	cur := cfg.Scan.ContainerImages
	var b strings.Builder
	switch cur.Mode() {
	case "true":
		b.WriteString("container_images: true (every Dockerfile at the repository root)\n")
		for _, df := range cur.Dockerfiles(root) {
			fmt.Fprintf(&b, "%s\n", df)
		}
	case "list":
		b.WriteString("container_images: list\n")
		for _, e := range cur.Entries() {
			fmt.Fprintf(&b, "%s\n", e)
		}
	default:
		b.WriteString("container_images: false\n")
	}
	return b.String(), nil
}

// imageStore opens the initialised repository for the image verb.
func imageStore() (string, *store.Store, error) {
	s, err := openStore()
	if err != nil {
		return "", nil, err
	}
	root, err := repoRoot()
	if err != nil {
		return "", nil, err
	}
	return root, s, nil
}

// imageArgRel maps a CLI argument to a repo-relative slash path, rejecting
// paths outside the repository.
func imageArgRel(root, arg string) (string, error) {
	abs := arg
	if !filepath.IsAbs(abs) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = filepath.Join(wd, arg)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the repository", arg)
	}
	return filepath.ToSlash(rel), nil
}

// resolveImageArg additionally requires an existing regular file: add only
// accepts Dockerfiles that are present.
func resolveImageArg(root, arg string) (string, error) {
	rel, err := imageArgRel(root, arg)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", fmt.Errorf("%s does not exist", arg)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("%s is a directory, not a Dockerfile", arg)
	}
	return rel, nil
}

// writeImageConfig round-trips the whole config through yaml.Marshal: the
// scaffolded file carries no comments, and strict Load means no unknown keys
// can be lost on the way.
func writeImageConfig(s *store.Store, cfg config.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return store.AtomicWrite(filepath.Join(s.Cavet, "config.yaml"), b)
}

func sliceContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
