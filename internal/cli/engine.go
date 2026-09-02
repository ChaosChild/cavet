package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/engineclient"
)

func newEngineCmd() *cobra.Command {
	var all bool
	prune := &cobra.Command{
		Use:   "prune [--all]",
		Short: "Remove engine containers whose repository root is gone from the host",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			cfg := loadConfig(s)
			root, _ := repoRoot()
			c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			entries, err := c.Prune(ctx, all)
			if err != nil {
				return fail(err.Error())
			}
			if len(entries) == 0 {
				fmt.Println("no cavet engine containers")
				return nil
			}
			for _, e := range entries {
				if e.Root != "" {
					fmt.Printf("%s %s: %s\n", e.Name, e.Root, e.Action)
				} else {
					fmt.Printf("%s: %s\n", e.Name, e.Action)
				}
			}
			return nil
		},
	}
	prune.Flags().BoolVar(&all, "all", false, "remove every cavet-* container except this repository's")

	cmd := &cobra.Command{
		Use:   "engine (status|start|stop|pull|prune|shell)",
		Short: "Control the long-lived scanner container",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "status",
			Short: "Container state, image vs configured pin, warmth",
			RunE: func(_ *cobra.Command, _ []string) error {
				s, err := openStore()
				if err != nil {
					return err
				}
				cfg := loadConfig(s)
				root, _ := repoRoot()
				c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				running, healthy, imageID, err := c.Status(ctx)
				if err != nil {
					return fail(err.Error())
				}
				fmt.Printf("container %s: ", c.Name())
				switch {
				case running && healthy:
					fmt.Println("running (warm)")
				case running:
					fmt.Println("running (probing…)")
				default:
					fmt.Println("stopped")
				}
				fmt.Printf("image: %s\n", imageID)
				if cfg.Engine.Digest != "" && !strings.Contains(imageID, strings.TrimPrefix(cfg.Engine.Digest, "sha256:")) {
					fmt.Println("warning: running image does not match the configured pin; run 'cavet rebaseline'")
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "start",
			Short: "Create/start the container and wait for health",
			RunE: func(_ *cobra.Command, _ []string) error {
				s, err := openStore()
				if err != nil {
					return err
				}
				cfg := loadConfig(s)
				root, _ := repoRoot()
				c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := c.EnsureRunning(ctx); err != nil {
					return fail(err.Error())
				}
				fmt.Println("engine running")
				return nil
			},
		},
		&cobra.Command{
			Use:   "stop",
			Short: "Remove the container (it holds no unique state)",
			RunE: func(_ *cobra.Command, _ []string) error {
				s, err := openStore()
				if err != nil {
					return err
				}
				cfg := loadConfig(s)
				root, _ := repoRoot()
				c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := c.Remove(ctx); err != nil {
					return fail(err.Error())
				}
				fmt.Println("engine stopped")
				return nil
			},
		},
		&cobra.Command{
			Use:   "pull",
			Short: "Fetch the engine image; rebaseline stays deliberate and separate",
			RunE: func(_ *cobra.Command, _ []string) error {
				s, err := openStore()
				if err != nil {
					return err
				}
				cfg := loadConfig(s)
				root, _ := repoRoot()
				ref := engineRef(cfg)
				c := engineclient.New(ref, cfg.Engine.Digest, root)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
				defer cancel()
				old, _ := c.ImageDigest(ctx, ref)
				rc, err := c.Pull(ctx, ref)
				if err != nil {
					return fail(err.Error())
				}
				_, _ = io.Copy(io.Discard, rc)
				rc.Close()
				newD, _ := c.ImageDigest(ctx, ref)
				fmt.Printf("pulled %s\nold digest: %s\nnew digest: %s\n", ref, orNone(old), orNone(newD))
				fmt.Println("run 'cavet rebaseline' to adopt the new image")
				return nil
			},
		},
		prune,
		&cobra.Command{
			Use:   "shell",
			Short: "Interactive shell in the engine container (operator only)",
			RunE: func(_ *cobra.Command, _ []string) error {
				// TTY gate BEFORE contacting Docker — this is what makes the
				// `cavet *` subagent allowlist safe (cli-spec §4.4).
				for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
					if !isTTY(f) {
						return fail("engine shell needs a terminal; it refuses otherwise by design")
					}
				}
				s, err := openStore()
				if err != nil {
					return err
				}
				cfg := loadConfig(s)
				root, _ := repoRoot()
				c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root)
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				if err := c.EnsureRunning(ctx); err != nil {
					return fail(err.Error())
				}
				// ponytail: exec the docker binary for TTY fidelity (signal
				// handling, resize, raw mode); the SDK path stays for
				// everything non-interactive (cli-spec §16.20).
				docker, err := exec.LookPath("docker")
				if err != nil {
					return fail("docker binary not on PATH (needed only for engine shell)")
				}
				shell := exec.Command(docker, "exec", "-it", c.Name(), "sh")
				shell.Stdin, shell.Stdout, shell.Stderr = os.Stdin, os.Stdout, os.Stderr
				return shell.Run()
			},
		},
	)
	return cmd
}

func orNone(s string) string {
	if s == "" {
		return "(none recorded)"
	}
	return s
}
