package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/scan"
	"github.com/ChaosChild/cavet/internal/store"
)

func progress(msg string) { fmt.Fprintln(os.Stderr, "· "+msg) }

func newInitCmd() *cobra.Command {
	var hooks bool
	cmd := &cobra.Command{
		Use:   "init [--hooks]",
		Short: "Scaffold .cavet/, start the engine, record existing debt as baseline",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit(hooks)
		},
	}
	cmd.Flags().BoolVar(&hooks, "hooks", false, "also install the advisory pre-commit hook")
	return cmd
}

func runInit(hooks bool) error {
	// init scaffolds at cwd, deliberately not via repoRoot's upward walk —
	// a nested-dir init must target the cwd, not silently adopt a parent.
	root, err := os.Getwd()
	if err != nil {
		return fail(err.Error())
	}
	if _, err := os.Stat(filepath.Join(root, ".cavet", "config.yaml")); err == nil {
		return fail(".cavet/ already initialised here")
	}
	cfg := config.Default()
	ref := engineRef(cfg)

	progress("checking docker…")
	c := engineclient.New(ref, "", root)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		return fail("docker daemon unreachable; start Docker Desktop or set DOCKER_HOST")
	}

	progress("pulling engine image " + ref)
	if err := pullOrUseLocal(ctx, c, ref); err != nil {
		return err
	}
	digest, err := c.ImageDigest(ctx, ref)
	if err != nil {
		return fail(err.Error())
	}

	progress("scaffolding .cavet/")
	s, err := store.Init(root)
	if err != nil {
		return fail(err.Error())
	}
	if digest != "" {
		if err := recordDigest(s, digest); err != nil {
			return fail(err.Error())
		}
		cfg.Engine.Digest = digest
	}

	progress("starting engine container")
	c = engineclient.New(ref, cfg.Engine.Digest, root)
	if err := c.EnsureRunning(ctx); err != nil {
		return fail(err.Error())
	}

	// The baseline scan is always full-tier, however long it takes (spec §5.1).
	progress("running full baseline scan (this can take a minute)")
	if _, err := scan.Run(ctx, s, c, scan.Options{
		Scope: scan.ScopeFull, Actor: events.ActorOperator, Phase: events.PhaseBuild,
		Context: events.ContextPosture, Engine: ref,
	}); err != nil {
		return fail(err.Error())
	}

	rel, err := s.Lock()
	if err != nil {
		return fail(err.Error())
	}
	defer rel()
	st, err := s.LoadState()
	if err != nil {
		return fail(err.Error())
	}
	var fps []string
	for _, f := range st.Findings {
		fps = append(fps, f.Fingerprint)
		f.InBaseline = true // pre-existing debt, not new work (artefacts §6.3)
	}
	if err := s.WriteBaseline(store.Baseline{
		EngineDigest: ref, CreatedAt: time.Now().UTC(), Fingerprints: fps,
	}); err != nil {
		return fail(err.Error())
	}
	ev, err := events.NewRebaselined(time.Now().UTC(), events.ActorOperator, events.PhaseBuild, ref,
		events.RebaselinedData{FromDigest: "", ToDigest: digest, Reason: "initial baseline"})
	if err != nil {
		return fail(err.Error())
	}
	if err := s.Append(ev); err != nil {
		return fail(err.Error())
	}
	if err := s.WriteState(st); err != nil {
		return fail(err.Error())
	}

	fmt.Printf("initialised. %d existing findings recorded as baseline.\n", len(fps))
	fmt.Println("run `cavet debt` when you want to work through them.")
	if hooks {
		if err := installHook(root); err != nil {
			return fail("hook installation failed: " + err.Error())
		}
		fmt.Println("pre-commit hook installed (advisory; exits 0 unless scan.hook_exit_1).")
	}
	return nil
}

// pullOrUseLocal pulls the image; a registry-less dev image that already
// exists locally is accepted with a note.
func pullOrUseLocal(ctx context.Context, c *engineclient.Client, ref string) error {
	rc, err := c.Pull(ctx, ref)
	if err == nil {
		_, _ = io.Copy(io.Discard, rc)
		rc.Close()
		return nil
	}
	if err := c.ImagePresent(ctx); err == nil {
		progress("registry pull unavailable; using local image " + ref)
		return nil
	}
	return fail("engine image unavailable: " + err.Error())
}

// recordDigest writes the pin into the scaffolded config.yaml — our file, no
// operator comments to preserve.
func recordDigest(s *store.Store, digest string) error {
	p := filepath.Join(s.Cavet, "config.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	out := strings.Replace(string(b), `digest: ""`, `digest: "`+digest+`"`, 1)
	if out == string(b) {
		return fmt.Errorf("config.yaml: digest placeholder not found")
	}
	return os.WriteFile(p, []byte(out), 0o644)
}
