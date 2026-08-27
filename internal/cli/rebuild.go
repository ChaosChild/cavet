package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/scan"
	"github.com/ChaosChild/cavet/internal/store"
)

func newRebuildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild",
		Short: "Regenerate state/ from the log (the source of truth)",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			rel, err := s.Lock()
			if err != nil {
				return fail(err.Error())
			}
			defer rel()
			evs, err := s.ReadLog() // counts for the report line
			if err != nil {
				return fail(err.Error())
			}
			files := map[string]bool{}
			for _, e := range evs {
				files[e.File] = true
			}
			st, err := s.Rebuild()
			if err != nil {
				return fail(err.Error())
			}
			fmt.Printf("replayed %d events from %d files; %d findings, %d items, baseline %d.\n",
				len(evs), len(files), len(st.Findings), len(st.Items), len(st.Baseline.Fingerprints))
			return nil
		},
	}
}

func newRebaselineCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rebaseline",
		Short: "After a deliberate engine change: regenerate the baseline",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			cfg := loadConfig(s)
			root, _ := repoRoot()
			ref := engineRef(cfg)
			c := engineclient.New(ref, cfg.Engine.Digest, root)

			// A subagent cannot be asked; rebaseline changes debt accounting —
			// operator-only in practice (cli-spec §5).
			if !yes {
				if !isTTY(os.Stdin) {
					return fail("rebaseline needs a terminal confirmation or --yes")
				}
				fmt.Print("rebaseline regenerates baseline debt accounting. continue? [y/N] ")
				r := bufio.NewReader(os.Stdin)
				line, _ := r.ReadString('\n')
				if line != "y\n" && line != "y\r\n" && line != "Y\n" && line != "Y\r\n" {
					return fail("aborted")
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := c.Ping(ctx); err != nil {
				return fail("docker daemon unreachable: " + err.Error())
			}
			if err := c.EnsureRunning(ctx); err != nil {
				return fail(err.Error())
			}
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
				if f.Verdict == nil {
					f.InBaseline = true // untriaged pre-existing debt (artefacts §6.3)
				}
			}
			digest := cfg.Engine.Digest
			if digest == "" {
				if d, err := c.ImageDigest(ctx, ref); err == nil {
					digest = d
				}
			}
			if err := s.WriteBaseline(store.Baseline{
				EngineDigest: ref, CreatedAt: time.Now().UTC(), Fingerprints: fps,
			}); err != nil {
				return fail(err.Error())
			}
			ev, err := events.NewRebaselined(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
				ref, events.RebaselinedData{
					FromDigest: st.Baseline.EngineDigest, ToDigest: digest, Reason: "engine image changed",
				})
			if err != nil {
				return fail(err.Error())
			}
			if err := s.Append(ev); err != nil {
				return fail(err.Error())
			}
			if err := s.WriteState(st); err != nil {
				return fail(err.Error())
			}
			fmt.Printf("rebaselined: %d findings recorded; verdicts preserved.\n", len(fps))
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation (scripts)")
	return cmd
}

// isTTY reports whether f is attached to a terminal (cli-spec §4.4).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
