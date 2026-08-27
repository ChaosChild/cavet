package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/output"
	"github.com/ChaosChild/cavet/internal/scan"
)

func newScanCmd() *cobra.Command {
	var staged, full, deep bool
	var diffRef, phase, surfaceCtx string
	cmd := &cobra.Command{
		Use:   "scan [--staged|--diff <ref>|--full] [--deep] [--phase <phase>] [--context <ctx>]",
		Short: "Run scanners for a scope and fold the delta",
		RunE: func(_ *cobra.Command, _ []string) error {
			scopes := 0
			for _, b := range []bool{staged, diffRef != "", full} {
				if b {
					scopes++
				}
			}
			if scopes > 1 {
				return fail("exactly one scope flag (--staged, --diff, --full)")
			}
			return runScan(staged, full, deep, diffRef, phase, surfaceCtx)
		},
	}
	cmd.Flags().BoolVar(&staged, "staged", false, "scan staged index content (default when the index is non-empty)")
	cmd.Flags().StringVar(&diffRef, "diff", "", "scan worktree content of files changed vs <ref>")
	cmd.Flags().BoolVar(&full, "full", false, "scan the whole workspace, history included")
	cmd.Flags().BoolVar(&deep, "deep", false, "add SAST (opengrep) to a staged/diff scan")
	cmd.Flags().StringVar(&phase, "phase", "", "design|build|test|deploy (default build)")
	cmd.Flags().StringVar(&surfaceCtx, "context", "", "where the result is shown: pre-commit|dispatch|posture (default dispatch)")
	return cmd
}

func runScan(staged, full, deep bool, diffRef, phase, surfaceCtx string) error {
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
	if err := c.EnsureRunning(ctx); err != nil {
		return fail(err.Error())
	}

	var scope scan.Scope
	switch {
	case staged, diffRef != "":
		if diffRef != "" {
			scope = scan.ScopeDiff
		} else {
			scope = scan.ScopeStaged
		}
	case full:
		scope = scan.ScopeFull
	default:
		// Default: staged when the index is non-empty, else full with a note
		// (cli-spec §5).
		scope, err = scan.ResolveDefaultScope(ctx, c)
		if err != nil {
			return fail(err.Error())
		}
		if scope == scan.ScopeFull {
			fmt.Fprintln(os.Stderr, "note: index empty; scanning full workspace")
		}
	}
	if phase != "" && events.Phase(phase) != events.PhaseDesign &&
		events.Phase(phase) != events.PhaseBuild && events.Phase(phase) != events.PhaseTest &&
		events.Phase(phase) != events.PhaseDeploy {
		return fail("phase must be design, build, test, or deploy")
	}
	if surfaceCtx != "" && surfaceCtx != string(events.ContextPreCommit) &&
		surfaceCtx != string(events.ContextDispatch) && surfaceCtx != string(events.ContextPosture) {
		return fail("context must be pre-commit, dispatch, or posture")
	}

	res, err := scan.Run(ctx, s, c, scan.Options{
		Scope: scope, DiffRef: diffRef,
		Deep: deep || cfg.Scan.DeepDefault,
		Actor: events.ActorAgent, Phase: events.Phase(phase),
		Context: events.SurfaceContext(surfaceCtx), Engine: ref,
	})
	if err != nil {
		return fail(err.Error())
	}
	if res.NothingStaged {
		fmt.Println("nothing staged")
		return nil
	}

	view := output.ScanView{
		Scope: res.ScopeLabel, Scanners: res.Scanners, Phase: string(res.Phase),
		EngineShort: shortEngine(ref),
		Counts: output.Counts{
			Confirmed: res.Counts.Confirmed, Critical: res.Counts.Critical,
			High: res.Counts.High, Medium: res.Counts.Medium, Low: res.Counts.Low,
			Info: res.Counts.Info, Dismissed: res.Counts.Dismissed,
			Suppressed: res.Counts.Suppressed, Baseline: res.Counts.Baseline,
		},
		Hints: hints(res),
	}
	for _, r := range res.Rows {
		view.Findings = append(view.Findings, output.FindingView{
			ID: r.DisplayID, Sev: r.Sev, Rule: r.Rule, Path: r.Path, Line: r.Line,
			Desc: r.Desc,
		})
	}
	fmt.Print(output.RenderResult(view))

	// Advisory hook contract: pre-commit always exits 0 unless configured
	// otherwise (cli-spec §13).
	if surfaceCtx == string(events.ContextPreCommit) && !cfg.Scan.HookExit1 {
		return nil
	}
	if len(res.Rows) > 0 {
		return &exitErr{code: 1} // findings present — informational, not gating
	}
	return nil
}

// hints picks the concrete next-step templates mechanically, at most three
// (cli-spec §9): top finding, a log view, and debt when there is nothing
// better to suggest.
func hints(res *scan.Result) []string {
	var out []string
	if len(res.Rows) > 0 {
		out = append(out, "cavet finding "+res.Rows[0].DisplayID+" --full")
		if len(res.Rows) > 1 {
			out = append(out, "cavet log --fingerprint "+res.Rows[1].DisplayID)
		} else {
			out = append(out, "cavet log --fingerprint "+res.Rows[0].DisplayID)
		}
		return out
	}
	if res.Counts.Baseline > 0 {
		out = append(out, "cavet debt")
	}
	return out
}
