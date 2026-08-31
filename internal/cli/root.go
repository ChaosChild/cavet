// Package cli wires the cavet command surface (cli-spec §5). Commands are
// thin: flags in, calls to internal packages, output shaped by internal/output.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/output"
	"github.com/ChaosChild/cavet/internal/scan"
	"github.com/ChaosChild/cavet/internal/store"
)

// version is set at build time via -ldflags.
var version = "dev"

// exitErr carries a chosen exit code (cli-spec §4.1: informational, never
// gating). An empty message prints nothing — exit 1 on findings is silent.
type exitErr struct {
	code int
	msg  string
}

func (e *exitErr) Error() string { return e.msg }

func fail(msg string) error { return &exitErr{code: 2, msg: msg} }

// Execute runs the root command and returns the process exit code.
func Execute() int {
	root, err := newRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cavet: "+err.Error())
		return 2
	}
	if err := root.Execute(); err != nil {
		var ec *exitErr
		if errors.As(err, &ec) {
			if ec.msg != "" {
				fmt.Fprintln(os.Stderr, "cavet: "+ec.msg)
			}
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "cavet: "+err.Error())
		return 2
	}
	return 0
}

func newRoot() (*cobra.Command, error) {
	root := &cobra.Command{
		Use:   "cavet",
		Short: "A warning, not a prohibition — security tooling for coding agents",
		// Content-first: bare cavet prints posture, not help (spec §4.7).
		RunE: runPosture,
	}
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.Version = version
	root.SetVersionTemplate("cavet {{.Version}}\n")

	root.AddCommand(
		newInitCmd(),
		newScanCmd(),
		newFindingCmd(),
		newTriageCmd(),
		newSuppressCmd(),
		newDeferCmd(),
		newRaiseCmd(),
		newResolveCmd(),
		newItemsCmd(),
		newLogCmd(),
		newDebtCmd(),
		newRebuildCmd(),
		newRebaselineCmd(),
		newEngineCmd(),
		newLookupCmd(),
		newDescribeCmd(),
	)
	return root, nil
}

// --- shared helpers ---

// repoRoot resolves the cavet-initialised root: walk up from cwd like git
// until a directory holding .cavet/config.yaml appears (cli-spec §16.24), so
// commands work from nested directories. init deliberately does not use this
// — it scaffolds at cwd.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if fi, serr := os.Stat(filepath.Join(dir, ".cavet", "config.yaml")); serr == nil && !fi.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fail("no .cavet/ found in " + wd + " or any parent — cd into the cavet-initialised repo root or run 'cavet init'")
}

// openStore enforces the initialisation gate (cli-spec §4.3).
func openStore() (*store.Store, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	s, err := store.Open(root)
	if err != nil {
		return nil, fail(err.Error())
	}
	return s, nil
}

func loadConfig(s *store.Store) config.Config {
	c, err := config.Load(s.Cavet + string(os.PathSeparator) + "config.yaml")
	if err != nil {
		return config.Default()
	}
	return c
}

// engineRef builds the engine image reference: fixed name plus variant tag,
// pinned digest when recorded. CAVET_ENGINE_IMAGE overrides the name for
// development against a locally built image (cli-spec §16.19).
func engineRef(cfg config.Config) string {
	ref := os.Getenv("CAVET_ENGINE_IMAGE")
	if ref == "" {
		ref = "ghcr.io/chaoschild/cavet-engine:" + cfg.Engine.Variant
	}
	if cfg.Engine.Digest != "" && !strings.Contains(ref, "@") {
		ref += "@" + cfg.Engine.Digest
	}
	return ref
}

// shortEngine renders the header form: name@sha256:4f2a… (spec §4.1).
func shortEngine(ref string) string {
	i := strings.Index(ref, "@sha256:")
	if i < 0 {
		return ref
	}
	d := ref[i+8:]
	if len(d) > 4 {
		d = d[:4] + "…"
	}
	return ref[:i] + "@sha256:" + d
}

// runPosture is the bare-cavet home view (cli-spec §5): coverage header from
// the last scan, actionable-findings table, open items, baseline size.
func runPosture(_ *cobra.Command, _ []string) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	st, err := s.LoadState()
	if err != nil {
		return fail(err.Error())
	}
	view := output.ScanView{Scope: "posture"}
	if ls, err := scan.ReadLastScan(s); err == nil && ls != nil {
		view.Scanners = ls.Scanners
		view.Phase = ls.Phase
		view.EngineShort = shortEngine(ls.Engine)
	}
	counts := output.Counts{Baseline: len(st.Baseline.Fingerprints)}
	for _, f := range st.Findings {
		conf := ""
		if f.Verdict != nil {
			conf = f.Verdict.Confidence
		}
		switch f.Status {
		case "open", "confirmed":
			counts.Confirmed++
			switch conf {
			case "high":
				counts.ConfirmedHigh++
			case "low":
				counts.ConfirmedLow++
			}
			sec := output.FindingView{ID: f.DisplayID, Sev: f.Severity, Rule: f.RuleID, Desc: f.Description, Conf: conf}
			if len(f.Locations) > 0 {
				sec.Path, sec.Line = f.Locations[0].Path, f.Locations[0].Line
			}
			view.Findings = append(view.Findings, sec)
			switch f.Severity {
			case "critical":
				counts.Critical++
			case "high":
				counts.High++
			case "medium":
				counts.Medium++
			case "low":
				counts.Low++
			case "info":
				counts.Info++
			}
		case "dismissed":
			counts.Dismissed++
		case "suppressed":
			counts.Suppressed++
		}
	}
	view.Counts = counts
	fmt.Print(output.RenderResult(view))
	fmt.Printf("%d open items\n", len(st.Items))
	return nil
}
