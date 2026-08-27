package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

// resolveFinding maps a display-id (possibly a prefix) to one live finding.
func resolveFinding(st *store.State, id string) (*store.Finding, error) {
	var match *store.Finding
	for _, f := range st.Findings {
		if f.DisplayID == id {
			return f, nil
		}
		if strings.HasPrefix(f.DisplayID, id) || strings.HasPrefix(f.Fingerprint, id) {
			if match != nil {
				return nil, fmt.Errorf("id %q is ambiguous; extend the prefix", id)
			}
			match = f
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no finding %q", id)
	}
	return match, nil
}

func newFindingCmd() *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "finding <id> [--full]",
		Short: "Show one finding: row, locations, verdict",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			st, err := s.LoadState()
			if err != nil {
				return fail(err.Error())
			}
			f, err := resolveFinding(st, args[0])
			if err != nil {
				return fail(err.Error())
			}
			fmt.Printf("%s · %s · %s · %s\n", f.DisplayID, f.Severity, f.RuleID, f.Status)
			if f.Secret && len(f.CollapsedWith) > 0 {
				fmt.Printf("secret finding (collapsed: %s)\n", strings.Join(f.CollapsedWith, ","))
			}
			for _, loc := range f.Locations {
				fmt.Printf("  %s:%d\n", loc.Path, loc.Line)
			}
			fmt.Println(strings.TrimSpace(f.Description))
			if f.Verdict != nil {
				fmt.Printf("verdict: %s (%s confidence, by %s): %s\n",
					f.Verdict.Verdict, f.Verdict.Confidence, f.Verdict.By, f.Verdict.Reason)
			}
			if full {
				return showHistory(s, f.Fingerprint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "include the complete event history")
	return cmd
}

// showHistory renders the inline log a --full view needs.
func showHistory(s *store.Store, fp string) error {
	evs, err := s.ReadLog()
	if err != nil {
		return fail(err.Error())
	}
	fmt.Println("history:")
	for i := len(evs) - 1; i >= 0; i-- { // newest first
		e := evs[i]
		if e.Fingerprint != fp {
			continue
		}
		fmt.Printf("  %s · %s · %s · %s\n",
			e.TS.UTC().Format(time.RFC3339), e.Kind, e.Actor, excerpt(e.Event))
	}
	return nil
}

func excerpt(e events.Event) string {
	switch d := e.Payload().(type) {
	case events.TriagedData:
		return d.Reason
	case events.DetectedData:
		return d.Description
	case events.SurfacedData:
		return "shown via " + string(d.Context)
	case events.RemediatedData:
		return d.Reason
	case events.SuppressedData:
		return d.Reason
	case events.DeferredData:
		return d.Reason
	case events.RaisedData:
		return d.Question
	case events.ResolvedData:
		return d.Answer
	case events.RebaselinedData:
		return d.Reason
	}
	return ""
}
