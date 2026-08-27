package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

// parseSources turns --source id=url arguments into cite-or-omit records.
func parseSources(pairs []string) ([]events.Source, error) {
	var out []events.Source
	for _, p := range pairs {
		i := strings.Index(p, "=")
		if i < 1 || i == len(p)-1 {
			return nil, fmt.Errorf("source %q must be id=url", p)
		}
		out = append(out, events.Source{ID: p[:i], URL: p[i+1:]})
	}
	return out, nil
}

func newTriageCmd() *cobra.Command {
	var confirm, dismiss bool
	var reason, confidence string
	var sources []string
	cmd := &cobra.Command{
		Use:   "triage <id> (--confirm|--dismiss) --reason \"…\" --confidence high|low [--source id=url]…",
		Short: "Record a confirm or dismiss verdict with reason and confidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if confirm == dismiss {
				return fail("exactly one of --confirm or --dismiss")
			}
			if reason == "" {
				return fail("--reason is required")
			}
			if confidence != string(events.ConfidenceHigh) && confidence != string(events.ConfidenceLow) {
				return fail("--confidence must be high or low — there is deliberately no default (spec §6)")
			}
			srcs, err := parseSources(sources)
			if err != nil {
				return fail(err.Error())
			}
			verdict := events.VerdictConfirmed
			if dismiss {
				verdict = events.VerdictDismissed
			}
			return mutateFinding(args[0], func(f *store.Finding, eng string) (events.Event, error) {
				return events.NewTriaged(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
					eng, f.Fingerprint, events.TriagedData{
						Verdict: verdict, Confidence: events.Confidence(confidence),
						Reason: reason, Sources: srcs,
					})
			}, func(f *store.Finding, ev events.Event) {
				f.Status = string(verdict)
				f.Verdict = &store.Verdict{
					Verdict: string(verdict), Confidence: confidence, Reason: reason,
					Sources: srcs, At: ev.TS, By: string(events.ActorOperator),
				}
			})
		},
	}
	cmd.Flags().BoolVar(&confirm, "confirm", false, "the finding is real")
	cmd.Flags().BoolVar(&dismiss, "dismiss", false, "the finding is not worth acting on")
	cmd.Flags().StringVar(&reason, "reason", "", "why — recorded in the audit trail (required)")
	cmd.Flags().StringVar(&confidence, "confidence", "", "high|low (required)")
	cmd.Flags().StringArrayVar(&sources, "source", nil, "evidence as id=url, repeatable")
	return cmd
}

func newSuppressCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "suppress <id> --reason \"…\"",
		Short: "Silence a finding deliberately, with a reason",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if reason == "" {
				return fail("--reason is required")
			}
			return mutateFinding(args[0], func(f *store.Finding, eng string) (events.Event, error) {
				return events.NewSuppressed(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
					eng, f.Fingerprint, reason)
			}, func(f *store.Finding, _ events.Event) { f.Status = "suppressed" })
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why this stays silenced (required)")
	return cmd
}

func newDeferCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "defer <id> --reason \"…\"",
		Short: "Acknowledge a finding, act later",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if reason == "" {
				return fail("--reason is required")
			}
			return mutateFinding(args[0], func(f *store.Finding, eng string) (events.Event, error) {
				return events.NewDeferred(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
					eng, f.Fingerprint, reason)
			}, func(f *store.Finding, _ events.Event) { f.Status = "deferred" })
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why it waits (required)")
	return cmd
}

// mutateFinding is the shared shape of triage/suppress/defer: lock, resolve,
// append the event, update state, persist — all under the artefact lock.
func mutateFinding(id string, mk func(*store.Finding, string) (events.Event, error),
	apply func(*store.Finding, events.Event)) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	cfg := loadConfig(s)
	rel, err := s.Lock()
	if err != nil {
		return fail(err.Error())
	}
	defer rel()
	st, err := s.LoadState()
	if err != nil {
		return fail(err.Error())
	}
	f, err := resolveFinding(st, id)
	if err != nil {
		return fail(err.Error())
	}
	ev, err := mk(f, engineRef(cfg))
	if err != nil {
		return fail(err.Error())
	}
	if err := s.Append(ev); err != nil {
		return fail(err.Error())
	}
	apply(f, ev)
	if err := s.WriteState(st); err != nil {
		return fail(err.Error())
	}
	return nil
}
