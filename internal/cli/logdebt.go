package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/store"
	"github.com/spf13/cobra"
)

func newLogCmd() *cobra.Command {
	var since, fingerprint string
	var limit int
	cmd := &cobra.Command{
		Use:   "log [--since <date>] [--fingerprint <id>]",
		Short: "Read the audit trail, newest first",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			if fingerprint != "" {
				st, err := s.LoadState()
				if err != nil {
					return fail(err.Error())
				}
				if f, err := resolveFinding(st, fingerprint); err == nil {
					fingerprint = f.Fingerprint
				}
			}
			evs, err := s.ReadLog()
			if err != nil {
				return fail(err.Error())
			}
			var sinceT time.Time
			if since != "" {
				t, err := time.Parse("2006-01-02", since)
				if err != nil {
					return fail("--since must be YYYY-MM-DD")
				}
				sinceT = t
			}
			if limit < 1 {
				return fail("--limit must be at least 1")
			}
			shown := 0
			for i := len(evs) - 1; i >= 0 && shown < limit; i-- {
				e := evs[i]
				if since != "" && e.TS.Before(sinceT) {
					continue
				}
				if fingerprint != "" && e.Fingerprint != fingerprint &&
					!strings.Contains(string(e.Raw), fingerprint) {
					continue
				}
				short := ""
				if len(e.Fingerprint) >= 6 {
					short = e.Fingerprint[:6]
				}
				fmt.Printf("%s · %-10s · %6s · %-8s · %s\n",
					e.TS.UTC().Format(time.RFC3339), e.Kind, short, e.Actor, truncateExcerpt(excerpt(e.Event)))
				shown++
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only events at or after this date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "one finding's history")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum rows to show (default 50)")
	return cmd
}

func truncateExcerpt(s string) string {
	if len(s) > 60 {
		return s[:59] + "…"
	}
	return s
}

func newDebtCmd() *cobra.Command {
	var severity string
	var showAll bool
	cmd := &cobra.Command{
		Use:   "debt [--severity <level>]",
		Short: "The pre-existing baseline, on demand only",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			st, err := s.LoadState()
			if err != nil {
				return fail(err.Error())
			}
			if severity != "" {
				switch severity {
				case "critical", "high", "medium", "low", "info":
				default:
					return fail("severity must be critical, high, medium, low, or info")
				}
			}
			inBaseline := map[string]bool{}
			for _, fp := range st.Baseline.Fingerprints {
				inBaseline[fp] = true
			}
			var rows []store.Finding
			for _, f := range st.Findings {
				if !inBaseline[f.Fingerprint] {
					continue
				}
				if severity != "" && f.Severity != severity {
					continue
				}
				rows = append(rows, *f)
			}
			hidden := 0
			for i := range rows {
				if !undecided(&rows[i]) {
					hidden++
				}
			}
			fmt.Print(debtTable(rows, showAll))
			fmt.Printf("baseline: %d findings (%d undecided shown, %d hidden; --all shows everything)\n",
				len(st.Baseline.Fingerprints), len(rows)-hidden, hidden)
			return nil
		},
	}
	cmd.Flags().StringVar(&severity, "severity", "", "critical|high|medium|low|info")
	cmd.Flags().BoolVar(&showAll, "all", false, "show triaged rows too, with a verdict column")
	return cmd
}

// undecided reports whether a finding still awaits a triage decision.
// Deferred rows stay visible until the deferred-rework item lands; suppressed
// rows are decisions too.
func undecided(f *store.Finding) bool {
	if f.Verdict != nil {
		return false
	}
	return f.Status != "suppressed"
}

func debtTable(rows []store.Finding, showAll bool) string {
	var b strings.Builder
	if showAll {
		fmt.Fprintf(&b, "| %-6s | %-8s | %-24s | %-24s | %-10s | %s |\n",
			"id", "sev", "rule", "location", "verdict", "description")
	} else {
		fmt.Fprintf(&b, "| %-6s | %-8s | %-24s | %-24s | %s |\n",
			"id", "sev", "rule", "location", "description")
	}
	b.WriteString("|" + strings.Repeat("-", 8) + "|" + strings.Repeat("-", 10) + "|" +
		strings.Repeat("-", 26) + "|" + strings.Repeat("-", 26) + "|" +
		strings.Repeat("-", 12) + "|")
	if showAll {
		b.WriteString(strings.Repeat("-", 12) + "|")
	}
	b.WriteString("\n")
	for _, f := range rows {
		if !showAll && !undecided(&f) {
			continue
		}
		loc := ""
		if len(f.Locations) > 0 {
			loc = fmt.Sprintf("%s:%d", f.Locations[0].Path, f.Locations[0].Line)
		}
		verdict := f.Status
		if f.Verdict != nil {
			verdict = f.Verdict.Verdict
		}
		if showAll {
			fmt.Fprintf(&b, "| %-6s | %-8s | %-24s | %-24s | %-10s | %s |\n",
				f.DisplayID, f.Severity, f.RuleID, loc, verdict, truncateExcerpt(f.Description))
		} else {
			fmt.Fprintf(&b, "| %-6s | %-8s | %-24s | %-24s | %s |\n",
				f.DisplayID, f.Severity, f.RuleID, loc, truncateExcerpt(f.Description))
		}
	}
	return b.String()
}
