package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newLogCmd() *cobra.Command {
	var since, fingerprint string
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
			shown := 0
			for i := len(evs) - 1; i >= 0 && shown < 50; i-- {
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
			rows := 0
			fmt.Printf("| %-6s | %-8s | %-24s | %-24s | %s |\n", "id", "sev", "rule", "location", "description")
			fmt.Printf("|%s|%s|%s|%s|%s|\n", strings.Repeat("-", 8), strings.Repeat("-", 10),
				strings.Repeat("-", 26), strings.Repeat("-", 26), strings.Repeat("-", 12))
			for _, f := range st.Findings {
				if !inBaseline[f.Fingerprint] {
					continue
				}
				if severity != "" && f.Severity != severity {
					continue
				}
				loc := ""
				if len(f.Locations) > 0 {
					loc = fmt.Sprintf("%s:%d", f.Locations[0].Path, f.Locations[0].Line)
				}
				fmt.Printf("| %-6s | %-8s | %-24s | %-24s | %s |\n",
					f.DisplayID, f.Severity, f.RuleID, loc, truncateExcerpt(f.Description))
				rows++
			}
			fmt.Printf("baseline: %d findings (%d shown)\n", len(st.Baseline.Fingerprints), rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&severity, "severity", "", "critical|high|medium|low|info")
	return cmd
}
