package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

func newRaiseCmd() *cobra.Command {
	var kind, question, fingerprint string
	cmd := &cobra.Command{
		Use:   "raise --kind (design|verification) --question \"…\" [--fingerprint <id>]",
		Short: "Open an item: a design concern or a verification request",
		RunE: func(_ *cobra.Command, _ []string) error {
			if question == "" {
				return fail("--question is required")
			}
			if kind != string(events.ItemDesign) && kind != string(events.ItemVerification) {
				return fail("--kind must be design or verification")
			}
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
			d := events.RaisedData{Kind: events.ItemKind(kind), Question: question}
			if kind == string(events.ItemVerification) {
				f, err := resolveFinding(st, fingerprint)
				if err != nil {
					return fail("verification needs a resolvable --fingerprint: " + err.Error())
				}
				d.Fingerprint = f.Fingerprint
			}
			ev, err := events.NewRaised(time.Now().UTC(), events.ActorAgent, events.PhaseDesign,
				engineRef(cfg), d)
			if err != nil {
				return fail(err.Error())
			}
			if err := s.Append(ev); err != nil {
				return fail(err.Error())
			}
			id := store.ItemID(ev)
			st.Items = append(st.Items, store.Item{
				ID: id, Kind: kind, Question: question, Fingerprint: d.Fingerprint,
				RaisedAt: ev.TS, RaisedBy: string(events.ActorAgent),
			})
			if err := s.WriteState(st); err != nil {
				return fail(err.Error())
			}
			fmt.Println(id) // the handle skills use with resolve
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "design|verification (required)")
	cmd.Flags().StringVar(&question, "question", "", "the concern or question, verbatim (required)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "finding id the verification concerns")
	return cmd
}

func newResolveCmd() *cobra.Command {
	var answer string
	var sources []string
	cmd := &cobra.Command{
		Use:   "resolve <item-id> --answer \"…\" [--source id=url]…",
		Short: "Close an open item with the decision or answer",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if answer == "" {
				return fail("--answer is required")
			}
			srcs, err := parseSources(sources)
			if err != nil {
				return fail(err.Error())
			}
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
			found := false
			for _, it := range st.Items {
				if it.ID == args[0] {
					found = true
					break
				}
			}
			if !found {
				return fail("no open item " + args[0])
			}
			ev, err := events.NewResolved(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
				engineRef(cfg), events.ResolvedData{Item: args[0], Answer: answer, Sources: srcs})
			if err != nil {
				return fail(err.Error())
			}
			if err := s.Append(ev); err != nil {
				return fail(err.Error())
			}
			kept := st.Items[:0]
			for _, it := range st.Items {
				if it.ID != args[0] {
					kept = append(kept, it)
				}
			}
			st.Items = kept
			if err := s.WriteState(st); err != nil {
				return fail(err.Error())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&answer, "answer", "", "the decision or answer (required)")
	cmd.Flags().StringArrayVar(&sources, "source", nil, "evidence as id=url, repeatable")
	return cmd
}

func newItemsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "items",
		Short: "List open items: design concerns and verification requests",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			st, err := s.LoadState()
			if err != nil {
				return fail(err.Error())
			}
			if len(st.Items) == 0 {
				fmt.Println("no open items")
				return nil
			}
			fmt.Printf("| %-12s | %-12s | %-40s | %s |\n", "id", "kind", "question", "raised by")
			fmt.Printf("|%s|%s|%s|%s|\n",
				strings.Repeat("-", 14), strings.Repeat("-", 14), strings.Repeat("-", 42), strings.Repeat("-", 12))
			for _, it := range st.Items {
				q := it.Question
				if len(q) > 40 {
					q = q[:39] + "…"
				}
				fmt.Printf("| %-12s | %-12s | %-40s | %s |\n", it.ID, it.Kind, q, it.RaisedBy)
			}
			return nil
		},
	}
}
