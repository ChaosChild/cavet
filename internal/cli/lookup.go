package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/lookup"
)

func newLookupCmd() *cobra.Command {
	var refresh bool
	cmd := &cobra.Command{
		Use:   "lookup <identifier>… [--refresh]",
		Short: "Advisory, package, and rule lookup — identifiers only, by design",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fail("lookup needs at least one identifier (CVE, GHSA/OSV, purl, CWE, rule id)")
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			src := lookup.NewSources(lookup.NewCache(filepath.Join(s.Cavet, "cache", "advisories")))
			src.Rules = lookup.NewFileCatalog(lookup.CatalogPath(filepath.Join(s.Cavet, "cache", "advisories")))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			rows, err := lookup.Run(ctx, args, src, refresh)
			if err != nil {
				return fail(err.Error()) // names the offending argument — the no-leak rejection
			}
			fmt.Print(lookup.Render(rows))
			return nil
		},
	}
	cmd.Flags().BoolVar(&refresh, "refresh", false, "bypass cache reads")
	return cmd
}
