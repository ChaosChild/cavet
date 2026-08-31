package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/describe"
	"github.com/ChaosChild/cavet/internal/store"
)

func newDescribeCmd() *cobra.Command {
	var jsonOut bool
	var skillsDir string
	cmd := &cobra.Command{
		Use:   "describe --json",
		Short: "Machine contract for third-party installers",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Refuses without --json (cli-spec §16.6): no drifting human format.
			if !jsonOut {
				return fail("describe emits JSON only; pass --json")
			}
			// Works before init (cli-spec §4.3 exception list).
			cfg := config.Default()
			if root, rerr := repoRoot(); rerr == nil {
				if s, oerr := store.Open(root); oerr == nil {
					cfg = loadConfig(s)
				}
			}
			b, err := describe.JSON(resolveVersion(), cfg.Engine.Variant, cfg.Engine.Digest, skillsDir)
			if err != nil {
				return fail(err.Error())
			}
			os.Stdout.Write(b)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the JSON contract (required)")
	cmd.Flags().StringVar(&skillsDir, "skills-dir", "", "override recommended_path prefix for installer layouts")
	return cmd
}
