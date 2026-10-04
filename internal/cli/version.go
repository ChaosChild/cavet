package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/store"
)

// newVersionCmd prints the local version story: cavet itself, the engine
// image pin, and the advisory database state. Everything comes from the
// binary, config and state: no container contact, no network. Outside an
// initialised repository it still prints cavet and the default engine ref.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print cavet, engine, and advisory database versions",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("cavet %s\n", resolveVersion())
			cfg := config.Default()
			var st store.DBState
			if s, err := openStore(); err == nil {
				c, err := config.Load(s.Cavet + string(os.PathSeparator) + "config.yaml")
				if err != nil {
					return fail(err.Error())
				}
				cfg = c
				st, err = s.LoadDBState()
				if err != nil {
					return fail(err.Error())
				}
			}
			fmt.Printf("engine %s\n", engineRef(cfg))
			for _, line := range dbLines(cfg, st) {
				fmt.Println(line)
			}
			return nil
		},
	}
}

// dbLines renders the per-artifact advisory lines for `cavet version` and
// `cavet engine status`: digest plus advisory age when a swap is recorded,
// the baked-era note when not (SPECIFICATION.md §7.5 status promise). Only
// the variant's artifacts render: a core engine has no java DB.
func dbLines(cfg config.Config, st store.DBState) []string {
	var lines []string
	for _, a := range engineclient.Artifacts(cfg.Engine.Variant) {
		if rec, ok := st.Artifacts[a.Name]; ok && rec.Digest != "" {
			lines = append(lines, fmt.Sprintf("db %s: %s (advisories %s, %s old)",
				a.Name, rec.Digest, rec.UpdatedAt.Format("2006-01-02"), dbAge(rec.UpdatedAt)))
			continue
		}
		lines = append(lines, "db "+a.Name+": baked (engine image build), age not recorded")
	}
	return lines
}

// dbAge renders the advisory age in whole days for the status surfaces.
func dbAge(t time.Time) string {
	if days := int(time.Since(t).Hours() / 24); days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	return "<1d"
}
