package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/serve"
)

// newServeCmd runs the dashboard. Loopback-only with a hard-coded bind and no
// auth: the page must never be reachable off-host (serve-task-1 D4).
func newServeCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "serve [--port]",
		Short: "Dashboard on loopback: posture, findings, metrics",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			if port < 1 || port > 65535 {
				return fail(fmt.Sprintf("invalid port %d", port))
			}
			return serve.Run(s, port)
		},
	}
	cmd.Flags().IntVar(&port, "port", 8765, "loopback port to listen on")
	return cmd
}
