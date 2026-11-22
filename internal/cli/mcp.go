package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/version"
	"bonjoski/argus/pkg/mcp"
)

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the canonical Argus STDIO MCP server (UB-MCP-v1)",
		Long: `Starts a local JSON-RPC 2.0 Model Context Protocol (MCP) server over STDIO
exposing the canonical 'argus_vet' pre-flight supply-chain vetting tool.

Returns calm <=3-line human text alongside UB-MCP-v1 structuredContent FixForwardError
payloads and emits atomic signed BLPR-v1 DSSE receipts under FABRIAL_RECEIPT_DIR.`,
		Example: `  argus mcp
  FABRIAL_SESSION_ID=sess_01J... FABRIAL_RECEIPT_DIR=.fabrial/receipts/sess_01J... argus mcp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			srv := mcp.NewServer(
				cmd.InOrStdin(),
				cmd.OutOrStdout(),
				mcp.WithVersion(version.Version),
			)
			if err := srv.Serve(ctx); err != nil && err != context.Canceled {
				return err
			}
			return nil
		},
	}
	return cmd
}
