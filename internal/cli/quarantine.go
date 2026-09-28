package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/sanitizer"
)

func newQuarantineCmd() *cobra.Command {
	quarantineCmd := &cobra.Command{
		Use:   "quarantine",
		Short: "Manage quarantined malicious/suspicious package archives",
		Long: `View, inspect, and purge quarantined package archives and forensic metadata reports
stored in ~/.argus/quarantine/.`,
	}

	quarantineCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all quarantined package archives",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := sanitizer.NewQuarantineStore("")
			if err != nil {
				return err
			}

			records, err := store.List()
			if err != nil {
				return fmt.Errorf("failed to list quarantine records: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(records)
			}

			if len(records) == 0 {
				fmt.Println("Quarantine store is empty. No packages currently quarantined.")
				return nil
			}

			fmt.Printf("Quarantine Store (%s):\n\n", store.BaseDir())
			fmt.Printf("%-28s %-10s %-25s %-12s %-6s %s\n", "ID", "ECOSYSTEM", "PACKAGE", "VERSION", "RISK", "QUARANTINED AT")
			fmt.Println(strings.Repeat("-", 95))
			for _, r := range records {
				fmt.Printf("%-28s %-10s %-25s %-12s %-6d %s\n",
					truncateStr(r.ID, 28),
					r.Ecosystem,
					truncateStr(r.Package, 25),
					truncateStr(r.Version, 12),
					r.RiskScore,
					r.QuarantineTime.Format("2006-01-02 15:04:05"),
				)
			}
			return nil
		},
	})

	quarantineCmd.AddCommand(&cobra.Command{
		Use:   "inspect <id>",
		Short: "Display detailed forensic report for a quarantined package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := sanitizer.NewQuarantineStore("")
			if err != nil {
				return err
			}

			rec, err := store.Inspect(args[0])
			if err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rec)
			}

			fmt.Printf("☣️  Quarantine Forensics Report: %s\n", rec.ID)
			fmt.Println(strings.Repeat("=", 60))
			fmt.Printf("Package:          %s\n", rec.Package)
			fmt.Printf("Version:          %s\n", rec.Version)
			fmt.Printf("Ecosystem:        %s\n", rec.Ecosystem)
			fmt.Printf("Risk Score:       %d/100 (%s)\n", rec.RiskScore, rec.RiskLevel)
			fmt.Printf("Quarantined At:   %s\n", rec.QuarantineTime.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("Raw Tarball:      %s (%d bytes)\n", rec.TarballPath, rec.TarballSize)
			fmt.Printf("SHA256:           %s\n", rec.SHA256)
			if rec.SourceURL != "" {
				fmt.Printf("Source URL:       %s\n", rec.SourceURL)
			}

			if len(rec.TriggeredRules) > 0 {
				fmt.Println("\nTriggered Heuristics:")
				for _, rule := range rec.TriggeredRules {
					fmt.Printf(" - %s\n", rule)
				}
			}

			if len(rec.ASTFindings) > 0 {
				fmt.Println("\nAST Threat Findings:")
				for _, finding := range rec.ASTFindings {
					fmt.Printf(" - %s\n", finding)
				}
			}

			return nil
		},
	})

	quarantineCmd.AddCommand(&cobra.Command{
		Use:   "purge",
		Short: "Delete all quarantined archives and forensic records",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := sanitizer.NewQuarantineStore("")
			if err != nil {
				return err
			}

			count, err := store.Purge()
			if err != nil {
				return fmt.Errorf("purge failed: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"purged_count": count,
					"status":       "success",
				})
			}

			fmt.Printf("🧹 Successfully purged %d quarantined records from %s\n", count, store.BaseDir())
			return nil
		},
	})

	return quarantineCmd
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
