package cli

import (
	"fmt"
	"strings"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
	"github.com/spf13/cobra"
)

var (
	explainAI        bool
	explainEcosystem string
)

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <package>",
		Short: "Explain slopsquatting risk and suggest safe alternative packages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkgName := args[0]
			cmd.Printf("Analyzing package: %s (ecosystem: %s)\n", pkgName, explainEcosystem)

			// Heuristic analysis
			heuristic := analyzePackageRiskHeuristic(pkgName, explainEcosystem)
			cmd.Println(heuristic)

			if explainAI {
				engine := shield.NewEngine(shield.DefaultConfig())
				prompt := fmt.Sprintf("Explain the supply-chain security risks for package %q in ecosystem %q. Analyze if it appears to be slopsquatted, hallucinated, or typo-squatted, and recommend the canonical packages.", pkgName, explainEcosystem)

				redacted, _, err := engine.Redact(prompt)
				if err != nil {
					return fmt.Errorf("failed to redact prompt: %w", err)
				}
				if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
					return fmt.Errorf("wire guard blocked outbound prompt: %w", err)
				}

				prov := provider.NewFromEnv()
				resp, err := prov.Complete(cmd.Context(), provider.Request{
					Model: "auto",
					Messages: []provider.Message{
						{Role: provider.RoleUser, Content: redacted},
					},
				})
				if err != nil {
					return fmt.Errorf("shield ai completion failed: %w", err)
				}

				cmd.Println("\n[Shield Protected AI Advisory]")
				cmd.Println(resp.Content)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&explainAI, "ai", false, "Use Shield-protected AI inference to explain supply-chain risks and canonical alternatives")
	cmd.Flags().StringVar(&explainEcosystem, "ecosystem", "npm", "Package ecosystem (npm, pypi, crates)")
	return cmd
}

func analyzePackageRiskHeuristic(pkg string, ecosystem string) string {
	lower := strings.ToLower(pkg)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Heuristic Assessment for %s [%s]:\n", pkg, ecosystem))

	knownSquats := map[string]string{
		"reqeusts":   "requests",
		"express-js": "express",
		"color-term": "chalk or colorette",
		"lodas-node": "lodash",
		"cryp-to":    "crypto-js",
	}

	if canonical, found := knownSquats[lower]; found {
		sb.WriteString(fmt.Sprintf("⚠️ HIGH RISK: %q is a known slopsquatted/typosquatted clone of canonical package %q.\n", pkg, canonical))
		sb.WriteString(fmt.Sprintf("Action: Do not install %q. Use %q instead.\n", pkg, canonical))
	} else if strings.Contains(lower, "test-") || strings.Contains(lower, "-temp") {
		sb.WriteString("⚠️ MODERATE RISK: Ephemeral or unvetted naming pattern detected.\n")
	} else {
		sb.WriteString("ℹ️ Package name does not match known slopsquat signatures. Verify author and download count before install.\n")
	}

	return sb.String()
}
