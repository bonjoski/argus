package cli

import (
	"fmt"
	"strings"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
	"github.com/spf13/cobra"

	"bonjoski/argus/pkg/quarry"
	"bonjoski/argus/pkg/ux"
)

var (
	explainAI        bool
	explainEcosystem string
	explainWhy       bool
	explainJSON      bool
)

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain [package-or-topic]",
		Short: "Explain slopsquatting risk with calm UB-CLI-v2 Fix-Forward suggestions and --why breakdown",
		Example: `  argus explain
  argus explain reqeusts --ecosystem pypi
  argus explain opneai --ecosystem npm --why
  argus explain opneai --ecosystem npm --json
  argus explain argus_slopsquat_suspect`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			defer func() {
				explainAI = false
				explainWhy = false
				explainJSON = false
				explainEcosystem = "npm"
				_ = cmd.Flags().Set("ai", "false")
				_ = cmd.Flags().Set("why", "false")
				_ = cmd.Flags().Set("json", "false")
				_ = cmd.Flags().Set("ecosystem", "npm")
			}()

			pkgName := "argus_slopsquat_suspect"
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				pkgName = args[0]
			}
			asJSON := jsonOutput || explainJSON
			showWhy := whyOutput || explainWhy

			// Topic-based progressive disclosure (e.g., `argus explain argus_slopsquat_suspect`)
			if topic := lookupExplainTopic(pkgName); topic != nil {
				return topic.Render(cmd.OutOrStdout(), asJSON, true)
			}

			// Structured UB-CLI-v2 JSON mode
			if asJSON {
				ffe := buildExplainFixForward(pkgName, explainEcosystem)
				return ffe.Render(cmd.OutOrStdout(), true, showWhy)
			}

			// Calm UB-CLI-v2 Fix-Forward spellchecker output (preserving heuristic signal for callers)
			ffe := buildExplainFixForward(pkgName, explainEcosystem)
			if err := ffe.Render(cmd.OutOrStdout(), false, showWhy); err != nil {
				return err
			}

			heuristic := analyzePackageRiskHeuristic(pkgName, explainEcosystem)
			if showWhy || strings.Contains(heuristic, "HIGH RISK") {
				cmd.Println(heuristic)
			}

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
	cmd.Flags().StringVar(&explainEcosystem, "ecosystem", "npm", "Package ecosystem (npm, pypi, cargo, go)")
	cmd.Flags().BoolVar(&explainWhy, "why", false, "Show full Quarry provenance signals and CWE/OWASP LLM references")
	cmd.Flags().BoolVar(&explainJSON, "json", false, "Emit structured UB-CLI-v2 FixForwardError JSON")
	return cmd
}

func lookupExplainTopic(topic string) *ux.FixForwardError {
	switch strings.ToLower(strings.TrimSpace(topic)) {
	case "argus_slopsquat_suspect", "slopsquat", "typosquat":
		return &ux.FixForwardError{
			Tool:           "argus",
			Code:           "ARGUS_SLOPSQUAT_SUSPECT",
			Summary:        "Pre-flight AI slopsquatting & typosquatting spellchecker",
			RemediationCmd: "argus explain <package> --ecosystem npm --why",
			WhyOneLiner:    "Catches hallucinated or typosquatted package names before install hooks execute.",
			DeepWhy:        "LLMs frequently hallucinate plausible package names or transpose letters (e.g., opneai, reqeusts, reactDom). Adversaries register those names with postinstall scripts that read ~/.ssh, ~/.aws, and .env. Argus runs local Levenshtein + Quarry heuristics and only suggests allowlist-verified canonical package names.",
			References:     []string{"OWASP-LLM03", "CWE-829"},
			ExitCode:       0,
		}
	default:
		return nil
	}
}

func buildExplainFixForward(pkgName, ecosystem string) *ux.FixForwardError {
	detail := ""
	if isHall, target, pattern := quarry.DetectNameHallucination(pkgName); isHall {
		detail = fmt.Sprintf("Quarry detected %s (canonical target: %s)", pattern, target)
	}
	ffe := ux.NewSpellcheckFixForward(ecosystem, pkgName, detail, 0, 0)
	ffe.ExitCode = 0
	return ffe
}

func analyzePackageRiskHeuristic(pkg string, ecosystem string) string {
	cleanPkg := ux.SanitizeTerminalText(pkg)
	lower := strings.ToLower(cleanPkg)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Heuristic Assessment for %s [%s]:\n", cleanPkg, ux.SanitizeTerminalText(ecosystem)))

	if suggested, _, reason := ux.SuggestCanonicalPackage(ecosystem, pkg); suggested != "" {
		sb.WriteString(fmt.Sprintf("⚠️ HIGH RISK: %q matches a likely typosquat/slopsquat of canonical package %q (%s).\n", cleanPkg, suggested, reason))
		if safeCmd := ux.BuildSafeInstallCommand(ecosystem, suggested); safeCmd != "" {
			sb.WriteString(fmt.Sprintf("Action: Do not install %q. Run `%s` instead.\n", cleanPkg, safeCmd))
		}
	} else if isHall, target, pattern := quarry.DetectNameHallucination(pkg); isHall {
		sb.WriteString(fmt.Sprintf("⚠️ HIGH RISK: %q flagged by Quarry (%s).\n", cleanPkg, ux.SanitizeTerminalText(pattern)))
		if ux.ValidateRemediationToken(target) {
			if safeCmd := ux.BuildSafeInstallCommand(ecosystem, target); safeCmd != "" {
				sb.WriteString(fmt.Sprintf("Action: Verify canonical package %q (`%s`).\n", target, safeCmd))
			}
		}
	} else if strings.Contains(lower, "test-") || strings.Contains(lower, "-temp") {
		sb.WriteString("⚠️ MODERATE RISK: Ephemeral or unvetted naming pattern detected.\n")
	} else {
		sb.WriteString("ℹ️ Package name does not match known slopsquat signatures. Verify author and download count before install.\n")
	}

	return sb.String()
}
