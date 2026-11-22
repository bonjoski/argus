package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/version"
	"bonjoski/argus/pkg/ux"
)

var (
	Version   = version.Version
	GitCommit = version.GitCommit
	BuildDate = version.BuildDate

	jsonOutput  bool
	sarifOutput bool
	whyOutput   bool
	strictMode  bool
	threshold   int
	noCache     bool
	force       bool
)

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus: Pre-Flight Dependency Provenance & Slopsquatting Interceptor",
	Long: `Argus is a fast, ecosystem-agnostic, zero-SaaS CLI tool designed to inspect
package provenance and intercept hallucinated or slopsquatted dependencies before
they are installed by developers or autonomous AI coding agents.`,
	Version:       version.Formatted(),
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	if Version != "" && (Version != version.Version || GitCommit != "none" || BuildDate != "unknown") {
		rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
	}
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	rootCmd.PersistentFlags().BoolVar(&sarifOutput, "sarif", false, "Output results in OASIS SARIF v2.1.0 format")
	rootCmd.PersistentFlags().BoolVar(&whyOutput, "why", false, "Show progressive disclosure explanation, Quarry signals, and CWE/OWASP references")
	rootCmd.PersistentFlags().BoolVar(&strictMode, "strict", false, "Strict mode: fail on HIGH (>=60) risk scores in addition to CRITICAL")
	rootCmd.PersistentFlags().IntVar(&threshold, "threshold", 50, "Risk score threshold to trigger hard blocking (default: 50)")
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Bypass local SQLite cache and force fresh upstream query")
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force installation even if package risk score is CRITICAL (>=80)")

	rootCmd.AddCommand(newVetCmd())
	rootCmd.AddCommand(newAddCmd())
	rootCmd.AddCommand(newDiffCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newShimCmd())
	rootCmd.AddCommand(newDaemonCmd())
	rootCmd.AddCommand(newMirrorCmd())
	rootCmd.AddCommand(newSanitizeCmd())
	rootCmd.AddCommand(newQuarantineCmd())
	rootCmd.AddCommand(newSandboxCmd())
	rootCmd.AddCommand(newTestCmd())
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of argus",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(rootCmd.Version)
		},
	})
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		var ffe *ux.FixForwardError
		if errors.As(err, &ffe) {
			_ = ffe.Render(os.Stderr, jsonOutput, whyOutput)
			code := ffe.ExitCode
			if code == 0 {
				code = 1
			}
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
