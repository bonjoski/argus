package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	GitCommit = "none"
	BuildDate = "unknown"

	jsonOutput  bool
	sarifOutput bool
	strictMode  bool
	threshold   int
	noCache     bool
	force       bool
)

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus (vetpkg): Pre-Flight Dependency Provenance & Slopsquatting Interceptor",
	Long: `Argus is a fast, ecosystem-agnostic, zero-SaaS CLI tool designed to inspect
package provenance and intercept hallucinated or slopsquatted dependencies before
they are installed by developers or autonomous AI coding agents.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildDate),
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	rootCmd.PersistentFlags().BoolVar(&sarifOutput, "sarif", false, "Output results in OASIS SARIF v2.1.0 format")
	rootCmd.PersistentFlags().BoolVar(&strictMode, "strict", false, "Strict mode: fail on HIGH (>=60) risk scores in addition to CRITICAL")
	rootCmd.PersistentFlags().IntVar(&threshold, "threshold", 50, "Risk score threshold to trigger hard blocking (default: 50)")
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Bypass local SQLite cache and force fresh upstream query")
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force installation even if package risk score is CRITICAL (>=80)")

	rootCmd.AddCommand(newVetCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newShimCmd())
	rootCmd.AddCommand(newDaemonCmd())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
