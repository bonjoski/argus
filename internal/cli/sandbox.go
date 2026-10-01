package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/sandbox"
)

var (
	sandboxAllowNet       bool
	sandboxAirgap         bool
	sandboxAllowedDomains []string
	sandboxKeepEnv        []string
	sandboxWorkDir        string
	sandboxVetStrict      bool
	sandboxAirlockBin     string
)

func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Execute processes in hardware-isolated sandboxes via Airlock",
		Long: `Argus Sandbox delegates workstation-level process and network isolation to Airlock
(https://github.com/bonjoski/airlock). Airlock enforces kernel isolation using Apple Seatbelt
on macOS and Landlock LSM/namespaces on Linux.

When invoked, Argus configures isolation parameters, strips sensitive host secrets, and runs
the target command in an ephemeral, isolated workspace.`,
	}

	cmd.PersistentFlags().StringVar(&sandboxAirlockBin, "airlock-bin", "", "Custom path to airlock binary executable")

	cmd.AddCommand(newSandboxRunCmd())
	cmd.AddCommand(newSandboxDoctorCmd())
	cmd.AddCommand(newSandboxStatusCmd())

	return cmd
}

func newSandboxRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Execute a command inside an isolated system sandbox via Airlock",
		Example: `  argus sandbox run -- npm install
  argus sandbox run --airgap -- cargo build
  argus sandbox run --allow-net --allow-domain registry.npmjs.org -- npm update
  argus sandbox run --workdir /tmp/project -- python setup.py build`,
		Args: cobra.MinimumNArgs(1),
		RunE: runSandboxRun,
	}

	cmd.Flags().BoolVar(&sandboxAllowNet, "allow-net", false, "Permit direct external outbound networking (development mode)")
	cmd.Flags().BoolVar(&sandboxAllowNet, "net", false, "Alias for --allow-net")
	cmd.Flags().BoolVar(&sandboxAirgap, "airgap", false, "Total offline isolation (denies all outbound network traffic)")
	cmd.Flags().StringSliceVar(&sandboxAllowedDomains, "allow-domain", nil, "Comma-separated list of additional permitted registry domains")
	cmd.Flags().StringSliceVar(&sandboxKeepEnv, "keep-env", nil, "Comma-separated list of environment variables to preserve")
	cmd.Flags().StringVar(&sandboxWorkDir, "workdir", "", "Working directory for sandboxed command (default: current directory)")
	cmd.Flags().StringVar(&sandboxWorkDir, "workspace", "", "Alias for --workdir")
	cmd.Flags().BoolVar(&sandboxVetStrict, "vet-strict", false, "Fail closed if Argus pre-flight intelligence flags high/critical risks")

	return cmd
}

func runSandboxRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified to run in sandbox")
	}

	workDir := sandboxWorkDir
	if workDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workDir = cwd
		}
	}

	profile := &sandbox.Profile{
		AllowNetwork:   sandboxAllowNet,
		Airgap:         sandboxAirgap,
		AllowedDomains: sandboxAllowedDomains,
		KeepEnvVars:    sandboxKeepEnv,
		Workspace:      workDir,
		VetStrict:      sandboxVetStrict,
	}

	engine := sandbox.NewBridge(sandboxAirlockBin)
	if !engine.Available() {
		return renderAirlockMissingError()
	}

	ctx := cmd.Context()
	command := args[0]
	cmdArgs := args[1:]

	res, err := engine.Run(ctx, profile, command, cmdArgs...)
	if err != nil {
		return fmt.Errorf("sandbox execution failed: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	if len(res.Stdout) > 0 {
		os.Stdout.Write(res.Stdout)
	}
	if len(res.Stderr) > 0 {
		os.Stderr.Write(res.Stderr)
	}

	if len(res.Violations) > 0 && !jsonOutput {
		fmt.Fprintf(os.Stderr, "\n🛡️ Argus/Airlock Sandbox Intercepted %d Violations:\n", len(res.Violations))
		for _, v := range res.Violations {
			fmt.Fprintf(os.Stderr, "  • %s\n", v)
		}
	}

	if res.ExitCode != 0 {
		os.Exit(res.ExitCode)
	}

	return nil
}

func newSandboxDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor [flags]",
		Short: "Diagnose host sandbox isolation capabilities and prerequisites",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine := sandbox.NewBridge(sandboxAirlockBin)
			if !engine.Available() {
				return renderAirlockMissingError()
			}

			workDir := sandboxWorkDir
			if workDir == "" {
				workDir, _ = os.Getwd()
			}

			report, err := engine.Doctor(cmd.Context(), workDir)
			if err != nil {
				return fmt.Errorf("failed diagnosing sandbox: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}

			headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58A6FF"))
			fmt.Println(headerStyle.Render(fmt.Sprintf("Airlock Sandbox Diagnostics (%s)", report.Platform)))
			fmt.Printf("  Workspace: %s\n", report.WorkspaceRoot)
			if report.Healthy {
				fmt.Printf("  Status:    %s (%d passed, %d warnings, %d failures)\n\n",
					lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("HEALTHY"),
					report.Passed, report.Warnings, report.Failures)
			} else {
				fmt.Printf("  Status:    %s (%d passed, %d warnings, %d failures)\n\n",
					lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F85149")).Render("UNHEALTHY"),
					report.Passed, report.Warnings, report.Failures)
			}

			for _, r := range report.Results {
				badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render(" PASS ")
				if r.Status == "WARN" {
					badge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E3B341")).Render(" WARN ")
				} else if r.Status == "FAIL" {
					badge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F85149")).Render(" FAIL ")
				}

				fmt.Printf("[%s] %s: %s\n", badge, r.Title, r.Details)
				if r.Recommendation != "" {
					fmt.Printf("         💡 %s\n", r.Recommendation)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&sandboxWorkDir, "workdir", "", "Target workspace root directory for diagnosis")
	cmd.Flags().StringVar(&sandboxWorkDir, "workspace", "", "Alias for --workdir")

	return cmd
}

func newSandboxStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Display Airlock sandbox binary location, version, and availability",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine := sandbox.NewBridge(sandboxAirlockBin)
			binPath, found := sandbox.FindAirlock()
			if sandboxAirlockBin != "" {
				binPath = sandboxAirlockBin
				found = engine.Available()
			}

			type statusInfo struct {
				Available  bool   `json:"available"`
				BinaryPath string `json:"binary_path,omitempty"`
				Version    string `json:"version,omitempty"`
			}

			info := statusInfo{
				Available:  found,
				BinaryPath: binPath,
			}

			if found {
				if ver, err := engine.Version(cmd.Context()); err == nil {
					info.Version = ver
				}
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Render("Argus Sandbox Bridge Status:"))
			if found {
				fmt.Printf("  Status:     %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ Airlock Connected"))
				fmt.Printf("  Binary:     %s\n", binPath)
				if info.Version != "" {
					fmt.Printf("  Version:    %s\n", info.Version)
				}
			} else {
				fmt.Printf("  Status:     %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8000")).Render("⚡ Airlock Not Detected"))
				fmt.Println("\nTo install Airlock for hardware sandboxing:")
				fmt.Println("  brew install bonjoski/airlock/airlock")
				fmt.Println("  go install github.com/bonjoski/airlock/cmd/airlock@latest")
				fmt.Println("  https://github.com/bonjoski/airlock")
			}
			return nil
		},
	}
}

func renderAirlockMissingError() error {
	return fmt.Errorf("airlock binary not found\n\n" +
		"Argus relies on Airlock (https://github.com/bonjoski/airlock) for kernel process & network sandboxing.\n" +
		"To install:\n" +
		"  brew install bonjoski/airlock/airlock\n" +
		"  go install github.com/bonjoski/airlock/cmd/airlock@latest\n" +
		"  or set ARGUS_AIRLOCK_BIN=/path/to/airlock")
}
