package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/sandbox"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/shim"
	"bonjoski/argus/internal/vcs"
)

var (
	customShimDir string
	shimSandbox   bool
)

func newShimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shim",
		Short: "Manage PATH-prepend proxy shims for non-interactive agent interception",
	}

	cmd.PersistentFlags().StringVar(&customShimDir, "dir", "", "Target directory for shims (default: ~/.argus/bin)")
	cmd.PersistentFlags().BoolVar(&shimSandbox, "sandbox", false, "Enforce system sandbox hardware isolation during command execution")

	cmd.AddCommand(newShimInstallCmd())
	cmd.AddCommand(newShimUninstallCmd())
	cmd.AddCommand(newShimStatusCmd())
	cmd.AddCommand(newShimExecCmd())

	return cmd
}

func getTargetShimDir() (string, error) {
	if customShimDir != "" {
		return customShimDir, nil
	}
	return shim.DefaultShimDir()
}

func newShimInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Generate and install executable shims in ~/.argus/bin",
		RunE: func(cmd *cobra.Command, args []string) error {
			shimDir, err := getTargetShimDir()
			if err != nil {
				return err
			}

			execPath, _ := os.Executable()
			if err := shim.Install(shimDir, execPath); err != nil {
				return fmt.Errorf("failed to install shims: %w", err)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Argus shims successfully installed:"))
			fmt.Printf("  Directory: %s\n", shimDir)
			fmt.Printf("  Tools:     %v\n\n", shim.SupportedTools)
			fmt.Println("To activate subshell protection for current environment, add to PATH:")
			fmt.Printf("  %s\n", lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("export PATH=%q:$PATH", shimDir)))
			return nil
		},
	}
}

func newShimUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall",
		Aliases: []string{"remove", "rm"},
		Short:   "Remove Argus proxy shims from ~/.argus/bin",
		RunE: func(cmd *cobra.Command, args []string) error {
			shimDir, err := getTargetShimDir()
			if err != nil {
				return err
			}

			if err := shim.Uninstall(shimDir); err != nil {
				return fmt.Errorf("failed to uninstall shims: %w", err)
			}

			fmt.Println("✔ Argus proxy shims uninstalled from:", shimDir)
			return nil
		},
	}
}

func newShimStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Inspect status and PATH presence of Argus shims",
		RunE: func(cmd *cobra.Command, args []string) error {
			shimDir, err := getTargetShimDir()
			if err != nil {
				return err
			}

			stat := shim.Status(shimDir)
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(stat)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Render("Argus PATH Shim Status:"))
			fmt.Printf("  Directory:   %s\n", stat.Directory)
			fmt.Printf("  Installed:   %d / %d tools\n", len(stat.Installed), len(shim.SupportedTools))
			if stat.IsInPath {
				fmt.Println("  PATH State:  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ Active in system $PATH"))
			} else {
				fmt.Println("  PATH State:  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8000")).Render("⚡ Not prepended to current $PATH"))
				fmt.Printf("               Run: %s\n", stat.ExportString)
			}
			return nil
		},
	}
}

func newShimExecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "exec <tool> [args...]",
		Short:  "Internal dispatcher invoked by shims",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE:   runShimExec,
	}
	// Disable flag parsing so all tool flags pass through intact
	cmd.DisableFlagParsing = true
	return cmd
}

func runShimExec(cmd *cobra.Command, args []string) error {
	tool := args[0]
	toolArgs := args[1:]

	shimDir, err := getTargetShimDir()
	if err != nil {
		shimDir = ""
	}

	// 1. Detect if this invocation is installing packages
	eco, targets, isInstall := shim.ExtractTargets(tool, toolArgs)

	if isInstall && len(targets) > 0 {
		ctx := context.Background()

		// Fast path: Check if resident daemon is active on IPC socket
		var daemonClient *daemon.Client
		if defaultSock, _, _, err := daemon.DefaultPaths(); err == nil {
			dc := daemon.NewClient(defaultSock).WithTimeout(300 * time.Millisecond)
			if dc.Ping(ctx) == nil {
				daemonClient = dc
			}
		}

		var vettingService *service.VettingService
		if daemonClient == nil {
			// Fallback: Initialize In-Process Vetting Service
			var cacheStore cache.Store
			dbPath, err := cache.DefaultCachePath()
			if err == nil {
				cacheStore, _ = cache.NewSQLiteStore(dbPath)
			}
			if cacheStore != nil {
				defer cacheStore.Close()
			}

			adapters := registry.DefaultAdapters()

			vcsVerifier := vcs.NewHTTPVerifier(nil)
			evaluator := heuristics.DefaultEngine()
			vettingService = service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)
		}

		for _, spec := range targets {
			pkgName, version := parsePackageSpec(spec)
			if pkgName == "" {
				continue
			}

			var report *model.RiskReport
			var err error

			if daemonClient != nil {
				report, err = daemonClient.Vet(ctx, eco, pkgName, version, false)
			}
			if report == nil && vettingService != nil {
				report, err = vettingService.Vet(ctx, eco, pkgName, version)
			}

			if err != nil {
				// Registry not found or resolution error
				fmt.Fprintf(os.Stderr, "⛔ ARGUS INTERCEPT: Dependency %q failed resolution: %v\n", spec, err)
				os.Exit(1)
			}

			if report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintf(os.Stderr, "⛔ ARGUS INTERCEPT: Blocked installation of untrusted dependency!\n")
				fmt.Fprintf(os.Stderr, "   Package:    %s:%s@%s\n", report.Ecosystem, report.Package, report.ResolvedVersion)
				fmt.Fprintf(os.Stderr, "   Risk Score: %d/100 (%s)\n", report.TotalScore, report.RiskLevel)
				for _, p := range report.Penalties {
					if p.Triggered {
						fmt.Fprintf(os.Stderr, "     • [+%2d pts] %s (%s)\n", p.Points, p.Name, p.RuleID)
					}
				}
				fmt.Fprintf(os.Stderr, "   Action:     Execution halted before package manager was invoked.\n\n")
				os.Exit(1)
			}
		}
	}

	// 2. Delegate to real underlying binary
	realBinary, err := shim.FindRealBinary(tool, shimDir)
	if err != nil {
		return fmt.Errorf("argus shim failed to locate real binary for %s: %w", tool, err)
	}

	if shimSandbox || os.Getenv("ARGUS_SANDBOX") == "1" || os.Getenv("ARGUS_SANDBOX") == "true" {
		cwd, _ := os.Getwd()
		profile := &sandbox.Profile{
			AllowNetwork: true,
			Workspace:    cwd,
		}
		engine := sandbox.NewEngine()
		res, err := engine.Run(context.Background(), profile, realBinary, toolArgs...)
		if err != nil {
			return fmt.Errorf("sandboxed execution failed: %w", err)
		}
		if len(res.Stdout) > 0 {
			os.Stdout.Write(res.Stdout)
		}
		if len(res.Stderr) > 0 {
			os.Stderr.Write(res.Stderr)
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}
		return nil
	}

	execCmd := exec.Command(realBinary, toolArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		os.Exit(1)
	}

	return nil
}
