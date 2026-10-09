package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/shim"
	"bonjoski/argus/internal/vcs"
)

func newAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [tool] <package...>",
		Short: "Up-front safe package installation with pre-flight provenance vetting",
		Long: `Argus Add provides up-front dependency protection before package manager invocation.
It verifies package provenance and intercepts hallucinated or slopsquatted dependencies.
If all targets pass vetting thresholds, it delegates directly to the underlying package manager.`,
		Example: `  argus add npm express
  argus add pip requests
  argus add cargo serde
  argus add go github.com/gin-gonic/gin
  argus add express  # Auto-detects npm if package.json is present`,
		Args: cobra.MinimumNArgs(1),
		RunE: runAdd,
	}
}

func runAdd(cmd *cobra.Command, args []string) error {
	tool, eco, targets := resolveToolAndTargets(args)
	if len(targets) == 0 {
		return fmt.Errorf("no package targets specified to install")
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Pre-Flight Vetting Phase
	bannerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	fmt.Printf("%s Vetting %d dependency target(s) for %s...\n\n",
		bannerStyle.Render("ARGUS PRE-FLIGHT"),
		len(targets),
		eco,
	)

	// Check resident daemon IPC fast-path
	var daemonClient *daemon.Client
	if !noCache {
		if defaultSock, _, _, pErr := daemon.DefaultPaths(); pErr == nil {
			dc := daemon.NewClient(defaultSock).WithTimeout(1 * time.Second)
			if dc.Ping(ctx) == nil {
				daemonClient = dc
			}
		}
	}

	var vettingService *service.VettingService
	if daemonClient == nil {
		var cacheStore cache.Store
		if !noCache {
			dbPath, cErr := cache.DefaultCachePath()
			if cErr == nil {
				cacheStore, _ = cache.NewSQLiteStore(dbPath)
			}
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
			// Registry 404 / resolution error: slopsquat or non-existent package
			fmt.Fprintf(os.Stderr, "⛔ ARGUS PRE-FLIGHT BLOCK: Package %q could not be resolved from %s registry: %v\n", spec, eco, err)
			fmt.Fprintf(os.Stderr, "   Halting before package manager execution to prevent slopsquatting/hallucination risk.\n\n")
			os.Exit(1)
		}

		if report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical {
			fmt.Fprintf(os.Stderr, "⛔ ARGUS PRE-FLIGHT BLOCK: Package %q is untrusted or slopsquatted!\n", spec)
			fmt.Fprintf(os.Stderr, "   Risk Score: %d/100 (%s)\n", report.TotalScore, report.RiskLevel)
			for _, p := range report.Penalties {
				if p.Triggered {
					fmt.Fprintf(os.Stderr, "     • [+%2d pts] %s (%s)\n", p.Points, p.Name, p.RuleID)
				}
			}
			fmt.Fprintf(os.Stderr, "   Halting execution before %s is invoked.\n\n", tool)
			os.Exit(1)
		}

		fmt.Printf("  ✔ [%s] %s (risk: %d/100 %s)\n", eco, pkgName, report.TotalScore, report.RiskLevel)
	}

	fmt.Printf("\n%s All targets verified. Invoking %s...\n\n",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ SAFE TO INSTALL:"),
		tool,
	)

	// 2. Execution Delegation Phase
	realBinary, err := shim.FindRealBinary(tool, "")
	if err != nil {
		return fmt.Errorf("failed to locate underlying binary %q: %w", tool, err)
	}

	subCmdArgs := buildSubcommandArgs(tool, targets)
	runCmd := exec.CommandContext(ctx, realBinary, subCmdArgs...)
	runCmd.Stdin = os.Stdin
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	if err := runCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed executing %s: %w", tool, err)
	}

	return nil
}

func resolveToolAndTargets(args []string) (tool string, eco model.Ecosystem, targets []string) {
	first := strings.ToLower(args[0])
	switch first {
	case "npm", "npx":
		return first, model.EcosystemNPM, args[1:]
	case "pnpm", "yarn", "bun":
		return first, model.EcosystemNPM, args[1:]
	case "pip", "pip3", "python":
		return "pip", model.EcosystemPyPI, args[1:]
	case "pypi":
		return "pip", model.EcosystemPyPI, args[1:]
	case "cargo", "crates", "rust":
		return "cargo", model.EcosystemCargo, args[1:]
	case "go", "golang":
		return "go", model.EcosystemGo, args[1:]
	case "gem", "ruby":
		return "gem", model.EcosystemRubyGems, args[1:]
	case "composer", "packagist", "php":
		return "composer", model.EcosystemPackagist, args[1:]
	}

	// Auto-detect tool from manifest in current directory
	if _, err := os.Stat("package.json"); err == nil {
		return "npm", model.EcosystemNPM, args
	}
	if _, err := os.Stat("requirements.txt"); err == nil {
		return "pip", model.EcosystemPyPI, args
	}
	if _, err := os.Stat("pyproject.toml"); err == nil {
		return "pip", model.EcosystemPyPI, args
	}
	if _, err := os.Stat("Cargo.toml"); err == nil {
		return "cargo", model.EcosystemCargo, args
	}
	if _, err := os.Stat("go.mod"); err == nil {
		return "go", model.EcosystemGo, args
	}

	// Default fallback to npm
	return "npm", model.EcosystemNPM, args
}

func buildSubcommandArgs(tool string, targets []string) []string {
	switch tool {
	case "npm":
		return append([]string{"install"}, targets...)
	case "pnpm", "yarn", "bun":
		return append([]string{"add"}, targets...)
	case "pip", "pip3":
		return append([]string{"install"}, targets...)
	case "cargo":
		return append([]string{"add"}, targets...)
	case "go":
		return append([]string{"get"}, targets...)
	case "gem":
		return append([]string{"install"}, targets...)
	case "composer":
		return append([]string{"require"}, targets...)
	default:
		return append([]string{"install"}, targets...)
	}
}
