package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
	"bonjoski/argus/internal/policy"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

func newVetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vet <ecosystem> <package>[@version]",
		Short: "Inspect provenance and compute risk score for a package",
		Example: `  argus vet npm express
  argus vet npm @angular/core@17.0.0
  argus vet pypi requests
  argus vet pypi langchain-super-tool --strict`,
		Args: cobra.ExactArgs(2),
		RunE: runVet,
	}
}

func parsePackageSpec(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "@") {
		// Scoped package like @scope/pkg@1.0.0
		rest := spec[1:]
		atIdx := strings.LastIndex(rest, "@")
		if atIdx != -1 {
			return "@" + rest[:atIdx], rest[atIdx+1:]
		}
		return spec, ""
	}

	atIdx := strings.Index(spec, "@")
	if atIdx != -1 {
		return spec[:atIdx], spec[atIdx+1:]
	}
	return spec, ""
}

func runVet(cmd *cobra.Command, args []string) error {
	ecoStr := strings.ToLower(args[0])
	var eco model.Ecosystem
	switch ecoStr {
	case "npm":
		eco = model.EcosystemNPM
	case "pypi", "pip", "python":
		eco = model.EcosystemPyPI
	case "cargo", "crates", "rust":
		eco = model.EcosystemCargo
	case "go", "golang":
		eco = model.EcosystemGo
	case "rubygems", "gem", "ruby":
		eco = model.EcosystemRubyGems
	case "maven", "mvn":
		eco = model.EcosystemMaven
	case "packagist", "composer", "php":
		eco = model.EcosystemPackagist
	default:
		return fmt.Errorf("unsupported ecosystem %q (supported: npm, pypi, cargo, go, rubygems, maven, packagist)", ecoStr)
	}

	pkgName, version := parsePackageSpec(args[1])
	if pkgName == "" {
		return fmt.Errorf("invalid package specification: %s", args[1])
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Load enterprise policy (.argusrc.yaml) if available
	entPolicy, _ := policy.Load("")
	if entPolicy != nil {
		if entPolicy.Threshold > 0 && !cmd.Flags().Changed("threshold") {
			threshold = entPolicy.Threshold
		}
		if entPolicy.Strict && !cmd.Flags().Changed("strict") {
			strictMode = entPolicy.Strict
		}

		// Pre-flight blocklist check
		if blocked, reason := entPolicy.MatchBlocklist(pkgName, ""); blocked {
			return fmt.Errorf("POLICY BLOCK: %s", reason)
		}
	}

	var report *model.RiskReport
	var err error

	// Fast path: Query resident daemon over IPC if running and no-cache is false
	if !noCache {
		if defaultSock, _, _, pErr := daemon.DefaultPaths(); pErr == nil {
			dc := daemon.NewClient(defaultSock).WithTimeout(1 * time.Second)
			if dc.Ping(ctx) == nil {
				report, err = dc.Vet(ctx, eco, pkgName, version, false)
			}
		}
	}

	// Fallback to in-process service if daemon was not active or did not provide report
	if report == nil {
		// Initialize Cache Store
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

		// Initialize Adapters
		adapters := []registry.Adapter{
			registry.NewNPMAdapter(nil),
			registry.NewPyPIAdapter(nil),
			registry.NewCratesAdapter(nil),
			registry.NewGoModAdapter(nil),
			registry.NewRubyGemsAdapter(nil),
			registry.NewMavenAdapter(nil),
			registry.NewPackagistAdapter(nil),
		}

		vcsVerifier := vcs.NewHTTPVerifier(nil)
		evaluator := heuristics.DefaultEngine()
		vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

		report, err = vettingService.Vet(ctx, eco, pkgName, version)
		if err != nil {
			return fmt.Errorf("vetting failed: %w", err)
		}
	}

	// Post-evaluation allowlist override
	if entPolicy != nil {
		if allowed, reason := entPolicy.MatchAllowlist(pkgName, report.Provenance.AuthorName); allowed {
			report.TotalScore = 0
			report.RiskLevel = model.RiskLevelLow
			report.Offsets = append(report.Offsets, model.MitigatingOffsetFinding{
				OffsetID:    "MO-POLICY",
				Name:        "Enterprise Allowlist Exemption",
				Credits:     100,
				Description: reason,
				Triggered:   true,
			})
		}
	}

	// Output Formatting
	var reporter output.Reporter = output.TTYReporter{}
	if jsonOutput {
		reporter = output.JSONReporter{}
	} else if sarifOutput {
		reporter = output.SARIFReporter{Version: Version}
	}

	if err := reporter.Render(os.Stdout, report); err != nil {
		return fmt.Errorf("rendering output failed: %w", err)
	}

	// Interactive TTY Mode Check
	isInteractive := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) && !jsonOutput && !sarifOutput

	if isInteractive {
		switch {
		case report.TotalScore < 30:
			// Score < 30: Clean (Green) -> proceed cleanly
			return nil
		case report.TotalScore >= 30 && report.TotalScore < 80:
			// Score 30 - 79: Suspicious (Yellow) -> prompt [y/N] confirmation in interactive TTY
			fmt.Printf("\n⚠ Package risk score is %d/100 (Suspicious). Proceed with installation? [y/N]: ", report.TotalScore)
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				response = ""
			}
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "y" || response == "yes" {
				fmt.Println("Proceeding with installation upon user confirmation.")
				return nil
			}
			fmt.Println("Installation aborted by user.")
			os.Exit(1)
		default:
			// Score >= 80: Critical Threat (Red) -> hard block; requires --force
			if force {
				fmt.Printf("\n⚡ Warning: Critical threat (%d/100) overridden with --force. Proceeding.\n", report.TotalScore)
				return nil
			}
			fmt.Printf("\n⛔ Hard Block: Critical risk score %d/100 (>= 80). Installation aborted. (Override with --force)\n", report.TotalScore)
			os.Exit(1)
		}
	}

	// Non-Interactive / CI Policies
	if force {
		return nil
	}

	if report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical {
		os.Exit(1)
	}

	if strictMode && report.RiskLevel == model.RiskLevelHigh {
		os.Exit(2)
	}

	return nil
}
