package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
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
	case "pypi", "pip":
		eco = model.EcosystemPyPI
	case "cargo", "crates", "rust":
		eco = model.EcosystemCargo
	case "go", "golang":
		eco = model.EcosystemGo
	default:
		return fmt.Errorf("unsupported ecosystem %q (supported: npm, pypi, cargo, go)", ecoStr)
	}

	pkgName, version := parsePackageSpec(args[1])
	if pkgName == "" {
		return fmt.Errorf("invalid package specification: %s", args[1])
	}

	// Initialize Cache Store
	var cacheStore cache.Store
	if !noCache {
		dbPath, err := cache.DefaultCachePath()
		if err == nil {
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
	}

	vcsVerifier := vcs.NewHTTPVerifier(nil)
	evaluator := heuristics.DefaultEngine()

	vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	report, err := vettingService.Vet(ctx, eco, pkgName, version)
	if err != nil {
		return fmt.Errorf("vetting failed: %w", err)
	}

	// Output Formatting
	var reporter output.Reporter = output.TTYReporter{}
	if jsonOutput {
		reporter = output.JSONReporter{}
	}

	if err := reporter.Render(os.Stdout, report); err != nil {
		return fmt.Errorf("rendering output failed: %w", err)
	}

	// Exit Code Policies
	if report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical {
		os.Exit(1)
	}

	if strictMode && report.RiskLevel == model.RiskLevelHigh {
		os.Exit(2)
	}

	return nil
}
