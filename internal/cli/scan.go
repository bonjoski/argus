package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <lockfile>",
		Short: "Perform transitive provenance scan across a project lockfile",
		Example: `  argus scan package-lock.json
  argus scan Cargo.lock --json
  argus scan poetry.lock --sarif
  argus scan go.sum --strict`,
		Args: cobra.ExactArgs(1),
		RunE: runScan,
	}
}

type scanSummary struct {
	TotalScanned int                 `json:"total_scanned"`
	CleanCount   int                 `json:"clean_count"`
	WarningCount int                 `json:"warning_count"`
	BlockedCount int                 `json:"blocked_count"`
	Reports      []*model.RiskReport `json:"reports"`
}

func runScan(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open lockfile: %w", err)
	}
	defer f.Close()

	parser, eco, err := lockfile.Detect(filePath)
	if err != nil {
		return fmt.Errorf("lockfile detection failed: %w", err)
	}

	deps, err := parser.Parse(f)
	if err != nil {
		return fmt.Errorf("lockfile parsing failed: %w", err)
	}

	if len(deps) == 0 {
		fmt.Printf("Notice: No dependencies found in %s\n", filePath)
		return nil
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

	adapters := registry.DefaultAdapters()

	vcsVerifier := vcs.NewHTTPVerifier(nil)
	evaluator := heuristics.DefaultEngine()
	vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Concurrently vet dependencies with bounded worker pool
	const workerCount = 5
	jobs := make(chan lockfile.LockedDependency, len(deps))
	results := make(chan *model.RiskReport, len(deps))

	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dep := range jobs {
				targetEco := dep.Ecosystem
				if targetEco == "" {
					targetEco = eco
				}
				report, err := vettingService.Vet(ctx, targetEco, dep.Name, dep.Version)
				if err != nil {
					// Record synthetic error report
					report = &model.RiskReport{
						Package:         dep.Name,
						Ecosystem:       targetEco,
						ResolvedVersion: dep.Version,
						TotalScore:      60,
						RiskLevel:       model.RiskLevelHigh,
						Penalties: []model.HeuristicFinding{
							{
								RuleID:      "HR-05A",
								Name:        "Unresolved Dependency",
								Points:      60,
								Description: fmt.Sprintf("Failed to resolve from upstream registry: %v", err),
								Triggered:   true,
							},
						},
					}
				}
				results <- report
			}
		}()
	}

	for _, dep := range deps {
		jobs <- dep
	}
	close(jobs)

	wg.Wait()
	close(results)

	var allReports []*model.RiskReport
	var cleanCount, warningCount, blockedCount int

	for report := range results {
		allReports = append(allReports, report)
		switch {
		case report.TotalScore < 30:
			cleanCount++
		case report.TotalScore >= threshold || report.RiskLevel == model.RiskLevelCritical:
			blockedCount++
		default:
			warningCount++
		}
	}

	summary := scanSummary{
		TotalScanned: len(allReports),
		CleanCount:   cleanCount,
		WarningCount: warningCount,
		BlockedCount: blockedCount,
		Reports:      allReports,
	}

	// Output Formatting
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			return fmt.Errorf("failed to encode JSON output: %w", err)
		}
	} else if sarifOutput {
		sarifRep := output.SARIFReporter{Version: Version}
		// Wrap first or combine all flagged reports into SARIF
		for _, rep := range allReports {
			if rep.TotalScore >= 30 {
				_ = sarifRep.Render(os.Stdout, rep)
			}
		}
	} else {
		renderScanSummary(os.Stdout, filePath, summary)
	}

	// Exit Code Policies
	if force {
		return nil
	}

	if blockedCount > 0 {
		os.Exit(1)
	}

	if strictMode && warningCount > 0 {
		os.Exit(2)
	}

	return nil
}

func renderScanSummary(w *os.File, filePath string, s scanSummary) {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	fmt.Fprintf(w, "%s %s (%d packages scanned)\n\n",
		headerStyle.Render("ARGUS SCAN"),
		lipgloss.NewStyle().Bold(true).Render(filePath),
		s.TotalScanned,
	)

	fmt.Fprintf(w, "  ✔ Clean / Verified:  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render(fmt.Sprintf("%d", s.CleanCount)))
	if s.WarningCount > 0 {
		fmt.Fprintf(w, "  ⚠ Suspicious:        %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD535")).Render(fmt.Sprintf("%d", s.WarningCount)))
	}
	if s.BlockedCount > 0 {
		fmt.Fprintf(w, "  ⛔ Hard Blocked:      %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render(fmt.Sprintf("%d", s.BlockedCount)))
	}
	fmt.Fprintln(w)

	// List flagged packages
	if s.WarningCount > 0 || s.BlockedCount > 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Underline(true).Render("Flagged Dependencies:"))
		for _, r := range s.Reports {
			if r.TotalScore >= 30 {
				color := "#FCD535"
				if r.TotalScore >= 80 {
					color = "#F8312F"
				}
				badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(color)).Render(fmt.Sprintf("[%d/100 %s]", r.TotalScore, r.RiskLevel))
				fmt.Fprintf(w, "  • %-32s %s\n", fmt.Sprintf("%s@%s", r.Package, r.ResolvedVersion), badge)
				for _, p := range r.Penalties {
					if p.Triggered {
						fmt.Fprintf(w, "      [+%2d] %s (%s)\n", p.Points, p.Name, p.RuleID)
					}
				}
			}
		}
		fmt.Fprintln(w)
	}

	if s.BlockedCount == 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ All lockfile dependencies passed provenance thresholds."))
	} else {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("⛔ Pre-flight lockfile scan failed. Malicious or hallucinated dependencies detected."))
	}
}
