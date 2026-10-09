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

	"bonjoski/argus/internal/ast"
	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/gitdiff"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

var (
	diffCached bool
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff [workdir]",
		Short: "Inspect git diff (working tree or staged) and vet newly introduced source imports",
		Long: `Argus Diff parses git diff changes across Python, JavaScript/TypeScript, and Go,
extracts added import statements, normalizes them to registry distribution packages,
and verifies provenance before commit.`,
		Example: `  argus diff
  argus diff --cached
  argus diff --cached --strict
  argus diff --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDiff,
	}

	cmd.Flags().BoolVar(&diffCached, "cached", false, "Inspect staged changes (git diff --cached)")

	return cmd
}

type diffSummary struct {
	TotalScanned int                 `json:"total_scanned"`
	CleanCount   int                 `json:"clean_count"`
	WarningCount int                 `json:"warning_count"`
	BlockedCount int                 `json:"blocked_count"`
	Reports      []*model.RiskReport `json:"reports"`
}

func runDiff(cmd *cobra.Command, args []string) error {
	workDir := ""
	if len(args) > 0 {
		workDir = args[0]
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	candidates, err := gitdiff.InspectDiff(ctx, nil, workDir, diffCached)
	if err != nil {
		return fmt.Errorf("failed to inspect git diff: %w", err)
	}

	if len(candidates) == 0 {
		if jsonOutput {
			summary := diffSummary{TotalScanned: 0, Reports: []*model.RiskReport{}}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(summary)
		}
		modeStr := "working tree"
		if diffCached {
			modeStr = "staged"
		}
		fmt.Printf("✔ No new third-party imports detected in %s git diff.\n", modeStr)
		return nil
	}

	// Deduplicate candidates by ecosystem + package name
	candidateMap := make(map[string]ast.ImportCandidate)
	for _, cand := range candidates {
		key := fmt.Sprintf("%s:%s", cand.Ecosystem, cand.PackageName)
		if _, exists := candidateMap[key]; !exists {
			candidateMap[key] = cand
		}
	}

	var uniqueCandidates []ast.ImportCandidate
	for _, cand := range candidateMap {
		uniqueCandidates = append(uniqueCandidates, cand)
	}

	// Initialize Vetting Service
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
	vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

	// Concurrently vet candidates
	const workerCount = 5
	jobs := make(chan ast.ImportCandidate, len(uniqueCandidates))
	results := make(chan *model.RiskReport, len(uniqueCandidates))

	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				var rep *model.RiskReport
				var vErr error

				// Fast path: daemon IPC if available
				if !noCache {
					if defaultSock, _, _, pErr := daemon.DefaultPaths(); pErr == nil {
						dc := daemon.NewClient(defaultSock).WithTimeout(1 * time.Second)
						if dc.Ping(ctx) == nil {
							rep, vErr = dc.Vet(ctx, cand.Ecosystem, cand.PackageName, "", false)
						}
					}
				}

				// Fallback to in-process service
				if rep == nil {
					rep, vErr = vettingService.Vet(ctx, cand.Ecosystem, cand.PackageName, "")
				}

				if vErr != nil {
					// Synthetic report for 404 / phantom package
					rep = &model.RiskReport{
						Package:         cand.PackageName,
						Ecosystem:       cand.Ecosystem,
						ResolvedVersion: "phantom",
						TotalScore:      85,
						RiskLevel:       model.RiskLevelCritical,
						Penalties: []model.HeuristicFinding{
							{
								RuleID:      "HR-05A",
								Name:        "Phantom / Unresolved Dependency",
								Points:      85,
								Description: fmt.Sprintf("Failed to resolve %s package %q from authoritative registry: %v", cand.Ecosystem, cand.PackageName, vErr),
								Triggered:   true,
							},
						},
					}
				}

				results <- rep
			}
		}()
	}

	for _, cand := range uniqueCandidates {
		jobs <- cand
	}
	close(jobs)

	wg.Wait()
	close(results)

	var allReports []*model.RiskReport
	var cleanCount, warningCount, blockedCount int

	for rep := range results {
		allReports = append(allReports, rep)
		switch {
		case rep.TotalScore < 30:
			cleanCount++
		case rep.TotalScore >= threshold || rep.RiskLevel == model.RiskLevelCritical:
			blockedCount++
		default:
			warningCount++
		}
	}

	summary := diffSummary{
		TotalScanned: len(allReports),
		CleanCount:   cleanCount,
		WarningCount: warningCount,
		BlockedCount: blockedCount,
		Reports:      allReports,
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			return fmt.Errorf("failed to encode JSON diff output: %w", err)
		}
	} else if sarifOutput {
		sarifRep := output.SARIFReporter{Version: Version}
		for _, rep := range allReports {
			if rep.TotalScore >= 30 {
				_ = sarifRep.Render(os.Stdout, rep)
			}
		}
	} else {
		modeStr := "working tree changes"
		if diffCached {
			modeStr = "staged changes (--cached)"
		}
		renderDiffSummary(os.Stdout, modeStr, summary, candidateMap)
	}

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

func renderDiffSummary(w *os.File, modeStr string, s diffSummary, candidates map[string]ast.ImportCandidate) {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	fmt.Fprintf(w, "%s %s (%d packages analyzed)\n\n",
		headerStyle.Render("ARGUS DIFF SENTINEL"),
		lipgloss.NewStyle().Bold(true).Render(modeStr),
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

	if s.WarningCount > 0 || s.BlockedCount > 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Underline(true).Render("Flagged Import Additions:"))
		for _, r := range s.Reports {
			if r.TotalScore >= 30 {
				color := "#FCD535"
				if r.TotalScore >= 80 {
					color = "#F8312F"
				}
				badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(color)).Render(fmt.Sprintf("[%d/100 %s]", r.TotalScore, r.RiskLevel))

				fileLocation := ""
				key := fmt.Sprintf("%s:%s", r.Ecosystem, r.Package)
				if cand, ok := candidates[key]; ok && cand.FilePath != "" {
					fileLocation = fmt.Sprintf(" (%s:%d)", cand.FilePath, cand.LineNumber)
				}

				fmt.Fprintf(w, "  • %-32s %s%s\n", fmt.Sprintf("[%s] %s", r.Ecosystem, r.Package), badge, fileLocation)
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
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ All newly introduced imports passed provenance thresholds."))
	} else {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("⛔ Pre-commit diff inspection failed: Malicious or hallucinated imports detected."))
	}
}
