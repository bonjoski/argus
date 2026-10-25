package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/ast"
	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/gitdiff"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/output"
	"bonjoski/argus/internal/policy"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/sanitizer"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

var (
	vetSanitize   bool
	vetQuarantine bool
	vetSandbox    bool
	vetLockfile   string
	vetDiff       bool
	vetCached     bool
)

func newVetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vet [<ecosystem> <package>[@version]]",
		Short: "Inspect package provenance, audit lockfiles, or inspect git diffs for hallucinated packages and weaponized traps",
		Example: `  argus vet npm express
  argus vet npm @angular/core@17.0.0
  argus vet pypi requests
  argus vet --lockfile package-lock.json
  argus vet --lockfile Cargo.lock --strict
  argus vet --lockfile go.sum
  argus vet --lockfile
  argus vet --diff
  argus vet --diff --cached
  argus vet --diff ./workspace --json`,
		Args: cobra.ArbitraryArgs,
		RunE: runVet,
	}

	cmd.Flags().StringVar(&vetLockfile, "lockfile", "", "Audit lockfile for hallucinated packages and integrity tampering")
	cmd.Flags().Lookup("lockfile").NoOptDefVal = "auto"
	cmd.Flags().BoolVar(&vetDiff, "diff", false, "Inspect git diff (working tree or staged) to catch hallucinated package names and weaponized diffs")
	cmd.Flags().BoolVar(&vetCached, "cached", false, "Inspect staged changes (git diff --cached)")

	cmd.Flags().BoolVar(&vetSanitize, "sanitize", false, "Download and neutralize lifecycle scripts from package archive")
	cmd.Flags().BoolVar(&vetQuarantine, "quarantine", false, "Download and store package archive in Quarantine Store")
	cmd.Flags().BoolVar(&vetSandbox, "sandbox", false, "Run vetting hooks / pre-flight tests in isolated system sandbox")

	return cmd
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
	// 1. Dispatch --lockfile
	if vetLockfile != "" {
		targetFile := vetLockfile
		if targetFile == "auto" && len(args) > 0 {
			targetFile = args[0]
		}
		return runVetLockfile(cmd, targetFile)
	}

	// 2. Dispatch --diff
	if vetDiff {
		return runVetDiff(cmd, args)
	}

	// 3. Fallback to package-specific vetting: requires exactly 2 args
	if len(args) != 2 {
		return fmt.Errorf("accepts 2 arg(s), received %d (Usage: argus vet <ecosystem> <package>[@version], or pass --lockfile / --diff)", len(args))
	}

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
	case "nuget", "dotnet", "csharp":
		eco = model.EcosystemNuGet
	case "pub", "dart", "flutter":
		eco = model.EcosystemPub
	case "hex", "elixir", "erlang":
		eco = model.EcosystemHex
	case "swift", "spm", "swiftpm":
		eco = model.EcosystemSwift
	default:
		return fmt.Errorf("unsupported ecosystem %q (supported: npm, pypi, cargo, go, rubygems, maven, packagist, nuget, pub, hex, swift)", ecoStr)
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

	// Action on --quarantine and --sanitize flags if tarball URL is known
	if (vetQuarantine || vetSanitize) && report.Provenance.TarballURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", report.Provenance.TarballURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Argus/1.0")
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				data, err := io.ReadAll(io.LimitReader(resp.Body, 25*1024*1024))
				_ = resp.Body.Close()
				if err == nil {
					if vetQuarantine {
						if qStore, qErr := sanitizer.NewQuarantineStore(""); qErr == nil {
							qRec, qErr := qStore.Quarantine(eco, pkgName, report.ResolvedVersion, data, report, report.Provenance.TarballURL)
							if qErr == nil && !jsonOutput && !sarifOutput {
								fmt.Printf("\n☣️ Quarantined raw package archive: %s (ID: %s)\n", qRec.TarballPath, qRec.ID)
							}
						}
					}
					if vetSanitize {
						res, sErr := sanitizer.NeutralizeBytes(data, filepath.Base(report.Provenance.TarballURL))
						if sErr == nil {
							cleanFileName := fmt.Sprintf("%s-%s.clean.tgz", sanitizer.SanitizePackageName(pkgName), report.ResolvedVersion)
							if err := os.WriteFile(cleanFileName, res.Data, 0644); err == nil {
								if !jsonOutput && !sarifOutput {
									fmt.Printf("🛡️ Neutralized package saved to %s (stripped %d lifecycle hooks)\n", cleanFileName, len(res.StrippedHooks))
								}
							}
						}
					}
				}
			}
		}
	}

	// Interactive TTY Mode Check
	isInteractive := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) && !jsonOutput && !sarifOutput

	if isInteractive {
		switch {
		case report.TotalScore < 30:
			return nil
		case report.TotalScore >= 30 && report.TotalScore < 80:
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

// runVetLockfile audits a project lockfile for unpinned/tampered checksums and hallucinated packages.
func runVetLockfile(cmd *cobra.Command, filePath string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if filePath == "auto" || filePath == "" {
		detectedPath, err := lockfile.FindLockfile(".")
		if err != nil {
			return fmt.Errorf("no lockfile detected in current directory; specify with --lockfile=<path>: %w", err)
		}
		filePath = detectedPath
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open lockfile %s: %w", filePath, err)
	}
	defer f.Close()

	parser, eco, err := lockfile.Detect(filePath)
	if err != nil {
		return fmt.Errorf("lockfile format detection failed for %s: %w", filePath, err)
	}

	deps, err := parser.Parse(f)
	if err != nil {
		return fmt.Errorf("lockfile parsing failed: %w", err)
	}

	if len(deps) == 0 {
		if jsonOutput {
			summary := map[string]interface{}{
				"lockfile":       filePath,
				"total_packages": 0,
				"allowed":        true,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(summary)
		}
		fmt.Printf("✔ Notice: No external dependencies declared in %s.\n", filePath)
		return nil
	}

	// 1. Checksum & Integrity Audit using synchronized engine
	validator := lockfile.NewLockfileValidator(nil)
	integrityReport := validator.AuditLockedDependencies(deps)

	// 2. Concurrently vet all dependencies for hallucination / slopsquatting
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

				var rep *model.RiskReport
				var vErr error

				if !noCache {
					if defaultSock, _, _, pErr := daemon.DefaultPaths(); pErr == nil {
						dc := daemon.NewClient(defaultSock).WithTimeout(1 * time.Second)
						if dc.Ping(ctx) == nil {
							rep, vErr = dc.Vet(ctx, targetEco, dep.Name, dep.Version, false)
						}
					}
				}

				if rep == nil {
					rep, vErr = vettingService.Vet(ctx, targetEco, dep.Name, dep.Version)
				}

				if vErr != nil {
					rep = &model.RiskReport{
						Package:         dep.Name,
						Ecosystem:       targetEco,
						ResolvedVersion: dep.Version,
						TotalScore:      85,
						RiskLevel:       model.RiskLevelCritical,
						Penalties: []model.HeuristicFinding{
							{
								RuleID:      "HR-05A",
								Name:        "Phantom / Hallucinated Package",
								Points:      85,
								Description: fmt.Sprintf("Failed to resolve %s package %q from authoritative registry (potential hallucinated package / slopsquat): %v", targetEco, dep.Name, vErr),
								Triggered:   true,
							},
						},
					}
				}
				results <- rep
			}
		}()
	}

	for _, d := range deps {
		jobs <- d
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

	// Add tampered dependencies to blocked count
	if integrityReport.TamperedCount > 0 {
		blockedCount += integrityReport.TamperedCount
	}

	summary := struct {
		Lockfile     string                        `json:"lockfile"`
		TotalScanned int                           `json:"total_scanned"`
		CleanCount   int                           `json:"clean_count"`
		WarningCount int                           `json:"warning_count"`
		BlockedCount int                           `json:"blocked_count"`
		Integrity    *lockfile.LockfileAuditReport `json:"integrity_audit"`
		Reports      []*model.RiskReport           `json:"reports"`
	}{
		Lockfile:     filePath,
		TotalScanned: len(allReports),
		CleanCount:   cleanCount,
		WarningCount: warningCount,
		BlockedCount: blockedCount,
		Integrity:    integrityReport,
		Reports:      allReports,
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			return fmt.Errorf("failed to encode JSON output: %w", err)
		}
	} else if sarifOutput {
		sarifRep := output.SARIFReporter{Version: Version}
		for _, rep := range allReports {
			if rep.TotalScore >= 30 {
				_ = sarifRep.Render(os.Stdout, rep)
			}
		}
	} else {
		renderLockfileSummary(os.Stdout, filePath, summary.TotalScanned, cleanCount, warningCount, blockedCount, integrityReport, allReports)
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

func renderLockfileSummary(w *os.File, filePath string, total, clean, warning, blocked int, integrity *lockfile.LockfileAuditReport, reports []*model.RiskReport) {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	fmt.Fprintf(w, "%s %s (%d packages verified)\n\n",
		headerStyle.Render("ARGUS LOCKFILE VET"),
		lipgloss.NewStyle().Bold(true).Render(filePath),
		total,
	)

	fmt.Fprintf(w, "  ✔ Clean / Verified:  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render(fmt.Sprintf("%d", clean)))
	if warning > 0 {
		fmt.Fprintf(w, "  ⚠ Suspicious:        %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD535")).Render(fmt.Sprintf("%d", warning)))
	}
	if blocked > 0 {
		fmt.Fprintf(w, "  ⛔ Hard Blocked:      %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render(fmt.Sprintf("%d", blocked)))
	}
	if integrity != nil && integrity.TamperedCount > 0 {
		fmt.Fprintf(w, "  ☣️  Tampered Hashes:   %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render(fmt.Sprintf("%d", integrity.TamperedCount)))
	}
	fmt.Fprintln(w)

	if warning > 0 || blocked > 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Underline(true).Render("Flagged Dependencies / Integrity Findings:"))
		for _, r := range reports {
			if r.TotalScore >= 30 {
				color := "#FCD535"
				if r.TotalScore >= 80 {
					color = "#F8312F"
				}
				badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(color)).Render(fmt.Sprintf("[%d/100 %s]", r.TotalScore, r.RiskLevel))
				fmt.Fprintf(w, "  • %-32s %s\n", fmt.Sprintf("[%s] %s@%s", r.Ecosystem, r.Package, r.ResolvedVersion), badge)
				for _, p := range r.Penalties {
					if p.Triggered {
						fmt.Fprintf(w, "      [+%2d] %s (%s)\n", p.Points, p.Name, p.RuleID)
					}
				}
			}
		}
		if integrity != nil {
			for _, t := range integrity.TamperedDeps {
				fmt.Fprintf(w, "  • %-32s %s\n", fmt.Sprintf("[%s] %s@%s", t.Dependency.Ref.Ecosystem, t.Dependency.Ref.Name, t.Dependency.Ref.Version), lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("[CHECKSUM TAMPER]"))
				fmt.Fprintf(w, "      Reason: %s\n", t.Reason)
			}
		}
		fmt.Fprintln(w)
	}

	if blocked == 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ Lockfile verified: 0 hallucinated packages, all cryptographic checksums valid."))
	} else {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("⛔ Pre-flight lockfile inspection failed: Hallucinated dependencies or integrity tampering detected."))
	}
}

// runVetDiff audits git diff for weaponized execution traps and hallucinated import dependencies.
func runVetDiff(cmd *cobra.Command, args []string) error {
	workDir := ""
	if len(args) > 0 {
		workDir = args[0]
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	runner := gitdiff.NewExecGitRunner()

	// 1. Retrieve raw diff and changed file names
	rawDiff, diffErr := runner.Diff(ctx, workDir, vetCached)
	changedFiles, _ := runner.ChangedFiles(ctx, workDir, vetCached)

	if diffErr != nil && len(rawDiff) == 0 && len(changedFiles) == 0 {
		return fmt.Errorf("failed to retrieve git diff in %q: %w", workDir, diffErr)
	}

	// 2. Weaponized Diff Auditing (SemanticDiffAuditor)
	auditor := gitdiff.NewSemanticDiffAuditor(workDir)
	weaponReport, _ := auditor.AuditFiles(ctx, workDir, changedFiles)
	if len(rawDiff) > 0 {
		if streamReport, err := auditor.AuditDiffStream(bytes.NewReader(rawDiff)); err == nil && streamReport != nil {
			seen := make(map[string]bool)
			for _, f := range weaponReport.Findings {
				seen[f.File+":"+f.Category] = true
			}
			for _, f := range streamReport.Findings {
				key := f.File + ":" + f.Category
				if !seen[key] {
					seen[key] = true
					weaponReport.Findings = append(weaponReport.Findings, f)
					if f.Severity == gitdiff.DiffSeverityCritical || f.Severity == gitdiff.DiffSeverityHigh {
						weaponReport.Allowed = false
					}
				}
			}
		}
	}

	// 3. Hallucinated Imports Auditing
	var candidates []ast.ImportCandidate
	if len(rawDiff) > 0 {
		var extractErr error
		candidates, extractErr = gitdiff.ExtractImportsFromDiff(bytes.NewReader(rawDiff))
		if extractErr != nil {
			return fmt.Errorf("failed to extract imports from git diff: %w", extractErr)
		}
	}

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

	var allImportReports []*model.RiskReport
	var cleanCount, warningCount, blockedCount int

	if len(uniqueCandidates) > 0 {
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

					if !noCache {
						if defaultSock, _, _, pErr := daemon.DefaultPaths(); pErr == nil {
							dc := daemon.NewClient(defaultSock).WithTimeout(1 * time.Second)
							if dc.Ping(ctx) == nil {
								rep, vErr = dc.Vet(ctx, cand.Ecosystem, cand.PackageName, "", false)
							}
						}
					}

					if rep == nil {
						rep, vErr = vettingService.Vet(ctx, cand.Ecosystem, cand.PackageName, "")
					}

					if vErr != nil {
						rep = &model.RiskReport{
							Package:         cand.PackageName,
							Ecosystem:       cand.Ecosystem,
							ResolvedVersion: "phantom",
							TotalScore:      85,
							RiskLevel:       model.RiskLevelCritical,
							Penalties: []model.HeuristicFinding{
								{
									RuleID:      "HR-05A",
									Name:        "Phantom / Hallucinated Package",
									Points:      85,
									Description: fmt.Sprintf("Failed to resolve %s package %q from authoritative registry (slopsquat / hallucinated package): %v", cand.Ecosystem, cand.PackageName, vErr),
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

		for rep := range results {
			allImportReports = append(allImportReports, rep)
			switch {
			case rep.TotalScore < 30:
				cleanCount++
			case rep.TotalScore >= threshold || rep.RiskLevel == model.RiskLevelCritical:
				blockedCount++
			default:
				warningCount++
			}
		}
	}

	weaponizedBlocked := !weaponReport.Allowed
	overallAllowed := !weaponizedBlocked && blockedCount == 0

	modeStr := "working tree changes"
	if vetCached {
		modeStr = "staged changes (--cached)"
	}

	if jsonOutput {
		summary := struct {
			Mode           string                   `json:"mode"`
			Allowed        bool                     `json:"allowed"`
			WeaponizedDiff *gitdiff.DiffAuditReport `json:"weaponized_diff"`
			TotalImports   int                      `json:"total_imports"`
			CleanImports   int                      `json:"clean_imports"`
			WarningImports int                      `json:"warning_imports"`
			BlockedImports int                      `json:"blocked_imports"`
			ImportReports  []*model.RiskReport      `json:"import_reports"`
		}{
			Mode:           modeStr,
			Allowed:        overallAllowed,
			WeaponizedDiff: weaponReport,
			TotalImports:   len(allImportReports),
			CleanImports:   cleanCount,
			WarningImports: warningCount,
			BlockedImports: blockedCount,
			ImportReports:  allImportReports,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	if sarifOutput {
		sarifRep := output.SARIFReporter{Version: Version}
		for _, rep := range allImportReports {
			if rep.TotalScore >= 30 {
				_ = sarifRep.Render(os.Stdout, rep)
			}
		}
	} else {
		renderDiffVetSummary(os.Stdout, modeStr, weaponReport, len(allImportReports), cleanCount, warningCount, blockedCount, allImportReports, candidateMap)
	}

	if force {
		return nil
	}

	if weaponizedBlocked || blockedCount > 0 {
		os.Exit(1)
	}

	if strictMode && warningCount > 0 {
		os.Exit(2)
	}

	return nil
}

func renderDiffVetSummary(w *os.File, modeStr string, weaponReport *gitdiff.DiffAuditReport, totalImports, clean, warning, blocked int, reports []*model.RiskReport, candidates map[string]ast.ImportCandidate) {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	fmt.Fprintf(w, "%s %s\n\n",
		headerStyle.Render("ARGUS PRE-FLIGHT DIFF VET"),
		lipgloss.NewStyle().Bold(true).Render(modeStr),
	)

	// Section 1: Weaponized Diff Findings
	if len(weaponReport.Findings) > 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("🚨 Weaponized Diff Traps Detected:"))
		for _, f := range weaponReport.Findings {
			badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("[" + string(f.Severity) + "]")
			fmt.Fprintf(w, "  • %s %s (%s): %s\n", badge, f.File, f.Category, f.Description)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("  ✔ No weaponized diff execution traps detected."))
	}

	// Section 2: Hallucinated / New Imports
	fmt.Fprintf(w, "\n%s (%d imports analyzed)\n", lipgloss.NewStyle().Bold(true).Render("Third-Party Source Imports:"), totalImports)
	fmt.Fprintf(w, "  ✔ Clean / Verified:  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render(fmt.Sprintf("%d", clean)))
	if warning > 0 {
		fmt.Fprintf(w, "  ⚠ Suspicious:        %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD535")).Render(fmt.Sprintf("%d", warning)))
	}
	if blocked > 0 {
		fmt.Fprintf(w, "  ⛔ Hard Blocked:      %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render(fmt.Sprintf("%d", blocked)))
	}
	fmt.Fprintln(w)

	if warning > 0 || blocked > 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Underline(true).Render("Flagged Import Additions:"))
		for _, r := range reports {
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

	if weaponReport.Allowed && blocked == 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Pre-flight diff inspection passed: 0 weaponized traps, all imports verified."))
	} else {
		fmt.Fprintln(w, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("⛔ Pre-flight diff inspection failed: Weaponized diff traps or hallucinated dependencies detected before microVM dispatch."))
	}
}
