package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"bonjoski/argus/internal/model"
)

// SupportedTools lists all package manager and ephemeral runner CLI commands intercepted by Argus shims.
var SupportedTools = []string{
	"npm",
	"npx",
	"pnpm",
	"yarn",
	"bun",
	"bunx",
	"pip",
	"pip3",
	"pipx",
	"uv",
	"uvx",
	"cargo",
	"go",
	"gem",
	"bundle",
	"composer",
	"dotnet",
	"nuget",
	"swift",
}

// DefaultShimDir returns ~/.argus/bin.
func DefaultShimDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine user home directory: %w", err)
	}
	return filepath.Join(home, ".argus", "bin"), nil
}

// ShimStatus summarizes the state of the Argus PATH shims.
type ShimStatus struct {
	Directory    string   `json:"directory"`
	Installed    []string `json:"installed"`
	Missing      []string `json:"missing"`
	IsInPath     bool     `json:"is_in_path"`
	ExportString string   `json:"export_string"`
}

// Status checks the installed state of shims in the target directory.
func Status(shimDir string) ShimStatus {
	stat := ShimStatus{
		Directory:    shimDir,
		Installed:    make([]string, 0),
		Missing:      make([]string, 0),
		ExportString: fmt.Sprintf("export PATH=%q:$PATH", shimDir),
	}

	for _, tool := range SupportedTools {
		target := filepath.Join(shimDir, tool)
		targetCmd := filepath.Join(shimDir, tool+".cmd")
		installed := false
		if fi, err := os.Stat(target); err == nil && !fi.IsDir() && (runtime.GOOS == "windows" || fi.Mode()&0111 != 0) {
			installed = true
		} else if runtime.GOOS == "windows" {
			if fi, err := os.Stat(targetCmd); err == nil && !fi.IsDir() {
				installed = true
			}
		}

		if installed {
			stat.Installed = append(stat.Installed, tool)
		} else {
			stat.Missing = append(stat.Missing, tool)
		}
	}

	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		cleanP := filepath.Clean(p)
		if cleanP == filepath.Clean(shimDir) {
			stat.IsInPath = true
			break
		}
	}

	return stat
}

// resolveTrustedArgusBinary resolves and validates the absolute path to the argus binary
// to embed immutably inside generated shim scripts (blocking ARGUS_BIN env hijacking).
func resolveTrustedArgusBinary(argusBin string) (string, error) {
	candidate := strings.TrimSpace(argusBin)
	if candidate == "" {
		execPath, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to resolve current argus executable path: %w", err)
		}
		candidate = execPath
	}

	if strings.ContainsAny(candidate, "\x00\r\n`$") {
		return "", fmt.Errorf("refusing unsafe characters in argus binary path %q", candidate)
	}

	absPath, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path for argus binary %q: %w", candidate, err)
	}
	if resolved, evalErr := filepath.EvalSymlinks(absPath); evalErr == nil {
		absPath = resolved
	}
	if !filepath.IsAbs(absPath) {
		return "", fmt.Errorf("argus binary path %q is not absolute", absPath)
	}
	return filepath.Clean(absPath), nil
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Install writes executable shims to the specified directory with a hardcoded absolute argus binary path.
func Install(shimDir, argusBin string) error {
	resolvedBin, err := resolveTrustedArgusBinary(argusBin)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(shimDir, 0700); err != nil {
		return fmt.Errorf("failed to create shim directory %s: %w", shimDir, err)
	}

	quotedBin := shellSingleQuote(resolvedBin)

	for _, tool := range SupportedTools {
		shimPath := filepath.Join(shimDir, tool)
		content := fmt.Sprintf("#!/bin/sh\n# Argus Pre-Flight Subshell Interception Shim (immutable binary target)\nexec %s shim exec %s \"$@\"\n", quotedBin, tool)

		if err := os.WriteFile(shimPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to write shim for %s: %w", tool, err)
		}

		// On Windows, additionally generate .cmd batch wrapper without %ARGUS_BIN% env override
		if runtime.GOOS == "windows" {
			cmdPath := filepath.Join(shimDir, tool+".cmd")
			safeWinBin := strings.ReplaceAll(resolvedBin, `"`, "")
			cmdContent := fmt.Sprintf("@echo off\r\nrem Argus Pre-Flight Subshell Interception Shim for %s\r\n\"%s\" shim exec %s %%*\r\n", tool, safeWinBin, tool)
			if err := os.WriteFile(cmdPath, []byte(cmdContent), 0755); err != nil {
				return fmt.Errorf("failed to write cmd wrapper for %s: %w", tool, err)
			}
		}
	}

	return nil
}

// Uninstall removes all generated shims from the specified directory.
func Uninstall(shimDir string) error {
	for _, tool := range SupportedTools {
		shimPath := filepath.Join(shimDir, tool)
		if err := os.Remove(shimPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove shim for %s: %w", tool, err)
		}

		cmdPath := filepath.Join(shimDir, tool+".cmd")
		if err := os.Remove(cmdPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove cmd shim for %s: %w", tool, err)
		}
	}
	return nil
}

// ExtractTargets inspects command arguments to identify package installation and ephemeral runner attempts.
func ExtractTargets(tool string, args []string) (eco model.Ecosystem, targets []string, isInstall bool) {
	if len(args) == 0 {
		return "", nil, false
	}

	switch tool {
	case "npx", "bunx":
		t := parseNPXEphemeralArgs(args)
		if len(t) > 0 {
			return model.EcosystemNPM, t, true
		}
		return "", nil, false

	case "npm", "pnpm", "yarn", "bun":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			switch arg {
			case "install", "i", "add", "ci", "clean-install", "install-clean":
				return model.EcosystemNPM, parseInstallArgs(args[i+1:]), true
			case "dlx", "exec", "x", "create":
				t := parseNPXEphemeralArgs(args[i+1:])
				if arg == "create" && len(t) > 0 && !strings.HasPrefix(t[0], "create-") && !strings.Contains(t[0], "/create-") {
					if strings.HasPrefix(t[0], "@") && !strings.Contains(t[0], "/") {
						t[0] = t[0] + "/create"
					} else if !strings.HasPrefix(t[0], "@") {
						name, ver := SplitNPMSpec(t[0])
						if ver != "" {
							t[0] = "create-" + name + "@" + ver
						} else {
							t[0] = "create-" + name
						}
					}
				}
				if len(t) > 0 {
					return model.EcosystemNPM, t, true
				}
				return "", nil, false
			default:
				return "", nil, false
			}
		}

	case "pip", "pip3":
		for i, arg := range args {
			if arg == "install" {
				return model.EcosystemPyPI, parseInstallArgs(args[i+1:]), true
			}
		}

	case "pipx":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if arg == "run" || arg == "install" {
				t := parsePipxArgs(args[i+1:])
				if len(t) > 0 {
					return model.EcosystemPyPI, t, true
				}
			}
			return "", nil, false
		}

	case "uvx":
		t := parseUVXArgs(args)
		if len(t) > 0 {
			return model.EcosystemPyPI, t, true
		}
		return "", nil, false

	case "uv":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			switch arg {
			case "add":
				return model.EcosystemPyPI, parseInstallArgs(args[i+1:]), true
			case "sync":
				return model.EcosystemPyPI, nil, true
			case "pip":
				if i+1 < len(args) && (args[i+1] == "install" || args[i+1] == "sync") {
					return model.EcosystemPyPI, parseInstallArgs(args[i+2:]), true
				}
				return "", nil, false
			case "tool":
				if i+1 < len(args) && (args[i+1] == "run" || args[i+1] == "install") {
					t := parseUVXArgs(args[i+2:])
					if len(t) > 0 {
						return model.EcosystemPyPI, t, true
					}
				}
				return "", nil, false
			case "run":
				t := parseUVRunWithOnly(args[i+1:])
				if len(t) > 0 {
					return model.EcosystemPyPI, t, true
				}
				return "", nil, false
			default:
				return "", nil, false
			}
		}

	case "cargo":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if arg == "add" || arg == "install" {
				return model.EcosystemCargo, parseCargoInstallArgs(args[i+1:]), true
			}
			return "", nil, false
		}

	case "go":
		for i, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			switch arg {
			case "get":
				return model.EcosystemGo, parseInstallArgs(args[i+1:]), true
			case "install", "run":
				t := parseGoRunOrInstallArgs(args[i+1:])
				if len(t) > 0 {
					return model.EcosystemGo, t, true
				}
				return "", nil, false
			default:
				return "", nil, false
			}
		}

	case "gem":
		for i, arg := range args {
			if arg == "install" || arg == "i" {
				return model.EcosystemRubyGems, parseInstallArgs(args[i+1:]), true
			}
		}

	case "bundle":
		for i, arg := range args {
			if arg == "add" {
				return model.EcosystemRubyGems, parseInstallArgs(args[i+1:]), true
			}
		}

	case "composer":
		for i, arg := range args {
			if arg == "require" || arg == "install" {
				return model.EcosystemPackagist, parseInstallArgs(args[i+1:]), true
			}
		}

	case "dotnet":
		for i, arg := range args {
			if arg == "add" && i+1 < len(args) && (args[i+1] == "package" || args[i+1] == "pkg") {
				return model.EcosystemNuGet, parseInstallArgs(args[i+2:]), true
			}
		}

	case "nuget":
		for i, arg := range args {
			if arg == "install" || arg == "add" {
				return model.EcosystemNuGet, parseInstallArgs(args[i+1:]), true
			}
		}

	case "swift":
		for i, arg := range args {
			if arg == "package" && i+1 < len(args) {
				sub := args[i+1]
				if sub == "add-dependency" || sub == "add" {
					return model.EcosystemSwift, parseInstallArgs(args[i+2:]), true
				}
			}
		}
	}

	return "", nil, false
}

func parseNPXEphemeralArgs(args []string) []string {
	var pkgFlags []string
	var firstPositional string
	skipNext := false
	valueFlags := map[string]bool{
		"--registry":   true,
		"--cache":      true,
		"--userconfig": true,
		"--prefix":     true,
		"-c":           true,
		"--call":       true,
		"--shell":      true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--" {
			if len(pkgFlags) == 0 && firstPositional == "" && i+1 < len(args) {
				cand := strings.TrimSpace(args[i+1])
				if cand != "" && !strings.HasPrefix(cand, "-") {
					firstPositional = cand
				}
			}
			break
		}
		if a == "-h" || a == "--help" || a == "-v" || a == "--version" {
			if len(pkgFlags) == 0 && firstPositional == "" {
				return nil
			}
			continue
		}
		if a == "-p" || a == "--package" {
			if i+1 < len(args) {
				pkgFlags = append(pkgFlags, strings.TrimSpace(args[i+1]))
				skipNext = true
			}
			continue
		}
		if strings.HasPrefix(a, "--package=") {
			pkgFlags = append(pkgFlags, strings.TrimSpace(strings.TrimPrefix(a, "--package=")))
			continue
		}
		if strings.HasPrefix(a, "-p=") {
			pkgFlags = append(pkgFlags, strings.TrimSpace(strings.TrimPrefix(a, "-p=")))
			continue
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}
		if firstPositional == "" {
			firstPositional = strings.TrimSpace(a)
			// Positional args after the package name are arguments to the executed package itself.
			if len(pkgFlags) == 0 {
				break
			}
		}
	}

	if len(pkgFlags) > 0 {
		return pkgFlags
	}
	if firstPositional != "" {
		return []string{firstPositional}
	}
	return nil
}

func parseUVXArgs(args []string) []string {
	var fromPkg string
	var withPkgs []string
	var firstPositional string
	skipNext := false
	valueFlags := map[string]bool{
		"--python":          true,
		"-p":                true,
		"--index":           true,
		"--index-url":       true,
		"-i":                true,
		"--default-index":   true,
		"--extra-index-url": true,
		"--find-links":      true,
		"-f":                true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--" {
			if fromPkg == "" && firstPositional == "" && i+1 < len(args) {
				firstPositional = strings.TrimSpace(args[i+1])
			}
			break
		}
		if a == "-h" || a == "--help" || a == "-V" || a == "--version" {
			if fromPkg == "" && firstPositional == "" && len(withPkgs) == 0 {
				return nil
			}
			continue
		}
		if a == "--from" && i+1 < len(args) {
			fromPkg = strings.TrimSpace(args[i+1])
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "--from=") {
			fromPkg = strings.TrimSpace(strings.TrimPrefix(a, "--from="))
			continue
		}
		if (a == "--with" || a == "-w") && i+1 < len(args) {
			withPkgs = append(withPkgs, strings.Split(args[i+1], ",")...)
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "--with=") {
			withPkgs = append(withPkgs, strings.Split(strings.TrimPrefix(a, "--with="), ",")...)
			continue
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}
		if firstPositional == "" {
			firstPositional = strings.TrimSpace(a)
			break
		}
	}

	var out []string
	if fromPkg != "" {
		out = append(out, fromPkg)
	} else if firstPositional != "" {
		out = append(out, firstPositional)
	}
	for _, w := range withPkgs {
		if trimmed := strings.TrimSpace(w); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseUVRunWithOnly(args []string) []string {
	var withPkgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if (a == "--with" || a == "-w") && i+1 < len(args) {
			for _, w := range strings.Split(args[i+1], ",") {
				if trimmed := strings.TrimSpace(w); trimmed != "" {
					withPkgs = append(withPkgs, trimmed)
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "--with=") {
			for _, w := range strings.Split(strings.TrimPrefix(a, "--with="), ",") {
				if trimmed := strings.TrimSpace(w); trimmed != "" {
					withPkgs = append(withPkgs, trimmed)
				}
			}
		}
	}
	return withPkgs
}

func parsePipxArgs(args []string) []string {
	var specPkg string
	var firstPositional string
	skipNext := false
	valueFlags := map[string]bool{
		"--python":     true,
		"--index-url":  true,
		"-i":           true,
		"--pip-args":   true,
		"--suffix":     true,
		"--executable": true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--" {
			break
		}
		if a == "-h" || a == "--help" || a == "--version" {
			return nil
		}
		if a == "--spec" && i+1 < len(args) {
			specPkg = strings.TrimSpace(args[i+1])
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "--spec=") {
			specPkg = strings.TrimSpace(strings.TrimPrefix(a, "--spec="))
			continue
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}
		if firstPositional == "" {
			firstPositional = strings.TrimSpace(a)
			break
		}
	}
	if specPkg != "" {
		return []string{specPkg}
	}
	if firstPositional != "" {
		return []string{firstPositional}
	}
	return nil
}

func parseGoRunOrInstallArgs(args []string) []string {
	skipNext := false
	valueFlags := map[string]bool{
		"-c":         true,
		"-mod":       true,
		"-modfile":   true,
		"-tags":      true,
		"-ldflags":   true,
		"-gcflags":   true,
		"-asmflags":  true,
		"-buildmode": true,
		"-exec":      true,
		"-overlay":   true,
		"-p":         true,
		"-pkgdir":    true,
	}

	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") && valueFlags[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}
		cand := strings.TrimSpace(a)
		if cand == "" {
			continue
		}
		// Local source files / relative package patterns are not external module fetches
		if cand == "." || cand == "..." || strings.HasPrefix(cand, "./") || strings.HasPrefix(cand, "../") ||
			strings.HasPrefix(cand, "/") || strings.HasSuffix(cand, ".go") {
			return nil
		}
		firstSeg := cand
		if slashIdx := strings.IndexByte(cand, '/'); slashIdx != -1 {
			firstSeg = cand[:slashIdx]
		}
		if strings.Contains(cand, "@") || strings.Contains(firstSeg, ".") {
			return []string{cand}
		}
		return nil
	}
	return nil
}

func parseCargoInstallArgs(args []string) []string {
	var targets []string
	skipNext := false
	valueFlags := map[string]bool{
		"-f":         true,
		"--features": true,
		"--version":  true,
		"--branch":   true,
		"--tag":      true,
		"--rev":      true,
		"--target":   true,
		"--root":     true,
		"--bin":      true,
		"--example":  true,
		"--index":    true,
		"--registry": true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		// Capture --git and --path targets so ParseAndValidatePackageSpec rejects unverified VCS/local sources!
		if (a == "--git" || a == "--path") && i+1 < len(args) {
			val := strings.TrimSpace(args[i+1])
			if a == "--git" && !strings.Contains(val, "://") {
				val = "git+" + val
			} else if a == "--path" && !strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "./") && !strings.HasPrefix(val, "../") {
				val = "./" + val
			}
			targets = append(targets, val)
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "--git=") {
			targets = append(targets, strings.TrimSpace(strings.TrimPrefix(a, "--git=")))
			continue
		}
		if strings.HasPrefix(a, "--path=") {
			val := strings.TrimSpace(strings.TrimPrefix(a, "--path="))
			if !strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "./") && !strings.HasPrefix(val, "../") {
				val = "./" + val
			}
			targets = append(targets, val)
			continue
		}
		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") && valueFlags[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}
		if clean := strings.TrimSpace(a); clean != "" {
			targets = append(targets, clean)
		}
	}
	return targets
}

func parseInstallArgs(args []string) []string {
	var targets []string
	skipNext := false

	flagsWithValues := map[string]bool{
		"-r":                true,
		"--requirement":     true,
		"-c":                true,
		"--constraint":      true,
		"-f":                true,
		"--find-links":      true,
		"-F":                true,
		"--features":        true,
		"--version":         true,
		"--git":             true,
		"--branch":          true,
		"--tag":             true,
		"--rev":             true,
		"--path":            true,
		"--target":          true,
		"-t":                true,
		"--prefix":          true,
		"-i":                true,
		"--index":           true,
		"--index-url":       true,
		"--default-index":   true,
		"--extra-index-url": true,
		"--trusted-host":    true,
		"--registry":        true,
		"-s":                true,
		"-source":           true,
		"--source":          true,
		"--exact":           true,
		"--from":            true,
	}

	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") && flagsWithValues[strings.ToLower(a)] {
				skipNext = true
			}
			continue
		}

		clean := strings.TrimSpace(a)
		if clean != "" {
			targets = append(targets, clean)
		}
	}

	return targets
}

// FindRealBinary searches $PATH for the underlying real binary, skipping shimDir.
func FindRealBinary(tool, shimDir string) (string, error) {
	cleanShimDir := filepath.Clean(shimDir)
	pathEnv := os.Getenv("PATH")

	for _, dir := range filepath.SplitList(pathEnv) {
		cleanDir := filepath.Clean(dir)
		if cleanDir == cleanShimDir || strings.HasPrefix(cleanDir, cleanShimDir+string(filepath.Separator)) {
			continue
		}

		candidates := []string{filepath.Join(cleanDir, tool)}
		if runtime.GOOS == "windows" {
			candidates = append(candidates,
				filepath.Join(cleanDir, tool+".cmd"),
				filepath.Join(cleanDir, tool+".exe"),
				filepath.Join(cleanDir, tool+".bat"),
			)
		}

		for _, candidate := range candidates {
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				if runtime.GOOS == "windows" || (fi.Mode()&0111 != 0) {
					return candidate, nil
				}
			}
		}
	}

	// Fallback to common Unix system paths
	systemPaths := []string{
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/opt/homebrew/bin",
		filepath.Join(os.Getenv("HOME"), ".cargo/bin"),
		filepath.Join(os.Getenv("HOME"), "go/bin"),
	}

	for _, dir := range systemPaths {
		if filepath.Clean(dir) == cleanShimDir {
			continue
		}
		candidate := filepath.Join(dir, tool)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() && (runtime.GOOS == "windows" || fi.Mode()&0111 != 0) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("underlying executable %q not found in system PATH", tool)
}
