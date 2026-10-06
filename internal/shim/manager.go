package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"bonjoski/argus/internal/model"
)

// SupportedTools lists all package manager CLI commands intercepted by Argus shims.
var SupportedTools = []string{
	"npm",
	"npx",
	"pnpm",
	"yarn",
	"bun",
	"pip",
	"pip3",
	"cargo",
	"go",
	"gem",
	"composer",
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

// Install writes executable shims to the specified directory.
func Install(shimDir, argusBin string) error {
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return fmt.Errorf("failed to create shim directory %s: %w", shimDir, err)
	}

	if argusBin == "" {
		execPath, err := os.Executable()
		if err == nil {
			argusBin = execPath
		} else {
			argusBin = "argus"
		}
	}

	for _, tool := range SupportedTools {
		shimPath := filepath.Join(shimDir, tool)
		content := fmt.Sprintf(`#!/bin/sh
# Argus Pre-Flight Subshell Interception Shim
ARGUS_BIN="${ARGUS_BIN:-%s}"
if ! command -v "$ARGUS_BIN" >/dev/null 2>&1; then
    ARGUS_BIN="argus"
fi
exec "$ARGUS_BIN" shim exec %s "$@"
`, argusBin, tool)

		if err := os.WriteFile(shimPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to write shim for %s: %w", tool, err)
		}

		// On Windows, additionally generate .cmd batch wrapper for native cmd.exe/PowerShell
		if runtime.GOOS == "windows" {
			cmdPath := filepath.Join(shimDir, tool+".cmd")
			cmdContent := fmt.Sprintf(`@echo off
rem Argus Pre-Flight Subshell Interception Shim for %s
setlocal
set "ARGUS_BIN=%%ARGUS_BIN%%"
if "%%ARGUS_BIN%%"=="" set "ARGUS_BIN=%s"
endlocal & "%%ARGUS_BIN%%" shim exec %s %%*
`, tool, argusBin, tool)
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

// ExtractTargets inspects command arguments to identify package installation attempts.
func ExtractTargets(tool string, args []string) (eco model.Ecosystem, targets []string, isInstall bool) {
	if len(args) == 0 {
		return "", nil, false
	}

	switch tool {
	case "npm", "npx", "pnpm", "yarn", "bun":
		for i, arg := range args {
			if arg == "install" || arg == "i" || arg == "add" {
				isInstall = true
				eco = model.EcosystemNPM
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	case "pip", "pip3":
		for i, arg := range args {
			if arg == "install" {
				isInstall = true
				eco = model.EcosystemPyPI
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	case "cargo":
		for i, arg := range args {
			if arg == "add" {
				isInstall = true
				eco = model.EcosystemCargo
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	case "go":
		for i, arg := range args {
			if arg == "get" {
				isInstall = true
				eco = model.EcosystemGo
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	case "gem":
		for i, arg := range args {
			if arg == "install" || arg == "i" {
				isInstall = true
				eco = model.EcosystemRubyGems
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	case "composer":
		for i, arg := range args {
			if arg == "require" || arg == "install" {
				isInstall = true
				eco = model.EcosystemPackagist
				targets = parseInstallArgs(args[i+1:])
				return
			}
		}
	}

	return "", nil, false
}

func parseInstallArgs(args []string) []string {
	var targets []string
	skipNext := false

	flagsWithValues := map[string]bool{
		"-r":            true,
		"--requirement": true,
		"-c":            true,
		"--constraint":  true,
		"-f":            true,
		"--find-links":  true,
		"-F":            true,
		"--features":    true,
		"--version":     true,
		"--git":         true,
		"--branch":      true,
		"--tag":         true,
		"--rev":         true,
		"--path":        true,
		"--target":      true,
		"-t":            true,
		"--prefix":      true,
	}

	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if strings.HasPrefix(a, "-") {
			if flagsWithValues[a] {
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
