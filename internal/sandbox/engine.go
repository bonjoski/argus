package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Profile defines security policies and boundary restrictions for sandboxed execution.
type Profile struct {
	AllowNetwork      bool     `json:"allow_network"`
	AllowedWritePaths []string `json:"allowed_write_paths"`
	AllowedReadPaths  []string `json:"allowed_read_paths"`
	BlockedPaths      []string `json:"blocked_paths"`
	BlockedEnvVars    []string `json:"blocked_env_vars"`
	WorkDir           string   `json:"work_dir"`
}

// ExecResult contains the execution summary and violation telemetry of a sandboxed run.
type ExecResult struct {
	ExitCode   int           `json:"exit_code"`
	Stdout     []byte        `json:"stdout"`
	Stderr     []byte        `json:"stderr"`
	Duration   time.Duration `json:"duration"`
	Violations []string      `json:"violations"`
}

// Engine represents a platform-specific sandbox isolation provider.
type Engine interface {
	Available() bool
	Name() string
	Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error)
	GenerateProfile(profile *Profile) (string, error)
}

// DefaultBlockedPaths returns the standard high-risk credential and system paths.
func DefaultBlockedPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/tmp"
	}

	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config"),
		"/etc",
		"/private/etc",
		"/var/root",
		"/private/var/root",
		"/var/db",
		"/private/var/db",
		"/Library/Keychains",
		"/System",
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
	}
}

// DefaultBlockedEnvVars returns sensitive environment variables stripped during execution.
func DefaultBlockedEnvVars() []string {
	return []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"SSH_AUTH_SOCK",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"NPM_TOKEN",
		"NPM_AUTH_TOKEN",
		"PYPI_TOKEN",
		"PYPI_API_TOKEN",
		"ARGUS_API_KEY",
		"SLACK_BOT_TOKEN",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"GEMINI_API_KEY",
	}
}

// FilterEnv filters out blocked environment variables from the current environment.
func FilterEnv(blockedVars []string) []string {
	if len(blockedVars) == 0 {
		blockedVars = DefaultBlockedEnvVars()
	}

	blockedMap := make(map[string]struct{}, len(blockedVars))
	for _, v := range blockedVars {
		blockedMap[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}

	var filtered []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) > 0 {
			key := strings.ToUpper(strings.TrimSpace(parts[0]))
			if _, blocked := blockedMap[key]; !blocked {
				filtered = append(filtered, env)
			}
		}
	}
	filtered = append(filtered, "ARGUS_SANDBOX=1")
	return filtered
}

// ExpandPath expands leading ~ to user home directory and returns clean absolute path.
func ExpandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	abs, err := filepath.Abs(p)
	if err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

// ResolveAllPaths returns the original expanded path and its canonical symlink-resolved path.
func ResolveAllPaths(p string) []string {
	exp := ExpandPath(p)
	if exp == "" {
		return nil
	}
	results := []string{exp}
	if realPath, err := filepath.EvalSymlinks(exp); err == nil && realPath != "" && realPath != exp {
		results = append(results, filepath.Clean(realPath))
	}
	return results
}

// NewEngine returns the best available platform-specific sandbox engine.
func NewEngine() Engine {
	return defaultPlatformEngine()
}

// NewEngineByName instantiates an engine by identifier.
func NewEngineByName(name string) (Engine, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto":
		return NewEngine(), nil
	case "seatbelt", "macos", "darwin":
		return NewSeatbeltEngine(), nil
	case "landlock", "linux":
		return NewLandlockEngine(), nil
	case "fallback", "process":
		return NewFallbackEngine(), nil
	default:
		return nil, fmt.Errorf("unknown sandbox engine: %q (supported: auto, seatbelt, landlock, fallback)", name)
	}
}
