package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrAirlockNotFound is returned when the Airlock sandbox binary cannot be located.
	ErrAirlockNotFound = errors.New("airlock binary not found; install Airlock (https://github.com/bonjoski/airlock) for workstation sandbox isolation")
)

// Profile defines isolation flags and workspace policies passed to Airlock.
type Profile struct {
	AllowNetwork      bool     `json:"allow_network"`
	Airgap            bool     `json:"airgap"`
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	AllowedWritePaths []string `json:"allowed_write_paths,omitempty"`
	KeepEnvVars       []string `json:"keep_env_vars,omitempty"`
	Workspace         string   `json:"workspace,omitempty"`
	ConfigPath        string   `json:"config_path,omitempty"`
	VetStrict         bool     `json:"vet_strict,omitempty"`
	VetpkgPath        string   `json:"vetpkg_path,omitempty"`
	NonInteractive    bool     `json:"non_interactive,omitempty"`
	ExtraArgs         []string `json:"extra_args,omitempty"`
}

// ExecResult encapsulates process exit telemetry and captured outputs.
type ExecResult struct {
	ExitCode   int           `json:"exit_code"`
	Stdout     []byte        `json:"stdout"`
	Stderr     []byte        `json:"stderr"`
	Duration   time.Duration `json:"duration"`
	Violations []string      `json:"violations,omitempty"`
}

// DoctorResult represents an individual diagnostic check reported by Airlock doctor.
type DoctorResult struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Status         string `json:"status"`
	Title          string `json:"title"`
	Details        string `json:"details"`
	Recommendation string `json:"recommendation,omitempty"`
}

// DoctorReport contains diagnostic telemetry on workstation sandbox capabilities.
type DoctorReport struct {
	Timestamp     string         `json:"timestamp"`
	Platform      string         `json:"platform"`
	WorkspaceRoot string         `json:"workspace_root"`
	Healthy       bool           `json:"healthy"`
	Passed        int            `json:"passed"`
	Warnings      int            `json:"warnings"`
	Failures      int            `json:"failures"`
	Results       []DoctorResult `json:"results"`
}

// Engine defines the bridge interface for workstation process and network isolation.
type Engine interface {
	Available() bool
	Name() string
	BinaryPath() string
	Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error)
	Doctor(ctx context.Context, workspace string) (*DoctorReport, error)
	Version(ctx context.Context) (string, error)
}

// AirlockBridge implements Engine by delegating isolation to the external Airlock CLI.
type AirlockBridge struct {
	binaryPath string
}

// NewEngine creates an Engine backed by the detected Airlock binary.
func NewEngine() Engine {
	bin, _ := FindAirlock()
	return &AirlockBridge{binaryPath: bin}
}

// NewBridge creates an Engine with an explicitly configured Airlock binary path.
func NewBridge(customPath string) Engine {
	if customPath != "" {
		if abs, err := filepath.Abs(customPath); err == nil {
			if info, err := os.Stat(abs); err == nil && !info.IsDir() {
				return &AirlockBridge{binaryPath: abs}
			}
		}
	}
	return NewEngine()
}

// Available returns true if the Airlock executable is present on the system.
func (b *AirlockBridge) Available() bool {
	return b.binaryPath != ""
}

// Name returns the descriptive name of the sandbox engine.
func (b *AirlockBridge) Name() string {
	return "airlock"
}

// BinaryPath returns the resolved file path to the Airlock executable.
func (b *AirlockBridge) BinaryPath() string {
	return b.binaryPath
}

// Run executes the command inside Airlock's hardware-isolated sandbox container.
func (b *AirlockBridge) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	if !b.Available() {
		return nil, fmt.Errorf("cannot execute in sandbox: %w", ErrAirlockNotFound)
	}

	var airlockArgs []string
	airlockArgs = append(airlockArgs, "run")

	if profile != nil {
		if profile.Airgap {
			airlockArgs = append(airlockArgs, "--airgap")
		} else if profile.AllowNetwork {
			airlockArgs = append(airlockArgs, "--net")
		}

		if len(profile.AllowedDomains) > 0 {
			airlockArgs = append(airlockArgs, "--allow-domain", strings.Join(profile.AllowedDomains, ","))
		}

		if len(profile.KeepEnvVars) > 0 {
			airlockArgs = append(airlockArgs, "--keep-env", strings.Join(profile.KeepEnvVars, ","))
		}

		if profile.Workspace != "" {
			airlockArgs = append(airlockArgs, "--workspace", profile.Workspace)
		}

		if profile.ConfigPath != "" {
			airlockArgs = append(airlockArgs, "--config", profile.ConfigPath)
		}

		if profile.VetStrict {
			airlockArgs = append(airlockArgs, "--vet-strict")
		}

		if profile.VetpkgPath != "" {
			airlockArgs = append(airlockArgs, "--vetpkg", profile.VetpkgPath)
		}

		if profile.NonInteractive {
			airlockArgs = append(airlockArgs, "--non-interactive")
		}

		if len(profile.ExtraArgs) > 0 {
			airlockArgs = append(airlockArgs, profile.ExtraArgs...)
		}
	}

	airlockArgs = append(airlockArgs, "--", command)
	airlockArgs = append(airlockArgs, args...)

	start := time.Now()
	cmd := exec.CommandContext(ctx, b.binaryPath, airlockArgs...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if profile != nil && profile.Workspace != "" {
		cmd.Dir = profile.Workspace
	}

	err := cmd.Run()
	duration := time.Since(start)

	res := &ExecResult{
		ExitCode: 0,
		Stdout:   stdoutBuf.Bytes(),
		Stderr:   stderrBuf.Bytes(),
		Duration: duration,
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed running airlock subprocess: %w", err)
		}
	}

	// Parse violations from stderr if present
	stderrStr := string(res.Stderr)
	if strings.Contains(stderrStr, "Operation not permitted") ||
		strings.Contains(stderrStr, "Permission denied") ||
		strings.Contains(stderrStr, "blocked") {
		for _, line := range strings.Split(stderrStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && (strings.Contains(line, "Operation not permitted") ||
				strings.Contains(line, "Permission denied") ||
				strings.Contains(line, "blocked")) {
				res.Violations = append(res.Violations, line)
			}
		}
	}

	return res, nil
}

// Doctor inspects system sandbox capabilities via airlock doctor --json.
func (b *AirlockBridge) Doctor(ctx context.Context, workspace string) (*DoctorReport, error) {
	if !b.Available() {
		return nil, fmt.Errorf("cannot run sandbox doctor: %w", ErrAirlockNotFound)
	}

	var args []string
	args = append(args, "doctor", "--json")
	if workspace != "" {
		args = append(args, "--workspace", workspace)
	}

	cmd := exec.CommandContext(ctx, b.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("airlock doctor failed (%s): %w", strings.TrimSpace(stderr.String()), err)
	}

	var report DoctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("failed to parse airlock doctor json output: %w", err)
	}

	return &report, nil
}

// Version queries the Airlock binary version string.
func (b *AirlockBridge) Version(ctx context.Context) (string, error) {
	if !b.Available() {
		return "", fmt.Errorf("cannot query airlock version: %w", ErrAirlockNotFound)
	}

	cmd := exec.CommandContext(ctx, b.binaryPath, "version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed querying airlock version: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

// FindAirlock searches for the airlock executable on the host system in order of precedence:
//  1. ARGUS_AIRLOCK_BIN environment variable
//  2. System PATH (exec.LookPath) for 'airlock' or 'boxpkg'
//  3. Standard user installation locations (~/.airlock/bin/airlock, /opt/homebrew/bin/airlock, /usr/local/bin/airlock)
//  4. Local development sibling directories (../airlock/bin/airlock)
func FindAirlock() (string, bool) {
	// 1. Environment variable override
	if envPath := os.Getenv("ARGUS_AIRLOCK_BIN"); envPath != "" {
		if path, err := filepath.Abs(envPath); err == nil {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, true
			}
		}
	}

	// 2. PATH lookup
	for _, name := range []string{"airlock", "boxpkg"} {
		if path, err := exec.LookPath(name); err == nil {
			if abs, err := filepath.Abs(path); err == nil {
				return abs, true
			}
			return path, true
		}
	}

	// 3. Known installation paths
	home, _ := os.UserHomeDir()
	var candidates []string
	if home != "" {
		candidates = append(candidates, filepath.Join(home, ".airlock", "bin", "airlock"))
		candidates = append(candidates, filepath.Join(home, ".local", "bin", "airlock"))
		candidates = append(candidates, filepath.Join(home, "go", "bin", "airlock"))
	}
	candidates = append(candidates,
		"/opt/homebrew/bin/airlock",
		"/usr/local/bin/airlock",
		"/usr/bin/airlock",
	)

	// 4. Sibling development directories
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "..", "airlock", "bin", "airlock"),
			filepath.Join(cwd, "bin", "airlock"),
		)
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, "supplychain", "airlock", "bin", "airlock"),
		)
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs, true
			}
			return c, true
		}
	}

	return "", false
}
