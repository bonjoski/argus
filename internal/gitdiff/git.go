package gitdiff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"bonjoski/argus/internal/ast"
)

// GitRunner abstracts the execution of git commands (SOLID Dependency Inversion).
type GitRunner interface {
	Diff(ctx context.Context, workDir string, cached bool) ([]byte, error)
}

// ExecGitRunner executes real git CLI commands on the local machine.
type ExecGitRunner struct{}

// NewExecGitRunner creates an ExecGitRunner.
func NewExecGitRunner() *ExecGitRunner {
	return &ExecGitRunner{}
}

// Diff executes 'git diff' or 'git diff --cached' in the specified workDir.
func (r *ExecGitRunner) Diff(ctx context.Context, workDir string, cached bool) ([]byte, error) {
	args := []string{"diff"}
	if cached {
		args = append(args, "--cached")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed executing git diff: %w", err)
	}

	return out, nil
}

// InspectDiff extracts new import dependencies using the provided GitRunner.
func InspectDiff(ctx context.Context, runner GitRunner, workDir string, cached bool) ([]ast.ImportCandidate, error) {
	if runner == nil {
		runner = NewExecGitRunner()
	}

	rawDiff, err := runner.Diff(ctx, workDir, cached)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve git diff: %w", err)
	}

	if len(rawDiff) == 0 {
		return nil, nil
	}

	return ExtractImportsFromDiff(bytes.NewReader(rawDiff))
}
