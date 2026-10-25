package gitdiff

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"bonjoski/argus/internal/ast"
)

// GitRunner abstracts the execution of git commands (SOLID Dependency Inversion).
type GitRunner interface {
	Diff(ctx context.Context, workDir string, cached bool) ([]byte, error)
	ChangedFiles(ctx context.Context, workDir string, cached bool) ([]string, error)
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

// ChangedFiles lists paths of files added, modified, or deleted in the working tree or index.
func (r *ExecGitRunner) ChangedFiles(ctx context.Context, workDir string, cached bool) ([]string, error) {
	args := []string{"diff", "--name-only"}
	if cached {
		args = append(args, "--cached")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed executing git diff --name-only: %w", err)
	}

	var files []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			files = append(files, text)
		}
	}
	return files, nil
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
