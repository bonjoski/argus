package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/sandbox"
)

var (
	sandboxAllowNet   bool
	sandboxAllowWrite []string
	sandboxWorkDir    string
	sandboxEngine     string
)

func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Manage and run processes in hardware-isolated system sandboxes",
		Long: `Argus Sandbox provides hardware-level process and network isolation for running
untrusted dependencies, build scripts, AI agent tools, and package manager invocations.
On macOS it leverages Apple Seatbelt (SBPL), on Linux it leverages Landlock LSM and namespaces.`,
	}

	cmd.AddCommand(newSandboxRunCmd())
	cmd.AddCommand(newSandboxProfileCmd())

	return cmd
}

func newSandboxRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Execute a command inside a hardware-isolated system sandbox",
		Example: `  argus sandbox run -- npm install
  argus sandbox run --allow-net --allow-write ./dist -- cargo build
  argus sandbox run --workdir /tmp -- /bin/ls -la`,
		Args: cobra.MinimumNArgs(1),
		RunE: runSandboxRun,
	}

	cmd.Flags().BoolVar(&sandboxAllowNet, "allow-net", false, "Allow inbound and outbound network access")
	cmd.Flags().StringSliceVar(&sandboxAllowWrite, "allow-write", nil, "Additional filesystem paths allowed for writing")
	cmd.Flags().StringVar(&sandboxWorkDir, "workdir", "", "Working directory for sandboxed command (default: current directory)")
	cmd.Flags().StringVar(&sandboxEngine, "engine", "", "Sandbox engine to use (seatbelt, landlock, fallback, or auto)")

	return cmd
}

func runSandboxRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified to run in sandbox")
	}

	workDir := sandboxWorkDir
	if workDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workDir = cwd
		}
	}

	profile := &sandbox.Profile{
		AllowNetwork:      sandboxAllowNet,
		AllowedWritePaths: sandboxAllowWrite,
		WorkDir:           workDir,
	}

	engine, err := sandbox.NewEngineByName(sandboxEngine)
	if err != nil {
		return fmt.Errorf("sandbox engine initialization failed: %w", err)
	}

	if !engine.Available() {
		return fmt.Errorf("selected sandbox engine %q is not available on this platform", engine.Name())
	}

	ctx := cmd.Context()
	command := args[0]
	cmdArgs := args[1:]

	res, err := engine.Run(ctx, profile, command, cmdArgs...)
	if err != nil {
		return fmt.Errorf("sandbox execution error: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	if len(res.Stdout) > 0 {
		os.Stdout.Write(res.Stdout)
	}
	if len(res.Stderr) > 0 {
		os.Stderr.Write(res.Stderr)
	}

	if len(res.Violations) > 0 && !jsonOutput {
		fmt.Fprintf(os.Stderr, "\n🛡️ Argus Sandbox Intercepted %d Violations:\n", len(res.Violations))
		for _, v := range res.Violations {
			fmt.Fprintf(os.Stderr, "  • %s\n", v)
		}
	}

	if res.ExitCode != 0 {
		os.Exit(res.ExitCode)
	}

	return nil
}

func newSandboxProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile [flags]",
		Short: "Generate and display the sandbox isolation profile for the current platform",
		Example: `  argus sandbox profile
  argus sandbox profile --allow-net --allow-write /tmp/build`,
		RunE: runSandboxProfile,
	}

	cmd.Flags().BoolVar(&sandboxAllowNet, "allow-net", false, "Allow inbound and outbound network access")
	cmd.Flags().StringSliceVar(&sandboxAllowWrite, "allow-write", nil, "Additional filesystem paths allowed for writing")
	cmd.Flags().StringVar(&sandboxWorkDir, "workdir", "", "Working directory for sandboxed command (default: current directory)")
	cmd.Flags().StringVar(&sandboxEngine, "engine", "", "Sandbox engine to use (seatbelt, landlock, fallback, or auto)")

	return cmd
}

func runSandboxProfile(cmd *cobra.Command, args []string) error {
	workDir := sandboxWorkDir
	if workDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workDir = cwd
		}
	}

	profile := &sandbox.Profile{
		AllowNetwork:      sandboxAllowNet,
		AllowedWritePaths: sandboxAllowWrite,
		WorkDir:           workDir,
	}

	engine, err := sandbox.NewEngineByName(sandboxEngine)
	if err != nil {
		return fmt.Errorf("sandbox engine initialization failed: %w", err)
	}

	scheme, err := engine.GenerateProfile(profile)
	if err != nil {
		return fmt.Errorf("failed to generate sandbox profile: %w", err)
	}

	fmt.Fprint(cmd.OutOrStdout(), scheme)
	return nil
}
