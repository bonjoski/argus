package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/mirror"
	"bonjoski/argus/internal/policy"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

var (
	mirrorPort         int
	mirrorDaemon       bool
	mirrorUpstreamNPM  string
	mirrorUpstreamPyPI string
	mirrorPIDPath      string
	mirrorLogPath      string
)

func newMirrorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mirror",
		Short: "Manage zero-latency inline HTTP registry mirror proxy for dependency interception",
		Long: `Argus Mirror is a high-performance inline HTTP forward and mirror proxy server
that intercepts dependency downloads from package managers (npm, pip, cargo, etc.)
and validates them against security heuristics and enterprise policies before allowing
them to reach developer workstations or CI environments.`,
	}

	defPid, defLog, _, _ := mirror.DefaultMirrorPaths()

	cmd.PersistentFlags().IntVar(&mirrorPort, "port", 8080, "Port to listen on for mirror proxy traffic")
	cmd.PersistentFlags().StringVar(&mirrorUpstreamNPM, "upstream-npm", "https://registry.npmjs.org", "Upstream npm registry URL")
	cmd.PersistentFlags().StringVar(&mirrorUpstreamPyPI, "upstream-pypi", "https://pypi.org", "Upstream PyPI registry URL")
	cmd.PersistentFlags().StringVar(&mirrorPIDPath, "pid-file", defPid, "PID file path for mirror process")
	cmd.PersistentFlags().StringVar(&mirrorLogPath, "log-file", defLog, "Log file path for background mirror process")

	cmd.AddCommand(newMirrorStartCmd())
	cmd.AddCommand(newMirrorRunCmd())
	cmd.AddCommand(newMirrorStopCmd())
	cmd.AddCommand(newMirrorStatusCmd())

	return cmd
}

func newMirrorStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the Argus registry mirror proxy (foreground or background daemon)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if mirrorDaemon {
				execPath, _ := os.Executable()
				if err := mirror.StartBackgroundMirror(execPath, mirrorPort, mirrorUpstreamNPM, mirrorUpstreamPyPI, 50, false, mirrorPIDPath, mirrorLogPath); err != nil {
					return fmt.Errorf("failed to start background mirror: %w", err)
				}

				stats, err := mirror.GetMirrorStatus(mirrorPIDPath, mirrorPort)
				if err != nil {
					return fmt.Errorf("mirror started but status check failed: %w", err)
				}

				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Argus inline registry mirror started successfully:"))
				fmt.Printf("   PID:           %d\n", stats.PID)
				fmt.Printf("   Port:          %d\n", stats.Port)
				fmt.Printf("   Upstream NPM:  %s\n", stats.UpstreamNPM)
				fmt.Printf("   Upstream PyPI: %s\n", stats.UpstreamPyPI)
				fmt.Printf("   Logs:          %s\n", mirrorLogPath)
				fmt.Println("\nTo configure package managers:")
				fmt.Printf("   npm:  npm config set registry http://127.0.0.1:%d/npm/\n", stats.Port)
				fmt.Printf("   pip:  pip config set global.index-url http://127.0.0.1:%d/pypi/simple/\n", stats.Port)
				return nil
			}

			return runMirrorServer(cmd)
		},
	}

	cmd.Flags().BoolVar(&mirrorDaemon, "daemon", false, "Run mirror proxy in the background as a resident daemon")
	return cmd
}

func newMirrorRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "run",
		Short:  "Run the Argus registry mirror proxy in the foreground",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMirrorServer(cmd)
		},
	}
}

func runMirrorServer(cmd *cobra.Command) error {
	// 1. Initialize SQLite Cache Store
	var cacheStore cache.Store
	dbPath, err := cache.DefaultCachePath()
	if err == nil {
		cacheStore, _ = cache.NewSQLiteStore(dbPath)
	}
	if cacheStore != nil {
		defer cacheStore.Close()
	}

	// 2. Initialize Upstream Registry Adapters
	npmAdapter := registry.NewNPMAdapter(nil)
	if mirrorUpstreamNPM != "" {
		npmAdapter.SetRegistryURL(mirrorUpstreamNPM)
	}

	pypiAdapter := registry.NewPyPIAdapter(nil)
	if mirrorUpstreamPyPI != "" {
		pypiAdapter.SetBaseURL(mirrorUpstreamPyPI + "/pypi")
	}

	adapters := []registry.Adapter{
		npmAdapter,
		pypiAdapter,
		registry.NewCratesAdapter(nil),
		registry.NewGoModAdapter(nil),
		registry.NewRubyGemsAdapter(nil),
		registry.NewMavenAdapter(nil),
		registry.NewPackagistAdapter(nil),
		registry.NewNuGetAdapter(nil),
		registry.NewPubAdapter(nil),
		registry.NewHexAdapter(nil),
		registry.NewSwiftAdapter(nil),
	}

	vcsVerifier := vcs.NewHTTPVerifier(nil)
	evaluator := heuristics.DefaultEngine()
	vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

	// 3. Load Enterprise Policy if available
	entPolicy, _ := policy.Load("")

	_, _, statePath, _ := mirror.DefaultMirrorPaths()

	cfg := mirror.Config{
		Host:           "127.0.0.1",
		Port:           mirrorPort,
		UpstreamNPM:    mirrorUpstreamNPM,
		UpstreamPyPI:   mirrorUpstreamPyPI,
		VettingService: vettingService,
		Policy:         entPolicy,
		PIDFile:        mirrorPIDPath,
		StateFile:      statePath,
		Threshold:      50,
	}

	server := mirror.NewServer(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("🚀 Starting Argus Inline Registry Mirror Proxy..."))
	fmt.Printf("   Port:          %d\n", mirrorPort)
	fmt.Printf("   PID:           %d\n", os.Getpid())
	fmt.Printf("   Upstream NPM:  %s\n", mirrorUpstreamNPM)
	fmt.Printf("   Upstream PyPI: %s\n", mirrorUpstreamPyPI)
	fmt.Println("   Routes:")
	fmt.Printf("     • NPM:       http://127.0.0.1:%d/npm/*\n", mirrorPort)
	fmt.Printf("     • PyPI:      http://127.0.0.1:%d/pypi/*\n", mirrorPort)
	fmt.Printf("     • Universal: http://127.0.0.1:%d/proxy/:ecosystem/*\n", mirrorPort)
	fmt.Printf("     • Status:    http://127.0.0.1:%d/_argus/status\n", mirrorPort)

	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("mirror server terminated with error: %w", err)
	}

	fmt.Println("Argus registry mirror proxy stopped.")
	return nil
}

func newMirrorStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the resident Argus registry mirror proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := mirror.StopMirror(mirrorPIDPath, mirrorPort); err != nil {
				return fmt.Errorf("failed to stop mirror: %w", err)
			}
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Argus registry mirror proxy stopped."))
			return nil
		},
	}
}

func newMirrorStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Query status and metrics of the registry mirror proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := mirror.GetMirrorStatus(mirrorPIDPath, mirrorPort)
			if err != nil {
				jsonFlag, _ := cmd.Flags().GetBool("json")
				if jsonFlag {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					_ = enc.Encode(map[string]any{
						"running": false,
						"port":    mirrorPort,
						"error":   err.Error(),
					})
					return nil
				}

				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8000")).Render("⚡ Argus mirror proxy is not running."))
				fmt.Printf("   Port: %d\n", mirrorPort)
				fmt.Println("   Run 'argus mirror start --daemon' to launch background mirror proxy.")
				return nil
			}

			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"running": true,
					"stats":   stats,
				})
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Render("Argus Inline Registry Mirror Status:"))
			fmt.Printf("   State:            %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("● Active / Healthy"))
			fmt.Printf("   PID:              %d\n", stats.PID)
			fmt.Printf("   Port:             %d\n", stats.Port)
			fmt.Printf("   Address:          %s\n", stats.Address)
			fmt.Printf("   Uptime:           %ds\n", stats.UptimeSeconds)
			fmt.Printf("   Total Requests:   %d\n", stats.TotalRequests)
			fmt.Printf("   Blocked Requests: %d\n", stats.BlockedRequests)
			fmt.Printf("   Allowed Requests: %d\n", stats.AllowedRequests)
			fmt.Printf("   Bytes Proxied:    %d bytes\n", stats.BytesProxied)
			fmt.Printf("   Upstream NPM:     %s\n", stats.UpstreamNPM)
			fmt.Printf("   Upstream PyPI:    %s\n", stats.UpstreamPyPI)
			return nil
		},
	}
}
