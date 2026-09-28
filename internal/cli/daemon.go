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
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/service"
	"bonjoski/argus/internal/vcs"
)

var (
	daemonSocketPath string
	daemonPidPath    string
)

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage high-speed resident IPC daemon for sub-millisecond dependency vetting",
	}

	defaultSock, defaultPid, _, _ := daemon.DefaultPaths()

	cmd.PersistentFlags().StringVar(&daemonSocketPath, "socket", defaultSock, "Unix domain socket path for daemon IPC")
	cmd.PersistentFlags().StringVar(&daemonPidPath, "pid-file", defaultPid, "PID file path for daemon process")

	cmd.AddCommand(newDaemonRunCmd())
	cmd.AddCommand(newDaemonStartCmd())
	cmd.AddCommand(newDaemonStopCmd())
	cmd.AddCommand(newDaemonStatusCmd())
	cmd.AddCommand(newDaemonPingCmd())

	return cmd
}

func newDaemonRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the Argus daemon in the foreground",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize resident SQLite Cache
			var cacheStore cache.Store
			dbPath, err := cache.DefaultCachePath()
			if err == nil {
				cacheStore, _ = cache.NewSQLiteStore(dbPath)
			}
			if cacheStore != nil {
				defer cacheStore.Close()
			}

			adapters := []registry.Adapter{
				registry.NewNPMAdapter(nil),
				registry.NewPyPIAdapter(nil),
				registry.NewCratesAdapter(nil),
				registry.NewGoModAdapter(nil),
				registry.NewRubyGemsAdapter(nil),
				registry.NewMavenAdapter(nil),
				registry.NewPackagistAdapter(nil),
			}

			vcsVerifier := vcs.NewHTTPVerifier(nil)
			evaluator := heuristics.DefaultEngine()
			vettingService := service.NewVettingService(cacheStore, adapters, vcsVerifier, evaluator, 24*time.Hour)

			server := daemon.NewServer(daemonSocketPath, daemonPidPath, vettingService)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("🚀 Starting Argus IPC Resident Daemon..."))
			fmt.Printf("   Socket: %s\n", daemonSocketPath)
			fmt.Printf("   PID:    %d\n", os.Getpid())

			if err := server.Start(ctx); err != nil {
				return fmt.Errorf("daemon server terminated with error: %w", err)
			}

			fmt.Println("Argus daemon gracefully stopped.")
			return nil
		},
	}
}

func newDaemonStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the Argus daemon in the background",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, logPath, err := daemon.DefaultPaths()
			if err != nil {
				return err
			}

			execPath, _ := os.Executable()
			if err := daemon.StartBackgroundDaemon(execPath, daemonSocketPath, daemonPidPath, logPath); err != nil {
				return fmt.Errorf("failed to start daemon: %w", err)
			}

			client := daemon.NewClient(daemonSocketPath)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			stats, err := client.Stats(ctx)
			if err != nil {
				return fmt.Errorf("daemon started but failed to query status: %w", err)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Argus resident daemon started successfully:"))
			fmt.Printf("   PID:    %d\n", stats.PID)
			fmt.Printf("   Socket: %s\n", daemonSocketPath)
			fmt.Printf("   Logs:   %s\n", logPath)
			return nil
		},
	}
}

func newDaemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the resident Argus daemon process",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemon.StopDaemon(daemonSocketPath, daemonPidPath); err != nil {
				return fmt.Errorf("failed to stop daemon: %w", err)
			}
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("✔ Argus daemon stopped."))
			return nil
		},
	}
}

func newDaemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Query status and performance metrics of the resident daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := daemon.NewClient(daemonSocketPath)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			stats, err := client.Stats(ctx)
			if err != nil {
				if jsonOutput {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					_ = enc.Encode(map[string]any{
						"running": false,
						"error":   err.Error(),
						"socket":  daemonSocketPath,
					})
					return nil
				}
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8000")).Render("⚡ Argus daemon is not running."))
				fmt.Printf("   Socket: %s\n", daemonSocketPath)
				fmt.Println("   Run 'argus daemon start' to launch background resident daemon.")
				return nil
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"running": true,
					"stats":   stats,
				})
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Render("Argus Resident IPC Daemon Status:"))
			fmt.Printf("   State:          %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("● Active / Healthy"))
			fmt.Printf("   PID:            %d\n", stats.PID)
			fmt.Printf("   Socket:         %s\n", stats.SocketPath)
			fmt.Printf("   Uptime:         %ds\n", stats.UptimeSeconds)
			fmt.Printf("   Memory Alloc:   %.2f MB\n", stats.MemoryAllocMB)
			fmt.Printf("   Total Requests: %d\n", stats.TotalRequests)
			fmt.Printf("   Cache Hits:     %d\n", stats.CacheHits)
			fmt.Printf("   Cache Misses:   %d\n", stats.CacheMisses)
			return nil
		},
	}
}

func newDaemonPingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ping",
		Short: "Send a health-check ping to the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := daemon.NewClient(daemonSocketPath)
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			if err := client.Ping(ctx); err != nil {
				return fmt.Errorf("daemon ping failed: %w", err)
			}
			latency := time.Since(start)

			fmt.Printf("✔ Daemon responded in %v (socket: %s)\n", latency, daemonSocketPath)
			return nil
		},
	}
}
