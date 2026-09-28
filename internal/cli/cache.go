package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/cache"
)

func newCacheCmd() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage local SQLite provenance cache",
	}

	cacheCmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Display cache entry counts and disk metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath, err := cache.DefaultCachePath()
			if err != nil {
				return err
			}
			store, err := cache.NewSQLiteStore(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open cache: %w", err)
			}
			defer store.Close()

			stats, err := store.Stats(context.Background())
			if err != nil {
				return err
			}

			fmt.Printf("Cache Location:  %s\n", dbPath)
			fmt.Printf("Total Entries:   %d\n", stats.TotalEntries)
			fmt.Printf("Expired Entries: %d\n", stats.ExpiredEntries)
			return nil
		},
	})

	cacheCmd.AddCommand(&cobra.Command{
		Use:   "prune",
		Short: "Delete all expired cache entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath, err := cache.DefaultCachePath()
			if err != nil {
				return err
			}
			store, err := cache.NewSQLiteStore(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open cache: %w", err)
			}
			pruned, err := store.Prune(context.Background())
			if err != nil {
				return err
			}

			fmt.Printf("Pruned %d expired entries from %s\n", pruned, dbPath)
			return nil
		},
	})

	cacheCmd.AddCommand(&cobra.Command{
		Use:   "seed <bundle.db>",
		Short: "Import a pre-seeded SQLite cache bundle for air-gapped runners",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seedPath := args[0]
			dbPath, err := cache.DefaultCachePath()
			if err != nil {
				return err
			}

			// Read seed bundle
			data, err := os.ReadFile(seedPath)
			if err != nil {
				return fmt.Errorf("failed to read seed bundle %s: %w", seedPath, err)
			}

			if err := os.WriteFile(dbPath, data, 0644); err != nil {
				return fmt.Errorf("failed to seed cache at %s: %w", dbPath, err)
			}

			fmt.Printf("Successfully seeded cache at %s from %s (%d bytes)\n", dbPath, seedPath, len(data))
			return nil
		},
	})

	cacheCmd.AddCommand(&cobra.Command{
		Use:   "export <bundle.db>",
		Short: "Export current SQLite cache bundle for air-gapped distribution",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exportPath := args[0]
			dbPath, err := cache.DefaultCachePath()
			if err != nil {
				return err
			}

			data, err := os.ReadFile(dbPath)
			if err != nil {
				return fmt.Errorf("failed to read cache database %s: %w", dbPath, err)
			}

			if err := os.WriteFile(exportPath, data, 0644); err != nil {
				return fmt.Errorf("failed to export cache bundle to %s: %w", exportPath, err)
			}

			fmt.Printf("Successfully exported cache bundle to %s (%d bytes)\n", exportPath, len(data))
			return nil
		},
	})

	return cacheCmd
}
