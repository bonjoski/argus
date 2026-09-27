package cli

import (
	"context"
	"fmt"

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
			defer store.Close()

			pruned, err := store.Prune(context.Background())
			if err != nil {
				return err
			}

			fmt.Printf("Pruned %d expired entries from %s\n", pruned, dbPath)
			return nil
		},
	})

	return cacheCmd
}
