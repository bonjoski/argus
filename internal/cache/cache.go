package cache

import (
	"context"
	"time"

	"bonjoski/argus/internal/model"
)

// CacheStats provides usage diagnostics for the local SQLite cache.
type CacheStats struct {
	TotalEntries   int64 `json:"total_entries"`
	ExpiredEntries int64 `json:"expired_entries"`
	SizeBytes      int64 `json:"size_bytes"`
}

// Store defines the interface for local persistence of provenance and evaluation reports.
type Store interface {
	GetProvenance(ctx context.Context, eco model.Ecosystem, pkg, version, hash string) (*model.PackageProvenance, string, bool, error)
	SetProvenance(ctx context.Context, prov *model.PackageProvenance, etag string, ttl time.Duration) error

	GetReport(ctx context.Context, eco model.Ecosystem, pkg, version string) (*model.RiskReport, string, bool, error)
	SetReport(ctx context.Context, report *model.RiskReport, etag string, ttl time.Duration) error

	Prune(ctx context.Context) (int64, error)
	Stats(ctx context.Context) (*CacheStats, error)
	Close() error
}
