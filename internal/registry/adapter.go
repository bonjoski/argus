package registry

import (
	"context"

	"bonjoski/argus/internal/model"
)

// Adapter standardizes querying authoritative package registries.
type Adapter interface {
	Ecosystem() model.Ecosystem
	FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error)
}
