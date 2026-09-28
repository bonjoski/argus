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

// DefaultAdapters initializes and returns all supported ecosystem registry adapters.
func DefaultAdapters() []Adapter {
	return []Adapter{
		NewNPMAdapter(nil),
		NewPyPIAdapter(nil),
		NewCratesAdapter(nil),
		NewGoModAdapter(nil),
		NewRubyGemsAdapter(nil),
		NewMavenAdapter(nil),
		NewPackagistAdapter(nil),
		NewNuGetAdapter(nil),
		NewPubAdapter(nil),
		NewHexAdapter(nil),
		NewSwiftAdapter(nil),
	}
}
