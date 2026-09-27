package lockfile

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"bonjoski/argus/internal/model"
)

// LockedDependency represents a resolved package from a lockfile.
type LockedDependency struct {
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Ecosystem     model.Ecosystem `json:"ecosystem"`
	IntegrityHash string          `json:"integrity_hash,omitempty"`
	IsTransitive  bool            `json:"is_transitive"`
	Parent        string          `json:"parent,omitempty"`
}

// Parser defines the contract for reading dependencies from lockfiles.
type Parser interface {
	Parse(r io.Reader) ([]LockedDependency, error)
}

// Detect identifies the ecosystem and returns the appropriate parser for a lockfile path.
func Detect(path string) (Parser, model.Ecosystem, error) {
	base := strings.ToLower(filepath.Base(path))

	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return &NPMLockParser{}, model.EcosystemNPM, nil
	case "cargo.lock":
		return &CargoLockParser{}, model.EcosystemCargo, nil
	case "poetry.lock":
		return &PoetryLockParser{}, model.EcosystemPyPI, nil
	case "go.sum":
		return &GoSumParser{}, model.EcosystemGo, nil
	default:
		return nil, "", fmt.Errorf("unsupported or unrecognized lockfile format: %s", filepath.Base(path))
	}
}
