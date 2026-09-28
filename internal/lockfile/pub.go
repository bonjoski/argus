package lockfile

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"bonjoski/argus/internal/model"
)

// PubLockParser parses Dart / Flutter pubspec.lock YAML files.
type PubLockParser struct{}

type pubLockFileDoc struct {
	Packages map[string]pubLockPackageEntry `yaml:"packages"`
}

type pubLockPackageEntry struct {
	Dependency  string `yaml:"dependency"`
	Description any    `yaml:"description"`
	Source      string `yaml:"source"`
	Version     string `yaml:"version"`
}

// Parse reads pubspec.lock and extracts all locked Dart/Flutter packages.
func (p *PubLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	body, err := io.ReadAll(io.LimitReader(r, 20*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read pubspec.lock: %w", err)
	}

	var doc pubLockFileDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse pubspec.lock YAML: %w", err)
	}

	var deps []LockedDependency
	for name, entry := range doc.Packages {
		version := strings.TrimSpace(entry.Version)
		if version == "" {
			continue
		}

		depType := strings.ToLower(strings.TrimSpace(entry.Dependency))
		isTransitive := true
		if strings.HasPrefix(depType, "direct") {
			isTransitive = false
		}

		hash := ""
		if descMap, ok := entry.Description.(map[string]any); ok {
			if sha, ok := descMap["sha256"].(string); ok && sha != "" {
				hash = "sha256-" + sha
			}
		}

		deps = append(deps, LockedDependency{
			Name:          name,
			Version:       version,
			Ecosystem:     model.EcosystemPub,
			IntegrityHash: hash,
			IsTransitive:  isTransitive,
		})
	}

	return deps, nil
}
