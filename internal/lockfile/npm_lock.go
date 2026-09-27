package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"bonjoski/argus/internal/model"
)

// NPMLockParser parses npm package-lock.json (v1, v2, v3).
type NPMLockParser struct{}

type npmLockDoc struct {
	Name            string                     `json:"name"`
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage  `json:"packages"`
	Dependencies    map[string]npmV1Dependency `json:"dependencies"`
}

type npmLockPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Integrity    string                     `json:"integrity"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// Parse extracts all direct and transitive dependencies from a package-lock.json.
func (p *NPMLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	body, err := io.ReadAll(io.LimitReader(r, 50*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var doc npmLockDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	seen := make(map[string]bool)
	var deps []LockedDependency

	// Support v2 / v3 modern format
	if len(doc.Packages) > 0 {
		for key, pkg := range doc.Packages {
			if key == "" {
				continue
			}

			const prefix = "node_modules/"
			lastIdx := strings.LastIndex(key, prefix)
			if lastIdx == -1 {
				continue
			}

			name := key[lastIdx+len(prefix):]
			if name == "" {
				continue
			}

			isTransitive := strings.Count(key, prefix) > 1

			uniqueKey := name + "@" + pkg.Version
			if !seen[uniqueKey] {
				seen[uniqueKey] = true
				deps = append(deps, LockedDependency{
					Name:          name,
					Version:       pkg.Version,
					Ecosystem:     model.EcosystemNPM,
					IntegrityHash: pkg.Integrity,
					IsTransitive:  isTransitive,
				})
			}
		}
		return deps, nil
	}

	// Fallback to v1 legacy format
	var parseV1 func(parent string, depsMap map[string]npmV1Dependency, isTransitive bool)
	parseV1 = func(parent string, depsMap map[string]npmV1Dependency, isTransitive bool) {
		for name, dep := range depsMap {
			uniqueKey := name + "@" + dep.Version
			if !seen[uniqueKey] {
				seen[uniqueKey] = true
				deps = append(deps, LockedDependency{
					Name:          name,
					Version:       dep.Version,
					Ecosystem:     model.EcosystemNPM,
					IntegrityHash: dep.Integrity,
					IsTransitive:  isTransitive,
					Parent:        parent,
				})
			}
			if len(dep.Dependencies) > 0 {
				parseV1(name, dep.Dependencies, true)
			}
		}
	}

	parseV1("", doc.Dependencies, false)
	return deps, nil
}
