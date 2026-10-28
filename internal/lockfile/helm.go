package lockfile

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"bonjoski/argus/internal/model"
)

// HelmLockParser parses Helm Chart.lock files.
type HelmLockParser struct{}

type helmChartLockDoc struct {
	Dependencies []struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		Repository string `yaml:"repository"`
		Digest     string `yaml:"digest"`
	} `yaml:"dependencies"`
	Digest    string `yaml:"digest"`
	Generated string `yaml:"generated"`
}

// Parse reads Chart.lock YAML and extracts locked Helm chart dependencies.
func (p *HelmLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	body, err := io.ReadAll(io.LimitReader(r, 20*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read Chart.lock: %w", err)
	}

	var doc helmChartLockDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse Chart.lock YAML: %w", err)
	}

	var deps []LockedDependency
	seen := make(map[string]bool)

	for _, d := range doc.Dependencies {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			continue
		}

		key := fmt.Sprintf("%s@%s", strings.ToLower(name), d.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, LockedDependency{
			Name:          name,
			Version:       d.Version,
			Ecosystem:     model.EcosystemHelm,
			IntegrityHash: d.Digest,
		})
	}

	return deps, nil
}
