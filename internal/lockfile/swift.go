package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"bonjoski/argus/internal/model"
)

// SwiftLockParser parses Swift Package.resolved files across v1, v2, and v3 schemas.
type SwiftLockParser struct{}

// Generic representation supporting v1, v2, and v3 formats
type swiftResolvedDoc struct {
	Version int `json:"version"`

	// v1 format
	Object *struct {
		Pins []swiftV1Pin `json:"pins"`
	} `json:"object"`

	// v2 and v3 format
	Pins []swiftV2V3Pin `json:"pins"`
}

type swiftV1Pin struct {
	Package       string        `json:"package"`
	RepositoryURL string        `json:"repositoryURL"`
	State         swiftPinState `json:"state"`
}

type swiftV2V3Pin struct {
	Identity string        `json:"identity"`
	Kind     string        `json:"kind"`
	Location string        `json:"location"`
	State    swiftPinState `json:"state"`
}

type swiftPinState struct {
	Branch   *string `json:"branch"`
	Revision string  `json:"revision"`
	Version  *string `json:"version"`
	Checksum *string `json:"checksum"`
}

// Parse reads Package.resolved and extracts all locked Swift packages.
func (p *SwiftLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	body, err := io.ReadAll(io.LimitReader(r, 20*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read Package.resolved: %w", err)
	}

	var doc swiftResolvedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse Package.resolved JSON: %w", err)
	}

	var deps []LockedDependency
	seen := make(map[string]bool)

	extractPin := func(name, location string, state swiftPinState) {
		name = strings.TrimSpace(name)
		if name == "" && location != "" {
			// Extract from repo URL: https://github.com/apple/swift-algorithms.git -> swift-algorithms
			cleanURL := strings.TrimSuffix(location, ".git")
			cleanURL = strings.TrimRight(cleanURL, "/")
			name = path.Base(cleanURL)
		}

		if name == "" {
			return
		}

		version := ""
		if state.Version != nil && *state.Version != "" {
			version = *state.Version
		} else if state.Revision != "" {
			version = state.Revision
		} else if state.Branch != nil && *state.Branch != "" {
			version = *state.Branch
		}

		if version == "" {
			return
		}

		key := fmt.Sprintf("%s@%s", strings.ToLower(name), version)
		if seen[key] {
			return
		}
		seen[key] = true

		hash := ""
		if state.Checksum != nil && *state.Checksum != "" {
			hash = *state.Checksum
		} else if state.Revision != "" {
			hash = "git-" + state.Revision
		}

		deps = append(deps, LockedDependency{
			Name:          name,
			Version:       version,
			Ecosystem:     model.EcosystemSwift,
			IntegrityHash: hash,
			IsTransitive:  false,
		})
	}

	// Process v1 pins if present
	if doc.Object != nil && len(doc.Object.Pins) > 0 {
		for _, pin := range doc.Object.Pins {
			extractPin(pin.Package, pin.RepositoryURL, pin.State)
		}
	}

	// Process v2/v3 pins if present
	if len(doc.Pins) > 0 {
		for _, pin := range doc.Pins {
			extractPin(pin.Identity, pin.Location, pin.State)
		}
	}

	return deps, nil
}
