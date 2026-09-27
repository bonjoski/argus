package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"bonjoski/argus/internal/model"
)

// CargoLockParser parses Cargo.lock TOML dependency specifications.
type CargoLockParser struct{}

var (
	cargoNameRe     = regexp.MustCompile(`^\s*name\s*=\s*["']([^"']+)["']`)
	cargoVersionRe  = regexp.MustCompile(`^\s*version\s*=\s*["']([^"']+)["']`)
	cargoChecksumRe = regexp.MustCompile(`^\s*checksum\s*=\s*["']([^"']+)["']`)
	cargoSourceRe   = regexp.MustCompile(`^\s*source\s*=\s*["']([^"']+)["']`)
)

// Parse reads Cargo.lock and extracts all declared crates.
func (p *CargoLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 20*1024*1024))

	var deps []LockedDependency
	var inPackage bool
	var currentName, currentVersion, currentChecksum, currentSource string

	flush := func() {
		if currentName != "" && currentVersion != "" {
			// Crates with a registry source are dependencies; those without source are local workspace crates
			isTransitive := currentSource != ""
			hash := ""
			if currentChecksum != "" {
				hash = "sha256-" + currentChecksum
			}
			deps = append(deps, LockedDependency{
				Name:          currentName,
				Version:       currentVersion,
				Ecosystem:     model.EcosystemCargo,
				IntegrityHash: hash,
				IsTransitive:  isTransitive,
			})
		}
		currentName = ""
		currentVersion = ""
		currentChecksum = ""
		currentSource = ""
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage {
				flush()
			}
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if m := cargoNameRe.FindStringSubmatch(line); len(m) > 1 {
			currentName = m[1]
		} else if m := cargoVersionRe.FindStringSubmatch(line); len(m) > 1 {
			currentVersion = m[1]
		} else if m := cargoChecksumRe.FindStringSubmatch(line); len(m) > 1 {
			currentChecksum = m[1]
		} else if m := cargoSourceRe.FindStringSubmatch(line); len(m) > 1 {
			currentSource = m[1]
		}
	}

	if inPackage {
		flush()
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Cargo.lock: %w", err)
	}

	return deps, nil
}
