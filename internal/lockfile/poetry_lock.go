package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"bonjoski/argus/internal/model"
)

// PoetryLockParser parses poetry.lock TOML dependency specifications.
type PoetryLockParser struct{}

var (
	poetryNameRe    = regexp.MustCompile(`^\s*name\s*=\s*["']([^"']+)["']`)
	poetryVersionRe = regexp.MustCompile(`^\s*version\s*=\s*["']([^"']+)["']`)
	poetryHashRe    = regexp.MustCompile(`hash\s*=\s*["']([^"']+)["']`)
)

// Parse reads poetry.lock and extracts all Python packages.
func (p *PoetryLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 20*1024*1024))

	var deps []LockedDependency
	var inPackage bool
	var currentName, currentVersion, currentHash string

	flush := func() {
		if currentName != "" && currentVersion != "" {
			hash := ""
			if currentHash != "" {
				if strings.HasPrefix(currentHash, "sha256:") {
					hash = "sha256-" + strings.TrimPrefix(currentHash, "sha256:")
				} else {
					hash = currentHash
				}
			}
			deps = append(deps, LockedDependency{
				Name:          currentName,
				Version:       currentVersion,
				Ecosystem:     model.EcosystemPyPI,
				IntegrityHash: hash,
				IsTransitive:  true, // All locked poetry packages are resolved dependencies
			})
		}
		currentName = ""
		currentVersion = ""
		currentHash = ""
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

		if m := poetryNameRe.FindStringSubmatch(line); len(m) > 1 {
			currentName = m[1]
		} else if m := poetryVersionRe.FindStringSubmatch(line); len(m) > 1 {
			currentVersion = m[1]
		} else if currentHash == "" {
			if m := poetryHashRe.FindStringSubmatch(line); len(m) > 1 {
				currentHash = m[1]
			}
		}
	}

	if inPackage {
		flush()
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading poetry.lock: %w", err)
	}

	return deps, nil
}
