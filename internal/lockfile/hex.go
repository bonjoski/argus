package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"bonjoski/argus/internal/model"
)

// HexLockParser parses Elixir mix.lock files.
type HexLockParser struct{}

var (
	// Matches: "decimal": {:hex, :decimal, "2.1.1", "a96a...", ...}
	mixHexEntryRe = regexp.MustCompile(`"([^"]+)"\s*:\s*\{:hex,\s*:([^,\s]+),\s*"([^"]+)",\s*"([^"]+)"`)

	// Matches: "custom_dep": {:git, "https://github.com/...", "ref...", ...}
	mixGitEntryRe = regexp.MustCompile(`"([^"]+)"\s*:\s*\{:git,\s*"([^"]+)",\s*"([^"]+)"`)
)

// Parse reads mix.lock and extracts all locked Elixir/Hex packages.
func (p *HexLockParser) Parse(r io.Reader) ([]LockedDependency, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 20*1024*1024))

	var deps []LockedDependency
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "%{" || line == "}" {
			continue
		}

		if m := mixHexEntryRe.FindStringSubmatch(line); len(m) >= 5 {
			name := m[1]
			version := m[3]
			checksum := m[4]

			if seen[name] {
				continue
			}
			seen[name] = true

			hash := ""
			if checksum != "" {
				if strings.HasPrefix(checksum, "sha256-") {
					hash = checksum
				} else {
					hash = "sha256-" + checksum
				}
			}

			deps = append(deps, LockedDependency{
				Name:          name,
				Version:       version,
				Ecosystem:     model.EcosystemHex,
				IntegrityHash: hash,
				IsTransitive:  false,
			})
			continue
		}

		if m := mixGitEntryRe.FindStringSubmatch(line); len(m) >= 4 {
			name := m[1]
			revision := m[3]

			if seen[name] {
				continue
			}
			seen[name] = true

			deps = append(deps, LockedDependency{
				Name:          name,
				Version:       revision,
				Ecosystem:     model.EcosystemHex,
				IntegrityHash: "git-" + revision,
				IsTransitive:  false,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading mix.lock: %w", err)
	}

	return deps, nil
}
