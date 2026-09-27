package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"bonjoski/argus/internal/model"
)

// GoSumParser parses go.sum cryptographic record entries.
type GoSumParser struct{}

// Parse reads go.sum and extracts unique modules and version tags.
func (p *GoSumParser) Parse(r io.Reader) ([]LockedDependency, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 20*1024*1024))

	depsMap := make(map[string]*LockedDependency)
	var order []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		module := fields[0]
		verTag := fields[1]
		hash := fields[2]

		isGoMod := strings.HasSuffix(verTag, "/go.mod")
		cleanVer := strings.TrimSuffix(verTag, "/go.mod")

		key := module + "@" + cleanVer
		existing, ok := depsMap[key]
		if !ok {
			dep := &LockedDependency{
				Name:          module,
				Version:       cleanVer,
				Ecosystem:     model.EcosystemGo,
				IntegrityHash: hash,
				IsTransitive:  true,
			}
			depsMap[key] = dep
			order = append(order, key)
		} else if !isGoMod {
			// Prefer module code hash over go.mod hash
			existing.IntegrityHash = hash
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.sum: %w", err)
	}

	deps := make([]LockedDependency, 0, len(order))
	for _, key := range order {
		deps = append(deps, *depsMap[key])
	}

	return deps, nil
}
