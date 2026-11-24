package quarry

import (
	"fmt"
	"strconv"
	"strings"
)

// semVer represents a parsed Semantic Version with optional prerelease identifiers.
type semVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

// parseSemVer parses versions such as "v2.12.8", "0.21.1", "2.14.0-RC.1", or "3.8".
func parseSemVer(raw string) (semVer, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return semVer{}, fmt.Errorf("empty version")
	}

	// Strip build metadata (+...)
	if idx := strings.IndexByte(s, '+'); idx != -1 {
		s = s[:idx]
	}

	var prerelease string
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		prerelease = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semVer{}, fmt.Errorf("invalid semver %q", raw)
	}

	nums := [3]int{}
	for i, p := range parts {
		if p == "" {
			return semVer{}, fmt.Errorf("invalid semver component in %q", raw)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semVer{}, fmt.Errorf("invalid semver integer %q in %q", p, raw)
		}
		nums[i] = n
	}

	return semVer{
		Major:      nums[0],
		Minor:      nums[1],
		Patch:      nums[2],
		Prerelease: prerelease,
	}, nil
}

// compareSemVer compares a and b according to SemVer 2.0.0 precedence.
// Returns -1 if a < b, 0 if a == b, +1 if a > b.
func compareSemVer(a, b semVer) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}

	// Normal release has higher precedence than prerelease (2.14.0 > 2.14.0-RC.1)
	if a.Prerelease == "" && b.Prerelease == "" {
		return 0
	}
	if a.Prerelease == "" {
		return 1
	}
	if b.Prerelease == "" {
		return -1
	}

	aParts := strings.Split(a.Prerelease, ".")
	bParts := strings.Split(b.Prerelease, ".")
	minLen := len(aParts)
	if len(bParts) < minLen {
		minLen = len(bParts)
	}

	for i := 0; i < minLen; i++ {
		if aParts[i] == bParts[i] {
			continue
		}
		aNum, aErr := strconv.Atoi(aParts[i])
		bNum, bErr := strconv.Atoi(bParts[i])
		switch {
		case aErr == nil && bErr == nil:
			if aNum < bNum {
				return -1
			}
			return 1
		case aErr == nil:
			return -1 // numeric identifiers have lower precedence than non-numeric
		case bErr == nil:
			return 1
		default:
			if strings.ToLower(aParts[i]) < strings.ToLower(bParts[i]) {
				return -1
			}
			return 1
		}
	}

	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

type versionComparator struct {
	op  string // "<", "<=", ">", ">=", "="
	ver semVer
}

func (c versionComparator) matches(v semVer) bool {
	cmp := compareSemVer(v, c.ver)
	switch c.op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	default:
		return false
	}
}

// VersionConstraintSet represents a disjunction (||) of conjunctions (,) of SemVer comparators.
type VersionConstraintSet struct {
	raw    string
	groups [][]versionComparator
}

// ParseVersionConstraintSet parses expressions such as "<0.21.1" or
// "<2.12.8 || >=2.14.0-RC.1, <2.14.3".
func ParseVersionConstraintSet(expr string) (*VersionConstraintSet, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, fmt.Errorf("empty version constraint")
	}

	orGroups := strings.Split(trimmed, "||")
	var groups [][]versionComparator
	for _, grp := range orGroups {
		grp = strings.TrimSpace(grp)
		if grp == "" {
			return nil, fmt.Errorf("empty disjunction clause in version constraint %q", expr)
		}
		andClauses := strings.Split(grp, ",")
		var comps []versionComparator
		for _, clause := range andClauses {
			clause = strings.TrimSpace(clause)
			if clause == "" {
				continue
			}
			var op, verStr string
			switch {
			case strings.HasPrefix(clause, "<="):
				op = "<="
				verStr = strings.TrimSpace(clause[2:])
			case strings.HasPrefix(clause, ">="):
				op = ">="
				verStr = strings.TrimSpace(clause[2:])
			case strings.HasPrefix(clause, "=="):
				op = "="
				verStr = strings.TrimSpace(clause[2:])
			case strings.HasPrefix(clause, "<"):
				op = "<"
				verStr = strings.TrimSpace(clause[1:])
			case strings.HasPrefix(clause, ">"):
				op = ">"
				verStr = strings.TrimSpace(clause[1:])
			case strings.HasPrefix(clause, "="):
				op = "="
				verStr = strings.TrimSpace(clause[1:])
			default:
				op = "="
				verStr = clause
			}

			sv, err := parseSemVer(verStr)
			if err != nil {
				return nil, fmt.Errorf("invalid version comparator %q in %q: %w", clause, expr, err)
			}
			comps = append(comps, versionComparator{op: op, ver: sv})
		}
		if len(comps) == 0 {
			return nil, fmt.Errorf("no valid comparators in version constraint %q", expr)
		}
		groups = append(groups, comps)
	}

	return &VersionConstraintSet{
		raw:    trimmed,
		groups: groups,
	}, nil
}

// Matches returns true if versionStr satisfies any OR group (all AND comparators in that group).
// Unpinned or unparseable versions fail closed (return true) so vulnerable packages without
// explicit patched pins cannot bypass pre-flight Quarry blocking.
func (vcs *VersionConstraintSet) Matches(versionStr string) bool {
	if vcs == nil {
		return true
	}
	v, err := parseSemVer(versionStr)
	if err != nil {
		// Fail-closed: unknown, empty, or "latest" version of a known-vulnerable package is blocked.
		return true
	}

	for _, group := range vcs.groups {
		allMatch := true
		for _, comp := range group {
			if !comp.matches(v) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}
