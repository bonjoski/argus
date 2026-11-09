package registry

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type parsedSemver struct {
	raw        string
	major      int
	minor      int
	patch      int
	prerelease string
}

func parseSemver(v string) (parsedSemver, bool) {
	raw := strings.TrimSpace(v)
	cleaned := strings.TrimPrefix(strings.TrimPrefix(raw, "="), "v")
	if cleaned == "" {
		return parsedSemver{}, false
	}

	// Strip build metadata (+...)
	if plusIdx := strings.IndexByte(cleaned, '+'); plusIdx != -1 {
		cleaned = cleaned[:plusIdx]
	}

	var prerelease string
	if dashIdx := strings.IndexByte(cleaned, '-'); dashIdx != -1 {
		prerelease = cleaned[dashIdx+1:]
		cleaned = cleaned[:dashIdx]
		if prerelease == "" {
			return parsedSemver{}, false
		}
	}

	parts := strings.Split(cleaned, ".")
	if len(parts) != 3 {
		return parsedSemver{}, false
	}

	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || major < 0 || minor < 0 || patch < 0 {
		return parsedSemver{}, false
	}

	return parsedSemver{
		raw:        raw,
		major:      major,
		minor:      minor,
		patch:      patch,
		prerelease: prerelease,
	}, true
}

func compareSemver(a, b parsedSemver) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	if a.prerelease == b.prerelease {
		return 0
	}
	// Per SemVer 2.0.0, normal version takes precedence over pre-release.
	if a.prerelease == "" {
		return 1
	}
	if b.prerelease == "" {
		return -1
	}
	aParts := strings.Split(a.prerelease, ".")
	bParts := strings.Split(b.prerelease, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aNum, aErr := strconv.Atoi(aParts[i])
		bNum, bErr := strconv.Atoi(bParts[i])
		if aErr == nil && bErr == nil {
			if aNum != bNum {
				if aNum < bNum {
					return -1
				}
				return 1
			}
			continue
		}
		if aErr == nil && bErr != nil {
			return -1
		}
		if aErr != nil && bErr == nil {
			return 1
		}
		if aParts[i] != bParts[i] {
			if aParts[i] < bParts[i] {
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

type comparator struct {
	op  string // "=", ">", ">=", "<", "<="
	ver parsedSemver
}

func (c comparator) matches(candidate parsedSemver) bool {
	cmp := compareSemver(candidate, c.ver)
	switch c.op {
	case "=":
		return cmp == 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	default:
		return false
	}
}

func parsePartialVersion(raw string) (major int, hasMinor bool, minor int, hasPatch bool, patch int, prerelease string, ok bool) {
	s := strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	if s == "" || s == "*" || s == "x" || s == "X" {
		return 0, false, 0, false, 0, "", true
	}
	if plusIdx := strings.IndexByte(s, '+'); plusIdx != -1 {
		s = s[:plusIdx]
	}
	if dashIdx := strings.IndexByte(s, '-'); dashIdx != -1 {
		prerelease = s[dashIdx+1:]
		s = s[:dashIdx]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return 0, false, 0, false, 0, "", false
	}
	isWild := func(p string) bool {
		return p == "*" || p == "x" || p == "X" || p == ""
	}
	if isWild(parts[0]) {
		return 0, false, 0, false, 0, "", true
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil || maj < 0 {
		return 0, false, 0, false, 0, "", false
	}
	if len(parts) == 1 || isWild(parts[1]) {
		return maj, false, 0, false, 0, "", true
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil || min < 0 {
		return 0, false, 0, false, 0, "", false
	}
	if len(parts) == 2 || isWild(parts[2]) {
		return maj, true, min, false, 0, "", true
	}
	pat, err := strconv.Atoi(parts[2])
	if err != nil || pat < 0 {
		return 0, false, 0, false, 0, "", false
	}
	return maj, true, min, true, pat, prerelease, true
}

func expandToken(token string) ([]comparator, bool) {
	token = strings.TrimSpace(token)
	if token == "" || token == "*" || token == "x" || token == "X" {
		return []comparator{{op: ">=", ver: parsedSemver{major: 0, minor: 0, patch: 0}}}, true
	}

	if strings.HasPrefix(token, "^") {
		maj, hasMin, min, hasPat, pat, pre, ok := parsePartialVersion(token[1:])
		if !ok {
			return nil, false
		}
		if !hasMin {
			return []comparator{
				{op: ">=", ver: parsedSemver{major: maj, minor: 0, patch: 0}},
				{op: "<", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}},
			}, true
		}
		if !hasPat {
			if maj == 0 {
				return []comparator{
					{op: ">=", ver: parsedSemver{major: 0, minor: min, patch: 0}},
					{op: "<", ver: parsedSemver{major: 0, minor: min + 1, patch: 0}},
				}, true
			}
			return []comparator{
				{op: ">=", ver: parsedSemver{major: maj, minor: min, patch: 0}},
				{op: "<", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}},
			}, true
		}
		lower := parsedSemver{major: maj, minor: min, patch: pat, prerelease: pre}
		var upper parsedSemver
		if maj > 0 {
			upper = parsedSemver{major: maj + 1, minor: 0, patch: 0}
		} else if min > 0 {
			upper = parsedSemver{major: 0, minor: min + 1, patch: 0}
		} else {
			upper = parsedSemver{major: 0, minor: 0, patch: pat + 1}
		}
		return []comparator{{op: ">=", ver: lower}, {op: "<", ver: upper}}, true
	}

	if strings.HasPrefix(token, "~") {
		maj, hasMin, min, hasPat, pat, pre, ok := parsePartialVersion(token[1:])
		if !ok {
			return nil, false
		}
		if !hasMin {
			return []comparator{
				{op: ">=", ver: parsedSemver{major: maj, minor: 0, patch: 0}},
				{op: "<", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}},
			}, true
		}
		lowerPat := 0
		if hasPat {
			lowerPat = pat
		}
		return []comparator{
			{op: ">=", ver: parsedSemver{major: maj, minor: min, patch: lowerPat, prerelease: pre}},
			{op: "<", ver: parsedSemver{major: maj, minor: min + 1, patch: 0}},
		}, true
	}

	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(token, op) {
			rest := strings.TrimSpace(token[len(op):])
			maj, hasMin, min, hasPat, pat, pre, ok := parsePartialVersion(rest)
			if !ok {
				return nil, false
			}
			if hasMin && hasPat {
				return []comparator{{op: op, ver: parsedSemver{major: maj, minor: min, patch: pat, prerelease: pre}}}, true
			}
			switch op {
			case "=":
				return expandWildcardEqual(maj, hasMin, min)
			case ">=":
				return []comparator{{op: ">=", ver: parsedSemver{major: maj, minor: min, patch: 0}}}, true
			case ">":
				if !hasMin {
					return []comparator{{op: ">=", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}}}, true
				}
				return []comparator{{op: ">=", ver: parsedSemver{major: maj, minor: min + 1, patch: 0}}}, true
			case "<":
				return []comparator{{op: "<", ver: parsedSemver{major: maj, minor: min, patch: 0}}}, true
			case "<=":
				if !hasMin {
					return []comparator{{op: "<", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}}}, true
				}
				return []comparator{{op: "<", ver: parsedSemver{major: maj, minor: min + 1, patch: 0}}}, true
			}
		}
	}

	maj, hasMin, min, hasPat, pat, pre, ok := parsePartialVersion(token)
	if !ok {
		return nil, false
	}
	if hasMin && hasPat {
		return []comparator{{op: "=", ver: parsedSemver{major: maj, minor: min, patch: pat, prerelease: pre}}}, true
	}
	return expandWildcardEqual(maj, hasMin, min)
}

func expandWildcardEqual(maj int, hasMin bool, min int) ([]comparator, bool) {
	if !hasMin {
		return []comparator{
			{op: ">=", ver: parsedSemver{major: maj, minor: 0, patch: 0}},
			{op: "<", ver: parsedSemver{major: maj + 1, minor: 0, patch: 0}},
		}, true
	}
	return []comparator{
		{op: ">=", ver: parsedSemver{major: maj, minor: min, patch: 0}},
		{op: "<", ver: parsedSemver{major: maj, minor: min + 1, patch: 0}},
	}, true
}

func parseConjunctiveRange(expr string) ([]comparator, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return []comparator{{op: ">=", ver: parsedSemver{major: 0, minor: 0, patch: 0}}}, true
	}

	// Normalize operator spacing like ">= 1.2.0" -> ">=1.2.0"
	for _, op := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		expr = strings.ReplaceAll(expr, op+" ", op)
	}

	// Handle hyphen ranges: "1.2.3 - 2.3.4"
	if strings.Contains(expr, " - ") {
		parts := strings.SplitN(expr, " - ", 2)
		lowComps, ok1 := expandToken(">=" + strings.TrimSpace(parts[0]))
		highComps, ok2 := expandToken("<=" + strings.TrimSpace(parts[1]))
		if !ok1 || !ok2 {
			return nil, false
		}
		return append(lowComps, highComps...), true
	}

	fields := strings.Fields(expr)
	var all []comparator
	for _, f := range fields {
		comps, ok := expandToken(f)
		if !ok {
			return nil, false
		}
		all = append(all, comps...)
	}
	return all, true
}

func matchesComparatorSet(candidate parsedSemver, comps []comparator) bool {
	if candidate.prerelease != "" {
		// Per node-semver, pre-release versions only match if at least one comparator in the set
		// explicitly targets a pre-release on the exact same [major, minor, patch] tuple.
		explicitPre := false
		for _, c := range comps {
			if c.ver.prerelease != "" &&
				c.ver.major == candidate.major &&
				c.ver.minor == candidate.minor &&
				c.ver.patch == candidate.patch {
				explicitPre = true
				break
			}
		}
		if !explicitPre {
			return false
		}
	}
	for _, c := range comps {
		if !c.matches(candidate) {
			return false
		}
	}
	return true
}

// ResolveNPMVersion resolves a requested npm version, dist-tag (e.g., "latest", "next"), or semver
// range (e.g., "^1.2.0", "~2.0.1", ">=1.0.0 <2.0.0", "*", "") against published versions.
// Fails closed if no published concrete version satisfies the request.
func ResolveNPMVersion(requested string, distTags map[string]string, versions map[string]npmVersionDoc) (string, npmVersionDoc, error) {
	if len(versions) == 0 {
		return "", npmVersionDoc{}, fmt.Errorf("npm package metadata contains zero published versions")
	}

	req := strings.TrimSpace(requested)
	if req == "" {
		req = "latest"
	}

	// 1. Exact version match
	if verDoc, ok := versions[req]; ok {
		return req, verDoc, nil
	}
	if trimmed := strings.TrimPrefix(strings.TrimPrefix(req, "="), "v"); trimmed != req {
		if verDoc, ok := versions[trimmed]; ok {
			return trimmed, verDoc, nil
		}
	}

	// 2. Dist-tag lookup (e.g. "latest", "next", "beta", "canary")
	if tagVer, ok := distTags[req]; ok {
		if verDoc, exists := versions[tagVer]; exists {
			return tagVer, verDoc, nil
		}
		return "", npmVersionDoc{}, fmt.Errorf("npm dist-tag %q points to unpublished version %q", req, tagVer)
	}

	// If "latest" was requested via empty spec and dist-tags omitted "latest", fall back to "*" only if requested was empty
	if requested == "" && req == "latest" {
		req = "*"
	}

	// 3. Semver range evaluation across all published versions (pick highest matching version)
	orBranches := strings.Split(req, "||")
	var unionSets [][]comparator
	for _, branch := range orBranches {
		comps, ok := parseConjunctiveRange(branch)
		if !ok {
			return "", npmVersionDoc{}, fmt.Errorf("unable to resolve npm version/range %q against published versions", requested)
		}
		unionSets = append(unionSets, comps)
	}

	var candidates []parsedSemver
	for verKey := range versions {
		sv, ok := parseSemver(verKey)
		if !ok {
			continue
		}
		sv.raw = verKey
		for _, comps := range unionSets {
			if matchesComparatorSet(sv, comps) {
				candidates = append(candidates, sv)
				break
			}
		}
	}

	if len(candidates) == 0 {
		return "", npmVersionDoc{}, fmt.Errorf("no published npm version satisfies %q", requested)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return compareSemver(candidates[i], candidates[j]) < 0
	})
	best := candidates[len(candidates)-1].raw
	return best, versions[best], nil
}
