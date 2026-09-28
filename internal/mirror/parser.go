package mirror

import (
	"net/url"
	"strings"

	"bonjoski/argus/internal/model"
)

// TargetInfo holds parsed package details from an intercepted URL path.
type TargetInfo struct {
	Ecosystem model.Ecosystem
	Name      string
	Version   string
	IsTarget  bool
}

// ParseEcosystem parses an ecosystem string into its typed model.Ecosystem.
func ParseEcosystem(s string) (model.Ecosystem, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm":
		return model.EcosystemNPM, true
	case "pypi", "pip", "python":
		return model.EcosystemPyPI, true
	case "cargo", "crates", "rust":
		return model.EcosystemCargo, true
	case "go", "golang":
		return model.EcosystemGo, true
	case "rubygems", "gem", "ruby":
		return model.EcosystemRubyGems, true
	case "maven", "mvn":
		return model.EcosystemMaven, true
	case "packagist", "composer", "php":
		return model.EcosystemPackagist, true
	default:
		return model.Ecosystem(s), false
	}
}

// ParseNPMPath parses an incoming npm URL path (with /npm stripped).
func ParseNPMPath(rawPath string) (name, version string, isTarget bool) {
	path := strings.TrimPrefix(rawPath, "/")
	if path == "" {
		return "", "", false
	}

	// Unescape URL encoded slashes, e.g., @scope%2fpackage -> @scope/package
	unescaped, err := url.PathUnescape(path)
	if err == nil {
		path = unescaped
	}

	// NPM metadata / non-package administrative endpoints
	if strings.HasPrefix(path, "-/") {
		return "", "", false
	}

	// Check for tarball download pattern: /{pkgName}/-/{filename}.tgz
	if strings.Contains(path, "/-/") {
		parts := strings.SplitN(path, "/-/", 2)
		name = strings.Trim(parts[0], "/")
		if name == "" {
			return "", "", false
		}
		filename := parts[1]
		version = extractVersionFromNPMTarball(filename, name)
		return name, version, true
	}

	// Regular metadata queries: /@scope/pkg/1.0.0, /@scope/pkg, /pkg/1.0.0, /pkg
	segments := splitPathSegments(path)
	if len(segments) == 0 {
		return "", "", false
	}

	if strings.HasPrefix(segments[0], "@") {
		// Scoped package
		if len(segments) == 1 {
			// Incomplete scope like /@scope
			return "", "", false
		}
		name = segments[0] + "/" + segments[1]
		if len(segments) >= 3 {
			version = segments[2]
		}
		return name, version, true
	}

	// Unscoped package
	name = segments[0]
	if len(segments) >= 2 {
		version = segments[1]
	}
	return name, version, true
}

func extractVersionFromNPMTarball(filename, pkgName string) string {
	stem := strings.TrimSuffix(filename, ".tgz")
	stem = strings.TrimSuffix(stem, ".tar.gz")

	// Unscoped pkg name if scoped
	unscoped := pkgName
	if idx := strings.LastIndex(pkgName, "/"); idx != -1 {
		unscoped = pkgName[idx+1:]
	}

	prefix := unscoped + "-"
	if strings.HasPrefix(stem, prefix) {
		return strings.TrimPrefix(stem, prefix)
	}

	// Fallback: extract substring after last '-'
	if idx := strings.LastIndex(stem, "-"); idx != -1 {
		return stem[idx+1:]
	}
	return ""
}

// ParsePyPIPath parses an incoming PyPI URL path (with /pypi stripped).
func ParsePyPIPath(rawPath string) (name, version string, isTarget bool) {
	path := strings.TrimPrefix(rawPath, "/")
	if path == "" {
		return "", "", false
	}

	unescaped, err := url.PathUnescape(path)
	if err == nil {
		path = unescaped
	}

	// 1. Simple Index: /simple/{pkg}/ or /simple/
	if strings.HasPrefix(path, "simple/") || path == "simple" {
		rest := strings.TrimPrefix(path, "simple")
		rest = strings.Trim(rest, "/")
		if rest == "" {
			return "", "", false
		}
		// In simple index, rest is the package name
		segments := splitPathSegments(rest)
		return segments[0], "", true
	}

	// 2. Packages (Wheels & Source Distributions): /packages/.../{filename}
	if strings.HasPrefix(path, "packages/") {
		segments := splitPathSegments(path)
		if len(segments) == 0 {
			return "", "", false
		}
		filename := segments[len(segments)-1]
		name, version = extractPyPIPackageFromFilename(filename)
		if name != "" {
			return name, version, true
		}
		return "", "", false
	}

	// 3. JSON API: /pypi/{pkg}/json, /pypi/{pkg}/{version}/json, /{pkg}/json, /{pkg}/{version}/json
	cleanPath := strings.TrimPrefix(path, "pypi/")
	if strings.HasSuffix(cleanPath, "/json") || cleanPath == "json" {
		trimmed := strings.TrimSuffix(cleanPath, "/json")
		trimmed = strings.Trim(trimmed, "/")
		segments := splitPathSegments(trimmed)
		if len(segments) == 1 {
			return segments[0], "", true
		}
		if len(segments) >= 2 {
			return segments[0], segments[1], true
		}
		return "", "", false
	}

	// 4. Direct package query
	segments := splitPathSegments(cleanPath)
	if len(segments) == 1 {
		return segments[0], "", true
	}
	if len(segments) >= 2 {
		return segments[0], segments[1], true
	}

	return "", "", false
}

func extractPyPIPackageFromFilename(filename string) (name, version string) {
	// Wheel format: distribution-version(-build)?-python-abi-platform.whl
	if strings.HasSuffix(filename, ".whl") {
		stem := strings.TrimSuffix(filename, ".whl")
		parts := strings.Split(stem, "-")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}

	// Source archive format: distribution-version.tar.gz / .zip / .tgz
	for _, ext := range []string{".tar.gz", ".zip", ".tgz", ".tar.bz2"} {
		if strings.HasSuffix(filename, ext) {
			stem := strings.TrimSuffix(filename, ext)
			idx := strings.LastIndex(stem, "-")
			if idx != -1 {
				return stem[:idx], stem[idx+1:]
			}
			return stem, ""
		}
	}

	return "", ""
}

// ParseGenericEcosystemPath parses path for generic ecosystem registries in /proxy/:ecosystem/*
func ParseGenericEcosystemPath(eco model.Ecosystem, rawPath string) (name, version string, isTarget bool) {
	switch eco {
	case model.EcosystemNPM:
		return ParseNPMPath(rawPath)
	case model.EcosystemPyPI:
		return ParsePyPIPath(rawPath)
	case model.EcosystemCargo:
		// Cargo/Crates routes:
		// /api/v1/crates/{crate}/{version}/download
		// /api/v1/crates/{crate}
		// /crates/{crate}/{version}/download
		path := strings.Trim(rawPath, "/")
		path = strings.TrimPrefix(path, "api/v1/")
		segments := splitPathSegments(path)
		if len(segments) >= 2 && segments[0] == "crates" {
			name = segments[1]
			if len(segments) >= 4 && segments[3] == "download" {
				version = segments[2]
			}
			return name, version, true
		}
	case model.EcosystemRubyGems:
		// RubyGems routes:
		// /api/v1/gems/{gem}.json
		// /gems/{gem}-{version}.gem
		path := strings.Trim(rawPath, "/")
		if strings.HasPrefix(path, "api/v1/gems/") && strings.HasSuffix(path, ".json") {
			gem := strings.TrimPrefix(path, "api/v1/gems/")
			gem = strings.TrimSuffix(gem, ".json")
			return gem, "", true
		}
		if strings.HasPrefix(path, "gems/") && strings.HasSuffix(path, ".gem") {
			gemFile := strings.TrimPrefix(path, "gems/")
			stem := strings.TrimSuffix(gemFile, ".gem")
			if idx := strings.LastIndex(stem, "-"); idx != -1 {
				return stem[:idx], stem[idx+1:], true
			}
			return stem, "", true
		}
	case model.EcosystemPackagist:
		// Packagist routes:
		// /p2/{vendor}/{pkg}.json
		// /packages/{vendor}/{pkg}.json
		path := strings.Trim(rawPath, "/")
		path = strings.TrimPrefix(path, "p2/")
		path = strings.TrimPrefix(path, "packages/")
		if strings.HasSuffix(path, ".json") {
			clean := strings.TrimSuffix(path, ".json")
			segments := splitPathSegments(clean)
			if len(segments) >= 2 {
				return segments[0] + "/" + segments[1], "", true
			}
		}
	case model.EcosystemGo:
		// Go module proxy routes:
		// /{module}/@v/{version}.mod
		// /{module}/@v/{version}.zip
		// /{module}/@v/list
		path := strings.Trim(rawPath, "/")
		if idx := strings.Index(path, "/@v/"); idx != -1 {
			mod := path[:idx]
			rest := path[idx+4:]
			if rest == "list" {
				return mod, "", true
			}
			for _, ext := range []string{".mod", ".zip", ".info"} {
				if strings.HasSuffix(rest, ext) {
					ver := strings.TrimSuffix(rest, ext)
					return mod, ver, true
				}
			}
			return mod, "", true
		}
	}

	// Fallback heuristic: first non-empty segment as package name
	segments := splitPathSegments(strings.Trim(rawPath, "/"))
	if len(segments) > 0 {
		return segments[0], "", true
	}

	return "", "", false
}

func splitPathSegments(p string) []string {
	parts := strings.Split(p, "/")
	var res []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}
