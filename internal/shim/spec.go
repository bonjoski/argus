package shim

import (
	"fmt"
	"net/url"
	"strings"

	"bonjoski/argus/internal/model"
)

var forbiddenSpecPrefixes = []string{
	"git+ssh://",
	"git+https://",
	"git+http://",
	"git+file://",
	"git://",
	"ssh://",
	"http://",
	"https://",
	"ftp://",
	"file:",
	"link:",
	"portal:",
	"workspace:",
	"patch:",
	"github:",
	"gitlab:",
	"bitbucket:",
	"gist:",
	"git@",
}

var forbiddenArchiveSuffixes = []string{
	".tgz",
	".tar.gz",
	".tar",
	".tar.bz2",
	".tar.xz",
	".whl",
	".zip",
	".gem",
	".crate",
	".nupkg",
	".jar",
}

// SplitNPMSpec splits an npm-style spec (handling @scope/pkg@version and npm: aliases)
// without ecosystem-specific validation. Used by legacy callers while unwrapping npm: aliases.
func SplitNPMSpec(spec string) (name, version string) {
	s := strings.TrimSpace(spec)
	for depth := 0; depth < 4; depth++ {
		if strings.HasPrefix(strings.ToLower(s), "npm:") {
			s = strings.TrimSpace(s[4:])
			continue
		}
		var n, v string
		if strings.HasPrefix(s, "@") {
			rest := s[1:]
			if atIdx := strings.Index(rest, "@"); atIdx != -1 {
				n = "@" + rest[:atIdx]
				v = rest[atIdx+1:]
			} else {
				return s, ""
			}
		} else if atIdx := strings.Index(s, "@"); atIdx != -1 {
			n = s[:atIdx]
			v = s[atIdx+1:]
		} else {
			return s, ""
		}
		if strings.HasPrefix(strings.ToLower(v), "npm:") {
			s = strings.TrimSpace(v[4:])
			continue
		}
		return n, v
	}
	return s, ""
}

// ParseAndValidatePackageSpec unwraps package aliases (e.g., malicious@npm:target@1.2.3)
// and rejects direct VCS/URL/tarball/local-path bypass specifications fail-closed.
func ParseAndValidatePackageSpec(eco model.Ecosystem, raw string) (name, version string, err error) {
	spec := strings.TrimSpace(raw)
	if spec == "" {
		return "", "", fmt.Errorf("empty package specification")
	}
	if strings.ContainsAny(spec, "\x00\r\n") {
		return "", "", fmt.Errorf("control characters forbidden in package specification %q", raw)
	}

	// SwiftPM packages legitimately use https://github.com/<owner>/<repo> or <owner>/<repo>
	if eco == model.EcosystemSwift {
		return parseSwiftSpec(spec)
	}

	// Reject CLI flags smuggled as positional targets (e.g. --git)
	if strings.HasPrefix(spec, "-") {
		return "", "", fmt.Errorf("unexpected flag token in package target %q", raw)
	}

	// Unwrap npm: protocol aliases (e.g. benign-name@npm:malicious-pkg@1.2.3 or npm:malicious-pkg@^1.0.0)
	const maxAliasDepth = 4
	aliasDepth := 0
	for {
		if err := rejectDirectBypassProtocols(spec, raw); err != nil {
			return "", "", err
		}
		if strings.HasPrefix(strings.ToLower(spec), "npm:") {
			aliasDepth++
			if aliasDepth > maxAliasDepth {
				return "", "", fmt.Errorf("excessive npm: alias nesting in %q", raw)
			}
			spec = strings.TrimSpace(spec[4:])
			if spec == "" {
				return "", "", fmt.Errorf("empty target in npm: alias %q", raw)
			}
			continue
		}

		n, v, hasAt := splitAtVersion(spec)
		if hasAt && strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "npm:") {
			aliasDepth++
			if aliasDepth > maxAliasDepth {
				return "", "", fmt.Errorf("excessive npm: alias nesting in %q", raw)
			}
			if strings.TrimSpace(n) == "" {
				return "", "", fmt.Errorf("invalid alias name in %q", raw)
			}
			spec = strings.TrimSpace(strings.TrimSpace(v)[4:])
			if spec == "" {
				return "", "", fmt.Errorf("empty target in npm: alias %q", raw)
			}
			continue
		}
		break
	}

	if err := rejectDirectBypassProtocols(spec, raw); err != nil {
		return "", "", err
	}

	if eco == model.EcosystemPyPI {
		return parsePyPISpec(spec, raw)
	}

	if eco == model.EcosystemPackagist {
		// Composer supports vendor/pkg:^1.0 or vendor/pkg@dev
		if colonIdx := strings.IndexByte(spec, ':'); colonIdx != -1 {
			pkgPart := strings.TrimSpace(spec[:colonIdx])
			verPart := strings.TrimSpace(spec[colonIdx+1:])
			if err := rejectDirectBypassProtocols(verPart, raw); err != nil {
				return "", "", err
			}
			return pkgPart, verPart, nil
		}
	}

	pkgName, ver, hasAt := splitAtVersion(spec)
	if strings.TrimSpace(pkgName) == "" {
		return "", "", fmt.Errorf("invalid package name in %q", raw)
	}
	if hasAt {
		if err := rejectDirectBypassProtocols(ver, raw); err != nil {
			return "", "", err
		}
	}

	// Ecosystem-specific structural guards
	if eco == model.EcosystemNPM {
		// Unscoped npm specs containing '/' are GitHub repo shorthands (e.g. attacker/repo#branch)
		// or local paths that bypass the npm registry!
		if strings.HasPrefix(pkgName, "@") {
			parts := strings.Split(pkgName, "/")
			if len(parts) != 2 || parts[0] == "@" || parts[1] == "" || strings.Contains(pkgName, "#") {
				return "", "", fmt.Errorf("invalid scoped npm package %q (VCS/shorthand specs are blocked)", raw)
			}
		} else if strings.ContainsAny(pkgName, "/\\#") {
			return "", "", fmt.Errorf("unscoped npm specification %q contains path/GitHub shorthand characters; direct VCS/tarball installs are blocked", raw)
		}
	}

	return pkgName, ver, nil
}

func splitAtVersion(spec string) (name, version string, hasAt bool) {
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		atIdx := strings.IndexByte(rest, '@')
		if atIdx != -1 {
			return "@" + rest[:atIdx], rest[atIdx+1:], true
		}
		return spec, "", false
	}
	if atIdx := strings.IndexByte(spec, '@'); atIdx != -1 {
		return spec[:atIdx], spec[atIdx+1:], true
	}
	return spec, "", false
}

func rejectDirectBypassProtocols(fragment, fullRaw string) error {
	trimmed := strings.TrimSpace(fragment)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)

	for _, p := range forbiddenSpecPrefixes {
		if strings.HasPrefix(lower, p) {
			return fmt.Errorf("unverified direct URL/VCS/local protocol %q is blocked in package spec %q", p, fullRaw)
		}
	}

	if strings.Contains(lower, "://") {
		return fmt.Errorf("direct URL reference is blocked in package spec %q", fullRaw)
	}

	if strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") ||
		strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "~/") ||
		strings.HasPrefix(trimmed, `.\\`) || strings.HasPrefix(trimmed, `..\\`) ||
		trimmed == "." || trimmed == ".." || strings.Contains(trimmed, "..") {
		return fmt.Errorf("local filesystem path is blocked in package spec %q", fullRaw)
	}

	for _, ext := range forbiddenArchiveSuffixes {
		if strings.HasSuffix(lower, ext) {
			return fmt.Errorf("direct archive install (%s) is blocked in package spec %q", ext, fullRaw)
		}
	}

	return nil
}

func parsePyPISpec(spec, raw string) (string, string, error) {
	// Reject PEP 508 direct URL references: "pkg @ https://..." or "pkg@https://..."
	if atIdx := strings.IndexByte(spec, '@'); atIdx != -1 {
		target := strings.TrimSpace(spec[atIdx+1:])
		return "", "", fmt.Errorf("PEP 508 direct URL/VCS reference (@ %s) is blocked in %q", target, raw)
	}

	// Strip environment markers (; python_version >= '3.10')
	if semiIdx := strings.IndexByte(spec, ';'); semiIdx != -1 {
		spec = strings.TrimSpace(spec[:semiIdx])
	}

	// Split version comparators: ===, ==, ~=, !=, >=, <=, >, <
	var namePart, opFound, verPart string
	for _, op := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(spec, op); idx != -1 {
			namePart = strings.TrimSpace(spec[:idx])
			opFound = op
			verPart = strings.TrimSpace(spec[idx+len(op):])
			break
		}
	}
	if opFound == "" {
		namePart = strings.TrimSpace(spec)
	}

	// Strip extras: requests[security,socks] -> requests
	if bracketIdx := strings.IndexByte(namePart, '['); bracketIdx != -1 {
		if !strings.HasSuffix(namePart, "]") {
			return "", "", fmt.Errorf("malformed extras bracket in PyPI spec %q", raw)
		}
		namePart = strings.TrimSpace(namePart[:bracketIdx])
	}

	if namePart == "" || strings.ContainsAny(namePart, "/\\ \t:") {
		return "", "", fmt.Errorf("invalid PyPI package name %q in spec %q", namePart, raw)
	}

	if (opFound == "==" || opFound == "===") && verPart != "" && !strings.Contains(verPart, ",") && !strings.Contains(verPart, "*") {
		return namePart, verPart, nil
	}
	return namePart, "", nil
}

func parseSwiftSpec(spec string) (string, string, error) {
	n, v, _ := splitAtVersion(spec)
	if strings.Contains(n, "..") {
		return "", "", fmt.Errorf("path traversal forbidden in Swift package spec %q", spec)
	}
	if strings.Contains(n, "://") || strings.HasPrefix(strings.ToLower(n), "git@") || strings.HasPrefix(strings.ToLower(n), "file:") {
		u, err := url.Parse(n)
		if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") {
			return "", "", fmt.Errorf("Swift package URL %q must use https://github.com/<owner>/<repo>", spec)
		}
		parts := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid GitHub repository path in Swift spec %q", spec)
		}
		return n, v, nil
	}
	parts := strings.Split(strings.Trim(n, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid Swift package identifier %q", spec)
	}
	return n, v, nil
}
