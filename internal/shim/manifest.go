package shim

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bonjoski/argus/internal/model"
)

// ExtractManifestTargets inspects manifest-driven install/build invocations
// (e.g. `pip install -r requirements.txt`, `npm install`, `npm ci`, `pip install .`, `uv sync`, `cargo build`)
// and returns all dependency specs declared in the referenced manifest(s).
// Fails closed if a referenced manifest cannot be read/parsed or embeds registry/VCS overrides.
func ExtractManifestTargets(tool string, args []string, workDir string) (eco model.Ecosystem, specs []string, triggered bool, err error) {
	if workDir == "" {
		workDir = "."
	}

	// 1. Check pip / pip3 / uv pip install for -r / --requirement / -c / --constraint or `.` / `-e .`
	if isPipInstallInvocation(tool, args) {
		reqFiles, hasLocalDot := extractPipRequirementFiles(args)
		if len(reqFiles) > 0 {
			var collected []string
			visited := make(map[string]bool)
			for _, rf := range reqFiles {
				path := rf
				if !filepath.IsAbs(path) {
					path = filepath.Join(workDir, path)
				}
				parsed, pErr := parseRequirementsFile(path, visited, 0)
				if pErr != nil {
					return model.EcosystemPyPI, nil, true, pErr
				}
				collected = append(collected, parsed...)
			}
			return model.EcosystemPyPI, collected, true, nil
		}
		if hasLocalDot {
			pyprojPath := filepath.Join(workDir, "pyproject.toml")
			parsed, pErr := parsePyProjectTOML(pyprojPath)
			if pErr != nil {
				return model.EcosystemPyPI, nil, true, pErr
			}
			return model.EcosystemPyPI, parsed, true, nil
		}
	}

	// 2. uv sync -> parse pyproject.toml
	if tool == "uv" && firstSubcommand(args) == "sync" {
		pyprojPath := filepath.Join(workDir, "pyproject.toml")
		parsed, pErr := parsePyProjectTOML(pyprojPath)
		if pErr != nil {
			return model.EcosystemPyPI, nil, true, pErr
		}
		return model.EcosystemPyPI, parsed, true, nil
	}

	// 3. Bare npm/pnpm/yarn/bun install or ci -> parse package.json
	if isNodeBareInstall(tool, args) {
		pkgJSONPath := filepath.Join(workDir, "package.json")
		parsed, pErr := parsePackageJSONManifest(pkgJSONPath)
		if pErr != nil {
			return model.EcosystemNPM, nil, true, pErr
		}
		return model.EcosystemNPM, parsed, true, nil
	}

	// 4. cargo build / check / run -> parse Cargo.toml
	if tool == "cargo" {
		sub := firstSubcommand(args)
		if sub == "build" || sub == "b" || sub == "check" || sub == "c" || sub == "run" || sub == "r" {
			manifestPath := extractCargoManifestPath(args, workDir)
			parsed, pErr := parseCargoTOMLManifest(manifestPath)
			if pErr != nil {
				return model.EcosystemCargo, nil, true, pErr
			}
			return model.EcosystemCargo, parsed, true, nil
		}
	}

	return "", nil, false, nil
}

func firstSubcommand(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func isPipInstallInvocation(tool string, args []string) bool {
	if tool == "pip" || tool == "pip3" {
		return firstSubcommand(args) == "install"
	}
	if tool == "uv" {
		for i, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if a == "pip" && i+1 < len(args) && (args[i+1] == "install" || args[i+1] == "sync") {
				return true
			}
			return false
		}
	}
	return false
}

func extractPipRequirementFiles(args []string) (reqFiles []string, hasLocalDot bool) {
	seenInstall := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !seenInstall {
			if a == "install" || a == "sync" {
				seenInstall = true
			}
			continue
		}
		if (a == "-r" || a == "--requirement" || a == "-c" || a == "--constraint") && i+1 < len(args) {
			reqFiles = append(reqFiles, args[i+1])
			i++
			continue
		}
		for _, prefix := range []string{"--requirement=", "--constraint=", "-r=", "-c="} {
			if strings.HasPrefix(a, prefix) {
				reqFiles = append(reqFiles, strings.TrimPrefix(a, prefix))
			}
		}
		if (a == "-e" || a == "--editable") && i+1 < len(args) && args[i+1] == "." {
			hasLocalDot = true
			i++
			continue
		}
		if a == "." {
			hasLocalDot = true
		}
	}
	return reqFiles, hasLocalDot
}

func isNodeBareInstall(tool string, args []string) bool {
	if tool != "npm" && tool != "pnpm" && tool != "yarn" && tool != "bun" {
		return false
	}
	if tool == "yarn" && len(args) == 0 {
		return true
	}
	sub := firstSubcommand(args)
	if sub != "install" && sub != "i" && sub != "ci" && sub != "clean-install" && sub != "install-clean" {
		return false
	}
	_, targets, _ := ExtractTargets(tool, args)
	return len(targets) == 0
}

func extractCargoManifestPath(args []string, workDir string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--manifest-path" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--manifest-path=") {
			return strings.TrimPrefix(args[i], "--manifest-path=")
		}
	}
	return filepath.Join(workDir, "Cargo.toml")
}

func parseRequirementsFile(path string, visited map[string]bool, depth int) ([]string, error) {
	if depth > 5 {
		return nil, fmt.Errorf("nested requirements file depth exceeded at %s", path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve requirements path %s: %w", path, err)
	}
	if visited[absPath] {
		return nil, nil
	}
	visited[absPath] = true

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements file %s: %w", path, err)
	}
	defer f.Close()

	var specs []string
	var continued strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, " #"); idx != -1 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, `\`) {
			continued.WriteString(strings.TrimSuffix(trimmed, `\`))
			continued.WriteByte(' ')
			continue
		}
		if continued.Len() > 0 {
			continued.WriteString(trimmed)
			trimmed = strings.TrimSpace(continued.String())
			continued.Reset()
		}
		if trimmed == "" {
			continue
		}

		// Handle embedded options inside requirements.txt
		if strings.HasPrefix(trimmed, "-") {
			fields := strings.Fields(trimmed)
			if err := ValidateRegistryOverrides("pip", fields, nil); err != nil {
				return nil, fmt.Errorf("blocked directive in %s: %w", path, err)
			}
			for i := 0; i < len(fields); i++ {
				tok := fields[i]
				if (tok == "-r" || tok == "--requirement" || tok == "-c" || tok == "--constraint") && i+1 < len(fields) {
					nestedPath := fields[i+1]
					if !filepath.IsAbs(nestedPath) {
						nestedPath = filepath.Join(filepath.Dir(absPath), nestedPath)
					}
					nested, nErr := parseRequirementsFile(nestedPath, visited, depth+1)
					if nErr != nil {
						return nil, nErr
					}
					specs = append(specs, nested...)
					i++
				} else if (tok == "-e" || tok == "--editable") && i+1 < len(fields) {
					specs = append(specs, fields[i+1])
					i++
				}
			}
			continue
		}

		// Strip inline --hash=... trailers from pip-compile lockfiles
		if hashIdx := strings.Index(trimmed, "--hash"); hashIdx != -1 {
			trimmed = strings.TrimSpace(trimmed[:hashIdx])
		}
		if trimmed != "" {
			specs = append(specs, trimmed)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading requirements file %s: %w", path, err)
	}
	return specs, nil
}

func parsePackageJSONManifest(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s for manifest vetting: %w", path, err)
	}
	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	var specs []string
	addGroup := func(m map[string]string) {
		for name, ver := range m {
			v := strings.TrimSpace(ver)
			if v == "" {
				specs = append(specs, name)
			} else {
				specs = append(specs, name+"@"+v)
			}
		}
	}
	addGroup(doc.Dependencies)
	addGroup(doc.DevDependencies)
	addGroup(doc.OptionalDependencies)
	return specs, nil
}

func parsePyProjectTOML(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s for manifest vetting: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	var specs []string
	section := ""
	inDepsArray := false

	for _, rawLine := range lines {
		line := stripTOMLComment(rawLine)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !inDepsArray {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}

		if inDepsArray {
			specs = append(specs, extractQuotedStrings(trimmed)...)
			if strings.Contains(trimmed, "]") {
				inDepsArray = false
			}
			continue
		}

		if section == "project" && strings.HasPrefix(trimmed, "dependencies") {
			if eqIdx := strings.IndexByte(trimmed, '='); eqIdx != -1 {
				rhs := strings.TrimSpace(trimmed[eqIdx+1:])
				specs = append(specs, extractQuotedStrings(rhs)...)
				if strings.HasPrefix(rhs, "[") && !strings.Contains(rhs, "]") {
					inDepsArray = true
				}
			}
			continue
		}

		if section == "project.optional-dependencies" || section == "dependency-groups" {
			if eqIdx := strings.IndexByte(trimmed, '='); eqIdx != -1 {
				rhs := strings.TrimSpace(trimmed[eqIdx+1:])
				specs = append(specs, extractQuotedStrings(rhs)...)
				if strings.HasPrefix(rhs, "[") && !strings.Contains(rhs, "]") {
					inDepsArray = true
				}
			}
			continue
		}

		if section == "tool.poetry.dependencies" || strings.HasSuffix(section, ".dependencies") && strings.HasPrefix(section, "tool.poetry.") {
			if eqIdx := strings.IndexByte(trimmed, '='); eqIdx != -1 {
				depName := strings.Trim(strings.TrimSpace(trimmed[:eqIdx]), `"'`)
				if strings.EqualFold(depName, "python") || depName == "" {
					continue
				}
				rhs := strings.TrimSpace(trimmed[eqIdx+1:])
				if strings.Contains(rhs, "git") && strings.Contains(rhs, "://") {
					specs = append(specs, depName+" @ git+https://unverified")
				} else if strings.Contains(rhs, "url") && strings.Contains(rhs, "://") {
					specs = append(specs, depName+" @ https://unverified")
				} else if strings.Contains(rhs, "path") && strings.Contains(rhs, "=") {
					specs = append(specs, "./"+depName)
				} else {
					specs = append(specs, depName)
				}
			}
		}
	}
	return specs, nil
}

func parseCargoTOMLManifest(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s for Cargo manifest vetting: %w", path, err)
	}
	content := string(data)
	if !strings.Contains(content, "[") {
		return nil, fmt.Errorf("malformed Cargo manifest %s", path)
	}

	lines := strings.Split(content, "\n")
	var specs []string
	section := ""

	isDepSection := func(sec string) bool {
		return sec == "dependencies" ||
			sec == "dev-dependencies" ||
			sec == "build-dependencies" ||
			sec == "workspace.dependencies" ||
			strings.HasSuffix(sec, ".dependencies") ||
			strings.HasSuffix(sec, ".dev-dependencies") ||
			strings.HasSuffix(sec, ".build-dependencies")
	}

	for _, rawLine := range lines {
		line := stripTOMLComment(rawLine)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(strings.Trim(trimmed, "[]"))
			// Handle [dependencies.foo] sub-table style
			for _, prefix := range []string{"dependencies.", "dev-dependencies.", "build-dependencies.", "workspace.dependencies."} {
				if strings.HasPrefix(section, prefix) {
					crate := strings.TrimSpace(strings.TrimPrefix(section, prefix))
					if crate != "" {
						specs = append(specs, crate)
					}
				}
			}
			continue
		}

		// Inside [dependencies.<crate>] check git / path / registry keys
		if strings.HasPrefix(section, "dependencies.") || strings.HasPrefix(section, "dev-dependencies.") || strings.HasPrefix(section, "build-dependencies.") {
			if eqIdx := strings.IndexByte(trimmed, '='); eqIdx != -1 {
				k := strings.TrimSpace(trimmed[:eqIdx])
				v := strings.Trim(strings.TrimSpace(trimmed[eqIdx+1:]), `"'`)
				if k == "git" {
					specs = append(specs, "git+"+v)
				} else if k == "path" {
					specs = append(specs, "./"+v)
				} else if k == "registry" && v != "" {
					return nil, fmt.Errorf("custom Cargo registry %q in %s is blocked by Argus policy", v, path)
				}
			}
			continue
		}

		if !isDepSection(section) {
			continue
		}

		eqIdx := strings.IndexByte(trimmed, '=')
		if eqIdx == -1 {
			continue
		}
		depKey := strings.Trim(strings.TrimSpace(trimmed[:eqIdx]), `"'`)
		rhs := strings.TrimSpace(trimmed[eqIdx+1:])
		if depKey == "" {
			continue
		}

		// Inline table: foo = { version = "1.0", package = "real_crate", git = "..." }
		if strings.HasPrefix(rhs, "{") {
			if gitVal := extractInlineTOMLKey(rhs, "git"); gitVal != "" {
				specs = append(specs, "git+"+gitVal)
				continue
			}
			if pathVal := extractInlineTOMLKey(rhs, "path"); pathVal != "" {
				specs = append(specs, "./"+pathVal)
				continue
			}
			if regVal := extractInlineTOMLKey(rhs, "registry"); regVal != "" {
				return nil, fmt.Errorf("custom Cargo registry %q for %s in %s is blocked by Argus policy", regVal, depKey, path)
			}
			realName := depKey
			if pkgAlias := extractInlineTOMLKey(rhs, "package"); pkgAlias != "" {
				realName = pkgAlias
			}
			specs = append(specs, realName)
			continue
		}

		specs = append(specs, depKey)
	}

	return specs, nil
}

func stripTOMLComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle && (i == 0 || line[i-1] != '\\') {
			inDouble = !inDouble
		} else if c == '#' && !inSingle && !inDouble {
			return line[:i]
		}
	}
	return line
}

func extractQuotedStrings(s string) []string {
	var out []string
	var quote byte
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == 0 {
			if c == '"' || c == '\'' {
				quote = c
				start = i + 1
			}
		} else if c == quote && (quote == '\'' || i == 0 || s[i-1] != '\\') {
			val := strings.TrimSpace(s[start:i])
			if val != "" {
				out = append(out, val)
			}
			quote = 0
		}
	}
	return out
}

func extractInlineTOMLKey(tableExpr, key string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(tableExpr), "{"), "}")
	for _, part := range strings.Split(inner, ",") {
		eqIdx := strings.IndexByte(part, '=')
		if eqIdx == -1 {
			continue
		}
		k := strings.TrimSpace(part[:eqIdx])
		if k == key {
			return strings.Trim(strings.TrimSpace(part[eqIdx+1:]), `"'`)
		}
	}
	return ""
}
