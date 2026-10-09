package ast

import (
	"regexp"
	"strings"

	"bonjoski/argus/internal/model"
)

var (
	// require("pkg") or require('pkg')
	jsRequireRegex = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// import("pkg") or import('pkg')
	jsDynamicImportRegex = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// import ... from "pkg" or export ... from "pkg" or import "pkg"
	jsStaticImportRegex = regexp.MustCompile(`(?:import|export)\s+(?:type\s+)?(?:.*?from\s+)?['"]([^'"]+)['"]`)

	// from "pkg" at end of multiline import
	jsFromEndRegex = regexp.MustCompile(`from\s+['"]([^'"]+)['"]`)
)

// ParseJavaScriptImports extracts npm package dependencies from JS/TS source code or diff chunks.
func ParseJavaScriptImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	inBlockComment := false
	inMultiLineImport := false
	var multiLineStart int

	for lineIdx, rawLine := range lines {
		lineNum := lineIdx + 1
		line := rawLine

		// Handle multiline /* ... */ comments
		if inBlockComment {
			if idx := strings.Index(line, "*/"); idx != -1 {
				inBlockComment = false
				line = line[idx+2:]
			} else {
				continue
			}
		}

		for strings.Contains(line, "/*") {
			startIdx := strings.Index(line, "/*")
			endIdx := strings.Index(line[startIdx:], "*/")
			if endIdx != -1 {
				line = line[:startIdx] + line[startIdx+endIdx+2:]
			} else {
				inBlockComment = true
				line = line[:startIdx]
				break
			}
		}

		// Strip single-line comments // (ignoring // in quotes if basic)
		if idx := strings.Index(line, "//"); idx != -1 {
			// Quick quote check
			quoteCount := strings.Count(line[:idx], `"`) + strings.Count(line[:idx], `'`)
			if quoteCount%2 == 0 {
				line = line[:idx]
			}
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Handle ongoing multi-line import
		if inMultiLineImport {
			if matches := jsFromEndRegex.FindStringSubmatch(trimmed); len(matches) >= 2 {
				inMultiLineImport = false
				addJSCandidate(filePath, matches[1], trimmed, multiLineStart, seen, &candidates)
				continue
			}
			if strings.HasSuffix(trimmed, ";") || strings.Contains(trimmed, " from ") {
				inMultiLineImport = false
			}
			continue
		}

		// Check for beginning of multi-line import/export: starts with import/export, no string literal yet
		if (strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "export ")) &&
			!strings.Contains(trimmed, `"`) && !strings.Contains(trimmed, `'`) {
			inMultiLineImport = true
			multiLineStart = lineNum
			continue
		}

		// 1. Static imports / exports
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "export ") {
			if matches := jsStaticImportRegex.FindStringSubmatch(trimmed); len(matches) >= 2 {
				addJSCandidate(filePath, matches[1], trimmed, lineNum, seen, &candidates)
			}
		}

		// 2. Dynamic import(...)
		if matches := jsDynamicImportRegex.FindAllStringSubmatch(trimmed, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) >= 2 {
					addJSCandidate(filePath, m[1], trimmed, lineNum, seen, &candidates)
				}
			}
		}

		// 3. CJS require(...)
		if matches := jsRequireRegex.FindAllStringSubmatch(trimmed, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) >= 2 {
					addJSCandidate(filePath, m[1], trimmed, lineNum, seen, &candidates)
				}
			}
		}
	}

	return candidates, nil
}

func addJSCandidate(filePath, spec, rawLine string, lineNum int, seen map[string]bool, out *[]ImportCandidate) {
	pkg := NormalizeImport(model.EcosystemNPM, spec)
	if pkg == "" || seen[pkg] {
		return
	}
	seen[pkg] = true
	*out = append(*out, ImportCandidate{
		Ecosystem:   model.EcosystemNPM,
		PackageName: pkg,
		RawImport:   spec,
		FilePath:    filePath,
		LineNumber:  lineNum,
	})
}
