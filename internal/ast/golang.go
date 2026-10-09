package ast

import (
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"bonjoski/argus/internal/model"
)

var (
	goImportLineRegex = regexp.MustCompile(`^\s*(?:import\s+)?(?:[a-zA-Z0-9_.]+\s+)?("([^"]+)")`)
)

// ParseGoImports extracts third-party Go package dependencies from Go source code or diff chunks.
func ParseGoImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	fset := token.NewFileSet()
	// Attempt standard Go AST parsing
	fileNode, err := parser.ParseFile(fset, filePath, content, parser.ImportsOnly)
	if err == nil && fileNode != nil {
		for _, imp := range fileNode.Imports {
			if imp.Path == nil {
				continue
			}
			rawPath, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				rawPath = strings.Trim(imp.Path.Value, `"`)
			}
			if IsGoStdlib(rawPath) {
				continue
			}
			pkg := NormalizeImport(model.EcosystemGo, rawPath)
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			pos := fset.Position(imp.Pos())
			candidates = append(candidates, ImportCandidate{
				Ecosystem:   model.EcosystemGo,
				PackageName: pkg,
				RawImport:   rawPath,
				FilePath:    filePath,
				LineNumber:  pos.Line,
			})
		}
		return candidates, nil
	}

	// Fallback for diff chunks / fragments: wrap in dummy package
	wrapped := "package main\nimport (\n" + content + "\n)\n"
	wrapFset := token.NewFileSet()
	wrapNode, wrapErr := parser.ParseFile(wrapFset, filePath, wrapped, parser.ImportsOnly)
	if wrapErr == nil && wrapNode != nil {
		for _, imp := range wrapNode.Imports {
			if imp.Path == nil {
				continue
			}
			rawPath, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				rawPath = strings.Trim(imp.Path.Value, `"`)
			}
			if IsGoStdlib(rawPath) {
				continue
			}
			pkg := NormalizeImport(model.EcosystemGo, rawPath)
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			candidates = append(candidates, ImportCandidate{
				Ecosystem:   model.EcosystemGo,
				PackageName: pkg,
				RawImport:   rawPath,
				FilePath:    filePath,
				LineNumber:  1,
			})
		}
		return candidates, nil
	}

	// Secondary fallback: regex scan line-by-line for diff fragments
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		matches := goImportLineRegex.FindStringSubmatch(trimmed)
		if len(matches) >= 3 {
			rawPath := matches[2]
			if IsGoStdlib(rawPath) {
				continue
			}
			pkg := NormalizeImport(model.EcosystemGo, rawPath)
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			candidates = append(candidates, ImportCandidate{
				Ecosystem:   model.EcosystemGo,
				PackageName: pkg,
				RawImport:   rawPath,
				FilePath:    filePath,
				LineNumber:  i + 1,
			})
		}
	}

	return candidates, nil
}
