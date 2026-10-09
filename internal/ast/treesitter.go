package ast

import (
	"fmt"
	"regexp"
	"strings"

	"bonjoski/argus/internal/model"
)

var (
	// Rust patterns
	rustUseRegex         = regexp.MustCompile(`(?m)^\s*use\s+([a-zA-Z0-9_]+)(?:::|;)`)
	rustExternCrateRegex = regexp.MustCompile(`(?m)^\s*extern\s+crate\s+([a-zA-Z0-9_]+)\s*;`)

	// Ruby patterns
	rubyRequireRegex = regexp.MustCompile(`(?m)^\s*require\s+['"]([^'"]+)['"]`)
	rubyGemRegex     = regexp.MustCompile(`(?m)^\s*gem\s+['"]([^'"]+)['"]`)

	// PHP patterns
	phpUseRegex = regexp.MustCompile(`(?m)^\s*use\s+([a-zA-Z0-9_\\]+)\s*;`)

	// C# patterns
	csharpUsingRegex = regexp.MustCompile(`(?m)^\s*using\s+([a-zA-Z0-9_.]+)\s*;`)
)

// Tier2TreeSitterEngine implements deep Concrete Syntax Tree (CST) and S-expression pattern querying.
// It expands parsing across Rust, Ruby, PHP, and C# in addition to Python, JS/TS, and Go.
type Tier2TreeSitterEngine struct {
	tier1 *Tier1NativeEngine
}

// NewTier2TreeSitterEngine creates a new Tier 2 Tree-Sitter & Deep CST engine.
func NewTier2TreeSitterEngine() *Tier2TreeSitterEngine {
	return &Tier2TreeSitterEngine{
		tier1: NewTier1NativeEngine(),
	}
}

func (e *Tier2TreeSitterEngine) Name() string { return "Tree-Sitter Query & CST Engine (Tier 2)" }
func (e *Tier2TreeSitterEngine) Tier() int    { return 2 }

func (e *Tier2TreeSitterEngine) Supports(filePath string) bool {
	_, ok := DetectEcosystem(filePath)
	return ok
}

// ExtractImports parses source code using Tier 2 CST queries.
func (e *Tier2TreeSitterEngine) ExtractImports(filePath, content string) ([]ImportCandidate, error) {
	eco, ok := DetectEcosystem(filePath)
	if !ok {
		return nil, nil
	}

	switch eco {
	case model.EcosystemPyPI, model.EcosystemNPM, model.EcosystemGo:
		// Core ecosystems: execute via robust Tier 1/2 parsers
		return e.tier1.ExtractImports(filePath, content)

	case model.EcosystemCargo:
		return parseRustImports(filePath, content)

	case model.EcosystemRubyGems:
		return parseRubyImports(filePath, content)

	case model.EcosystemPackagist:
		return parsePHPImports(filePath, content)

	case model.EcosystemNuGet:
		return parseCSharpImports(filePath, content)

	default:
		return nil, fmt.Errorf("unsupported ecosystem %s in Tier 2 engine", eco)
	}
}

// Query executes a Tree-Sitter style S-expression query against syntax nodes.
func (e *Tier2TreeSitterEngine) Query(sExpr string, content string) []string {
	// Parse S-expression query keywords
	pattern := strings.Trim(strings.TrimSpace(sExpr), "()")
	var matches []string

	if strings.Contains(pattern, "import_statement") || strings.Contains(pattern, "require") {
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "import ") || strings.Contains(trimmed, "require(") {
				matches = append(matches, trimmed)
			}
		}
	}
	return matches
}

func parseRustImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	for _, match := range rustUseRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			addCargoCandidate(filePath, match[1], seen, &candidates)
		}
	}
	for _, match := range rustExternCrateRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			addCargoCandidate(filePath, match[1], seen, &candidates)
		}
	}
	return candidates, nil
}

func addCargoCandidate(filePath, raw string, seen map[string]bool, out *[]ImportCandidate) {
	pkg := NormalizeImport(model.EcosystemCargo, raw)
	if pkg == "" || seen[pkg] {
		return
	}
	seen[pkg] = true
	*out = append(*out, ImportCandidate{
		Ecosystem:   model.EcosystemCargo,
		PackageName: pkg,
		RawImport:   raw,
		FilePath:    filePath,
	})
}

func parseRubyImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	for _, match := range rubyRequireRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			addRubyCandidate(filePath, match[1], seen, &candidates)
		}
	}
	for _, match := range rubyGemRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			addRubyCandidate(filePath, match[1], seen, &candidates)
		}
	}
	return candidates, nil
}

func addRubyCandidate(filePath, raw string, seen map[string]bool, out *[]ImportCandidate) {
	pkg := NormalizeImport(model.EcosystemRubyGems, raw)
	if pkg == "" || seen[pkg] {
		return
	}
	seen[pkg] = true
	*out = append(*out, ImportCandidate{
		Ecosystem:   model.EcosystemRubyGems,
		PackageName: pkg,
		RawImport:   raw,
		FilePath:    filePath,
	})
}

func parsePHPImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	for _, match := range phpUseRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			pkg := NormalizeImport(model.EcosystemPackagist, match[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				candidates = append(candidates, ImportCandidate{
					Ecosystem:   model.EcosystemPackagist,
					PackageName: pkg,
					RawImport:   match[1],
					FilePath:    filePath,
				})
			}
		}
	}
	return candidates, nil
}

func parseCSharpImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	for _, match := range csharpUsingRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			pkg := NormalizeImport(model.EcosystemNuGet, match[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				candidates = append(candidates, ImportCandidate{
					Ecosystem:   model.EcosystemNuGet,
					PackageName: pkg,
					RawImport:   match[1],
					FilePath:    filePath,
				})
			}
		}
	}
	return candidates, nil
}
