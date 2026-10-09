package ast

import (
	"fmt"
	"os"

	"bonjoski/argus/internal/model"
)

// ExtractImports parses the provided content and extracts candidate package dependencies
// based on the detected language ecosystem of filePath.
func ExtractImports(filePath, content string) ([]ImportCandidate, error) {
	eco, ok := DetectEcosystem(filePath)
	if !ok {
		return nil, nil
	}

	switch eco {
	case model.EcosystemPyPI:
		return ParsePythonImports(filePath, content)
	case model.EcosystemNPM:
		return ParseJavaScriptImports(filePath, content)
	case model.EcosystemGo:
		return ParseGoImports(filePath, content)
	case model.EcosystemCargo:
		return parseRustImports(filePath, content)
	case model.EcosystemRubyGems:
		return parseRubyImports(filePath, content)
	case model.EcosystemPackagist:
		return parsePHPImports(filePath, content)
	case model.EcosystemNuGet:
		return parseCSharpImports(filePath, content)
	default:
		return nil, fmt.Errorf("unsupported ecosystem for AST extraction: %s", eco)
	}
}

// ExtractImportsFromFile reads a file from disk and extracts candidate dependencies.
func ExtractImportsFromFile(filePath string) ([]ImportCandidate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return ExtractImports(filePath, string(data))
}
