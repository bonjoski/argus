package ast

import (
	"strings"

	"bonjoski/argus/internal/model"
)

// ParsePythonImports parses Python source code or diff chunks and extracts third-party package dependencies.
func ParsePythonImports(filePath, content string) ([]ImportCandidate, error) {
	var candidates []ImportCandidate
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	inTripleQuote := false
	tripleQuoteChar := ""
	inParenImport := false
	var parenModule string
	var parenLine int

	for lineIdx, rawLine := range lines {
		lineNum := lineIdx + 1
		line := rawLine

		// Handle multiline triple-quoted docstrings
		if inTripleQuote {
			if idx := strings.Index(line, tripleQuoteChar); idx != -1 {
				inTripleQuote = false
				line = line[idx+3:]
				tripleQuoteChar = ""
			} else {
				continue
			}
		}

		// Check for opening triple quotes
		for _, tq := range []string{`"""`, `'''`} {
			if count := strings.Count(line, tq); count > 0 {
				if count%2 == 1 {
					inTripleQuote = true
					tripleQuoteChar = tq
					// Strip everything from opening triple quote to end of line
					firstIdx := strings.Index(line, tq)
					line = line[:firstIdx]
					break
				}
			}
		}

		// Strip inline comments starting with '#' (ignoring '#' inside quotes)
		line = stripPythonComment(line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Handle continuation of parenthesized 'from ... import ('
		if inParenImport {
			if strings.Contains(trimmed, ")") {
				inParenImport = false
				parenModule = ""
			}
			continue
		}

		// 1. Check for 'from <pkg> import ...'
		if strings.HasPrefix(trimmed, "from ") {
			afterFrom := strings.TrimSpace(trimmed[len("from "):])
			importIdx := strings.Index(afterFrom, " import ")
			if importIdx == -1 {
				// Could be 'import(' without space
				importIdx = strings.Index(afterFrom, " import(")
			}

			if importIdx != -1 {
				modSpec := strings.TrimSpace(afterFrom[:importIdx])
				// Ignore relative imports (from . import x, from ..foo import y)
				if strings.HasPrefix(modSpec, ".") {
					continue
				}

				afterImport := strings.TrimSpace(afterFrom[importIdx+len(" import"):])
				if strings.HasPrefix(afterImport, "(") && !strings.Contains(afterImport, ")") {
					inParenImport = true
					parenModule = modSpec
					parenLine = lineNum
				}

				addPythonCandidate(filePath, modSpec, trimmed, lineNum, seen, &candidates)
				continue
			}
		}

		// 2. Check for 'import <pkg>[, <pkg2>]'
		if strings.HasPrefix(trimmed, "import ") {
			afterImport := strings.TrimSpace(trimmed[len("import "):])
			parts := strings.Split(afterImport, ",")
			for _, part := range parts {
				item := strings.TrimSpace(part)
				if asIdx := strings.Index(item, " as "); asIdx != -1 {
					item = strings.TrimSpace(item[:asIdx])
				}
				if item != "" && !strings.HasPrefix(item, ".") {
					addPythonCandidate(filePath, item, trimmed, lineNum, seen, &candidates)
				}
			}
		}
	}

	// If file ended while in paren import, ensure candidate was recorded
	if inParenImport && parenModule != "" {
		addPythonCandidate(filePath, parenModule, "from "+parenModule+" import (...) ", parenLine, seen, &candidates)
	}

	return candidates, nil
}

func addPythonCandidate(filePath, modSpec, rawLine string, lineNum int, seen map[string]bool, out *[]ImportCandidate) {
	pkg := NormalizeImport(model.EcosystemPyPI, modSpec)
	if pkg == "" || seen[pkg] {
		return
	}
	seen[pkg] = true
	*out = append(*out, ImportCandidate{
		Ecosystem:   model.EcosystemPyPI,
		PackageName: pkg,
		RawImport:   modSpec,
		FilePath:    filePath,
		LineNumber:  lineNum,
	})
}

// stripPythonComment removes comment text starting with '#' outside string literals.
func stripPythonComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false

	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if r == '#' && !inSingle && !inDouble {
			return line[:i]
		}
	}
	return line
}
