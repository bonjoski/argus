package gitdiff

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"bonjoski/argus/internal/ast"
)

// AddedLine represents a single line added in a git diff hunk.
type AddedLine struct {
	LineNumber int
	Content    string
}

// FileDiff represents changes to a specific file in a diff.
type FileDiff struct {
	Path       string
	AddedLines []AddedLine
}

// ParseDiff parses a unified git diff from an io.Reader and returns the added lines per file.
func ParseDiff(r io.Reader) ([]FileDiff, error) {
	var files []FileDiff
	scanner := bufio.NewScanner(r)

	var currentFile *FileDiff
	currentLineNum := 0
	inHunk := false

	for scanner.Scan() {
		line := scanner.Text()

		// New file header in git diff: diff --git a/path b/path
		if strings.HasPrefix(line, "diff --git ") {
			if currentFile != nil && len(currentFile.AddedLines) > 0 {
				files = append(files, *currentFile)
			}
			currentFile = &FileDiff{}
			inHunk = false
			continue
		}

		// Target file header: +++ b/path or +++ /dev/null
		if strings.HasPrefix(line, "+++ ") {
			target := strings.TrimSpace(line[4:])
			if target == "/dev/null" {
				// File deleted
				currentFile = nil
				inHunk = false
				continue
			}
			if strings.HasPrefix(target, "b/") {
				target = target[2:]
			}
			if currentFile == nil {
				currentFile = &FileDiff{}
			}
			currentFile.Path = target
			continue
		}

		// Hunk header: @@ -old,count +new,count @@
		if strings.HasPrefix(line, "@@ ") {
			inHunk = true
			lineNum, err := parseHunkNewStart(line)
			if err == nil {
				currentLineNum = lineNum
			} else {
				currentLineNum = 1
			}
			continue
		}

		if !inHunk || currentFile == nil {
			continue
		}

		// Added line
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:]
			currentFile.AddedLines = append(currentFile.AddedLines, AddedLine{
				LineNumber: currentLineNum,
				Content:    content,
			})
			currentLineNum++
			continue
		}

		// Deleted line (does not advance new file line counter)
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			continue
		}

		// Context line
		if strings.HasPrefix(line, " ") {
			currentLineNum++
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading diff: %w", err)
	}

	if currentFile != nil && len(currentFile.AddedLines) > 0 {
		files = append(files, *currentFile)
	}

	return files, nil
}

// ExtractImportsFromDiff parses a unified diff and extracts all newly added dependency candidates.
func ExtractImportsFromDiff(r io.Reader) ([]ast.ImportCandidate, error) {
	fileDiffs, err := ParseDiff(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse diff: %w", err)
	}

	var allCandidates []ast.ImportCandidate
	seen := make(map[string]bool)

	for _, fd := range fileDiffs {
		if _, ok := ast.DetectEcosystem(fd.Path); !ok {
			continue
		}

		// Build a single content block with line mapping
		var contentBuilder strings.Builder
		lineToActual := make(map[int]int)

		for syntheticIdx, al := range fd.AddedLines {
			syntheticLine := syntheticIdx + 1
			lineToActual[syntheticLine] = al.LineNumber
			contentBuilder.WriteString(al.Content)
			contentBuilder.WriteString("\n")
		}

		extracted, err := ast.ExtractImports(fd.Path, contentBuilder.String())
		if err != nil {
			return nil, fmt.Errorf("failed to extract imports for %s: %w", fd.Path, err)
		}

		for _, cand := range extracted {
			key := fmt.Sprintf("%s:%s:%s", cand.Ecosystem, cand.PackageName, cand.FilePath)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Map synthetic line number back to actual diff line number
			if actual, ok := lineToActual[cand.LineNumber]; ok {
				cand.LineNumber = actual
			} else if len(fd.AddedLines) > 0 {
				cand.LineNumber = fd.AddedLines[0].LineNumber
			}

			allCandidates = append(allCandidates, cand)
		}
	}

	return allCandidates, nil
}

// parseHunkNewStart parses the new file starting line from @@ -l,s +L,S @@
func parseHunkNewStart(header string) (int, error) {
	plusIdx := strings.Index(header, "+")
	if plusIdx == -1 {
		return 1, fmt.Errorf("no + found in hunk header")
	}

	rest := header[plusIdx+1:]
	spaceIdx := strings.Index(rest, " ")
	if spaceIdx == -1 {
		spaceIdx = strings.Index(rest, "@")
	}
	if spaceIdx != -1 {
		rest = rest[:spaceIdx]
	}

	commaIdx := strings.Index(rest, ",")
	if commaIdx != -1 {
		rest = rest[:commaIdx]
	}

	n, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		return 1, fmt.Errorf("invalid line number %q: %w", rest, err)
	}
	return n, nil
}
