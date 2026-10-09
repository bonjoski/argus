package ast

import (
	"path/filepath"
	"strings"

	"bonjoski/argus/internal/model"
)

// ImportCandidate represents a single imported dependency candidate extracted from source code.
type ImportCandidate struct {
	Ecosystem   model.Ecosystem `json:"ecosystem"`
	PackageName string          `json:"package_name"`
	RawImport   string          `json:"raw_import"`
	FilePath    string          `json:"file_path,omitempty"`
	LineNumber  int             `json:"line_number,omitempty"`
}

// DetectEcosystem identifies the relevant package manager ecosystem based on the source file extension.
func DetectEcosystem(path string) (model.Ecosystem, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py", ".pyw":
		return model.EcosystemPyPI, true
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx":
		return model.EcosystemNPM, true
	case ".go":
		return model.EcosystemGo, true
	case ".rs":
		return model.EcosystemCargo, true
	case ".rb":
		return model.EcosystemRubyGems, true
	case ".php":
		return model.EcosystemPackagist, true
	case ".cs":
		return model.EcosystemNuGet, true
	default:
		return "", false
	}
}
