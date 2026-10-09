package ast

import (
	"strings"

	"bonjoski/argus/internal/model"
)

// pythonImportMappings maps canonical Python import names to their PyPI distribution package names.
var pythonImportMappings = map[string]string{
	"sklearn":         "scikit-learn",
	"PIL":             "Pillow",
	"yaml":            "PyYAML",
	"bs4":             "beautifulsoup4",
	"cv2":             "opencv-python",
	"google.protobuf": "protobuf",
	"dotenv":          "python-dotenv",
	"dateutil":        "python-dateutil",
	"jwt":             "PyJWT",
	"serial":          "pyserial",
	"git":             "GitPython",
	"docx":            "python-docx",
	"magic":           "python-magic",
	"jose":            "python-jose",
	"pptx":            "python-pptx",
	"bio":             "biopython",
	"OpenGL":          "PyOpenGL",
	"OpenSSL":         "pyOpenSSL",
	"attr":            "attrs",
	"fitz":            "PyMuPDF",
	"Crypto":          "pycryptodome",
	"socks":           "PySocks",
	"gi":              "PyGObject",
	"pydantic_core":   "pydantic-core",
}

// NormalizeImport converts an extracted import specifier into its public registry distribution package name.
// Returns an empty string if the import is a local file, standard library module, or invalid specifier.
func NormalizeImport(eco model.Ecosystem, importSpec string) string {
	spec := strings.Trim(strings.TrimSpace(importSpec), `"'`+"`")
	if spec == "" {
		return ""
	}

	switch eco {
	case model.EcosystemPyPI:
		return normalizePythonImport(spec)
	case model.EcosystemNPM:
		return normalizeJavaScriptImport(spec)
	case model.EcosystemGo:
		return normalizeGoImport(spec)
	case model.EcosystemCargo:
		return normalizeCargoImport(spec)
	case model.EcosystemRubyGems:
		return normalizeRubyImport(spec)
	case model.EcosystemPackagist:
		return normalizePHPImport(spec)
	case model.EcosystemNuGet:
		return normalizeCSharpImport(spec)
	default:
		return spec
	}
}

func normalizeCargoImport(spec string) string {
	parts := strings.Split(spec, "::")
	root := strings.TrimSpace(parts[0])
	if IsRustStdlib(root) {
		return ""
	}
	return root
}

func normalizeRubyImport(spec string) string {
	clean := strings.TrimSpace(spec)
	if IsRubyStdlib(clean) {
		return ""
	}
	parts := strings.Split(clean, "/")
	if len(parts) > 0 && IsRubyStdlib(parts[0]) {
		return ""
	}
	return clean
}

func normalizePHPImport(spec string) string {
	clean := strings.Trim(strings.TrimSpace(spec), `\`)
	parts := strings.Split(clean, `\`)
	if len(parts) >= 2 {
		return strings.ToLower(parts[0] + "/" + parts[1])
	}
	return strings.ToLower(clean)
}

func normalizeCSharpImport(spec string) string {
	clean := strings.TrimSpace(spec)
	if strings.HasPrefix(clean, "System") || strings.HasPrefix(clean, "Microsoft") {
		return ""
	}
	parts := strings.Split(clean, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return clean
}

func normalizePythonImport(spec string) string {
	// Filter out relative imports
	if strings.HasPrefix(spec, ".") {
		return ""
	}

	// Check explicit multi-level mapping first (e.g. google.protobuf)
	parts := strings.Split(spec, ".")
	if len(parts) >= 2 {
		twoLevel := parts[0] + "." + parts[1]
		if mapped, found := pythonImportMappings[twoLevel]; found {
			return mapped
		}
	}

	root := parts[0]
	if IsPythonStdlib(root) {
		return ""
	}

	if mapped, found := pythonImportMappings[root]; found {
		return mapped
	}

	return root
}

func normalizeJavaScriptImport(spec string) string {
	// Filter out relative and absolute local paths
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~/") {
		return ""
	}
	// Filter out URLs
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		return ""
	}

	// Filter out Node.js built-ins
	if IsNodeStdlib(spec) {
		return ""
	}

	clean := strings.TrimPrefix(spec, "node:")

	if strings.HasPrefix(clean, "@") {
		// Scoped package: @scope/name[/subpath] -> @scope/name
		parts := strings.Split(clean, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return clean
	}

	// Unscoped package: name[/subpath] -> name
	parts := strings.Split(clean, "/")
	return parts[0]
}

func normalizeGoImport(spec string) string {
	// Standard library imports do not contain dots in the first segment
	if IsGoStdlib(spec) {
		return ""
	}

	parts := strings.Split(spec, "/")
	if len(parts) == 0 {
		return ""
	}

	domain := parts[0]
	switch domain {
	case "github.com", "gitlab.com", "bitbucket.org":
		// github.com/owner/repo[/subpath] -> github.com/owner/repo
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
		return spec

	case "golang.org", "google.golang.org":
		// golang.org/x/crypto[/subpath] -> golang.org/x/crypto
		if len(parts) >= 3 && parts[1] == "x" {
			return strings.Join(parts[:3], "/")
		}
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
		return spec

	case "gopkg.in":
		// gopkg.in/yaml.v2 or gopkg.in/user/repo.v1
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
		return spec

	default:
		// Generic custom vanity domain e.g. go.uber.org/zap/buffer -> go.uber.org/zap
		if len(parts) >= 2 {
			// If 3 parts and part 2 is version or module root, handle typical domain/module
			if len(parts) >= 3 && (parts[1] == "pkg" || strings.HasPrefix(parts[2], "v")) {
				return strings.Join(parts[:3], "/")
			}
			return strings.Join(parts[:2], "/")
		}
		return spec
	}
}
