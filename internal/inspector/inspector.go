package inspector

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Category identifies the threat category of a detected AST pattern.
type Category string

const (
	CategoryProcessExec Category = "PROCESS_EXECUTION"
	CategoryObfuscation Category = "OBFUSCATION_EVAL"
	CategoryNetwork     Category = "NETWORK_EXFILTRATION"
	CategoryCredentials Category = "CREDENTIAL_HARVESTING"
)

// Finding represents a suspicious code pattern discovered inside a package archive or script.
type Finding struct {
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Category    Category `json:"category"`
	Pattern     string   `json:"pattern"`
	Snippet     string   `json:"snippet"`
	Description string   `json:"description"`
}

// Result summarizes the static pre-flight inspection of a package payload.
type Result struct {
	ScannedFiles int       `json:"scanned_files"`
	Findings     []Finding `json:"findings"`
	IsDangerous  bool      `json:"is_dangerous"`
}

type patternDef struct {
	Category    Category
	Regex       *regexp.Regexp
	Description string
}

var dangerPatterns = []patternDef{
	// Process execution patterns
	{
		Category:    CategoryProcessExec,
		Regex:       regexp.MustCompile(`(?i)(?:child_process|execSync|spawnSync|\bos\.system\b|subprocess\.(?:Popen|run|call|check_output)|Runtime\.getRuntime\(\)\.exec)`),
		Description: "Direct operating system command or child process execution",
	},
	// Code obfuscation and dynamic evaluation
	{
		Category:    CategoryObfuscation,
		Regex:       regexp.MustCompile(`(?i)(?:eval\s*\(|Function\s*\([^)]*\)\s*\(|exec\s*\(\s*(?:base64|b64decode|codecs\.decode)|String\.fromCharCode|Buffer\.from\([^)]*['"]hex['"]\)|__import__\s*\(\s*['"]os['"]\))`),
		Description: "Obfuscated code execution or dynamic code evaluation",
	},
	// Unauthorized network socket / exfiltration
	{
		Category:    CategoryNetwork,
		Regex:       regexp.MustCompile(`(?i)(?:net\.connect|dgram\.createSocket|socket\.socket\(|/dev/tcp/|curl\s+-[sS]|wget\s+-q|nc\s+-[elp]|urllib\.request\.urlopen)`),
		Description: "Low-level network socket creation or remote download/reverse shell command",
	},
	// Credential and environment harvesting
	{
		Category:    CategoryCredentials,
		Regex:       regexp.MustCompile(`(?i)(?:/etc/(?:passwd|shadow)|\.aws/credentials|\.ssh/id_|\.kube/config|process\.env(?:\.[A-Z0-9_]+)?\s*\|\s*curl|os\.environ\.copy\(\))`),
		Description: "Access to sensitive system paths or credentials harvesting",
	},
}

// Inspector performs in-memory static AST and pattern inspection on package archives.
type Inspector struct {
	client     *http.Client
	maxSize    int64 // Max uncompressed bytes to scan (default: 15MB)
	maxFiles   int   // Max files to scan (default: 200)
	maxDLBytes int64 // Max bytes to download (default: 5MB)
}

// New creates a new static payload inspector with strict resource bounds.
func New(client *http.Client) *Inspector {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &Inspector{
		client:     client,
		maxSize:    15 * 1024 * 1024,
		maxFiles:   200,
		maxDLBytes: 5 * 1024 * 1024,
	}
}

// InspectURL streams and inspects a package tarball or zip from a remote URL.
func (insp *Inspector) InspectURL(ctx context.Context, downloadURL string) (*Result, error) {
	if downloadURL == "" {
		return &Result{}, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create inspect request: %w", err)
	}
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := insp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package payload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("payload server returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, insp.maxDLBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	return insp.InspectBytes(data, downloadURL)
}

// InspectBytes inspects archive bytes (tar.gz or zip).
func (insp *Inspector) InspectBytes(data []byte, filename string) (*Result, error) {
	if len(data) == 0 {
		return &Result{}, nil
	}

	// Check if zip archive
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) || strings.HasSuffix(strings.ToLower(filename), ".zip") || strings.HasSuffix(strings.ToLower(filename), ".whl") {
		return insp.inspectZip(data)
	}

	// Assume tar.gz / tgz by default
	return insp.inspectTarGz(data)
}

func (insp *Inspector) inspectTarGz(data []byte) (*Result, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		// Fallback: try reading as uncompressed tar
		return insp.inspectTarReader(tar.NewReader(bytes.NewReader(data)))
	}
	defer gzr.Close()

	return insp.inspectTarReader(tar.NewReader(gzr))
}

func (insp *Inspector) inspectTarReader(tr *tar.Reader) (*Result, error) {
	res := &Result{Findings: make([]Finding, 0)}
	var totalBytes int64

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		res.ScannedFiles++
		if res.ScannedFiles > insp.maxFiles {
			break
		}

		if shouldInspectFile(header.Name) {
			content, err := io.ReadAll(io.LimitReader(tr, 256*1024))
			if err != nil {
				continue
			}
			totalBytes += int64(len(content))
			if totalBytes > insp.maxSize {
				break
			}

			findings := InspectScriptContent(string(content), header.Name)
			if len(findings) > 0 {
				res.Findings = append(res.Findings, findings...)
				res.IsDangerous = true
			}
		}
	}

	return res, nil
}

func (insp *Inspector) inspectZip(data []byte) (*Result, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip reader: %w", err)
	}

	res := &Result{Findings: make([]Finding, 0)}
	var totalBytes int64

	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}

		res.ScannedFiles++
		if res.ScannedFiles > insp.maxFiles {
			break
		}

		if shouldInspectFile(file.Name) {
			rc, err := file.Open()
			if err != nil {
				continue
			}

			content, err := io.ReadAll(io.LimitReader(rc, 256*1024))
			rc.Close()
			if err != nil {
				continue
			}

			totalBytes += int64(len(content))
			if totalBytes > insp.maxSize {
				break
			}

			findings := InspectScriptContent(string(content), file.Name)
			if len(findings) > 0 {
				res.Findings = append(res.Findings, findings...)
				res.IsDangerous = true
			}
		}
	}

	return res, nil
}

func shouldInspectFile(path string) bool {
	clean := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(clean)

	// Critical lifecycle and configuration files
	if base == "package.json" || base == "setup.py" || base == "setup.cfg" ||
		base == "build.rs" || base == "extconf.rb" || base == "install.js" ||
		base == "postinstall.js" || base == "preinstall.js" {
		return true
	}

	// Code files that could contain dangerous execution
	ext := filepath.Ext(clean)
	return ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".py" ||
		ext == ".sh" || ext == ".bash" || ext == ".rb" || ext == ".php"
}

// InspectScriptContent analyzes source text against danger patterns line-by-line.
func InspectScriptContent(content, filename string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, pat := range dangerPatterns {
			if match := pat.Regex.FindString(trimmed); match != "" {
				snippet := trimmed
				if len(snippet) > 120 {
					snippet = snippet[:117] + "..."
				}

				findings = append(findings, Finding{
					File:        filename,
					Line:        lineNum + 1,
					Category:    pat.Category,
					Pattern:     match,
					Snippet:     snippet,
					Description: pat.Description,
				})
			}
		}
	}

	return findings
}
