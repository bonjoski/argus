package sanitizer

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"bonjoski/argus/internal/inspector"
)

// DefaultLifecycleHooks lists the NPM lifecycle script hooks that are stripped during neutralization.
var DefaultLifecycleHooks = []string{
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"postuninstall",
}

// StrippedHook represents a lifecycle script hook that was removed.
type StrippedHook struct {
	File    string `json:"file"`
	Hook    string `json:"hook"`
	Command string `json:"command"`
}

// NeutralizeResult encapsulates the results of archive neutralization.
type NeutralizeResult struct {
	StrippedHooks    []StrippedHook `json:"stripped_hooks"`
	RemovedFiles     []string       `json:"removed_files"`
	NeutralizedFiles []string       `json:"neutralized_files"`
	OriginalSize     int64          `json:"original_size"`
	NeutralizedSize  int64          `json:"neutralized_size"`
	OriginalSHA256   string         `json:"original_sha256"`
	CleanSHA256      string         `json:"clean_sha256"`
	Data             []byte         `json:"-"`
}

// Options configures the archive neutralization process.
type Options struct {
	LifecycleHooks []string
	StripBinaries  bool
	InspectAST     bool
}

// Option is a functional option for configuring neutralization.
type Option func(*Options)

// WithLifecycleHooks customizes the list of lifecycle script hooks to strip.
func WithLifecycleHooks(hooks []string) Option {
	return func(o *Options) {
		o.LifecycleHooks = hooks
	}
}

// WithStripBinaries configures whether binary wrappers/executables should be removed or stubbed.
func WithStripBinaries(strip bool) Option {
	return func(o *Options) {
		o.StripBinaries = strip
	}
}

// WithInspectAST configures whether static AST pattern inspection should be applied to script files.
func WithInspectAST(inspect bool) Option {
	return func(o *Options) {
		o.InspectAST = inspect
	}
}

func defaultOptions() *Options {
	return &Options{
		LifecycleHooks: DefaultLifecycleHooks,
		StripBinaries:  true,
		InspectAST:     true,
	}
}

// NeutralizeBytes takes raw archive bytes (tar.gz, tgz, zip, whl) and neutralizes install scripts.
func NeutralizeBytes(data []byte, filename string, opts ...Option) (*NeutralizeResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("archive data is empty")
	}

	opt := defaultOptions()
	for _, fn := range opts {
		fn(opt)
	}

	hasher := sha256.New()
	hasher.Write(data)
	origSHA := hex.EncodeToString(hasher.Sum(nil))

	var res *NeutralizeResult
	var err error

	// Check if zip archive (Magic bytes PK\x03\x04 or .zip/.whl extension)
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) || strings.HasSuffix(strings.ToLower(filename), ".zip") || strings.HasSuffix(strings.ToLower(filename), ".whl") {
		res, err = neutralizeZip(data, opt)
	} else {
		res, err = neutralizeTarGz(data, opt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to neutralize archive: %w", err)
	}

	res.OriginalSize = int64(len(data))
	res.NeutralizedSize = int64(len(res.Data))
	res.OriginalSHA256 = origSHA

	cleanHasher := sha256.New()
	cleanHasher.Write(res.Data)
	res.CleanSHA256 = hex.EncodeToString(cleanHasher.Sum(nil))

	return res, nil
}

// NeutralizeFile reads an archive file from srcPath, neutralizes it, and writes the clean archive to dstPath.
func NeutralizeFile(srcPath, dstPath string, opts ...Option) (*NeutralizeResult, error) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source archive %s: %w", srcPath, err)
	}

	res, err := NeutralizeBytes(data, srcPath, opts...)
	if err != nil {
		return nil, err
	}

	if dstPath != "" {
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create destination directory: %w", err)
		}
		if err := os.WriteFile(dstPath, res.Data, 0644); err != nil {
			return nil, fmt.Errorf("failed to write neutralized archive to %s: %w", dstPath, err)
		}
	}

	return res, nil
}

func neutralizeTarGz(data []byte, opt *Options) (*NeutralizeResult, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		// Try uncompressed tar fallback
		return neutralizeTarReader(tar.NewReader(bytes.NewReader(data)), opt, false)
	}
	defer gzr.Close()

	return neutralizeTarReader(tar.NewReader(gzr), opt, true)
}

func neutralizeTarReader(tr *tar.Reader, opt *Options, compressGzip bool) (*NeutralizeResult, error) {
	result := &NeutralizeResult{
		StrippedHooks:    make([]StrippedHook, 0),
		RemovedFiles:     make([]string, 0),
		NeutralizedFiles: make([]string, 0),
	}

	var buf bytes.Buffer
	var tw *tar.Writer
	var gw *gzip.Writer

	if compressGzip {
		gw = gzip.NewWriter(&buf)
		tw = tar.NewWriter(gw)
	} else {
		tw = tar.NewWriter(&buf)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar archive: %w", err)
		}

		cleanPath := strings.ToLower(filepath.ToSlash(header.Name))
		baseName := filepath.Base(cleanPath)

		// Check if regular file
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			content, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read tar entry %s: %w", header.Name, err)
			}

			// 1. Process package.json
			if baseName == "package.json" {
				neutralizedJSON, hooks := neutralizePackageJSON(content, header.Name, opt.LifecycleHooks)
				if len(hooks) > 0 {
					result.StrippedHooks = append(result.StrippedHooks, hooks...)
					content = neutralizedJSON
					header.Size = int64(len(content))
				}
			} else if isSuspiciousBinary(baseName, content) && opt.StripBinaries {
				// Strip malicious binary wrapper
				result.RemovedFiles = append(result.RemovedFiles, header.Name)
				continue
			} else if isLifecycleScriptFile(baseName) || isPythonSetupScript(baseName) {
				// Script files (setup.py, install.js, postinstall.js, *.sh)
				if opt.InspectAST {
					neutralizedContent, modified := neutralizeScriptContent(content, header.Name)
					if modified {
						result.NeutralizedFiles = append(result.NeutralizedFiles, header.Name)
						content = neutralizedContent
						header.Size = int64(len(content))
					}
				}
			}

			if err := tw.WriteHeader(header); err != nil {
				return nil, fmt.Errorf("failed to write tar header for %s: %w", header.Name, err)
			}
			if _, err := tw.Write(content); err != nil {
				return nil, fmt.Errorf("failed to write tar content for %s: %w", header.Name, err)
			}
		} else {
			// Directory, symlink, etc.
			if err := tw.WriteHeader(header); err != nil {
				return nil, fmt.Errorf("failed to write non-regular tar header for %s: %w", header.Name, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize tar writer: %w", err)
	}
	if gw != nil {
		if err := gw.Close(); err != nil {
			return nil, fmt.Errorf("failed to finalize gzip writer: %w", err)
		}
	}

	result.Data = buf.Bytes()
	return result, nil
}

func neutralizeZip(data []byte, opt *Options) (*NeutralizeResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip reader: %w", err)
	}

	result := &NeutralizeResult{
		StrippedHooks:    make([]StrippedHook, 0),
		RemovedFiles:     make([]string, 0),
		NeutralizedFiles: make([]string, 0),
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, file := range zr.File {
		cleanPath := strings.ToLower(filepath.ToSlash(file.Name))
		baseName := filepath.Base(cleanPath)

		if file.FileInfo().IsDir() {
			header := &zip.FileHeader{
				Name:     file.Name,
				Method:   file.Method,
				Modified: file.Modified,
			}
			header.SetMode(file.Mode())
			if _, err := zw.CreateHeader(header); err != nil {
				return nil, fmt.Errorf("failed to create zip dir entry %s: %w", file.Name, err)
			}
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file entry %s: %w", file.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read zip file entry %s: %w", file.Name, err)
		}

		// Process package.json or python setup scripts
		if baseName == "package.json" {
			neutralizedJSON, hooks := neutralizePackageJSON(content, file.Name, opt.LifecycleHooks)
			if len(hooks) > 0 {
				result.StrippedHooks = append(result.StrippedHooks, hooks...)
				content = neutralizedJSON
			}
		} else if isSuspiciousBinary(baseName, content) && opt.StripBinaries {
			result.RemovedFiles = append(result.RemovedFiles, file.Name)
			continue
		} else if isLifecycleScriptFile(baseName) || isPythonSetupScript(baseName) {
			if opt.InspectAST {
				neutralizedContent, modified := neutralizeScriptContent(content, file.Name)
				if modified {
					result.NeutralizedFiles = append(result.NeutralizedFiles, file.Name)
					content = neutralizedContent
				}
			}
		}

		header := &zip.FileHeader{
			Name:     file.Name,
			Method:   zip.Deflate,
			Modified: file.Modified,
		}
		header.SetMode(file.Mode())

		w, err := zw.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("failed to create zip header for %s: %w", file.Name, err)
		}
		if _, err := w.Write(content); err != nil {
			return nil, fmt.Errorf("failed to write zip content for %s: %w", file.Name, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize zip writer: %w", err)
	}

	result.Data = buf.Bytes()
	return result, nil
}

// neutralizePackageJSON parses package.json, removes specified lifecycle scripts, and preserves all other keys.
func neutralizePackageJSON(raw []byte, filename string, hooksToStrip []string) ([]byte, []StrippedHook) {
	var pkg map[string]any
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return raw, nil
	}

	scriptsRaw, ok := pkg["scripts"]
	if !ok {
		return raw, nil
	}

	scripts, ok := scriptsRaw.(map[string]any)
	if !ok {
		return raw, nil
	}

	var stripped []StrippedHook
	hookSet := make(map[string]bool)
	for _, h := range hooksToStrip {
		hookSet[strings.ToLower(strings.TrimSpace(h))] = true
	}

	for k, v := range scripts {
		lowerK := strings.ToLower(k)
		if hookSet[lowerK] {
			cmdStr := fmt.Sprintf("%v", v)
			stripped = append(stripped, StrippedHook{
				File:    filename,
				Hook:    k,
				Command: cmdStr,
			})
			delete(scripts, k)
		}
	}

	if len(stripped) == 0 {
		return raw, nil
	}

	pkg["scripts"] = scripts

	out, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return raw, nil
	}
	out = append(out, '\n')
	return out, stripped
}

var dangerousExecutionRegex = regexp.MustCompile(`(?i)(?:child_process|execSync|spawnSync|\bos\.system\b|subprocess\.(?:Popen|run|call|check_output)|Runtime\.getRuntime\(\)\.exec|curl\s+-[sS]|wget\s+-q|nc\s+-[elp]|/dev/tcp/|eval\s*\(|Function\s*\([^)]*\)\s*\(|exec\s*\(\s*(?:base64|b64decode|codecs\.decode)|String\.fromCharCode|Buffer\.from\([^)]*['"]hex['"]\)|__import__\s*\(\s*['"]os['"]\))`)

// neutralizeScriptContent comments out lines that contain dangerous execution hooks.
func neutralizeScriptContent(content []byte, filename string) ([]byte, bool) {
	text := string(content)
	lines := strings.Split(text, "\n")
	modified := false

	findings := inspector.InspectScriptContent(text, filename)
	if len(findings) == 0 {
		return content, false
	}

	dangerLines := make(map[int]bool)
	for _, f := range findings {
		dangerLines[f.Line] = true
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if dangerLines[lineNum] || dangerousExecutionRegex.MatchString(trimmed) {
			if !strings.HasPrefix(trimmed, "// [argus-neutralized]") && !strings.HasPrefix(trimmed, "# [argus-neutralized]") {
				commentPrefix := "//"
				if strings.HasSuffix(strings.ToLower(filename), ".py") || strings.HasSuffix(strings.ToLower(filename), ".sh") || strings.HasSuffix(strings.ToLower(filename), ".bash") || strings.HasSuffix(strings.ToLower(filename), ".rb") {
					commentPrefix = "#"
				}
				lines[i] = fmt.Sprintf("%s [argus-neutralized] %s", commentPrefix, line)
				modified = true
			}
		}
	}

	if !modified {
		return content, false
	}

	return []byte(strings.Join(lines, "\n")), true
}

func isSuspiciousBinary(baseName string, content []byte) bool {
	ext := strings.ToLower(filepath.Ext(baseName))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".node":
		return true
	}

	// Check magic bytes for executable binaries
	if len(content) >= 4 {
		// ELF magic: \x7fELF
		if bytes.HasPrefix(content, []byte("\x7fELF")) {
			return true
		}
		// Mach-O magic: \xfe\xed\xfa\xce, \xfe\xed\xfa\xcf, \xce\xfa\xed\xfe, \xcf\xfa\xed\xfe, \xca\xfe\xba\xbe
		if bytes.HasPrefix(content, []byte("\xfe\xed\xfa\xce")) ||
			bytes.HasPrefix(content, []byte("\xfe\xed\xfa\xcf")) ||
			bytes.HasPrefix(content, []byte("\xce\xfa\xed\xfe")) ||
			bytes.HasPrefix(content, []byte("\xcf\xfa\xed\xfe")) ||
			bytes.HasPrefix(content, []byte("\xca\xfe\xba\xbe")) {
			return true
		}
		// Windows PE / DOS magic: MZ
		if bytes.HasPrefix(content, []byte("MZ")) {
			return true
		}
	}

	return false
}

func isLifecycleScriptFile(baseName string) bool {
	switch baseName {
	case "install.js", "preinstall.js", "postinstall.js", "install.sh", "preinstall.sh", "postinstall.sh":
		return true
	}
	return false
}

func isPythonSetupScript(baseName string) bool {
	switch baseName {
	case "setup.py", "setup.cfg", "install.py", "build.py":
		return true
	}
	return false
}
