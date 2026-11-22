package ux

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// FixForwardError enforces the UB-CLI-v2 "Teach, Don't Scold" error invariant.
type FixForwardError struct {
	Tool           string   `json:"tool"`
	Code           string   `json:"code"`
	Summary        string   `json:"summary"`
	RemediationCmd string   `json:"remediation_cmd"`
	WhyOneLiner    string   `json:"why"`
	DeepWhy        string   `json:"deep_why,omitempty"`
	References     []string `json:"references,omitempty"`
	ExitCode       int      `json:"exit_code"`
}

func (e *FixForwardError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeSingleLine(e.Summary)
}

// Render writes machine-readable single-line JSON (--json), calm <=3-line default output,
// or full progressive-disclosure output (--why). All strings are ANSI/control-char sanitized.
func (e *FixForwardError) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if e == nil {
		return nil
	}
	if asJSON {
		sanitized := FixForwardError{
			Tool:           sanitizeSingleLine(e.Tool),
			Code:           sanitizeSingleLine(e.Code),
			Summary:        sanitizeSingleLine(e.Summary),
			RemediationCmd: sanitizeSingleLine(e.RemediationCmd),
			WhyOneLiner:    sanitizeSingleLine(e.WhyOneLiner),
			DeepWhy:        sanitizeTerminalText(e.DeepWhy),
			ExitCode:       e.ExitCode,
		}
		if len(e.References) > 0 {
			sanitized.References = make([]string, len(e.References))
			for i, ref := range e.References {
				sanitized.References[i] = sanitizeSingleLine(ref)
			}
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(&sanitized)
	}

	tool := sanitizeSingleLine(e.Tool)
	if tool == "" {
		tool = "argus"
	}
	summary := sanitizeSingleLine(e.Summary)
	fix := sanitizeSingleLine(e.RemediationCmd)
	why := sanitizeSingleLine(e.WhyOneLiner)
	deepWhy := strings.TrimSpace(sanitizeTerminalText(e.DeepWhy))

	if _, err := fmt.Fprintf(w, "⚠ %s: %s\n", tool, summary); err != nil {
		return err
	}
	if fix != "" {
		if _, err := fmt.Fprintf(w, "  Fix:  %s\n", fix); err != nil {
			return err
		}
	}
	if why != "" || (!showWhy && deepWhy != "") {
		whyLine := why
		if !showWhy && deepWhy != "" {
			codeArg := sanitizeSingleLine(strings.ToLower(e.Code))
			hint := fmt.Sprintf("re-run with --why or `%s explain %s` for details", tool, codeArg)
			if codeArg == "" {
				hint = "re-run with --why for details"
			}
			if whyLine != "" {
				whyLine = fmt.Sprintf("%s (%s)", whyLine, hint)
			} else {
				whyLine = fmt.Sprintf("Run `%s explain %s` (or re-run with --why) for details.", tool, codeArg)
			}
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	}
	if showWhy && deepWhy != "" {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n", strings.ReplaceAll(deepWhy, "\n", "\n  ")); err != nil {
			return err
		}
		for _, ref := range e.References {
			cleanRef := sanitizeSingleLine(ref)
			if cleanRef != "" {
				if _, err := fmt.Fprintf(w, "  Ref:  %s\n", cleanRef); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// remediationTokenRe enforces strict allowlist quoting for package suggestions.
var remediationTokenRe = regexp.MustCompile(`^[a-zA-Z0-9@._/-]+$`)

// ValidateRemediationToken verifies a package or CLI token matches ^[a-zA-Z0-9@._/-]+$
// and rejects flag injection (-...), path traversal (..), and non-ASCII homoglyphs.
func ValidateRemediationToken(token string) bool {
	if token == "" || len(token) > 214 {
		return false
	}
	if !remediationTokenRe.MatchString(token) {
		return false
	}
	if strings.HasPrefix(token, "-") || strings.HasPrefix(token, "/") || strings.HasSuffix(token, "/") {
		return false
	}
	if strings.Contains(token, "..") || strings.Contains(token, "//") {
		return false
	}
	return true
}

// BuildSafeInstallCommand returns a copy-pasteable install command ONLY if suggestedPkg
// passes strict ValidateRemediationToken allowlist verification.
func BuildSafeInstallCommand(ecosystem, suggestedPkg string) string {
	if !ValidateRemediationToken(suggestedPkg) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi", "pip", "python":
		return "pip install " + suggestedPkg
	case "cargo", "crates", "rust":
		return "cargo add " + suggestedPkg
	case "go", "golang":
		return "go get " + suggestedPkg
	case "rubygems", "gem", "ruby":
		return "gem install " + suggestedPkg
	default:
		return "npm install " + suggestedPkg
	}
}

// canonicalPackagesByEcosystem holds verified popular packages for deterministic Levenshtein spellchecking.
var canonicalPackagesByEcosystem = map[string][]string{
	"npm": {
		"@anthropic-ai/sdk", "@google/genai", "@modelcontextprotocol/sdk",
		"anthropic", "axios", "body-parser", "chalk", "colorette", "commander",
		"cookie-parser", "cors", "cross-env", "crypto-js", "date-fns", "dotenv",
		"esbuild", "eslint", "express", "helmet", "jest", "jsonwebtoken",
		"langchain", "langgraph", "lodash", "mcp", "mongoose", "next",
		"node-fetch", "openai", "prettier", "prisma", "react", "react-dom",
		"react-router", "react-router-dom", "semver", "sharp", "socket.io",
		"stripe", "svelte", "tailwindcss", "typescript", "uuid", "vite",
		"vitest", "vue", "webpack", "winston", "yargs",
	},
	"pypi": {
		"aiohttp", "anthropic", "beautifulsoup4", "boto3", "certifi", "click",
		"cryptography", "django", "fastapi", "flask", "flask-cors", "google-genai",
		"gunicorn", "httpx", "jinja2", "langchain", "langgraph", "matplotlib",
		"mcp", "numpy", "openai", "pandas", "pillow", "pydantic", "pytest",
		"python-dotenv", "pyyaml", "redis", "requests", "rich", "scikit-learn",
		"scipy", "sqlalchemy", "stripe", "urllib3", "uvicorn",
	},
	"cargo": {
		"anyhow", "async-openai", "bytes", "chrono", "clap", "futures", "hyper",
		"itertools", "log", "rand", "regex", "reqwest", "serde", "serde_json",
		"syn", "tempfile", "thiserror", "tokio", "tracing", "walkdir",
	},
}

var knownSquatSuggestions = map[string]string{
	"reqeusts":      "requests",
	"express-js":    "express",
	"color-term":    "chalk",
	"lodas-node":    "lodash",
	"cryp-to":       "crypto-js",
	"open-ai-sdk":   "openai",
	"openai-sdk":    "openai",
	"open-ai":       "openai",
	"anthropic-sdk": "anthropic",
}

// SuggestCanonicalPackage runs deterministic Levenshtein + casing/delimiter spellchecking
// against verified canonical registry packages. Untrusted input is NEVER returned directly;
// only verified allowlist-safe canonical names are returned.
func SuggestCanonicalPackage(ecosystem, pkgName string) (suggested string, distance int, reason string) {
	trimmed := strings.TrimSpace(pkgName)
	if trimmed == "" || !ValidateRemediationToken(trimmed) {
		// Never suggest or echo shell-hostile tokens directly.
		return "", 0, ""
	}

	lower := strings.ToLower(trimmed)

	// 1. Known high-confidence slopsquat aliases
	if canonical, ok := knownSquatSuggestions[lower]; ok && ValidateRemediationToken(canonical) {
		return canonical, levenshtein(lower, canonical), "known typosquat/slopsquat alias"
	}

	corpus := corpusForEcosystem(ecosystem)

	// 2. Exact match to canonical package -> not a typo
	for _, c := range corpus {
		if lower == c && trimmed == c {
			return "", 0, ""
		}
	}

	// 3. camelCase / snake_case / stripped-delimiter permutation check (e.g. reactDom -> react-dom)
	kebab := toKebab(trimmed)
	stripped := stripDelims(trimmed)
	for _, c := range corpus {
		if kebab == c && trimmed != c {
			return c, levenshtein(lower, c), "casing or delimiter permutation"
		}
		if len(stripped) >= 6 && stripDelims(c) == stripped && lower != c {
			return c, levenshtein(lower, c), "delimiter-stripped permutation"
		}
	}

	// 4. Deterministic Levenshtein nearest-neighbor (distance 1, or distance 2 for len >= 6)
	bestPkg := ""
	bestDist := 999
	for _, c := range corpus {
		d := levenshtein(lower, c)
		maxAllowed := 1
		if len(lower) >= 6 {
			maxAllowed = 2
		}
		if d > 0 && d <= maxAllowed {
			if d < bestDist || (d == bestDist && c < bestPkg) {
				bestDist = d
				bestPkg = c
			}
		}
	}
	if bestPkg != "" && ValidateRemediationToken(bestPkg) {
		return bestPkg, bestDist, fmt.Sprintf("Levenshtein distance %d", bestDist)
	}
	return "", 0, ""
}

// NewSpellcheckFixForward builds a calm UB-CLI-v2 FixForwardError for a flagged package.
// RemediationCmd ONLY contains strictly allowlisted canonical packages and NEVER interpolates
// untrusted shell characters.
func NewSpellcheckFixForward(ecosystem, pkgName, detailReason string, ageHours float64, weeklyDownloads int64) *FixForwardError {
	eco := normalizeEcosystem(ecosystem)
	cleanPkg := sanitizeSingleLine(pkgName)
	suggested, dist, matchReason := SuggestCanonicalPackage(eco, pkgName)

	summary := fmt.Sprintf("Paused install of unverified %s package %q", eco, cleanPkg)
	remediationCmd := fmt.Sprintf("argus explain --ecosystem %s <canonical-package>", eco)
	if suggested != "" {
		summary = fmt.Sprintf("Did you mean %q? %q looks like a typo or AI hallucination", suggested, cleanPkg)
		if cmd := BuildSafeInstallCommand(eco, suggested); cmd != "" {
			remediationCmd = cmd
		}
	}

	whyOneLiner := "Typosquatted and AI-hallucinated packages often run credential-stealing install hooks."
	if ageHours > 0 && ageHours < 72 {
		whyOneLiner = fmt.Sprintf("Published %.0fh ago with %d downloads; freshly squatted packages frequently hide malicious install hooks.", ageHours, weeklyDownloads)
	}

	var deepParts []string
	deepParts = append(deepParts, fmt.Sprintf("Package: %s (%s)", cleanPkg, eco))
	if suggested != "" {
		deepParts = append(deepParts, fmt.Sprintf("Spellchecker match: %q (%s, distance=%d)", suggested, matchReason, dist))
	}
	if strings.TrimSpace(detailReason) != "" {
		deepParts = append(deepParts, fmt.Sprintf("Quarry signal: %s", sanitizeSingleLine(detailReason)))
	}
	if ageHours > 0 {
		deepParts = append(deepParts, fmt.Sprintf("Registry telemetry: age=%.1fh, weekly_downloads=%d", ageHours, weeklyDownloads))
	}
	deepParts = append(deepParts, "Attack pattern (Slopsquatting / OWASP LLM03): Adversaries register plausible package names hallucinated by LLMs and attach preinstall/postinstall hooks that exfiltrate ~/.ssh, ~/.aws, and .env secrets.")

	return &FixForwardError{
		Tool:           "argus",
		Code:           "ARGUS_SLOPSQUAT_SUSPECT",
		Summary:        summary,
		RemediationCmd: remediationCmd,
		WhyOneLiner:    whyOneLiner,
		DeepWhy:        strings.Join(deepParts, "\n"),
		References:     []string{"OWASP-LLM03", "CWE-829"},
		ExitCode:       1,
	}
}

func normalizeEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pypi", "pip", "python":
		return "pypi"
	case "cargo", "crates", "rust":
		return "cargo"
	case "go", "golang":
		return "go"
	case "rubygems", "gem", "ruby":
		return "rubygems"
	default:
		return "npm"
	}
}

func corpusForEcosystem(eco string) []string {
	norm := normalizeEcosystem(eco)
	if list, ok := canonicalPackagesByEcosystem[norm]; ok {
		return list
	}
	seen := make(map[string]struct{})
	var all []string
	for _, list := range canonicalPackagesByEcosystem {
		for _, item := range list {
			if _, ok := seen[item]; !ok {
				seen[item] = struct{}{}
				all = append(all, item)
			}
		}
	}
	sort.Strings(all)
	return all
}

func toKebab(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 && unicode.IsLower(runes[i-1]) {
				b.WriteRune('-')
			}
			b.WriteRune(unicode.ToLower(r))
		} else if r == '_' || r == '.' {
			b.WriteRune('-')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripDelims(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r != '-' && r != '_' && r != '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func levenshtein(a, b string) int {
	r1, r2 := []rune(a), []rune(b)
	n, m := len(r1), len(r2)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	dp := make([]int, m+1)
	for j := 0; j <= m; j++ {
		dp[j] = j
	}
	for i := 1; i <= n; i++ {
		prev := dp[0]
		dp[0] = i
		for j := 1; j <= m; j++ {
			tmp := dp[j]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			ins := dp[j-1] + 1
			del := dp[j] + 1
			sub := prev + cost
			best := ins
			if del < best {
				best = del
			}
			if sub < best {
				best = sub
			}
			dp[j] = best
			prev = tmp
		}
	}
	return dp[m]
}

// SanitizeTerminalText strips ESC, CSI, OSC, DCS/SOS/PM/APC, C0/C1 controls, DEL, and bidi overrides.
func SanitizeTerminalText(s string) string {
	return sanitizeTerminalText(s)
}

func sanitizeSingleLine(s string) string {
	clean := sanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func sanitizeTerminalText(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x1b {
			if i+1 >= len(runes) {
				break
			}
			switch runes[i+1] {
			case '[':
				i += 2
				for i < len(runes) {
					if runes[i] >= 0x40 && runes[i] <= 0x7e {
						break
					}
					i++
				}
			case ']', 'P', 'X', '^', '_':
				i += 2
				for i < len(runes) {
					if runes[i] == 0x07 || runes[i] == 0x9c {
						break
					}
					if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
				i++
				for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
					i++
				}
			}
			continue
		}
		if r == 0x9b {
			i++
			for i < len(runes) {
				if runes[i] >= 0x40 && runes[i] <= 0x7e {
					break
				}
				i++
			}
			continue
		}
		if r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f {
			i++
			for i < len(runes) {
				if runes[i] == 0x07 || runes[i] == 0x9c {
					break
				}
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
