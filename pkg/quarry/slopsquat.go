package quarry

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// SlopsquatAssessment holds the unified threat evaluation result for a package or install event.
type SlopsquatAssessment struct {
	IsSuspicious     bool           `json:"is_suspicious"`
	IsHallucination  bool           `json:"is_hallucination"`
	IsFreshRelease   bool           `json:"is_fresh_release"`
	IsSuspiciousHook bool           `json:"is_suspicious_hook"`
	IsHighEntropy    bool           `json:"is_high_entropy"`
	IsDeadbugzMCP    bool           `json:"is_deadbugz_mcp"`
	EntropyScore     float64        `json:"entropy_score,omitempty"`
	TargetPackage    string         `json:"target_package,omitempty"`
	Pattern          string         `json:"pattern,omitempty"`
	Reasons          []string       `json:"reasons,omitempty"`
	Details          map[string]any `json:"details,omitempty"`
}

// Canonical high-reputation standard packages across major ecosystems (npm, PyPI, Cargo).
var popularPackages = map[string]struct{}{
	// npm
	"react": {}, "react-dom": {}, "react-router": {}, "react-router-dom": {},
	"body-parser": {}, "cookie-parser": {}, "express": {}, "express-session": {},
	"express-validator": {}, "express-rate-limit": {}, "node-fetch": {}, "cross-env": {},
	"aws-sdk": {}, "date-fns": {}, "lodash": {}, "lodash-es": {}, "path-to-regexp": {},
	"source-map": {}, "styled-components": {}, "socket.io": {}, "socket.io-client": {},
	"dotenv": {}, "dotenv-safe": {}, "json-schema": {}, "fast-json-stringify": {},
	"clean-css": {}, "color-convert": {}, "color-name": {}, "accepts": {},
	"mime-types": {}, "type-is": {}, "content-type": {}, "content-disposition": {},
	"cookie-signature": {}, "serve-static": {}, "serve-favicon": {}, "response-time": {},
	"compression": {}, "cors": {}, "helmet": {}, "morgan": {}, "winston": {},
	"axios": {}, "chalk": {}, "typescript": {}, "webpack": {}, "prettier": {},
	"eslint": {}, "vitest": {}, "jest": {}, "mocha": {}, "commander": {},
	"yargs": {}, "debug": {}, "uuid": {}, "glob": {}, "fs-extra": {},
	"rimraf": {}, "semver": {}, "rxjs": {}, "tslib": {}, "next": {},
	"vue": {}, "svelte": {}, "tailwindcss": {}, "postcss": {}, "rollup": {},
	"vite": {}, "esbuild": {}, "babel": {}, "nodemon": {}, "supertest": {},
	"fast-deep-equal": {}, "jsonwebtoken": {}, "passport": {}, "multer": {},
	"sharp": {}, "prisma": {}, "mongoose": {}, "pg": {}, "mysql2": {},
	"openai": {}, "anthropic": {}, "langchain": {}, "langgraph": {}, "stripe": {},

	// PyPI
	"requests": {}, "flask": {}, "django": {}, "flask-cors": {}, "python-dotenv": {},
	"beautifulsoup4": {}, "scikit-learn": {}, "numpy": {}, "pandas": {}, "scipy": {},
	"matplotlib": {}, "pydantic": {}, "fastapi": {}, "urllib3": {}, "certifi": {},
	"setuptools": {}, "wheel": {}, "pip": {}, "pytest": {}, "httpx": {},
	"sqlalchemy": {}, "celery": {}, "redis": {}, "cryptography": {}, "pillow": {},
	"boto3": {}, "botocore": {}, "click": {}, "rich": {}, "jinja2": {},
	"pyyaml": {}, "aiohttp": {}, "tornado": {}, "gunicorn": {}, "uvicorn": {},

	// Cargo
	"serde": {}, "serde_json": {}, "tokio": {}, "anyhow": {}, "thiserror": {},
	"clap": {}, "rand": {}, "reqwest": {}, "syn": {}, "quote": {},
	"bytes": {}, "futures": {}, "log": {}, "tracing": {}, "regex": {},
	"hyper": {}, "itertools": {}, "tempfile": {}, "walkdir": {}, "chrono": {},
}

// Generic hallucination tokens frequently appended or synthesized by LLMs.
var genericHallucinationTokens = map[string]struct{}{
	"auth":           {},
	"authentication": {},
	"authorize":      {},
	"helper":         {},
	"helpers":        {},
	"security":       {},
	"secure":         {},
	"token":          {},
	"tokens":         {},
	"jwt":            {},
	"oauth":          {},
	"sso":            {},
	"session":        {},
	"sessions":       {},
	"utils":          {},
	"util":           {},
	"utilities":      {},
	"client":         {},
	"service":        {},
	"server":         {},
	"core":           {},
	"common":         {},
	"base":           {},
	"sdk":            {},
	"lib":            {},
	"library":        {},
	"tools":          {},
	"tool":           {},
	"toolkit":        {},
	"ai":             {},
	"llm":            {},
	"gpt":            {},
	"agent":          {},
	"api":            {},
	"rest":           {},
	"grpc":           {},
	"sync":           {},
	"async":          {},
	"middleware":     {},
	"handler":        {},
	"plugin":         {},
	"color":          {},
	"colors":         {},
	"validator":      {},
	"parser":         {},
}

// Registry-enforced organizational scopes exempt from slopsquatting flags.
var approvedRegistryScopes = map[string]bool{
	"@types":                true,
	"@angular":              true,
	"@babel":                true,
	"@eslint":               true,
	"@vitejs":               true,
	"@rollup":               true,
	"@nestjs":               true,
	"@aws-sdk":              true,
	"@google-cloud":         true,
	"@azure":                true,
	"@opentelemetry":        true,
	"@vue":                  true,
	"@sveltejs":             true,
	"@prisma":               true,
	"@tanstack":             true,
	"@testing-library":      true,
	"@playwright":           true,
	"@modelcontextprotocol": true,
	"@octokit":              true,
	"@grpc":                 true,
	"@fastify":              true,
	"@radix-ui":             true,
	"@vercel":               true,
	"@cloudflare":           true,
	"@sentry":               true,
	"@stripe":               true,
	"@supabase":             true,
}

// IsApprovedNamespace checks if a package is under an organization-governed or domain-verified namespace.
func IsApprovedNamespace(pkgName string) bool {
	lower := strings.ToLower(strings.TrimSpace(pkgName))
	if strings.HasPrefix(lower, "@") {
		parts := strings.SplitN(lower, "/", 2)
		if len(parts) == 2 && parts[1] != "" {
			return approvedRegistryScopes[parts[0]]
		}
	}
	if strings.HasPrefix(lower, "golang.org/x/") ||
		strings.HasPrefix(lower, "google.golang.org/") ||
		strings.HasPrefix(lower, "github.com/") {
		return true
	}
	return false
}

// toKebabCase converts camelCase, snake_case, dot.case, or slash/delimited strings to kebab-case.
func toKebabCase(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if unicode.IsUpper(r) {
			if i > 0 && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
				b.WriteRune('-')
			}
			b.WriteRune(unicode.ToLower(r))
		} else if r == '_' || r == '.' || r == '/' || r == ':' {
			b.WriteRune('-')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripDelimiters removes delimiters (- _ . / :) to compare concatenated words.
func stripDelimiters(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r != '-' && r != '_' && r != '.' && r != '/' && r != ':' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TokenizePackageName splits a package name into distinct lowercase words across kebab, snake, dot, and camelCase.
func TokenizePackageName(name string) []string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			name = parts[1]
		}
	}

	var tokens []string
	var current strings.Builder

	runes := []rune(name)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '-' || r == '_' || r == '.' || r == '/' || r == ':' {
			if current.Len() > 0 {
				tokens = append(tokens, strings.ToLower(current.String()))
				current.Reset()
			}
			continue
		}

		if unicode.IsUpper(r) {
			if current.Len() > 0 && i > 0 && unicode.IsLower(runes[i-1]) {
				tokens = append(tokens, strings.ToLower(current.String()))
				current.Reset()
			}
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		tokens = append(tokens, strings.ToLower(current.String()))
	}

	return tokens
}

// DetectNameHallucination analyzes a package name for structural patterns typical of LLM hallucinations.
// It detects camelCase, kebab-case, snake_case permutations of standard packages, generic token conflations,
// and typosquats, while exempting approved namespaces and canonical standard packages.
func DetectNameHallucination(pkgName string) (bool, string, string) {
	cleanName := strings.TrimSpace(pkgName)
	if cleanName == "" {
		return false, "", ""
	}

	// 1. Exemption check
	if IsApprovedNamespace(cleanName) {
		return false, "", ""
	}

	// Strip scope if present for core identifier analysis
	unscoped := cleanName
	if strings.HasPrefix(cleanName, "@") {
		parts := strings.SplitN(cleanName, "/", 2)
		if len(parts) == 2 {
			unscoped = parts[1]
		}
	}

	lowerUnscoped := strings.ToLower(unscoped)

	// 2. Exact match check: if this IS the legitimate canonical package, no hallucination!
	if _, isPopular := popularPackages[lowerUnscoped]; isPopular && unscoped == lowerUnscoped {
		return false, "", ""
	}

	// 3. camelCase / case / delimiter permutation of a kebab-case standard package
	// Example: "reactDom" -> "react-dom", "nodeFetch" -> "node-fetch", "bodyParser" -> "body-parser"
	kebab := toKebabCase(unscoped)
	if kebab != unscoped && kebab != lowerUnscoped {
		if _, isTarget := popularPackages[kebab]; isTarget {
			hasUpper := false
			for _, r := range unscoped {
				if unicode.IsUpper(r) {
					hasUpper = true
					break
				}
			}
			if hasUpper {
				return true, kebab, fmt.Sprintf("camelCase permutation of standard package '%s'", kebab)
			}
			if strings.Contains(unscoped, "_") {
				return true, kebab, fmt.Sprintf("snake_case permutation of standard package '%s'", kebab)
			}
			return true, kebab, fmt.Sprintf("delimiter permutation of standard package '%s'", kebab)
		}
	}

	// 4. snake_case permutation of kebab-case standard package (e.g. "react_dom" -> "react-dom")
	if strings.Contains(unscoped, "_") {
		hyphenated := strings.ReplaceAll(lowerUnscoped, "_", "-")
		if _, isTarget := popularPackages[hyphenated]; isTarget && hyphenated != lowerUnscoped {
			return true, hyphenated, fmt.Sprintf("snake_case permutation of standard package '%s'", hyphenated)
		}
	}

	// 5. Delimiter-stripped / concatenated permutation (e.g. "reactdom" vs "react-dom", "bodyparser" vs "body-parser")
	stripped := stripDelimiters(unscoped)
	if len(stripped) >= 6 {
		for target := range popularPackages {
			if stripDelimiters(target) == stripped && target != lowerUnscoped {
				return true, target, fmt.Sprintf("delimiter-stripped permutation of standard package '%s'", target)
			}
		}
	}

	// 6. Generic hallucination token conflation (e.g. "chalkColor", "axios-helper", "lodash-utils", "react-security")
	tokens := TokenizePackageName(unscoped)
	if len(tokens) >= 2 {
		var matchedTarget string
		genericMatches := 0
		popularMatches := 0

		for _, tok := range tokens {
			if _, exists := popularPackages[tok]; exists {
				popularMatches++
				if matchedTarget == "" {
					matchedTarget = tok
				}
			} else if _, isGeneric := genericHallucinationTokens[tok]; isGeneric {
				genericMatches++
			}
		}

		if popularMatches >= 1 && (genericMatches >= 1 || popularMatches >= 2) {
			return true, matchedTarget, fmt.Sprintf("conflation of standard package '%s' with common generic token", matchedTarget)
		}

		// 6b. Joined-prefix conflation (e.g. "open-ai-sdk" -> ["open","ai","sdk"] -> "openai" + generic "sdk")
		if len(tokens) >= 3 {
			joinedPrefix := tokens[0] + tokens[1]
			if _, exists := popularPackages[joinedPrefix]; exists {
				for _, tok := range tokens[2:] {
					if _, isGeneric := genericHallucinationTokens[tok]; isGeneric {
						return true, joinedPrefix, fmt.Sprintf("conflation of split standard package '%s' with common generic token", joinedPrefix)
					}
				}
			}
		}
	}

	// 7. Typosquatting / Levenshtein distance check
	nameLen := len(lowerUnscoped)
	if nameLen >= 4 {
		for target := range popularPackages {
			tLen := len(target)
			diff := nameLen - tLen
			if diff < -2 || diff > 2 {
				continue
			}

			dist := levenshteinDistance(lowerUnscoped, target)
			if dist == 1 || (dist == 2 && nameLen >= 6) {
				return true, target, fmt.Sprintf("typosquat permutation of standard package '%s' (Levenshtein distance %d)", target, dist)
			}
		}
	}

	return false, "", ""
}

// DetectSuspiciousAgeAndDownloads flags packages published < 72 hours ago with low/zero historical downloads.
func DetectSuspiciousAgeAndDownloads(ageHours float64, downloads int64) (bool, string) {
	if ageHours <= 0 {
		return false, ""
	}

	if ageHours < 72.0 {
		if downloads == 0 {
			return true, fmt.Sprintf("newly published package (%.1fh old, <72h) with zero historical downloads", ageHours)
		}
		if downloads <= 100 {
			return true, fmt.Sprintf("newly published package (%.1fh old, <72h) with low historical download count (%d)", ageHours, downloads)
		}
	}

	return false, ""
}

var (
	// Matches attempts to access ~/.ssh or SSH key artifacts
	reSSHAccess = regexp.MustCompile(`(?i)(~|(\$HOME)|(%USERPROFILE%)|(/home/[^/\s"'\` + "`" + `]+)|(/root))?/?\.ssh(/|\b)|id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts`)

	// Matches attempts to access ~/.aws credentials or config
	reAWSAccess = regexp.MustCompile(`(?i)(~|(\$HOME)|(%USERPROFILE%)|(/home/[^/\s"'\` + "`" + `]+)|(/root))?/?\.aws(/|\b)|aws/credentials|aws/config|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN`)

	// Matches attempts to read/dump environment variables or credential tokens
	reEnvExfil = regexp.MustCompile(`(?i)process\.env|os\.environ|/proc/self/environ|printenv\b|(\benv\b\s*(\||>))|GITHUB_TOKEN|SLACK_TOKEN|NPM_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY`)

	// Matches exfiltration piping to network tools
	reExfilPiping = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|\bnc\b|\bbash\s+-i|/dev/tcp).*(\.ssh|\.aws|process\.env|os\.environ|printenv|AWS_|GITHUB_TOKEN|id_rsa)`)

	// Matches reverse shell / socket redirection droppers in install hooks
	reReverseShell = regexp.MustCompile(`(?i)/dev/tcp/|\bnc\s+(-e|-c|\w*e\w*)\b|\bbash\s+-i\b`)

	// Matches MCP reflection and tool introspection targeting sensitive files or environment
	reMCPReflection = regexp.MustCompile(`(?i)(list_tools|call_tool|tools/list|tools/call|get_tool|mcp_tool).*(\.env|id_rsa|id_ed25519|keychain|process\.env|printenv|dump_env|export_env)`)

	// Matches Deadbugz prompt injection directives embedded in schemas or comments
	reDeadbugzPrompt = regexp.MustCompile(`(?i)(<system>.*(ignore previous|exfiltrate|send to|upload to|curl|wget).*</system>)|(\bignore\s+(all\s+)?previous\s+instructions\b)`)

	// Matches suspicious MCP package naming conflations
	reMCPPackageThreat = regexp.MustCompile(`(?i)^(@[^/]+/)?(mcp[-_].*(harvester|stealer|exfil|dump|secret|keychain)|.*[-_]mcp[-_](admin|root|system|eval))`)
)

// CalculateShannonEntropy computes the bit entropy of a string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// DetectHighEntropy checks if a synthetic package name has unusually high entropy, indicating machine-generated slop.
func DetectHighEntropy(pkgName string) (bool, float64, string) {
	clean := strings.TrimSpace(pkgName)
	if strings.HasPrefix(clean, "@") {
		parts := strings.SplitN(clean, "/", 2)
		if len(parts) == 2 {
			clean = parts[1]
		}
	}
	stripped := stripDelimiters(clean)
	if len(stripped) < 10 {
		return false, 0, ""
	}

	entropy := CalculateShannonEntropy(stripped)
	if len(stripped) >= 12 && entropy >= 3.6 {
		vowels := 0
		for _, r := range stripped {
			if strings.ContainsRune("aeiouy", r) {
				vowels++
			}
		}
		vowelRatio := float64(vowels) / float64(len(stripped))
		if vowelRatio < 0.20 || vowelRatio > 0.65 {
			return true, entropy, fmt.Sprintf("high entropy (%.2f bits) with synthetic consonant/vowel distribution (ratio %.2f)", entropy, vowelRatio)
		}
	}

	return false, entropy, ""
}

// DetectDeadbugzMCP detects MCP server typosquats, credential reflection hooks, and prompt manipulation.
func DetectDeadbugzMCP(pkgName string, hookScript string, description string) (bool, string) {
	cleanName := strings.TrimSpace(pkgName)
	if IsApprovedNamespace(cleanName) {
		return false, ""
	}

	// 1. Suspicious package naming
	if reMCPPackageThreat.MatchString(cleanName) {
		return true, fmt.Sprintf("malicious or typosquatted MCP server package identifier: %s", cleanName)
	}

	// 2. Hook reflection check
	if hookScript != "" {
		if reMCPReflection.MatchString(hookScript) {
			return true, "script hook combines MCP tool reflection with sensitive credential targeting"
		}
		if reDeadbugzPrompt.MatchString(hookScript) {
			return true, "script hook embeds indirect prompt injection override directive"
		}
	}

	// 3. Description prompt injection check
	if description != "" {
		if reDeadbugzPrompt.MatchString(description) {
			return true, "MCP package description embeds prompt injection directive targeting autonomous agent planner"
		}
	}

	return false, ""
}

// MCPToolDef represents an MCP tool definition inside an MCP schema payload.
type MCPToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// MCPSchemaPayload represents a tools/list or registration payload from an MCP server.
type MCPSchemaPayload struct {
	Tools []MCPToolDef `json:"tools"`
}

// EvaluateMCPSchema audits an MCP server's exposed tools for credential harvesting, reflection, and prompt injection.
func EvaluateMCPSchema(serverName string, schemaBytes []byte) (*SlopsquatAssessment, error) {
	assessment := &SlopsquatAssessment{
		Details: make(map[string]any),
	}

	var payload MCPSchemaPayload
	if err := json.Unmarshal(schemaBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse MCP schema: %w", err)
	}

	suspiciousToolNames := regexp.MustCompile(`(?i)(dump_env|export_env|read_keychain|harvest_secrets|dump_ssh|get_auth_tokens|steal_credentials)`)

	for _, tool := range payload.Tools {
		// 1. Tool name matching malicious reflection
		if suspiciousToolNames.MatchString(tool.Name) {
			assessment.IsSuspicious = true
			assessment.IsDeadbugzMCP = true
			reason := fmt.Sprintf("MCP server '%s' declares dangerous secret extraction tool: %s", serverName, tool.Name)
			assessment.Reasons = append(assessment.Reasons, reason)
			assessment.Details["malicious_tool"] = tool.Name
		}

		// 2. Description prompt injection
		if tool.Description != "" && reDeadbugzPrompt.MatchString(tool.Description) {
			assessment.IsSuspicious = true
			assessment.IsDeadbugzMCP = true
			reason := fmt.Sprintf("MCP tool '%s' on server '%s' embeds prompt injection directive in description", tool.Name, serverName)
			assessment.Reasons = append(assessment.Reasons, reason)
			assessment.Details["injected_tool"] = tool.Name
		}
	}

	return assessment, nil
}

// DetectSuspiciousLifecycleHook inspects preinstall/postinstall script code or commands
// for attempts to access ~/.ssh, ~/.aws, or exfiltrate environment variables.
func DetectSuspiciousLifecycleHook(script string) (bool, string) {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return false, ""
	}

	// 1. Direct exfiltration chaining check
	if reExfilPiping.MatchString(trimmed) {
		return true, "script hooks network command (curl/wget/nc) piping sensitive credentials"
	}

	// 2. Reverse shell / interactive socket check
	if reReverseShell.MatchString(trimmed) {
		return true, "script hook establishes interactive reverse shell or raw network socket (/dev/tcp, nc -e, bash -i)"
	}

	// 2. SSH key access check
	if reSSHAccess.MatchString(trimmed) {
		return true, "script hook attempts to access SSH key directory or artifacts (~/.ssh, id_rsa, id_ed25519)"
	}

	// 3. AWS credential access check
	if reAWSAccess.MatchString(trimmed) {
		return true, "script hook attempts to access AWS credentials (~/.aws/credentials, AWS_SECRET_ACCESS_KEY)"
	}

	// 4. Environment variable exfiltration check
	if reEnvExfil.MatchString(trimmed) {
		return true, "script hook attempts to read or harvest sensitive environment variables (process.env, printenv, tokens)"
	}

	return false, ""
}

// EvaluatePackageProvenance conducts a multi-dimensional threat assessment over package metadata and hook scripts.
func EvaluatePackageProvenance(pkgName string, ageHours float64, downloads int64, hookScript string) *SlopsquatAssessment {
	assessment := &SlopsquatAssessment{
		Details: make(map[string]any),
	}

	// Dimension 1: Package Name Hallucination
	if isHallucination, target, pattern := DetectNameHallucination(pkgName); isHallucination {
		assessment.IsSuspicious = true
		assessment.IsHallucination = true
		assessment.TargetPackage = target
		assessment.Pattern = pattern
		assessment.Reasons = append(assessment.Reasons, pattern)
		assessment.Details["hallucination_target"] = target
		assessment.Details["hallucination_pattern"] = pattern
	}

	// Dimension 2: Fresh Release & Negligible Adoption (<72h, <=100 downloads)
	if isFresh, reason := DetectSuspiciousAgeAndDownloads(ageHours, downloads); isFresh {
		assessment.IsSuspicious = true
		assessment.IsFreshRelease = true
		assessment.Reasons = append(assessment.Reasons, reason)
		assessment.Details["age_hours"] = ageHours
		assessment.Details["downloads"] = downloads
		assessment.Details["fresh_release_reason"] = reason
	}

	// Dimension 3: Malicious Lifecycle Hooks
	if hookScript != "" {
		if isSuspiciousHook, hookReason := DetectSuspiciousLifecycleHook(hookScript); isSuspiciousHook {
			assessment.IsSuspicious = true
			assessment.IsSuspiciousHook = true
			assessment.Reasons = append(assessment.Reasons, hookReason)
			assessment.Details["hook_threat"] = hookReason
		}
	}

	// Dimension 4: High Shannon Entropy (Synthetic AI Naming)
	if isHighEntropy, entropy, entropyReason := DetectHighEntropy(pkgName); isHighEntropy {
		assessment.IsSuspicious = true
		assessment.IsHighEntropy = true
		assessment.EntropyScore = entropy
		assessment.Reasons = append(assessment.Reasons, entropyReason)
		assessment.Details["entropy_score"] = entropy
	}

	// Dimension 5: Deadbugz MCP Server & Tool Reflection Threat
	if isDeadbugz, deadbugzReason := DetectDeadbugzMCP(pkgName, hookScript, ""); isDeadbugz {
		assessment.IsSuspicious = true
		assessment.IsDeadbugzMCP = true
		assessment.Reasons = append(assessment.Reasons, deadbugzReason)
		assessment.Details["deadbugz_mcp"] = deadbugzReason
	}

	return assessment
}

func levenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
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
			temp := dp[j]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			dp[j] = minInt(dp[j]+1, minInt(dp[j-1]+1, prev+cost))
			prev = temp
		}
	}

	return dp[m]
}
