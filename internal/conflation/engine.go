package conflation

import (
	"bufio"
	"embed"
	"strings"
	"sync"
	"unicode"

	"bonjoski/argus/internal/model"
)

//go:embed data/*.txt
var corpusFiles embed.FS

// Engine provides lexical analysis, typosquatting detection, and namespace exemption checking.
type Engine struct {
	mu      sync.RWMutex
	corpora map[model.Ecosystem]map[string]struct{}
	trie    map[model.Ecosystem]*TrieNode
}

// TrieNode for prefix matching against popular package namespaces.
type TrieNode struct {
	children map[rune]*TrieNode
	isEnd    bool
	pkgName  string
}

func newTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[rune]*TrieNode),
	}
}

func (t *TrieNode) insert(word string) {
	curr := t
	for _, r := range word {
		if _, ok := curr.children[r]; !ok {
			curr.children[r] = newTrieNode()
		}
		curr = curr.children[r]
	}
	curr.isEnd = true
	curr.pkgName = word
}

var (
	defaultEngineInstance *Engine
	once                  sync.Once
)

// DefaultEngine returns the singleton embedded Conflation Engine.
func DefaultEngine() *Engine {
	once.Do(func() {
		defaultEngineInstance = NewEngine()
	})
	return defaultEngineInstance
}

// NewEngine initializes and parses embedded corpora.
func NewEngine() *Engine {
	e := &Engine{
		corpora: make(map[model.Ecosystem]map[string]struct{}),
		trie:    make(map[model.Ecosystem]*TrieNode),
	}

	ecosystems := []struct {
		eco  model.Ecosystem
		file string
	}{
		{model.EcosystemNPM, "data/npm.txt"},
		{model.EcosystemPyPI, "data/pypi.txt"},
		{model.EcosystemCargo, "data/cargo.txt"},
		{model.EcosystemGo, "data/go.txt"},
		{model.EcosystemRubyGems, "data/rubygems.txt"},
		{model.EcosystemMaven, "data/maven.txt"},
		{model.EcosystemPackagist, "data/packagist.txt"},
		{model.EcosystemNuGet, "data/nuget.txt"},
		{model.EcosystemPub, "data/pub.txt"},
		{model.EcosystemHex, "data/hex.txt"},
		{model.EcosystemSwift, "data/swift.txt"},
	}

	for _, entry := range ecosystems {
		words := loadCorpus(entry.file)
		wordMap := make(map[string]struct{}, len(words))
		root := newTrieNode()

		for _, w := range words {
			wLower := strings.ToLower(strings.TrimSpace(w))
			if wLower != "" {
				wordMap[wLower] = struct{}{}
				root.insert(wLower)
			}
		}

		e.corpora[entry.eco] = wordMap
		e.trie[entry.eco] = root
	}

	return e
}

func loadCorpus(path string) []string {
	f, err := corpusFiles.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" && !strings.HasPrefix(text, "#") {
			lines = append(lines, text)
		}
	}
	return lines
}

// Tokenize splits a package name into distinct words across kebab, snake, dot, and camelCase.
func Tokenize(name string) []string {
	// Strip scope if present (e.g., @scope/pkg -> pkg)
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

		// Detect camelCase transitions (e.g. reactDom -> react, dom)
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

// IsApprovedNamespace checks if a package follows legitimate community plugin naming patterns.
func IsApprovedNamespace(pkgName string, eco model.Ecosystem) bool {
	lower := strings.ToLower(strings.TrimSpace(pkgName))

	switch eco {
	case model.EcosystemPyPI:
		patterns := []string{"pytest-", "django-", "mkdocs-", "flake8-", "sphinx-", "celery-", "wagtail-"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemNPM:
		patterns := []string{"eslint-plugin-", "@types/", "babel-plugin-", "webpack-plugin-", "rollup-plugin-", "vite-plugin-", "postcss-"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemCargo:
		if strings.HasPrefix(lower, "cargo-") {
			return true
		}
	case model.EcosystemGo:
		// Subpackages under major domains or vanity hosts
		if strings.Contains(lower, "/plugins/") || strings.Contains(lower, "/contrib/") {
			return true
		}
	case model.EcosystemRubyGems:
		patterns := []string{"rails-", "sprockets-", "rspec-", "capistrano-", "omniauth-"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemMaven:
		patterns := []string{"org.springframework.boot:spring-boot-starter-", "org.apache.maven.plugins:", "org.junit.jupiter:"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemPackagist:
		patterns := []string{"symfony/", "laravel/", "doctrine/", "psr/", "illuminate/"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemNuGet:
		patterns := []string{"microsoft.", "system.", "azure.", "amazon.", "serilog."}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemPub:
		patterns := []string{"flutter_", "dart_"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemHex:
		patterns := []string{"phoenix_", "ecto_", "absinthe_", "broadway_"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	case model.EcosystemSwift:
		patterns := []string{"apple/", "swift-", "swiftui-", "combine"}
		for _, prefix := range patterns {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}

	return false
}

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
}

// ConflationResult contains the outcome of a lexical conflation evaluation.
type ConflationResult struct {
	IsConflated bool
	IsTyposquat bool
	TargetPkg   string
	Reason      string
}

// Evaluate analyzes a package name against the ecosystem corpus.
func (e *Engine) Evaluate(pkgName string, eco model.Ecosystem) ConflationResult {
	e.mu.RLock()
	corpus, ok := e.corpora[eco]
	e.mu.RUnlock()

	if !ok || len(corpus) == 0 {
		return ConflationResult{}
	}

	cleanName := strings.ToLower(strings.TrimSpace(pkgName))
	if strings.HasPrefix(cleanName, "@") {
		parts := strings.SplitN(cleanName, "/", 2)
		if len(parts) == 2 {
			cleanName = parts[1]
		}
	}

	// 1. Exemption check
	if IsApprovedNamespace(pkgName, eco) {
		return ConflationResult{}
	}

	// 2. Exact match check: if this IS the legitimate package, no conflation
	if _, exact := corpus[cleanName]; exact {
		return ConflationResult{}
	}

	// 3. Typosquatting check (Levenshtein distance <= 2)
	nameLen := len(cleanName)
	if nameLen >= 4 {
		for target := range corpus {
			tLen := len(target)
			diff := nameLen - tLen
			if diff < -2 || diff > 2 {
				continue
			}

			dist := levenshteinDistance(cleanName, target)
			if dist == 1 || (dist == 2 && nameLen >= 6) {
				return ConflationResult{
					IsConflated: true,
					IsTyposquat: true,
					TargetPkg:   target,
					Reason:      "Levenshtein distance " + string(rune('0'+dist)) + " from high-reputation package: " + target,
				}
			}
		}
	}

	// 4. Slopsquatting / Token conflation check
	tokens := Tokenize(pkgName)
	if len(tokens) >= 2 {
		var matchedTarget string
		genericMatches := 0
		popularMatches := 0

		for _, tok := range tokens {
			if _, exists := corpus[tok]; exists {
				popularMatches++
				if matchedTarget == "" {
					matchedTarget = tok
				}
			} else if _, isGeneric := genericHallucinationTokens[tok]; isGeneric {
				genericMatches++
			}
		}

		// If package synthesizes a popular library with generic primitives or another popular library
		if popularMatches >= 1 && (genericMatches >= 1 || popularMatches >= 2) {
			return ConflationResult{
				IsConflated: true,
				IsTyposquat: false,
				TargetPkg:   matchedTarget,
				Reason:      "Conflates high-reputation identifier (" + matchedTarget + ") with common primitives or ecosystem tokens",
			}
		}
	}

	return ConflationResult{}
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
			dp[j] = min(dp[j]+1, min(dp[j-1]+1, prev+cost))
			prev = temp
		}
	}

	return dp[m]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
