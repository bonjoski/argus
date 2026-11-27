package aiadvisor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

var (
	// ErrSecretLeakageDetected is returned by FailClosedWireGuard if unredacted secrets escape.
	ErrSecretLeakageDetected = errors.New("fail-closed wire guard: unredacted secret detected in outbound payload")

	validPlaceholderRe    = regexp.MustCompile(`^\[SECRET_REF_[0-9a-f]{16}\]$`)
	embeddedPlaceholderRe = regexp.MustCompile(`\[SECRET_REF_[0-9a-f]{16}\]`)
)

// SecretPattern defines a regex pattern paired with an identification label.
type SecretPattern struct {
	Name    string
	Regex   *regexp.Regexp
	MinLen  int
	Entropy float64
}

// BuiltinPatterns provides curated high-fidelity detection rules for credentials.
var BuiltinPatterns = []SecretPattern{
	{
		Name:  "AWS Access Key ID",
		Regex: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		Name:  "Anthropic API Key",
		Regex: regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_\-]{32,}\b`),
	},
	{
		Name:  "OpenAI API Key",
		Regex: regexp.MustCompile(`\bsk-[a-zA-Z0-9_\-]{20,}\b`),
	},
	{
		Name:  "Google API Key",
		Regex: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		Name:  "GitHub Personal Access Token",
		Regex: regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
	},
	{
		Name:  "GitHub Fine-Grained Token",
		Regex: regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`),
	},
	{
		Name:  "Slack Token",
		Regex: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b`),
	},
	{
		Name:  "Database Connection URI",
		Regex: regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^:\s]+:([^@\s]+)@[^\s]+\b`),
	},
	{
		Name:  "Private Key Header",
		Regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		Name:  "Generic Key Assignment",
		Regex: regexp.MustCompile(`(?i)(?:api_key|apikey|secret|password|token|bearer|credential)\s*[:=]\s*["']([^"']{8,})["']`),
	},
}

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// Strings with high randomness (like cryptographic keys and tokens) typically score >= 4.2.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	runeCount := 0
	for _, c := range s {
		freq[c]++
		runeCount++
	}

	length := float64(runeCount)
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy returns true if the candidate token exceeds the minimum entropy threshold
// and has sufficient length to qualify as a suspected cryptographic credential.
func IsHighEntropy(s string, minLen int, threshold float64) bool {
	if len(s) < minLen {
		return false
	}
	return ShannonEntropy(s) >= threshold
}

// TokenMap holds the bi-directional mapping between scrubbed placeholder references
// (e.g. "[SECRET_REF_e7a9b1c2d3e4f506]") and the original raw secret values.
// All values are stored strictly in-memory and can be explicitly zeroized.
type TokenMap struct {
	mu           sync.RWMutex
	refToSecret  map[string]string
	secretToRef  map[string]string
	namedSecrets map[string]string
}

// NewTokenMap initializes an empty thread-safe TokenMap.
func NewTokenMap() *TokenMap {
	return &TokenMap{
		refToSecret:  make(map[string]string),
		secretToRef:  make(map[string]string),
		namedSecrets: make(map[string]string),
	}
}

// Add inserts a raw secret, returning its consistent placeholder reference.
// If the secret already exists in the map, its existing reference is returned.
func (tm *TokenMap) Add(secret string, optionalName string) string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if ref, exists := tm.secretToRef[secret]; exists {
		if optionalName != "" {
			tm.namedSecrets[optionalName] = ref
		}
		return ref
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	ref := fmt.Sprintf("[SECRET_REF_%s]", hex.EncodeToString(b))

	tm.refToSecret[ref] = secret
	tm.secretToRef[secret] = ref
	if optionalName != "" {
		tm.namedSecrets[optionalName] = ref
	}

	return ref
}

// GetSecret resolves a placeholder reference back to the original secret.
func (tm *TokenMap) GetSecret(ref string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	secret, ok := tm.refToSecret[ref]
	return secret, ok
}

// GetRef returns the placeholder reference for a known secret value.
func (tm *TokenMap) GetRef(secret string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	ref, ok := tm.secretToRef[secret]
	return ref, ok
}

// Count returns the number of tracked secrets in the map.
func (tm *TokenMap) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.refToSecret)
}

// References returns all placeholder tokens in the map.
func (tm *TokenMap) References() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	refs := make([]string, 0, len(tm.refToSecret))
	for ref := range tm.refToSecret {
		refs = append(refs, ref)
	}
	return refs
}

// Zeroize explicitly clears all secret strings in memory to reduce heap residency.
func (tm *TokenMap) Zeroize() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for k, v := range tm.refToSecret {
		b := []byte(v)
		for i := range b {
			b[i] = 0
		}
		delete(tm.refToSecret, k)
	}
	for k := range tm.secretToRef {
		delete(tm.secretToRef, k)
	}
	for k := range tm.namedSecrets {
		delete(tm.namedSecrets, k)
	}
	runtime.GC()
}

// RedactorConfig configures client-side pre-flight secret detection and redaction.
type RedactorConfig struct {
	MinEntropyLen    int
	EntropyThreshold float64
	Patterns         []SecretPattern
	CustomVaultKeys  map[string]string
}

// DefaultRedactorConfig returns the production baseline secret-redaction configuration.
func DefaultRedactorConfig() RedactorConfig {
	return RedactorConfig{
		MinEntropyLen:    16,
		EntropyThreshold: 4.2,
		Patterns:         BuiltinPatterns,
		CustomVaultKeys:  make(map[string]string),
	}
}

// Redactor performs client-side pre-flight secret tokenization and fail-closed wire checks.
type Redactor struct {
	cfg RedactorConfig
}

// NewRedactor initializes a Redactor with the provided configuration.
func NewRedactor(cfg RedactorConfig) *Redactor {
	if cfg.MinEntropyLen == 0 {
		cfg.MinEntropyLen = 16
	}
	if cfg.EntropyThreshold == 0.0 {
		cfg.EntropyThreshold = 4.2
	}
	if len(cfg.Patterns) == 0 {
		cfg.Patterns = BuiltinPatterns
	}
	if cfg.CustomVaultKeys == nil {
		cfg.CustomVaultKeys = make(map[string]string)
	}
	return &Redactor{cfg: cfg}
}

// NormalizeInvisibleChars strips zero-width, bidi control, and Unicode Tag smuggling
// characters used by adversaries attempting to evade regex matching and entropy checks.
func NormalizeInvisibleChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u200e' || r == '\u200f':
			continue
		case r == '\ufeff' || r == '\u2060' || r == '\u00ad':
			continue
		case r >= '\u202a' && r <= '\u202e':
			continue
		case r >= '\u2066' && r <= '\u2069':
			continue
		case r >= '\U000E0000' && r <= '\U000E007F':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Redact scans the input string, substitutes all discovered secrets with opaque
// placeholders (e.g. "[SECRET_REF_e7a9b1c2d3e4f506]"), and stores mappings in a TokenMap.
func (r *Redactor) Redact(input string) (string, *TokenMap, error) {
	tm := NewTokenMap()
	output := NormalizeInvisibleChars(input)

	// 1. First Pass: Synchronized Vault Credentials (exact matches)
	for name, secret := range r.cfg.CustomVaultKeys {
		cleanSecret := NormalizeInvisibleChars(secret)
		if len(cleanSecret) < 4 {
			continue
		}
		if strings.Contains(output, cleanSecret) {
			ref := tm.Add(cleanSecret, name)
			output = strings.ReplaceAll(output, cleanSecret, ref)
		}
	}

	// 2. Second Pass: High-Fidelity RegEx Patterns
	for _, p := range r.cfg.Patterns {
		matches := p.Regex.FindAllStringSubmatch(output, -1)
		for _, m := range matches {
			if len(m) == 0 {
				continue
			}
			candidate := m[0]
			if len(m) > 1 && len(m[1]) > 0 {
				candidate = m[1]
			}

			if validPlaceholderRe.MatchString(candidate) {
				continue
			}

			if p.Entropy > 0 && !IsHighEntropy(candidate, p.MinLen, p.Entropy) {
				continue
			}

			ref := tm.Add(candidate, p.Name)
			output = strings.ReplaceAll(output, candidate, ref)
		}
	}

	// 3. Third Pass: High-Entropy Word Scanning (for unformatted raw tokens)
	scrubbedForScan := embeddedPlaceholderRe.ReplaceAllString(output, " ")
	for _, w := range strings.Fields(scrubbedForScan) {
		cleaned := strings.Trim(w, `"',;:()[]{}<>`)
		if validPlaceholderRe.MatchString(cleaned) {
			continue
		}
		if IsHighEntropy(cleaned, r.cfg.MinEntropyLen, r.cfg.EntropyThreshold) {
			ref := tm.Add(cleaned, "High-Entropy Token")
			output = strings.ReplaceAll(output, cleaned, ref)
		}
	}

	return output, tm, nil
}

// Restore substitutes all placeholder tokens in text back to their original secret values.
func (r *Redactor) Restore(text string, tm *TokenMap) string {
	if tm == nil {
		return text
	}

	result := text
	for pass := 0; pass < 5; pass++ {
		changed := false
		for _, ref := range tm.References() {
			if strings.Contains(result, ref) {
				if secret, ok := tm.GetSecret(ref); ok {
					result = strings.ReplaceAll(result, ref, secret)
					changed = true
				}
			}
		}
		if !changed || !strings.Contains(result, "[SECRET_REF_") {
			break
		}
	}
	return result
}

// FailClosedWireGuard performs a final safety check on the serialized payload before
// transmission over the network. If any unredacted pattern, custom vault key, or
// high-entropy secret token is found, the outbound call aborts immediately.
func (r *Redactor) FailClosedWireGuard(payload []byte) error {
	s := NormalizeInvisibleChars(string(payload))

	// 1. Vault credentials check
	for name, secret := range r.cfg.CustomVaultKeys {
		cleanSecret := NormalizeInvisibleChars(secret)
		if len(cleanSecret) >= 4 && strings.Contains(s, cleanSecret) {
			return fmt.Errorf("%w: matched custom vault key %s", ErrSecretLeakageDetected, name)
		}
	}

	// 2. High-fidelity patterns check
	for _, p := range r.cfg.Patterns {
		if len(p.Regex.SubexpNames()) > 1 {
			matches := p.Regex.FindAllStringSubmatch(s, -1)
			for _, m := range matches {
				if len(m) > 1 && len(m[1]) > 0 {
					if !validPlaceholderRe.MatchString(m[1]) {
						return fmt.Errorf("%w: unredacted credential in %s", ErrSecretLeakageDetected, p.Name)
					}
				}
			}
		} else {
			if p.Regex.MatchString(s) {
				return fmt.Errorf("%w: matched %s", ErrSecretLeakageDetected, p.Name)
			}
		}
	}

	// 3. Raw high-entropy token check (matching Pass 3 semantics)
	scrubbedForScan := embeddedPlaceholderRe.ReplaceAllString(s, " ")
	for _, w := range strings.Fields(scrubbedForScan) {
		cleaned := strings.Trim(w, `"',;:()[]{}<>`)
		if validPlaceholderRe.MatchString(cleaned) {
			continue
		}
		if IsHighEntropy(cleaned, r.cfg.MinEntropyLen, r.cfg.EntropyThreshold) {
			return fmt.Errorf("%w: unredacted high-entropy token detected", ErrSecretLeakageDetected)
		}
	}

	return nil
}
