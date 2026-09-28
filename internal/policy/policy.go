package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy represents the enterprise configuration defined in .argusrc.yaml.
type Policy struct {
	Version       int             `yaml:"version"`
	Threshold     int             `yaml:"threshold"`
	Strict        bool            `yaml:"strict"`
	Allowlist     AllowlistConfig `yaml:"allowlist"`
	Blocklist     BlocklistConfig `yaml:"blocklist"`
	RuleOverrides map[string]int  `yaml:"rule_overrides"`
	Offline       OfflineConfig   `yaml:"offline"`
	FilePath      string          `yaml:"-"`
}

type AllowlistConfig struct {
	Packages   []string `yaml:"packages"`
	Authors    []string `yaml:"authors"`
	Namespaces []string `yaml:"namespaces"`
}

type BlocklistConfig struct {
	Packages []string `yaml:"packages"`
	Authors  []string `yaml:"authors"`
}

type OfflineConfig struct {
	Enabled           bool `yaml:"enabled"`
	FallbackCacheOnly bool `yaml:"fallback_cache_only"`
}

// DefaultPolicy returns safe baseline defaults.
func DefaultPolicy() *Policy {
	return &Policy{
		Version:   1,
		Threshold: 50,
		Strict:    false,
		Allowlist: AllowlistConfig{
			Packages:   []string{},
			Authors:    []string{},
			Namespaces: []string{},
		},
		Blocklist: BlocklistConfig{
			Packages: []string{},
			Authors:  []string{},
		},
		RuleOverrides: make(map[string]int),
		Offline: OfflineConfig{
			Enabled:           false,
			FallbackCacheOnly: false,
		},
	}
}

// DiscoverPolicyFile searches current working directory, upward tree, and ~/.argus/config.yaml.
func DiscoverPolicyFile(startDir string) (string, error) {
	if startDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		startDir = cwd
	}

	curr := startDir
	for {
		candidate := filepath.Join(curr, ".argusrc.yaml")
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
		candidateYml := filepath.Join(curr, ".argusrc.yml")
		if fi, err := os.Stat(candidateYml); err == nil && !fi.IsDir() {
			return candidateYml, nil
		}

		parent := filepath.Dir(curr)
		if parent == curr || parent == "." {
			break
		}
		curr = parent
	}

	// Fallback to global user config
	if home, err := os.UserHomeDir(); err == nil {
		globalConfig := filepath.Join(home, ".argus", "config.yaml")
		if fi, err := os.Stat(globalConfig); err == nil && !fi.IsDir() {
			return globalConfig, nil
		}
	}

	return "", nil
}

// Load loads and parses a policy file, or returns the default policy if none exists.
func Load(path string) (*Policy, error) {
	if path == "" {
		var err error
		path, err = DiscoverPolicyFile("")
		if err != nil || path == "" {
			return DefaultPolicy(), nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	p := DefaultPolicy()
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("invalid policy syntax in %s: %w", path, err)
	}
	p.FilePath = path

	if p.Threshold <= 0 {
		p.Threshold = 50
	}

	return p, nil
}

// MatchAllowlist checks if a package or author is exempt under enterprise policy.
func (p *Policy) MatchAllowlist(pkgName, author string) (bool, string) {
	pkgLower := strings.ToLower(strings.TrimSpace(pkgName))
	authorLower := strings.ToLower(strings.TrimSpace(author))

	// 1. Check exact or wildcard package matches
	for _, pattern := range p.Allowlist.Packages {
		patLower := strings.ToLower(strings.TrimSpace(pattern))
		if patLower == pkgLower {
			return true, fmt.Sprintf("Package %q matched allowlist rule %q", pkgName, pattern)
		}
		if strings.HasSuffix(patLower, "*") {
			prefix := strings.TrimSuffix(patLower, "*")
			if strings.HasPrefix(pkgLower, prefix) {
				return true, fmt.Sprintf("Package %q matched allowlist wildcard %q", pkgName, pattern)
			}
		}
	}

	// 2. Check namespace prefixes
	for _, ns := range p.Allowlist.Namespaces {
		nsLower := strings.ToLower(strings.TrimSpace(ns))
		if strings.HasPrefix(pkgLower, nsLower) {
			return true, fmt.Sprintf("Package %q matched allowed namespace %q", pkgName, ns)
		}
	}

	// 3. Check author allowlist
	if authorLower != "" {
		for _, auth := range p.Allowlist.Authors {
			if strings.EqualFold(auth, authorLower) {
				return true, fmt.Sprintf("Author %q matched enterprise author allowlist", author)
			}
		}
	}

	return false, ""
}

// MatchBlocklist checks if a package or author is explicitly blacklisted.
func (p *Policy) MatchBlocklist(pkgName, author string) (bool, string) {
	pkgLower := strings.ToLower(strings.TrimSpace(pkgName))
	authorLower := strings.ToLower(strings.TrimSpace(author))

	for _, pattern := range p.Blocklist.Packages {
		patLower := strings.ToLower(strings.TrimSpace(pattern))
		if patLower == pkgLower {
			return true, fmt.Sprintf("Package %q explicitly blocked by enterprise policy", pkgName)
		}
		if strings.HasSuffix(patLower, "*") {
			prefix := strings.TrimSuffix(patLower, "*")
			if strings.HasPrefix(pkgLower, prefix) {
				return true, fmt.Sprintf("Package %q matched blocklist wildcard %q", pkgName, pattern)
			}
		}
	}

	if authorLower != "" {
		for _, auth := range p.Blocklist.Authors {
			if strings.EqualFold(auth, authorLower) {
				return true, fmt.Sprintf("Author %q explicitly blocked by enterprise policy", author)
			}
		}
	}

	return false, ""
}
