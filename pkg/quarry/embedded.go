package quarry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"bonjoski/argus/rules"
)

var (
	embeddedOnce   sync.Once
	embeddedRules  []*CompiledRule
	embeddedDigest string
	embeddedErr    error
)

// LoadEmbeddedRules parses all declarative Quarry YAML rules embedded in the binary.
func LoadEmbeddedRules() ([]*Rule, error) {
	entries, err := fs.ReadDir(rules.QuarryYAMLFS, "quarry")
	if err != nil {
		return nil, fmt.Errorf("failed reading embedded quarry rules: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []*Rule
	for _, name := range names {
		data, rErr := fs.ReadFile(rules.QuarryYAMLFS, "quarry/"+name)
		if rErr != nil {
			return nil, fmt.Errorf("failed reading embedded quarry rule %s: %w", name, rErr)
		}
		parsed, pErr := ParseRules(data)
		if pErr != nil {
			return nil, fmt.Errorf("failed parsing embedded quarry rule %s: %w", name, pErr)
		}
		out = append(out, parsed...)
	}
	return out, nil
}

func initEmbeddedCompiledRules() {
	embeddedOnce.Do(func() {
		entries, err := fs.ReadDir(rules.QuarryYAMLFS, "quarry")
		if err != nil {
			embeddedErr = fmt.Errorf("failed reading embedded quarry rules: %w", err)
			return
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)

		h := sha256.New()
		var compiled []*CompiledRule
		for _, name := range names {
			data, rErr := fs.ReadFile(rules.QuarryYAMLFS, "quarry/"+name)
			if rErr != nil {
				embeddedErr = fmt.Errorf("failed reading embedded quarry rule %s: %w", name, rErr)
				return
			}
			h.Write([]byte(name))
			h.Write([]byte{0})
			h.Write(data)
			h.Write([]byte{0})

			parsed, pErr := ParseRules(data)
			if pErr != nil {
				embeddedErr = fmt.Errorf("failed parsing embedded quarry rule %s: %w", name, pErr)
				return
			}
			for _, r := range parsed {
				cr, cErr := CompileRule(r)
				if cErr != nil {
					embeddedErr = fmt.Errorf("failed compiling embedded quarry rule %q (%s): %w", r.Name, name, cErr)
					return
				}
				compiled = append(compiled, cr)
			}
		}
		embeddedRules = compiled
		embeddedDigest = hex.EncodeToString(h.Sum(nil))
	})
}

// EmbeddedRulesDigest returns the deterministic SHA-256 hex digest of all embedded Quarry YAML rules.
func EmbeddedRulesDigest() string {
	initEmbeddedCompiledRules()
	if embeddedDigest != "" {
		return embeddedDigest
	}
	return "unavailable"
}

// EvaluateEmbeddedPackageAdvisory evaluates all single-step embedded supply-chain Quarry advisory
// rules (e.g. GHSA SemVer vulnerable_versions gates) lock-free and in-memory (<0.05ms).
// Fails closed if embedded rules failed compilation.
func EvaluateEmbeddedPackageAdvisory(pkgName, version, rawCmd string) ([]*Alert, error) {
	initEmbeddedCompiledRules()
	if embeddedErr != nil {
		return nil, embeddedErr
	}

	ev := &Event{
		Layer:     LayerSupplyChain,
		Action:    "package_install",
		Command:   rawCmd,
		Timestamp: time.Now(),
		Args:      map[string]any{},
	}
	if strings.TrimSpace(pkgName) != "" {
		ev.Args["package"] = strings.TrimSpace(pkgName)
	}
	if strings.TrimSpace(version) != "" {
		ev.Args["version"] = strings.TrimSpace(version)
	}

	var alerts []*Alert
	for _, cr := range embeddedRules {
		// Only evaluate single-step package advisory rules (rules with a package matcher + vulnerable_versions or explicit supply-chain block)
		if len(cr.Steps) != 1 {
			continue
		}
		step := &cr.Steps[0]
		isAdvisoryRule := false
		for i := range step.Matchers {
			if step.Matchers[i].PackageRegex != nil && step.Matchers[i].VulnerableVersions != nil {
				isAdvisoryRule = true
				break
			}
		}
		if !isAdvisoryRule {
			continue
		}
		if step.Matches(ev) {
			alerts = append(alerts, &Alert{
				RuleName:      cr.Rule.Name,
				RuleVersion:   cr.Rule.Version,
				Severity:      cr.Rule.Severity,
				Action:        cr.Rule.Action,
				TriggeredAt:   ev.Timestamp,
				SequenceSteps: []string{step.Name},
				MatchedEvents: []Event{*ev},
				Details: map[string]any{
					"description": cr.Rule.Description,
				},
			})
		}
	}
	return alerts, nil
}
