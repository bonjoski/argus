package quarry

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EventMatcher defines criteria to match an Event at Layer-7 or Layer-3.
type EventMatcher struct {
	Layer          string   `yaml:"layer" json:"layer"`
	Action         string   `yaml:"action" json:"action"`
	PathMatches    string   `yaml:"path_matches,omitempty" json:"path_matches,omitempty"`
	DestNotIn      []string `yaml:"dest_not_in,omitempty" json:"dest_not_in,omitempty"`
	DestIn         []string `yaml:"dest_in,omitempty" json:"dest_in,omitempty"`
	ToolMatches    string   `yaml:"tool_matches,omitempty" json:"tool_matches,omitempty"`
	CommandMatches string   `yaml:"command_matches,omitempty" json:"command_matches,omitempty"`

	// Precompiled matchers
	normLayer    Layer          `yaml:"-" json:"-"`
	actionRegex  *regexp.Regexp `yaml:"-" json:"-"`
	pathRegex    *regexp.Regexp `yaml:"-" json:"-"`
	toolRegex    *regexp.Regexp `yaml:"-" json:"-"`
	commandRegex *regexp.Regexp `yaml:"-" json:"-"`
}

// SequenceStep represents a named causal milestone containing one or more matching events.
type SequenceStep struct {
	Step   string         `yaml:"step" json:"step"`
	Events []EventMatcher `yaml:"events" json:"events"`
}

// Rule defines a declarative Cisco Project Quarry multi-action sequence detection policy.
type Rule struct {
	Name             string         `yaml:"name" json:"name"`
	Version          string         `yaml:"version" json:"version"`
	Description      string         `yaml:"description,omitempty" json:"description,omitempty"`
	Severity         string         `yaml:"severity,omitempty" json:"severity,omitempty"`
	WindowStr        string         `yaml:"window" json:"window"`
	Window           time.Duration  `yaml:"-" json:"-"`
	SessionWindowStr string         `yaml:"session_window,omitempty" json:"session_window,omitempty"`
	SessionWindow    time.Duration  `yaml:"-" json:"-"`
	Action           string         `yaml:"action" json:"action"` // "kill", "freeze", "alert"
	CausalSequence   []SequenceStep `yaml:"causal_sequence" json:"causal_sequence"`
}

// UnmarshalYAML implements custom unmarshaling to handle string or numeric version fields.
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	type rawRule struct {
		Name           string         `yaml:"name"`
		VersionNode    yaml.Node      `yaml:"version"`
		Description    string         `yaml:"description,omitempty"`
		Severity       string         `yaml:"severity,omitempty"`
		Window         string         `yaml:"window"`
		SessionWindow  string         `yaml:"session_window,omitempty"`
		Action         string         `yaml:"action"`
		CausalSequence []SequenceStep `yaml:"causal_sequence"`
	}

	var raw rawRule
	if err := value.Decode(&raw); err != nil {
		return err
	}

	r.Name = raw.Name
	r.Description = raw.Description
	r.Severity = raw.Severity
	if r.Severity == "" {
		r.Severity = "CRITICAL"
	}
	r.WindowStr = raw.Window
	r.SessionWindowStr = raw.SessionWindow
	r.Action = raw.Action
	if r.Action == "" {
		r.Action = "kill"
	}
	r.CausalSequence = raw.CausalSequence

	// Handle version as string or float or int
	switch raw.VersionNode.Kind {
	case yaml.ScalarNode:
		r.Version = raw.VersionNode.Value
	default:
		r.Version = "1.0"
	}

	// Parse duration
	if r.WindowStr != "" {
		d, err := parseDuration(r.WindowStr)
		if err != nil {
			return fmt.Errorf("invalid rule window %q: %w", r.WindowStr, err)
		}
		r.Window = d
	} else {
		r.Window = 60 * time.Second
		r.WindowStr = "60s"
	}

	if r.SessionWindowStr != "" {
		d, err := parseDuration(r.SessionWindowStr)
		if err != nil {
			return fmt.Errorf("invalid rule session_window %q: %w", r.SessionWindowStr, err)
		}
		r.SessionWindow = d
	} else {
		r.SessionWindow = 1 * time.Hour
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	// Try standard time.ParseDuration (handles "60s", "1m", "500ms")
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// Try numeric seconds (e.g. "60")
	if secs, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(secs * float64(time.Second)), nil
	}
	return 0, fmt.Errorf("cannot parse duration %q", s)
}

// CompiledRule contains pre-compiled regular expressions and lookup sets for zero-allocation matching.
type CompiledRule struct {
	Rule  *Rule
	Steps []CompiledStep
}

// CompiledStep contains precompiled matchers for a step.
type CompiledStep struct {
	Name     string
	Matchers []CompiledMatcher
}

// CompiledMatcher contains optimized matching functions and regexes.
type CompiledMatcher struct {
	Raw          EventMatcher
	NormLayer    Layer
	ActionRegex  *regexp.Regexp
	PathRegex    *regexp.Regexp
	ToolRegex    *regexp.Regexp
	CommandRegex *regexp.Regexp
	DestNotIn    []string
	DestIn       []string
}

// CompileRule pre-compiles regexes and normalizes patterns for a Quarry rule.
func CompileRule(r *Rule) (*CompiledRule, error) {
	if r.Name == "" {
		return nil, fmt.Errorf("rule name cannot be empty")
	}
	if len(r.CausalSequence) == 0 {
		return nil, fmt.Errorf("rule %q must have at least one causal sequence step", r.Name)
	}

	cr := &CompiledRule{
		Rule:  r,
		Steps: make([]CompiledStep, len(r.CausalSequence)),
	}

	for i, step := range r.CausalSequence {
		cs := CompiledStep{
			Name:     step.Step,
			Matchers: make([]CompiledMatcher, len(step.Events)),
		}

		for j, em := range step.Events {
			cm := CompiledMatcher{
				Raw:       em,
				NormLayer: NormalizeLayer(em.Layer),
				DestNotIn: em.DestNotIn,
				DestIn:    em.DestIn,
			}

			if em.Action != "" {
				// Escape or regex compile
				re, err := regexp.Compile("(?i)^(" + em.Action + ")$")
				if err != nil {
					return nil, fmt.Errorf("rule %q step %d invalid action regex %q: %w", r.Name, i, em.Action, err)
				}
				cm.ActionRegex = re
			}

			if em.PathMatches != "" {
				re, err := regexp.Compile("(?i)" + em.PathMatches)
				if err != nil {
					return nil, fmt.Errorf("rule %q step %d invalid path_matches regex %q: %w", r.Name, i, em.PathMatches, err)
				}
				cm.PathRegex = re
			}

			if em.ToolMatches != "" {
				re, err := regexp.Compile("(?i)^(" + em.ToolMatches + ")$")
				if err != nil {
					return nil, fmt.Errorf("rule %q step %d invalid tool_matches regex %q: %w", r.Name, i, em.ToolMatches, err)
				}
				cm.ToolRegex = re
			}

			if em.CommandMatches != "" {
				re, err := regexp.Compile("(?i)" + em.CommandMatches)
				if err != nil {
					return nil, fmt.Errorf("rule %q step %d invalid command_matches regex %q: %w", r.Name, i, em.CommandMatches, err)
				}
				cm.CommandRegex = re
			}

			cs.Matchers[j] = cm
		}

		cr.Steps[i] = cs
	}

	return cr, nil
}

// Matches checks whether an Event satisfies this compiled matcher.
func (cm *CompiledMatcher) Matches(e *Event) bool {
	if e == nil {
		return false
	}

	// 1. Layer check
	if cm.NormLayer != "" && NormalizeLayer(string(e.Layer)) != cm.NormLayer {
		return false
	}

	// 2. Action check
	if cm.ActionRegex != nil {
		matched := cm.ActionRegex.MatchString(e.Action)
		if !matched && e.Tool != "" {
			matched = cm.ActionRegex.MatchString(e.Tool)
		}
		if !matched {
			return false
		}
	}

	// 3. Path check
	if cm.PathRegex != nil {
		matched := false
		if e.Path != "" && cm.PathRegex.MatchString(e.Path) {
			matched = true
		} else if e.Command != "" && cm.PathRegex.MatchString(e.Command) {
			matched = true
		} else if e.Args != nil {
			if p, ok := e.Args["path"].(string); ok && cm.PathRegex.MatchString(p) {
				matched = true
			} else if p, ok := e.Args["file"].(string); ok && cm.PathRegex.MatchString(p) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}

	// 4. Tool check
	if cm.ToolRegex != nil {
		if e.Tool == "" || !cm.ToolRegex.MatchString(e.Tool) {
			return false
		}
	}

	// 5. Command check
	if cm.CommandRegex != nil {
		if e.Command == "" || !cm.CommandRegex.MatchString(e.Command) {
			return false
		}
	}

	// 6. DestIn check
	if len(cm.DestIn) > 0 {
		if e.Destination == "" {
			return false
		}
		if !matchesAnyDestination(e.Destination, cm.DestIn) {
			return false
		}
	}

	// 7. DestNotIn check
	if len(cm.DestNotIn) > 0 {
		if e.Destination == "" {
			return false
		}
		if matchesAnyDestination(e.Destination, cm.DestNotIn) {
			return false
		}
	}

	return true
}

// matchesAnyDestination checks if destination matches any rule destination (supporting host suffixes, IPs, CIDRs).
func matchesAnyDestination(dest string, allowed []string) bool {
	cleanDest := strings.ToLower(strings.TrimSpace(dest))
	// Strip port if present
	host, _, err := net.SplitHostPort(cleanDest)
	if err == nil {
		cleanDest = host
	}

	for _, item := range allowed {
		cleanItem := strings.ToLower(strings.TrimSpace(item))
		if cleanDest == cleanItem {
			return true
		}
		// Host suffix matching (e.g. allowed "github.com" matches "api.github.com")
		if strings.HasSuffix(cleanDest, "."+cleanItem) {
			return true
		}
		// CIDR matching
		if _, ipNet, err := net.ParseCIDR(cleanItem); err == nil {
			if ip := net.ParseIP(cleanDest); ip != nil && ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// MatchesStep returns true if any matcher in the step matches the event.
func (cs *CompiledStep) Matches(e *Event) bool {
	for i := range cs.Matchers {
		if cs.Matchers[i].Matches(e) {
			return true
		}
	}
	return false
}

// ParseRule parses a single Quarry YAML rule.
func ParseRule(data []byte) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("failed to unmarshal quarry rule YAML: %w", err)
	}
	return &r, nil
}

// ParseRules parses one or multiple Quarry YAML rules from bytes (supports multi-document YAML).
func ParseRules(data []byte) ([]*Rule, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var rules []*Rule

	for {
		var r Rule
		err := decoder.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode quarry rule: %w", err)
		}
		if r.Name != "" {
			rules = append(rules, &r)
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no valid quarry rules found in payload")
	}
	return rules, nil
}

// LoadRuleFromFile reads and parses a Quarry rule from a file.
func LoadRuleFromFile(filePath string) (*Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file %s: %w", filePath, err)
	}
	return ParseRule(data)
}

// LoadRulesFromDir recursively discovers and loads all .yaml/.yml rule files from a directory.
func LoadRulesFromDir(dirPath string) ([]*Rule, error) {
	var rules []*Rule
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			parsed, err := ParseRulesFromFile(path)
			if err == nil && len(parsed) > 0 {
				rules = append(rules, parsed...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory %s: %w", dirPath, err)
	}
	return rules, nil
}

// ParseRulesFromFile loads one or more rules from a single file.
func ParseRulesFromFile(filePath string) ([]*Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseRules(data)
}
