package cli

import (
	"reflect"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestResolveToolAndTargets(t *testing.T) {
	tests := []struct {
		args        []string
		wantTool    string
		wantEco     model.Ecosystem
		wantTargets []string
	}{
		{
			args:        []string{"npm", "express", "lodash@^4.17.21"},
			wantTool:    "npm",
			wantEco:     model.EcosystemNPM,
			wantTargets: []string{"express", "lodash@^4.17.21"},
		},
		{
			args:        []string{"pip", "requests==2.31.0"},
			wantTool:    "pip",
			wantEco:     model.EcosystemPyPI,
			wantTargets: []string{"requests==2.31.0"},
		},
		{
			args:        []string{"cargo", "serde", "tokio"},
			wantTool:    "cargo",
			wantEco:     model.EcosystemCargo,
			wantTargets: []string{"serde", "tokio"},
		},
		{
			args:        []string{"go", "github.com/gin-gonic/gin"},
			wantTool:    "go",
			wantEco:     model.EcosystemGo,
			wantTargets: []string{"github.com/gin-gonic/gin"},
		},
		{
			args:        []string{"gem", "rails"},
			wantTool:    "gem",
			wantEco:     model.EcosystemRubyGems,
			wantTargets: []string{"rails"},
		},
		{
			args:        []string{"composer", "monolog/monolog"},
			wantTool:    "composer",
			wantEco:     model.EcosystemPackagist,
			wantTargets: []string{"monolog/monolog"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantTool, func(t *testing.T) {
			gotTool, gotEco, gotTargets := resolveToolAndTargets(tt.args)
			if gotTool != tt.wantTool {
				t.Errorf("got tool %q, want %q", gotTool, tt.wantTool)
			}
			if gotEco != tt.wantEco {
				t.Errorf("got eco %q, want %q", gotEco, tt.wantEco)
			}
			if !reflect.DeepEqual(gotTargets, tt.wantTargets) {
				t.Errorf("got targets %v, want %v", gotTargets, tt.wantTargets)
			}
		})
	}
}

func TestBuildSubcommandArgs(t *testing.T) {
	targets := []string{"pkgA", "pkgB"}
	tests := []struct {
		tool     string
		expected []string
	}{
		{"npm", []string{"install", "pkgA", "pkgB"}},
		{"pnpm", []string{"add", "pkgA", "pkgB"}},
		{"pip", []string{"install", "pkgA", "pkgB"}},
		{"cargo", []string{"add", "pkgA", "pkgB"}},
		{"go", []string{"get", "pkgA", "pkgB"}},
		{"composer", []string{"require", "pkgA", "pkgB"}},
	}

	for _, tt := range tests {
		got := buildSubcommandArgs(tt.tool, targets)
		if !reflect.DeepEqual(got, tt.expected) {
			t.Errorf("[%s] buildSubcommandArgs = %v, want %v", tt.tool, got, tt.expected)
		}
	}
}
