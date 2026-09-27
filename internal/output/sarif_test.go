package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestSARIFReporter_Render(t *testing.T) {
	report := &model.RiskReport{
		Package:         "express-auth-helpers",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "1.0.0",
		TotalScore:      75,
		RiskLevel:       model.RiskLevelHigh,
		Penalties: []model.HeuristicFinding{
			{
				RuleID:      "HR-01",
				Name:        "Fresh Release",
				Points:      35,
				Description: "Published <= 7 days ago",
				Triggered:   true,
			},
			{
				RuleID:      "HR-06",
				Name:        "Lexical Conflation",
				Points:      25,
				Description: "Conflates popular primitives",
				Triggered:   true,
			},
			{
				RuleID:      "HR-09",
				Name:        "Install Hooks",
				Points:      15,
				Description: "Contains lifecycle hooks",
				Triggered:   false,
			},
		},
	}

	reporter := SARIFReporter{Version: "1.0.0"}
	var buf bytes.Buffer
	if err := reporter.Render(&buf, report); err != nil {
		t.Fatalf("unexpected error rendering SARIF: %v", err)
	}

	var parsed sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
	}

	run := parsed.Runs[0]
	if run.Tool.Driver.Name != "Argus" {
		t.Errorf("expected driver name Argus, got %s", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Errorf("expected 2 triggered results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("expected HR-01 (35 pts) level to be error, got %s", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("expected HR-06 (25 pts) level to be warning, got %s", run.Results[1].Level)
	}
}
