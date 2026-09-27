package output

import (
	"encoding/json"
	"fmt"
	"io"

	"bonjoski/argus/internal/model"
)

// SARIFReporter outputs results conforming to OASIS SARIF v2.1.0.
type SARIFReporter struct {
	Version string
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifToolComponent `json:"tool"`
	Results []sarifResult      `json:"results"`
}

type sarifToolComponent struct {
	Driver sarifToolDriver `json:"driver"`
}

type sarifToolDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMultiformatString `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig        `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMultiformatString struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string                 `json:"ruleId"`
	Level     string                 `json:"level"` // error, warning, note
	Message   sarifMultiformatString `json:"message"`
	Locations []sarifLocation        `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// Render writes a SARIF v2.1.0 document for the given RiskReport.
func (r SARIFReporter) Render(w io.Writer, report *model.RiskReport) error {
	version := r.Version
	if version == "" {
		version = "1.0.0"
	}

	run := sarifRun{
		Tool: sarifToolComponent{
			Driver: sarifToolDriver{
				Name:           "Argus",
				Version:        version,
				InformationURI: "https://github.com/bonjoski/argus",
				Rules:          make([]sarifRule, 0),
			},
		},
		Results: make([]sarifResult, 0),
	}

	ruleMap := make(map[string]bool)

	for _, p := range report.Penalties {
		level := "note"
		if p.Points >= 30 {
			level = "error"
		} else if p.Points >= 20 {
			level = "warning"
		}

		if !ruleMap[p.RuleID] {
			ruleMap[p.RuleID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               p.RuleID,
				Name:             p.Name,
				ShortDescription: sarifMultiformatString{Text: p.Description},
				DefaultConfig:    sarifRuleConfig{Level: level},
			})
		}

		if p.Triggered {
			targetURI := fmt.Sprintf("%s:%s@%s", report.Ecosystem, report.Package, report.ResolvedVersion)
			resultMsg := fmt.Sprintf("[%s] %s (+%d pts): %s", p.RuleID, p.Name, p.Points, p.Description)

			run.Results = append(run.Results, sarifResult{
				RuleID:  p.RuleID,
				Level:   level,
				Message: sarifMultiformatString{Text: resultMsg},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{
								URI: targetURI,
							},
						},
					},
				},
			})
		}
	}

	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
