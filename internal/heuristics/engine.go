package heuristics

import (
	"time"

	"bonjoski/argus/internal/model"
)

// Evaluator evaluates package provenance against penalties and mitigating offsets.
type Evaluator interface {
	Evaluate(prov *model.PackageProvenance) *model.RiskReport
}

// Engine implements Evaluator, holding extensible lists of PenaltyRule and OffsetRule.
type Engine struct {
	penalties []PenaltyRule
	offsets   []OffsetRule
}

// NewEngine creates an Engine with specific penalties and offsets (Dependency Inversion).
func NewEngine(penalties []PenaltyRule, offsets []OffsetRule) *Engine {
	return &Engine{
		penalties: penalties,
		offsets:   offsets,
	}
}

// DefaultEngine initializes the standard production-hardened scoring rules.
func DefaultEngine() *Engine {
	penalties := []PenaltyRule{
		FreshReleaseRule{},
		InfantPackageRule{},
		SingleVersionTrapRule{},
		NegligibleAdoptionRule{},
		DetachedVCSRule{},
		SpoofedVCSRule{},
		NewLexicalConflationRule(nil),
		AuthorEphemeralityRule{},
		SuddenSleeperRule{},
		InstallLifecycleHooksRule{},
		SuspiciousASTPayloadRule{},
	}

	offsets := []OffsetRule{
		CryptographicAttestationOffset{},
		EstablishedAuthorOffset{},
		ReciprocalVCSMatchOffset{},
		ApprovedNamespaceOffset{},
		CleanProvenanceOffset{},
	}

	return NewEngine(penalties, offsets)
}

// Evaluate applies all penalties and offsets, returning a complete RiskReport.
func (e *Engine) Evaluate(prov *model.PackageProvenance) *model.RiskReport {
	var penaltyFindings []model.HeuristicFinding
	totalPenalties := 0

	for _, rule := range e.penalties {
		triggered, meta := rule.Evaluate(prov)
		finding := model.HeuristicFinding{
			RuleID:      rule.ID(),
			Name:        rule.Name(),
			Points:      rule.Points(),
			Description: rule.Description(),
			Triggered:   triggered,
			Metadata:    meta,
		}
		penaltyFindings = append(penaltyFindings, finding)
		if triggered {
			totalPenalties += rule.Points()
		}
	}

	var offsetFindings []model.MitigatingOffsetFinding
	totalOffsets := 0

	for _, offset := range e.offsets {
		triggered, meta := offset.Evaluate(prov)
		finding := model.MitigatingOffsetFinding{
			OffsetID:    offset.ID(),
			Name:        offset.Name(),
			Credits:     offset.Credits(),
			Description: offset.Description(),
			Triggered:   triggered,
			Metadata:    meta,
		}
		offsetFindings = append(offsetFindings, finding)
		if triggered {
			totalOffsets += offset.Credits()
		}
	}

	rawScore := totalPenalties - totalOffsets
	clampedScore := rawScore
	if clampedScore < 0 {
		clampedScore = 0
	} else if clampedScore > 100 {
		clampedScore = 100
	}

	return &model.RiskReport{
		Package:         prov.Name,
		Ecosystem:       prov.Ecosystem,
		ResolvedVersion: prov.ResolvedVersion,
		IntegrityHash:   prov.IntegrityHash,
		TotalScore:      clampedScore,
		TotalPenalties:  totalPenalties,
		TotalOffsets:    totalOffsets,
		RiskLevel:       model.ComputeRiskLevel(clampedScore),
		Penalties:       penaltyFindings,
		Offsets:         offsetFindings,
		Provenance:      *prov,
		EvaluationTime:  time.Now(),
	}
}
