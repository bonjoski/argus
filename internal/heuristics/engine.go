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
		SecurityTombstoneRule{},
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

func isVetoRule(ruleID string) bool {
	switch ruleID {
	case "HR-05B", "HR-06", "HR-10", "HR-11":
		return true
	default:
		return false
	}
}

// Evaluate applies all penalties and offsets, returning a complete RiskReport.
func (e *Engine) Evaluate(prov *model.PackageProvenance) *model.RiskReport {
	var penaltyFindings []model.HeuristicFinding
	totalPenalties := 0
	vetoPenalties := 0
	hygienePenalties := 0
	hasVeto := false

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
			if isVetoRule(rule.ID()) {
				vetoPenalties += rule.Points()
				hasVeto = true
			} else {
				hygienePenalties += rule.Points()
			}
		}
	}

	var offsetFindings []model.MitigatingOffsetFinding
	totalOffsets := 0

	for _, offset := range e.offsets {
		var triggered bool
		var meta map[string]any
		if !prov.IsSecurityTombstone && prov.ResolvedVersion != "0.0.1-security" {
			triggered, meta = offset.Evaluate(prov)
		}
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

	// Reputational offsets can only mitigate hygiene penalties (HR-01, HR-02, HR-03, HR-04, etc.).
	// Identity impersonation and malice findings (HR-05B, HR-06, HR-10, HR-11) cannot be washed out by offsets.
	effectiveOffsets := totalOffsets
	if effectiveOffsets > hygienePenalties {
		effectiveOffsets = hygienePenalties
	}

	rawScore := vetoPenalties + (hygienePenalties - effectiveOffsets)
	if prov.IsSecurityTombstone || prov.ResolvedVersion == "0.0.1-security" {
		rawScore = 100
	}

	clampedScore := rawScore
	if clampedScore < 0 {
		clampedScore = 0
	} else if clampedScore > 100 {
		clampedScore = 100
	}

	riskLevel := model.ComputeRiskLevel(clampedScore)
	verdict := model.VerdictAllow
	blocked := false
	safe := true
	action := "allow"

	if clampedScore >= 80 || riskLevel == model.RiskLevelCritical || (hasVeto && clampedScore >= 50) || prov.IsSecurityTombstone {
		verdict = model.VerdictBlock
		blocked = true
		safe = false
		action = "block"
	} else if riskLevel == model.RiskLevelHigh || riskLevel == model.RiskLevelMedium || hasVeto {
		verdict = model.VerdictWarn
		blocked = false
		safe = false
		action = "warn"
	}

	return &model.RiskReport{
		Package:         prov.Name,
		Ecosystem:       prov.Ecosystem,
		ResolvedVersion: prov.ResolvedVersion,
		IntegrityHash:   prov.IntegrityHash,
		TotalScore:      clampedScore,
		TotalPenalties:  totalPenalties,
		TotalOffsets:    totalOffsets,
		RiskLevel:       riskLevel,
		Verdict:         verdict,
		Blocked:         blocked,
		Safe:            safe,
		Action:          action,
		Penalties:       penaltyFindings,
		Offsets:         offsetFindings,
		Provenance:      *prov,
		EvaluationTime:  time.Now(),
	}
}
