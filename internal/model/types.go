package model

import "time"

// Ecosystem represents a supported package ecosystem.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "pypi"
	EcosystemCargo     Ecosystem = "cargo"
	EcosystemGo        Ecosystem = "go"
	EcosystemRubyGems  Ecosystem = "rubygems"
	EcosystemMaven     Ecosystem = "maven"
	EcosystemPackagist Ecosystem = "packagist"
	EcosystemNuGet     Ecosystem = "nuget"
	EcosystemPub       Ecosystem = "pub"
	EcosystemHex       Ecosystem = "hex"
	EcosystemSwift     Ecosystem = "swift"
)

// RiskLevel defines the categorized severity of a risk score.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "LOW"      // 0 - 29: Allow
	RiskLevelMedium   RiskLevel = "MEDIUM"   // 30 - 59: Caution / Warn
	RiskLevelHigh     RiskLevel = "HIGH"     // 60 - 79: Warning / Prompt
	RiskLevelCritical RiskLevel = "CRITICAL" // 80 - 100: Hard Block
)

// VCSStatus represents the verified state of a declared repository.
type VCSStatus string

const (
	VCSStatusNone         VCSStatus = "NONE"         // No VCS declared in metadata
	VCSStatusVerified     VCSStatus = "VERIFIED"     // Manifest inside repo matches package name
	VCSStatusMismatch     VCSStatus = "MISMATCH"     // Repo exists but package manifest does not match (Spoofed)
	VCSStatusMissing      VCSStatus = "MISSING"      // Repo returns 404
	VCSStatusInconclusive VCSStatus = "INCONCLUSIVE" // Unauthenticated rate limit (403/429) or network timeout
)

// PackageProvenance represents the unified metadata extracted from upstream registries & VCS.
type PackageProvenance struct {
	Name            string    `json:"name"`
	Ecosystem       Ecosystem `json:"ecosystem"`
	ResolvedVersion string    `json:"resolved_version"`
	IntegrityHash   string    `json:"integrity_hash"`
	TarballURL      string    `json:"tarball_url"`

	// Release Lifecycle
	FirstReleaseDate  time.Time `json:"first_release_date"`
	LatestReleaseDate time.Time `json:"latest_release_date"`
	TotalReleases     int       `json:"total_releases"`

	// Ecosystem Specific Telemetry
	WeeklyDownloads       int64    `json:"weekly_downloads"`        // npm, crates.io
	HasInstallScripts     bool     `json:"has_install_scripts"`     // npm pre/postinstall
	HasSigstoreProvenance bool     `json:"has_sigstore_provenance"` // npm --provenance / Sigstore OIDC
	HasBinaryWheels       bool     `json:"has_binary_wheels"`       // PyPI wheel distributions
	HasPEP740Attestation  bool     `json:"has_pep740_attestation"`  // PyPI digital attestation
	InGoChecksumDB        bool     `json:"in_go_checksum_db"`       // Go sum.golang.org presence
	HasSuspiciousAST      bool     `json:"has_suspicious_ast"`      // Pre-flight static script inspector
	SuspiciousFindings    []string `json:"suspicious_findings,omitempty"`

	// VCS Provenance
	RepositoryURL          string    `json:"repository_url"`
	VCSStatus              VCSStatus `json:"vcs_status"`
	RepositoryManifestName string    `json:"repository_manifest_name"`
	RepositoryAgeMonths    int       `json:"repository_age_months"`
	RepositoryCommitsCount int       `json:"repository_commits_count"`

	// Author Provenance
	AuthorName          string     `json:"author_name"`
	AuthorCreatedAt     *time.Time `json:"author_created_at,omitempty"`
	AuthorTotalPackages int        `json:"author_total_packages"`

	// Scope & Isolation
	IsScoped       bool `json:"is_scoped"`
	IsPrivateScope bool `json:"is_private_scope"`
}

// HeuristicFinding represents an evaluated threat penalty.
type HeuristicFinding struct {
	RuleID      string         `json:"rule_id"`
	Name        string         `json:"name"`
	Points      int            `json:"points"`
	Description string         `json:"description"`
	Triggered   bool           `json:"triggered"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// MitigatingOffsetFinding represents an evaluated reputational offset.
type MitigatingOffsetFinding struct {
	OffsetID    string         `json:"offset_id"`
	Name        string         `json:"name"`
	Credits     int            `json:"credits"`
	Description string         `json:"description"`
	Triggered   bool           `json:"triggered"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// RiskReport is the canonical evaluation summary produced by Argus.
type RiskReport struct {
	Package         string                    `json:"package"`
	Ecosystem       Ecosystem                 `json:"ecosystem"`
	ResolvedVersion string                    `json:"resolved_version"`
	IntegrityHash   string                    `json:"integrity_hash"`
	TotalScore      int                       `json:"total_score"`     // Clamped net score [0, 100]
	TotalPenalties  int                       `json:"total_penalties"` // Raw sum of penalty points
	TotalOffsets    int                       `json:"total_offsets"`   // Raw sum of offset credits
	RiskLevel       RiskLevel                 `json:"risk_level"`
	LatencyMs       int64                     `json:"latency_ms"`
	Cached          bool                      `json:"cached"`
	Penalties       []HeuristicFinding        `json:"penalties"`
	Offsets         []MitigatingOffsetFinding `json:"offsets"`
	Provenance      PackageProvenance         `json:"provenance"`
	EvaluationTime  time.Time                 `json:"evaluation_time"`
}

// ComputeRiskLevel maps a net score to its RiskLevel category.
func ComputeRiskLevel(score int) RiskLevel {
	switch {
	case score < 30:
		return RiskLevelLow
	case score < 60:
		return RiskLevelMedium
	case score < 80:
		return RiskLevelHigh
	default:
		return RiskLevelCritical
	}
}
