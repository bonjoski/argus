package heuristics

import (
	"time"

	"bonjoski/argus/internal/conflation"
	"bonjoski/argus/internal/model"
)

// PenaltyRule defines the contract for an individual threat penalty detector.
type PenaltyRule interface {
	ID() string
	Name() string
	Points() int
	Description() string
	Evaluate(prov *model.PackageProvenance) (triggered bool, metadata map[string]any)
}

// OffsetRule defines the contract for an individual reputational credit detector.
type OffsetRule interface {
	ID() string
	Name() string
	Credits() int
	Description() string
	Evaluate(prov *model.PackageProvenance) (triggered bool, metadata map[string]any)
}

// --- Threat Penalties Implementation ---

// FreshReleaseRule (HR-01): Package released <= 7 days ago.
type FreshReleaseRule struct{}

func (r FreshReleaseRule) ID() string   { return "HR-01" }
func (r FreshReleaseRule) Name() string { return "Fresh Release" }
func (r FreshReleaseRule) Points() int  { return 35 }
func (r FreshReleaseRule) Description() string {
	return "Package first published within the last 7 days (peak hallucination/squat window)"
}
func (r FreshReleaseRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.FirstReleaseDate.IsZero() {
		return false, nil
	}
	days := int(time.Since(prov.FirstReleaseDate).Hours() / 24)
	if days <= 7 {
		return true, map[string]any{"age_days": days}
	}
	return false, nil
}

// InfantPackageRule (HR-02): Package released 8 - 30 days ago.
type InfantPackageRule struct{}

func (r InfantPackageRule) ID() string   { return "HR-02" }
func (r InfantPackageRule) Name() string { return "Infant Package" }
func (r InfantPackageRule) Points() int  { return 20 }
func (r InfantPackageRule) Description() string {
	return "Package first published 8 to 30 days ago (elevated unverified code risk)"
}
func (r InfantPackageRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.FirstReleaseDate.IsZero() {
		return false, nil
	}
	days := int(time.Since(prov.FirstReleaseDate).Hours() / 24)
	if days > 7 && days <= 30 {
		return true, map[string]any{"age_days": days}
	}
	return false, nil
}

// SingleVersionTrapRule (HR-03): Package has exactly 1 release lifetime.
type SingleVersionTrapRule struct{}

func (r SingleVersionTrapRule) ID() string   { return "HR-03" }
func (r SingleVersionTrapRule) Name() string { return "Single Version Trap" }
func (r SingleVersionTrapRule) Points() int  { return 15 }
func (r SingleVersionTrapRule) Description() string {
	return "Package has only a single release across its lifetime (common for placeholder/squat droppers)"
}
func (r SingleVersionTrapRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.TotalReleases == 1 {
		return true, map[string]any{"total_releases": 1}
	}
	return false, nil
}

// NegligibleAdoptionRule (HR-04): Low downloads, sdist-only, or missing checksum.
type NegligibleAdoptionRule struct{}

func (r NegligibleAdoptionRule) ID() string   { return "HR-04" }
func (r NegligibleAdoptionRule) Name() string { return "Negligible Adoption" }
func (r NegligibleAdoptionRule) Points() int  { return 15 }
func (r NegligibleAdoptionRule) Description() string {
	return "Lacks community adoption, verified downloads, or binary distribution wheels"
}
func (r NegligibleAdoptionRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	switch prov.Ecosystem {
	case model.EcosystemNPM, model.EcosystemCargo:
		if prov.WeeklyDownloads < 100 {
			return true, map[string]any{"weekly_downloads": prov.WeeklyDownloads}
		}
	case model.EcosystemPyPI:
		// PyPI signals: lack of pre-built wheels and low total releases
		if !prov.HasBinaryWheels && prov.TotalReleases <= 2 {
			return true, map[string]any{"has_wheels": false, "total_releases": prov.TotalReleases}
		}
	case model.EcosystemGo:
		if !prov.InGoChecksumDB {
			return true, map[string]any{"in_go_checksum_db": false}
		}
	}
	return false, nil
}

// DetachedVCSRule (HR-05A): No repository declared or returns 404.
type DetachedVCSRule struct{}

func (r DetachedVCSRule) ID() string   { return "HR-05A" }
func (r DetachedVCSRule) Name() string { return "Detached VCS Repo" }
func (r DetachedVCSRule) Points() int  { return 20 }
func (r DetachedVCSRule) Description() string {
	return "No upstream source repository declared, or declared repository returned HTTP 404"
}
func (r DetachedVCSRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.VCSStatus == model.VCSStatusNone || prov.VCSStatus == model.VCSStatusMissing {
		return true, map[string]any{"vcs_status": string(prov.VCSStatus)}
	}
	return false, nil
}

// SpoofedVCSRule (HR-05B): Repository exists, but reciprocal manifest names a different package.
type SpoofedVCSRule struct{}

func (r SpoofedVCSRule) ID() string   { return "HR-05B" }
func (r SpoofedVCSRule) Name() string { return "Spoofed VCS Impersonation" }
func (r SpoofedVCSRule) Points() int  { return 35 }
func (r SpoofedVCSRule) Description() string {
	return "Package points to an existing repository, but reciprocal manifest verification proved it does not belong to this package"
}
func (r SpoofedVCSRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.VCSStatus == model.VCSStatusMismatch {
		return true, map[string]any{
			"vcs_status":      string(prov.VCSStatus),
			"repo_manifest":   prov.RepositoryManifestName,
			"package_claimed": prov.Name,
		}
	}
	return false, nil
}

// LexicalConflationRule (HR-06): Blends high-reputation ecosystem tokens or typosquats a popular package.
type LexicalConflationRule struct {
	conflationEngine *conflation.Engine
}

func NewLexicalConflationRule(e *conflation.Engine) LexicalConflationRule {
	if e == nil {
		e = conflation.DefaultEngine()
	}
	return LexicalConflationRule{conflationEngine: e}
}

func (r LexicalConflationRule) ID() string   { return "HR-06" }
func (r LexicalConflationRule) Name() string { return "Lexical Conflation" }
func (r LexicalConflationRule) Points() int  { return 25 }
func (r LexicalConflationRule) Description() string {
	return "Package blends high-reputation ecosystem tokens or typosquats a popular package"
}
func (r LexicalConflationRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	engine := r.conflationEngine
	if engine == nil {
		engine = conflation.DefaultEngine()
	}
	res := engine.Evaluate(prov.Name, prov.Ecosystem)
	if res.IsConflated {
		return true, map[string]any{
			"target":    res.TargetPkg,
			"typosquat": res.IsTyposquat,
			"reason":    res.Reason,
		}
	}
	return false, nil
}

// AuthorEphemeralityRule (HR-07): Author account age < 30 days.
type AuthorEphemeralityRule struct{}

func (r AuthorEphemeralityRule) ID() string   { return "HR-07" }
func (r AuthorEphemeralityRule) Name() string { return "Author Ephemerality" }
func (r AuthorEphemeralityRule) Points() int  { return 15 }
func (r AuthorEphemeralityRule) Description() string {
	return "Maintainer account created recently (<30 days) with no prior track record"
}
func (r AuthorEphemeralityRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.AuthorCreatedAt != nil {
		days := int(time.Since(*prov.AuthorCreatedAt).Hours() / 24)
		if days < 30 && prov.AuthorTotalPackages <= 1 {
			return true, map[string]any{"author_age_days": days, "total_packages": prov.AuthorTotalPackages}
		}
	}
	return false, nil
}

// SuddenSleeperRule (HR-08): Created > 30 days ago with 0 updates, suddenly updated <= 14 days ago.
type SuddenSleeperRule struct{}

func (r SuddenSleeperRule) ID() string   { return "HR-08" }
func (r SuddenSleeperRule) Name() string { return "Sudden Sleeper Activation" }
func (r SuddenSleeperRule) Points() int  { return 25 }
func (r SuddenSleeperRule) Description() string {
	return "Package lay dormant for >30 days with no releases, but suddenly published a new version within the last 14 days"
}
func (r SuddenSleeperRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.FirstReleaseDate.IsZero() || prov.LatestReleaseDate.IsZero() {
		return false, nil
	}
	totalAgeDays := int(time.Since(prov.FirstReleaseDate).Hours() / 24)
	recentDays := int(time.Since(prov.LatestReleaseDate).Hours() / 24)

	if totalAgeDays > 30 && recentDays <= 14 && prov.TotalReleases <= 2 && prov.WeeklyDownloads < 50 {
		return true, map[string]any{
			"total_age_days": totalAgeDays,
			"recent_days":    recentDays,
			"total_releases": prov.TotalReleases,
		}
	}
	return false, nil
}

// InstallLifecycleHooksRule (HR-09): npm package contains install hooks.
type InstallLifecycleHooksRule struct{}

func (r InstallLifecycleHooksRule) ID() string   { return "HR-09" }
func (r InstallLifecycleHooksRule) Name() string { return "Install Lifecycle Hooks" }
func (r InstallLifecycleHooksRule) Points() int  { return 15 }
func (r InstallLifecycleHooksRule) Description() string {
	return "Package declares preinstall, install, or postinstall lifecycle scripts"
}
func (r InstallLifecycleHooksRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.HasInstallScripts {
		return true, map[string]any{"has_install_scripts": true}
	}
	return false, nil
}

// SuspiciousASTPayloadRule (HR-10): Pre-flight static inspector found dangerous AST patterns.
type SuspiciousASTPayloadRule struct{}

func (r SuspiciousASTPayloadRule) ID() string   { return "HR-10" }
func (r SuspiciousASTPayloadRule) Name() string { return "Suspicious Static AST In Payload" }
func (r SuspiciousASTPayloadRule) Points() int  { return 35 }
func (r SuspiciousASTPayloadRule) Description() string {
	return "Static pre-flight inspection detected suspicious process execution, obfuscated eval, or network exfiltration patterns"
}
func (r SuspiciousASTPayloadRule) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.HasSuspiciousAST || len(prov.SuspiciousFindings) > 0 {
		return true, map[string]any{
			"findings": prov.SuspiciousFindings,
			"count":    len(prov.SuspiciousFindings),
		}
	}
	return false, nil
}

// --- Reputational Mitigating Offsets Implementation ---

// CryptographicAttestationOffset (MO-01): Sigstore, GitHub OIDC, or PEP 740 attestation.
type CryptographicAttestationOffset struct{}

func (o CryptographicAttestationOffset) ID() string   { return "MO-01" }
func (o CryptographicAttestationOffset) Name() string { return "Cryptographic Attestation" }
func (o CryptographicAttestationOffset) Credits() int { return 40 }
func (o CryptographicAttestationOffset) Description() string {
	return "Artifact cryptographically signed with Sigstore, GitHub Actions OIDC, or PEP 740"
}
func (o CryptographicAttestationOffset) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.HasSigstoreProvenance || prov.HasPEP740Attestation {
		return true, map[string]any{
			"sigstore": prov.HasSigstoreProvenance,
			"pep740":   prov.HasPEP740Attestation,
		}
	}
	return false, nil
}

// EstablishedAuthorOffset (MO-02): Author has >1 year history and >=3 packages.
type EstablishedAuthorOffset struct{}

func (o EstablishedAuthorOffset) ID() string   { return "MO-02" }
func (o EstablishedAuthorOffset) Name() string { return "Established Author Anchor" }
func (o EstablishedAuthorOffset) Credits() int { return 30 }
func (o EstablishedAuthorOffset) Description() string {
	return "Maintainer has an established profile (>1 year) with 3 or more published packages"
}
func (o EstablishedAuthorOffset) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.AuthorCreatedAt != nil {
		days := int(time.Since(*prov.AuthorCreatedAt).Hours() / 24)
		if days >= 365 && prov.AuthorTotalPackages >= 3 {
			return true, map[string]any{
				"author_age_days": days,
				"total_packages":  prov.AuthorTotalPackages,
			}
		}
	}
	return false, nil
}

// ReciprocalVCSMatchOffset (MO-03): Two-way verified VCS repo > 6 months old.
type ReciprocalVCSMatchOffset struct{}

func (o ReciprocalVCSMatchOffset) ID() string   { return "MO-03" }
func (o ReciprocalVCSMatchOffset) Name() string { return "Reciprocal VCS Match" }
func (o ReciprocalVCSMatchOffset) Credits() int { return 25 }
func (o ReciprocalVCSMatchOffset) Description() string {
	return "Upstream VCS repository manifest verified with matching package name and established commit history"
}
func (o ReciprocalVCSMatchOffset) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if prov.VCSStatus == model.VCSStatusVerified && prov.RepositoryAgeMonths >= 6 {
		return true, map[string]any{
			"repo_age_months": prov.RepositoryAgeMonths,
			"manifest_name":   prov.RepositoryManifestName,
		}
	}
	return false, nil
}

// ApprovedNamespaceOffset (MO-04): Standard plugin naming convention or approved namespace.
type ApprovedNamespaceOffset struct{}

func (o ApprovedNamespaceOffset) ID() string   { return "MO-04" }
func (o ApprovedNamespaceOffset) Name() string { return "Approved Ecosystem Namespace" }
func (o ApprovedNamespaceOffset) Credits() int { return 20 }
func (o ApprovedNamespaceOffset) Description() string {
	return "Standard plugin naming convention (pytest-*, eslint-plugin-*, mkdocs-*, django-*, cargo-*) or approved scope"
}
func (o ApprovedNamespaceOffset) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if conflation.IsApprovedNamespace(prov.Name, prov.Ecosystem) {
		return true, map[string]any{
			"ecosystem": string(prov.Ecosystem),
			"package":   prov.Name,
		}
	}
	return false, nil
}

// CleanProvenanceOffset (MO-05): Clean packaging profile with no install scripts and binary distributions.
type CleanProvenanceOffset struct{}

func (o CleanProvenanceOffset) ID() string   { return "MO-05" }
func (o CleanProvenanceOffset) Name() string { return "Clean Provenance Profile" }
func (o CleanProvenanceOffset) Credits() int { return 10 }
func (o CleanProvenanceOffset) Description() string {
	return "Package conforms to modern packaging standards (no lifecycle scripts, verified distribution artifact)"
}
func (o CleanProvenanceOffset) Evaluate(prov *model.PackageProvenance) (bool, map[string]any) {
	if !prov.HasInstallScripts && (prov.HasBinaryWheels || prov.InGoChecksumDB || (prov.Ecosystem == model.EcosystemCargo && prov.IntegrityHash != "") || (prov.Ecosystem == model.EcosystemNPM && prov.IntegrityHash != "")) {
		if prov.TotalReleases > 1 || (!prov.FirstReleaseDate.IsZero() && time.Since(prov.FirstReleaseDate).Hours() > 24*7) {
			return true, map[string]any{"clean_profile": true}
		}
	}
	return false, nil
}
