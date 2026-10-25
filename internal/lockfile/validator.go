package lockfile

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"bonjoski/argus/internal/model"
)

// LockfileType identifies the lockfile ecosystem.
type LockfileType string

const (
	LockfileTypeNpm   LockfileType = "npm"
	LockfileTypeCargo LockfileType = "cargo"
	LockfileTypeGoSum LockfileType = "golang"
)

// PackageRef represents a package reference within a lockfile or manifest.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"` // e.g. "pypi", "npm", "cargo", "golang"
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// PinnedDependency represents an extracted dependency entry from a lockfile.
type PinnedDependency struct {
	Ref       PackageRef `json:"ref"`
	Integrity string     `json:"integrity"`
	Resolved  string     `json:"resolved,omitempty"`
}

// TamperedDep records an anomaly or integrity discrepancy for a dependency.
type TamperedDep struct {
	Dependency PinnedDependency `json:"dependency"`
	Expected   string           `json:"expected"`
	Actual     string           `json:"actual"`
	Reason     string           `json:"reason"`
}

// SBOMEnrichmentMeta holds CycloneDX supply-chain enrichment audit details.
type SBOMEnrichmentMeta struct {
	EnrichedWithCycloneDX bool     `json:"enriched_with_cyclonedx"`
	UnlicensedPackages    []string `json:"unlicensed_packages,omitempty"`
	AuditedLicenses       []string `json:"audited_licenses,omitempty"`
	NonCompliantLicenses  []string `json:"non_compliant_licenses,omitempty"`
}

// LockfileAuditReport contains the aggregated verification results.
type LockfileAuditReport struct {
	Allowed        bool                `json:"allowed"`
	TotalPackages  int                 `json:"total_packages"`
	TamperedCount  int                 `json:"tampered_count"`
	MissingHashes  int                 `json:"missing_hashes"`
	TamperedDeps   []TamperedDep       `json:"tampered_deps,omitempty"`
	EnrichmentData *SBOMEnrichmentMeta `json:"enrichment_data,omitempty"`
}

// LockfileValidator audits lockfiles for tampering, hash modifications, and license compliance.
type LockfileValidator struct {
	trustedHashes map[string]string // "ecosystem:name:version" -> integrity
}

// NewLockfileValidator initializes a validator with optional trusted baseline hashes.
func NewLockfileValidator(trustedHashes map[string]string) *LockfileValidator {
	if trustedHashes == nil {
		trustedHashes = make(map[string]string)
	}
	return &LockfileValidator{trustedHashes: trustedHashes}
}

// ParseNpmLock parses npm package-lock.json (supporting v1, v2, and v3 schemas).
func ParseNpmLock(content []byte) ([]PinnedDependency, error) {
	var root struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	var results []PinnedDependency

	// v2 / v3 packages map
	if len(root.Packages) > 0 {
		for pkgKey, pkg := range root.Packages {
			if pkgKey == "" {
				continue // Root package
			}
			name := strings.TrimPrefix(pkgKey, "node_modules/")
			if idx := strings.LastIndex(name, "node_modules/"); idx != -1 {
				name = name[idx+len("node_modules/"):]
			}
			results = append(results, PinnedDependency{
				Ref: PackageRef{
					Ecosystem: "npm",
					Name:      name,
					Version:   pkg.Version,
				},
				Integrity: pkg.Integrity,
				Resolved:  pkg.Resolved,
			})
		}
		return results, nil
	}

	// v1 dependencies fallback
	for name, dep := range root.Dependencies {
		results = append(results, PinnedDependency{
			Ref: PackageRef{
				Ecosystem: "npm",
				Name:      name,
				Version:   dep.Version,
			},
			Integrity: dep.Integrity,
		})
	}

	return results, nil
}

// ParseCargoLock parses a Cargo.lock TOML-like structure.
func ParseCargoLock(content []byte) ([]PinnedDependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var results []PinnedDependency

	var currentName, currentVersion, currentChecksum string
	inPackage := false

	flushPackage := func() {
		if currentName != "" && currentVersion != "" {
			results = append(results, PinnedDependency{
				Ref: PackageRef{
					Ecosystem: "cargo",
					Name:      currentName,
					Version:   currentVersion,
				},
				Integrity: currentChecksum,
			})
		}
		currentName, currentVersion, currentChecksum = "", "", ""
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage {
				flushPackage()
			}
			inPackage = true
			continue
		}

		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currentName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
			} else if strings.HasPrefix(line, "version = ") {
				currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
			} else if strings.HasPrefix(line, "checksum = ") {
				currentChecksum = strings.Trim(strings.TrimPrefix(line, "checksum = "), `"`)
			}
		}
	}

	if inPackage {
		flushPackage()
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning Cargo.lock: %w", err)
	}

	return results, nil
}

// ParseGoSum parses a go.sum file.
func ParseGoSum(content []byte) ([]PinnedDependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var results []PinnedDependency
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		mod := parts[0]
		ver := parts[1]
		hash := parts[2]

		verClean := strings.TrimSuffix(ver, "/go.mod")
		key := fmt.Sprintf("%s@%s", mod, verClean)
		if seen[key] {
			continue
		}
		seen[key] = true

		results = append(results, PinnedDependency{
			Ref: PackageRef{
				Ecosystem: "golang",
				Name:      mod,
				Version:   verClean,
			},
			Integrity: hash,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning go.sum: %w", err)
	}

	return results, nil
}

// AuditDependencies validates extracted dependencies against a trusted reference baseline.
func (v *LockfileValidator) AuditDependencies(deps []PinnedDependency) *LockfileAuditReport {
	report := &LockfileAuditReport{
		Allowed:       true,
		TotalPackages: len(deps),
		TamperedDeps:  make([]TamperedDep, 0),
	}

	for _, dep := range deps {
		if dep.Integrity == "" {
			report.MissingHashes++
			report.TamperedDeps = append(report.TamperedDeps, TamperedDep{
				Dependency: dep,
				Reason:     "Dependency lacks cryptographic checksum (unpinned)",
			})
			report.Allowed = false
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", dep.Ref.Ecosystem, dep.Ref.Name, dep.Ref.Version)
		if expected, ok := v.trustedHashes[key]; ok {
			if expected != dep.Integrity {
				report.TamperedCount++
				report.TamperedDeps = append(report.TamperedDeps, TamperedDep{
					Dependency: dep,
					Expected:   expected,
					Actual:     dep.Integrity,
					Reason:     "Integrity checksum mismatch against trusted baseline (possible supply-chain tampering)",
				})
				report.Allowed = false
			}
		}
	}

	return report
}

// AuditLockedDependencies validates LockedDependency items against the trusted reference baseline.
func (v *LockfileValidator) AuditLockedDependencies(deps []LockedDependency) *LockfileAuditReport {
	var pinned []PinnedDependency
	for _, dep := range deps {
		ecoStr := string(dep.Ecosystem)
		if dep.Ecosystem == model.EcosystemGo {
			ecoStr = "golang"
		}
		pinned = append(pinned, PinnedDependency{
			Ref: PackageRef{
				Ecosystem: ecoStr,
				Name:      dep.Name,
				Version:   dep.Version,
			},
			Integrity: dep.IntegrityHash,
		})
	}
	return v.AuditDependencies(pinned)
}

// EnrichWithCycloneDX audits packages for CycloneDX license compliance from sbom_enricher.
func (v *LockfileValidator) EnrichWithCycloneDX(report *LockfileAuditReport, licenses map[string]string, allowedLicenses []string) {
	meta := &SBOMEnrichmentMeta{
		EnrichedWithCycloneDX: true,
		AuditedLicenses:       make([]string, 0),
		UnlicensedPackages:    make([]string, 0),
		NonCompliantLicenses:  make([]string, 0),
	}

	allowedSet := make(map[string]bool)
	for _, lic := range allowedLicenses {
		allowedSet[strings.ToUpper(lic)] = true
	}

	for key, lic := range licenses {
		meta.AuditedLicenses = append(meta.AuditedLicenses, lic)
		if lic == "" || strings.EqualFold(lic, "UNKNOWN") {
			meta.UnlicensedPackages = append(meta.UnlicensedPackages, key)
			report.Allowed = false
		} else if len(allowedSet) > 0 && !allowedSet[strings.ToUpper(lic)] {
			meta.NonCompliantLicenses = append(meta.NonCompliantLicenses, fmt.Sprintf("%s (%s)", key, lic))
			report.Allowed = false
		}
	}

	report.EnrichmentData = meta
}

// VerifyFileDigest checks if data matches an expected integrity string (e.g. "sha512-...", "sha256-...", or hex).
func VerifyFileDigest(r io.Reader, expectedIntegrity string) (bool, error) {
	if expectedIntegrity == "" {
		return false, fmt.Errorf("empty expected integrity")
	}

	if strings.HasPrefix(expectedIntegrity, "sha512-") {
		h := sha512.New()
		if _, err := io.Copy(h, r); err != nil {
			return false, err
		}
		computed := "sha512-" + base64.StdEncoding.EncodeToString(h.Sum(nil))
		return computed == expectedIntegrity, nil
	}

	if strings.HasPrefix(expectedIntegrity, "sha256-") {
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return false, err
		}
		raw := expectedIntegrity[7:]
		if len(raw) == 64 {
			computedHex := hex.EncodeToString(h.Sum(nil))
			if strings.EqualFold(raw, computedHex) {
				return true, nil
			}
		}
		computed := "sha256-" + base64.StdEncoding.EncodeToString(h.Sum(nil))
		return computed == expectedIntegrity, nil
	}

	// Default hex sha256 (common in Cargo.lock)
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return false, err
	}
	computed := hex.EncodeToString(h.Sum(nil))
	return strings.EqualFold(computed, expectedIntegrity), nil
}

// DefaultLockfileNames defines the discovery sequence for automatic lockfile location.
var DefaultLockfileNames = []string{
	"package-lock.json",
	"Cargo.lock",
	"go.sum",
	"poetry.lock",
	"npm-shrinkwrap.json",
	"packages.lock.json",
	"pubspec.lock",
	"mix.lock",
	"Package.resolved",
	"package.resolved",
}

// FindLockfile searches dir for a known lockfile.
func FindLockfile(dir string) (string, error) {
	if dir == "" {
		dir = "."
	}
	for _, name := range DefaultLockfileNames {
		candidate := filepath.Join(dir, name)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no supported lockfile found in %s", dir)
}
