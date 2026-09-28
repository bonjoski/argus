package sanitizer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"bonjoski/argus/internal/model"
)

// QuarantineRecord captures the forensic metadata written to .meta.json.
type QuarantineRecord struct {
	ID             string          `json:"id"`
	Package        string          `json:"package"`
	Version        string          `json:"version"`
	Ecosystem      model.Ecosystem `json:"ecosystem"`
	RiskScore      int             `json:"risk_score"`
	RiskLevel      model.RiskLevel `json:"risk_level"`
	TriggeredRules []string        `json:"triggered_rules"`
	ASTFindings    []string        `json:"ast_findings,omitempty"`
	SourceURL      string          `json:"source_url,omitempty"`
	QuarantineTime time.Time       `json:"quarantine_time"`
	TarballPath    string          `json:"tarball_path"`
	MetadataPath   string          `json:"metadata_path"`
	TarballSize    int64           `json:"tarball_size"`
	SHA256         string          `json:"sha256"`
}

// QuarantineStore manages the persistence, listing, inspection, and purging of quarantined archives.
type QuarantineStore struct {
	baseDir string
	mu      sync.RWMutex
}

// DefaultQuarantineDir returns the canonical default directory for the quarantine store (~/.argus/quarantine).
func DefaultQuarantineDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".argus", "quarantine")
	}
	return filepath.Join(home, ".argus", "quarantine")
}

// NewQuarantineStore initializes a quarantine store backed by the specified directory.
func NewQuarantineStore(dir string) (*QuarantineStore, error) {
	if dir == "" {
		dir = DefaultQuarantineDir()
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create quarantine directory %s: %w", dir, err)
	}

	return &QuarantineStore{
		baseDir: dir,
	}, nil
}

// BaseDir returns the root storage directory for this quarantine store.
func (s *QuarantineStore) BaseDir() string {
	return s.baseDir
}

// SanitizePackageName converts package names with slashes (e.g. @scope/pkg) to filesystem-safe strings (@scope__pkg).
func SanitizePackageName(pkg string) string {
	return strings.ReplaceAll(pkg, "/", "__")
}

// Quarantine saves the raw tarball and accompanying .meta.json forensics file.
func (s *QuarantineStore) Quarantine(
	eco model.Ecosystem,
	pkg string,
	version string,
	tarballBytes []byte,
	report *model.RiskReport,
	sourceURL string,
) (*QuarantineRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(tarballBytes) == 0 {
		return nil, fmt.Errorf("cannot quarantine empty tarball payload")
	}

	if eco == "" {
		eco = model.EcosystemNPM
	}
	if version == "" {
		version = "unknown"
	}

	ecoDir := filepath.Join(s.baseDir, string(eco))
	if err := os.MkdirAll(ecoDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ecosystem quarantine directory: %w", err)
	}

	now := time.Now().UTC()
	timestampStr := now.Format("20060102_150405.000")
	safePkg := SanitizePackageName(pkg)
	fileBase := fmt.Sprintf("%s_%s_%s", safePkg, version, timestampStr)

	tarballPath := filepath.Join(ecoDir, fileBase+".tar.gz")
	metaPath := filepath.Join(ecoDir, fileBase+".meta.json")

	hasher := sha256.New()
	hasher.Write(tarballBytes)
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	var riskScore int
	var riskLevel model.RiskLevel = model.RiskLevelCritical
	var triggeredRules []string
	var astFindings []string

	if report != nil {
		riskScore = report.TotalScore
		riskLevel = report.RiskLevel
		if sourceURL == "" && report.Provenance.TarballURL != "" {
			sourceURL = report.Provenance.TarballURL
		}
		for _, p := range report.Penalties {
			if p.Triggered {
				triggeredRules = append(triggeredRules, fmt.Sprintf("%s: %s (+%d pts)", p.RuleID, p.Name, p.Points))
			}
		}
		if report.Provenance.HasSuspiciousAST && len(report.Provenance.SuspiciousFindings) > 0 {
			astFindings = append(astFindings, report.Provenance.SuspiciousFindings...)
		}
	}

	id := fmt.Sprintf("%s/%s", eco, fileBase)

	record := &QuarantineRecord{
		ID:             id,
		Package:        pkg,
		Version:        version,
		Ecosystem:      eco,
		RiskScore:      riskScore,
		RiskLevel:      riskLevel,
		TriggeredRules: triggeredRules,
		ASTFindings:    astFindings,
		SourceURL:      sourceURL,
		QuarantineTime: now,
		TarballPath:    tarballPath,
		MetadataPath:   metaPath,
		TarballSize:    int64(len(tarballBytes)),
		SHA256:         sha256Hex,
	}

	// Write raw tarball
	if err := os.WriteFile(tarballPath, tarballBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write quarantined tarball to %s: %w", tarballPath, err)
	}

	// Write .meta.json companion
	metaBytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		if rmErr := os.Remove(tarballPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, fmt.Errorf("failed to marshal quarantine metadata (%w) and cleanup failed: %v", err, rmErr)
		}
		return nil, fmt.Errorf("failed to marshal quarantine metadata: %w", err)
	}
	metaBytes = append(metaBytes, '\n')

	if err := os.WriteFile(metaPath, metaBytes, 0644); err != nil {
		if rmErr := os.Remove(tarballPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, fmt.Errorf("failed to write quarantine metadata to %s (%w) and cleanup failed: %v", metaPath, err, rmErr)
		}
		return nil, fmt.Errorf("failed to write quarantine metadata to %s: %w", metaPath, err)
	}

	return record, nil
}

// List returns all quarantined records found in the quarantine store, sorted newest first.
func (s *QuarantineStore) List() ([]*QuarantineRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var records []*QuarantineRecord

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to read quarantine directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ecoDir := filepath.Join(s.baseDir, entry.Name())
		files, err := os.ReadDir(ecoDir)
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".meta.json") {
				continue
			}

			metaPath := filepath.Join(ecoDir, f.Name())
			data, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}

			var rec QuarantineRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			records = append(records, &rec)
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].QuarantineTime.After(records[j].QuarantineTime)
	})

	return records, nil
}

// Inspect finds and loads the metadata for a specific quarantined record ID or package name.
func (s *QuarantineStore) Inspect(idOrPkg string) (*QuarantineRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records, err := s.List()
	if err != nil {
		return nil, err
	}

	idOrPkgClean := strings.TrimSpace(idOrPkg)

	for _, r := range records {
		if r.ID == idOrPkgClean ||
			strings.TrimPrefix(r.ID, string(r.Ecosystem)+"/") == idOrPkgClean ||
			r.Package == idOrPkgClean ||
			strings.EqualFold(r.Package, idOrPkgClean) ||
			filepath.Base(r.TarballPath) == idOrPkgClean ||
			filepath.Base(r.MetadataPath) == idOrPkgClean {
			return r, nil
		}
	}

	// Partial match fallback if not exact match
	for _, r := range records {
		if strings.Contains(r.ID, idOrPkgClean) || strings.Contains(r.Package, idOrPkgClean) {
			return r, nil
		}
	}

	return nil, fmt.Errorf("quarantined record %q not found", idOrPkg)
}

// Purge removes all quarantined packages and metadata files across all ecosystems.
func (s *QuarantineStore) Purge() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.listInternal()
	if err != nil {
		return 0, err
	}

	count := len(records)
	var firstErr error
	for _, r := range records {
		if err := os.Remove(r.TarballPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
		if err := os.Remove(r.MetadataPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}

	// Clean empty directories
	entries, readErr := os.ReadDir(s.baseDir)
	if readErr == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				if err := os.Remove(filepath.Join(s.baseDir, entry.Name())); err != nil && !os.IsNotExist(err) && firstErr == nil {
					firstErr = err
				}
			}
		}
	}

	if firstErr != nil {
		return count, fmt.Errorf("purge encountered error while removing quarantined files: %w", firstErr)
	}

	return count, nil
}

// GetTarball retrieves the raw bytes of a quarantined package archive.
func (s *QuarantineStore) GetTarball(idOrPkg string) ([]byte, error) {
	rec, err := s.Inspect(idOrPkg)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(rec.TarballPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tarball %s: %w", rec.TarballPath, err)
	}

	return data, nil
}

func (s *QuarantineStore) listInternal() ([]*QuarantineRecord, error) {
	var records []*QuarantineRecord

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to read quarantine directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ecoDir := filepath.Join(s.baseDir, entry.Name())
		files, err := os.ReadDir(ecoDir)
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".meta.json") {
				continue
			}

			metaPath := filepath.Join(ecoDir, f.Name())
			data, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}

			var rec QuarantineRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			records = append(records, &rec)
		}
	}

	return records, nil
}
