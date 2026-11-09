package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/procident"
)

type SQLiteStore struct {
	db     *sql.DB
	dbPath string
}

// DefaultCachePath returns the standard cache location in ~/.argus/cache.db.
func DefaultCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, ".argus", "cache.db"), nil
}

// NewSQLiteStore creates or opens the SQLite database at dbPath and initializes schemas.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
		if filepath.Base(dir) == ".argus" {
			if err := procident.VerifyFileOwnerAndNotSymlink(dir); err != nil {
				return nil, fmt.Errorf("unsafe cache directory %s: %w", dir, err)
			}
			if err := os.Chmod(dir, 0700); err != nil {
				return nil, fmt.Errorf("failed to set 0700 permissions on %s: %w", dir, err)
			}
		}
		if fi, err := os.Lstat(dbPath); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("refusing to open symlinked cache database %s", dbPath)
			}
			if err := procident.VerifyFileOwnerAndNotSymlink(dbPath); err != nil {
				return nil, fmt.Errorf("unsafe cache database ownership on %s: %w", dbPath, err)
			}
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Performance Pragmas
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA busy_timeout=5000;
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set pragmas: %w", err)
	}

	s := &SQLiteStore{db: db, dbPath: dbPath}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	if dbPath != ":memory:" {
		for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
			if _, statErr := os.Lstat(p); statErr == nil {
				if chmodErr := os.Chmod(p, 0600); chmodErr != nil {
					db.Close()
					return nil, fmt.Errorf("failed to enforce 0600 permissions on %s: %w", p, chmodErr)
				}
			}
		}
	}

	return s, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS provenance_cache (
		cache_key TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		package_name TEXT NOT NULL,
		version TEXT NOT NULL,
		integrity_hash TEXT,
		etag TEXT,
		payload_json TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_prov_expiry ON provenance_cache(expires_at);

	CREATE TABLE IF NOT EXISTS report_cache (
		cache_key TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		package_name TEXT NOT NULL,
		version TEXT NOT NULL,
		integrity_hash TEXT NOT NULL DEFAULT '',
		etag TEXT,
		report_json TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_rep_expiry ON report_cache(expires_at);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Ensure legacy databases without report_cache.integrity_hash are migrated cleanly
	if _, migErr := s.db.Exec(`ALTER TABLE report_cache ADD COLUMN integrity_hash TEXT NOT NULL DEFAULT ''`); migErr != nil {
		if !strings.Contains(strings.ToLower(migErr.Error()), "duplicate column") {
			return fmt.Errorf("failed migrating report_cache schema: %w", migErr)
		}
	}
	return nil
}

func provenanceKey(eco model.Ecosystem, pkg, version, hash string) string {
	return fmt.Sprintf("%s:%s@%s:%s", eco, pkg, version, hash)
}

func reportKey(eco model.Ecosystem, pkg, version string) string {
	return fmt.Sprintf("%s:%s@%s", eco, pkg, version)
}

func (s *SQLiteStore) GetProvenance(ctx context.Context, eco model.Ecosystem, pkg, version, hash string) (*model.PackageProvenance, string, bool, error) {
	key := provenanceKey(eco, pkg, version, hash)
	now := time.Now().UnixMilli()

	query := `SELECT payload_json, integrity_hash, etag, expires_at FROM provenance_cache WHERE cache_key = ?`
	row := s.db.QueryRowContext(ctx, query, key)

	var payloadJSON, storedHash, etag string
	var expiresAt int64
	if err := row.Scan(&payloadJSON, &storedHash, &etag, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}

	if now > expiresAt {
		return nil, etag, false, nil // Expired, return etag for conditional revalidation
	}

	var prov model.PackageProvenance
	if err := json.Unmarshal([]byte(payloadJSON), &prov); err != nil {
		return nil, etag, false, fmt.Errorf("failed to unmarshal cached provenance: %w", err)
	}
	if prov.Ecosystem != eco || prov.Name != pkg || prov.ResolvedVersion != version || prov.IntegrityHash != storedHash {
		return nil, etag, false, nil
	}
	if hash != "" && storedHash != hash {
		return nil, etag, false, nil
	}

	return &prov, etag, true, nil
}

func (s *SQLiteStore) SetProvenance(ctx context.Context, prov *model.PackageProvenance, etag string, ttl time.Duration) error {
	key := provenanceKey(prov.Ecosystem, prov.Name, prov.ResolvedVersion, prov.IntegrityHash)
	now := time.Now()
	expiresAt := now.Add(ttl).UnixMilli()

	data, err := json.Marshal(prov)
	if err != nil {
		return fmt.Errorf("failed to marshal provenance: %w", err)
	}

	query := `
	INSERT INTO provenance_cache (cache_key, ecosystem, package_name, version, integrity_hash, etag, payload_json, created_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(cache_key) DO UPDATE SET
		integrity_hash = excluded.integrity_hash,
		etag = excluded.etag,
		payload_json = excluded.payload_json,
		expires_at = excluded.expires_at;
	`
	_, err = s.db.ExecContext(ctx, query, key, string(prov.Ecosystem), prov.Name, prov.ResolvedVersion, prov.IntegrityHash, etag, string(data), now.UnixMilli(), expiresAt)
	return err
}

func (s *SQLiteStore) GetReport(ctx context.Context, eco model.Ecosystem, pkg, version string) (*model.RiskReport, string, bool, error) {
	return s.GetReportWithIntegrity(ctx, eco, pkg, version, "")
}

func (s *SQLiteStore) GetReportWithIntegrity(ctx context.Context, eco model.Ecosystem, pkg, version, expectedIntegrity string) (*model.RiskReport, string, bool, error) {
	key := reportKey(eco, pkg, version)
	now := time.Now().UnixMilli()

	query := `SELECT report_json, integrity_hash, etag, expires_at FROM report_cache WHERE cache_key = ?`
	row := s.db.QueryRowContext(ctx, query, key)

	var reportJSON, storedIntegrity, etag string
	var expiresAt int64
	if err := row.Scan(&reportJSON, &storedIntegrity, &etag, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}

	if now > expiresAt {
		return nil, etag, false, nil // Expired
	}

	var report model.RiskReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		return nil, etag, false, fmt.Errorf("failed to unmarshal cached report: %w", err)
	}

	reportIntegrity := report.IntegrityHash
	if reportIntegrity == "" {
		reportIntegrity = report.Provenance.IntegrityHash
	}

	// Verify report identity and cryptographic IntegrityHash binding
	if report.Ecosystem != eco || report.Package != pkg || report.ResolvedVersion != version {
		return nil, etag, false, nil
	}
	if storedIntegrity != reportIntegrity {
		return nil, etag, false, nil
	}
	if expectedIntegrity != "" && storedIntegrity != expectedIntegrity {
		return nil, etag, false, nil
	}

	return &report, etag, true, nil
}

func (s *SQLiteStore) SetReport(ctx context.Context, report *model.RiskReport, etag string, ttl time.Duration) error {
	key := reportKey(report.Ecosystem, report.Package, report.ResolvedVersion)
	now := time.Now()
	expiresAt := now.Add(ttl).UnixMilli()

	integrityHash := report.IntegrityHash
	if integrityHash == "" {
		integrityHash = report.Provenance.IntegrityHash
		report.IntegrityHash = integrityHash
	}

	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	query := `
	INSERT INTO report_cache (cache_key, ecosystem, package_name, version, integrity_hash, etag, report_json, created_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(cache_key) DO UPDATE SET
		integrity_hash = excluded.integrity_hash,
		etag = excluded.etag,
		report_json = excluded.report_json,
		expires_at = excluded.expires_at;
	`
	_, err = s.db.ExecContext(ctx, query, key, string(report.Ecosystem), report.Package, report.ResolvedVersion, integrityHash, etag, string(data), now.UnixMilli(), expiresAt)
	return err
}

func (s *SQLiteStore) Prune(ctx context.Context) (int64, error) {
	now := time.Now().UnixMilli()
	res1, err := s.db.ExecContext(ctx, `DELETE FROM provenance_cache WHERE expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	n1, _ := res1.RowsAffected()

	res2, err := s.db.ExecContext(ctx, `DELETE FROM report_cache WHERE expires_at < ?`, now)
	if err != nil {
		return n1, err
	}
	n2, _ := res2.RowsAffected()

	return n1 + n2, nil
}

func (s *SQLiteStore) Stats(ctx context.Context) (*CacheStats, error) {
	now := time.Now().UnixMilli()
	var stats CacheStats

	row := s.db.QueryRowContext(ctx, `
		SELECT 
			(SELECT COUNT(*) FROM provenance_cache) + (SELECT COUNT(*) FROM report_cache),
			(SELECT COUNT(*) FROM provenance_cache WHERE expires_at < ?) + (SELECT COUNT(*) FROM report_cache WHERE expires_at < ?)
	`, now, now)
	if err := row.Scan(&stats.TotalEntries, &stats.ExpiredEntries); err != nil {
		return nil, err
	}

	return &stats, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
