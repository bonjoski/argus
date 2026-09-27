package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"bonjoski/argus/internal/model"
)

// CratesAdapter queries the crates.io API for Rust package provenance.
type CratesAdapter struct {
	client    *http.Client
	baseURL   string
	limiter   *rate.Limiter
	userAgent string
}

// NewCratesAdapter constructs a CratesAdapter adhering to crates.io rate limiting policies.
func NewCratesAdapter(client *http.Client) *CratesAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	// crates.io crawling policy strictly enforces 1 request per second
	return &CratesAdapter{
		client:    client,
		baseURL:   "https://crates.io/api/v1/crates",
		limiter:   rate.NewLimiter(rate.Every(time.Second), 1),
		userAgent: "argus/1.0.0 (https://github.com/bonjoski/argus)",
	}
}

// SetBaseURL configures the crates.io API endpoint (used primarily in tests).
func (a *CratesAdapter) SetBaseURL(u string) {
	a.baseURL = strings.TrimRight(u, "/")
}

// SetLimiter overrides the default rate limiter (used in unit tests).
func (a *CratesAdapter) SetLimiter(l *rate.Limiter) {
	a.limiter = l
}

// SetUserAgent overrides the HTTP User-Agent header.
func (a *CratesAdapter) SetUserAgent(ua string) {
	a.userAgent = ua
}

// Ecosystem returns model.EcosystemCargo.
func (a *CratesAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemCargo
}

type cratesDoc struct {
	Crate struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		CreatedAt       string `json:"created_at"`
		UpdatedAt       string `json:"updated_at"`
		Downloads       int64  `json:"downloads"`
		RecentDownloads *int64 `json:"recent_downloads"`
		MaxVersion      string `json:"max_version"`
		Repository      string `json:"repository"`
		Homepage        string `json:"homepage"`
		Documentation   string `json:"documentation"`
	} `json:"crate"`
	Versions []cratesVersionItem `json:"versions"`
}

type cratesVersionItem struct {
	ID        int    `json:"id"`
	Num       string `json:"num"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Downloads int64  `json:"downloads"`
	Checksum  string `json:"checksum"`
	DlPath    string `json:"dl_path"`
	Yanked    bool   `json:"yanked"`
	License   string `json:"license"`
}

// FetchProvenance retrieves package metadata, download metrics, and integrity hashes from crates.io.
func (a *CratesAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	if a.limiter != nil {
		if err := a.limiter.Wait(ctx); err != nil {
			return nil, "", fmt.Errorf("crates.io rate limit wait failed: %w", err)
		}
	}

	pkgURL := fmt.Sprintf("%s/%s", a.baseURL, urlEncodePkg(pkgName))
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create crates.io request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", a.userAgent)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query crates.io: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on crates.io", pkgName)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, "", fmt.Errorf("crates.io rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("crates.io returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read crates.io response: %w", err)
	}

	var doc cratesDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse crates.io JSON response: %w", err)
	}

	targetVersion := version
	if targetVersion == "" || targetVersion == "latest" {
		targetVersion = doc.Crate.MaxVersion
		if targetVersion == "" && len(doc.Versions) > 0 {
			targetVersion = doc.Versions[0].Num
		}
	}

	// Locate version item
	var selectedVersion *cratesVersionItem
	for i := range doc.Versions {
		if doc.Versions[i].Num == targetVersion {
			selectedVersion = &doc.Versions[i]
			break
		}
	}
	if selectedVersion == nil && len(doc.Versions) > 0 {
		selectedVersion = &doc.Versions[0]
		targetVersion = selectedVersion.Num
	}

	prov := &model.PackageProvenance{
		Name:            doc.Crate.Name,
		Ecosystem:       model.EcosystemCargo,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(doc.Versions),
		RepositoryURL:   doc.Crate.Repository,
	}

	if prov.Name == "" {
		prov.Name = pkgName
	}
	if prov.RepositoryURL == "" {
		prov.RepositoryURL = doc.Crate.Homepage
	}

	// Parse timestamps
	if doc.Crate.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, doc.Crate.CreatedAt); err == nil {
			prov.FirstReleaseDate = t
		} else if t, err := time.Parse(time.RFC3339, doc.Crate.CreatedAt); err == nil {
			prov.FirstReleaseDate = t
		}
	}

	if selectedVersion != nil && selectedVersion.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, selectedVersion.CreatedAt); err == nil {
			prov.LatestReleaseDate = t
		} else if t, err := time.Parse(time.RFC3339, selectedVersion.CreatedAt); err == nil {
			prov.LatestReleaseDate = t
		}
	} else if doc.Crate.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, doc.Crate.UpdatedAt); err == nil {
			prov.LatestReleaseDate = t
		} else if t, err := time.Parse(time.RFC3339, doc.Crate.UpdatedAt); err == nil {
			prov.LatestReleaseDate = t
		}
	}

	// Calculate weekly downloads
	if doc.Crate.RecentDownloads != nil && *doc.Crate.RecentDownloads > 0 {
		// crates.io recent_downloads spans roughly 90 days (~13 weeks)
		prov.WeeklyDownloads = *doc.Crate.RecentDownloads / 12
		if prov.WeeklyDownloads == 0 && *doc.Crate.RecentDownloads > 0 {
			prov.WeeklyDownloads = *doc.Crate.RecentDownloads
		}
	} else if doc.Crate.Downloads > 0 {
		prov.WeeklyDownloads = doc.Crate.Downloads / 52
		if prov.WeeklyDownloads == 0 {
			prov.WeeklyDownloads = doc.Crate.Downloads
		}
	}

	// Checksum and download URL
	if selectedVersion != nil {
		if selectedVersion.Checksum != "" {
			prov.IntegrityHash = "sha256-" + selectedVersion.Checksum
		}
		if selectedVersion.DlPath != "" {
			if strings.HasPrefix(selectedVersion.DlPath, "http://") || strings.HasPrefix(selectedVersion.DlPath, "https://") {
				prov.TarballURL = selectedVersion.DlPath
			} else {
				prov.TarballURL = "https://crates.io" + selectedVersion.DlPath
			}
		}
	}

	return prov, etag, nil
}
