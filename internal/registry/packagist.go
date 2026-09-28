package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"bonjoski/argus/internal/model"
)

// PackagistAdapter queries Packagist (repo.packagist.org) for PHP/Composer package provenance.
type PackagistAdapter struct {
	client      *http.Client
	registryURL string
}

// NewPackagistAdapter creates a new PackagistAdapter.
func NewPackagistAdapter(client *http.Client) *PackagistAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &PackagistAdapter{
		client:      client,
		registryURL: "https://repo.packagist.org",
	}
}

// SetRegistryURL overrides the base Packagist URL for unit testing.
func (a *PackagistAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// Ecosystem returns model.EcosystemPackagist.
func (a *PackagistAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemPackagist
}

type packagistV2Doc struct {
	Packages map[string][]packagistVersionItem `json:"packages"`
}

type packagistVersionItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Time    string `json:"time"`
	Source  struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"source"`
	Dist struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
	Authors []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"authors"`
}

// FetchProvenance retrieves metadata for a Packagist package.
func (a *PackagistAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgName = strings.TrimSpace(pkgName)
	if !strings.Contains(pkgName, "/") {
		return nil, "", fmt.Errorf("invalid packagist package name %q (expected vendor/package)", pkgName)
	}

	pkgURL := fmt.Sprintf("%s/p2/%s.json", a.registryURL, pkgName)
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create packagist request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query packagist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on packagist", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("packagist returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read packagist response: %w", err)
	}

	var doc packagistV2Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse packagist response: %w", err)
	}

	versions, ok := doc.Packages[pkgName]
	if !ok || len(versions) == 0 {
		// Try case-insensitive lookup
		for k, v := range doc.Packages {
			if strings.EqualFold(k, pkgName) {
				versions = v
				break
			}
		}
	}

	if len(versions) == 0 {
		return nil, "", fmt.Errorf("no versions found for package %q on packagist", pkgName)
	}

	targetVersion := version
	var selectedVersion *packagistVersionItem

	if targetVersion != "" && targetVersion != "latest" {
		for i := range versions {
			if strings.EqualFold(versions[i].Version, targetVersion) || strings.EqualFold(versions[i].Version, "v"+targetVersion) {
				selectedVersion = &versions[i]
				break
			}
		}
	}

	if selectedVersion == nil {
		// First stable non-dev version or first version
		for i := range versions {
			if !strings.Contains(versions[i].Version, "dev") {
				selectedVersion = &versions[i]
				break
			}
		}
		if selectedVersion == nil {
			selectedVersion = &versions[0]
		}
		targetVersion = selectedVersion.Version
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemPackagist,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(versions),
		IsScoped:        true, // All Composer packages have vendor/ namespace
	}

	if selectedVersion.Dist.Shasum != "" {
		prov.IntegrityHash = "sha1-" + selectedVersion.Dist.Shasum
	}
	if selectedVersion.Dist.URL != "" {
		prov.TarballURL = selectedVersion.Dist.URL
	}
	if selectedVersion.Source.URL != "" {
		prov.RepositoryURL = selectedVersion.Source.URL
	}
	if len(selectedVersion.Authors) > 0 {
		prov.AuthorName = selectedVersion.Authors[0].Name
	}

	// Calculate release dates
	var earliestTime, latestTime time.Time
	for _, v := range versions {
		if v.Time != "" {
			if t, err := time.Parse(time.RFC3339, v.Time); err == nil {
				if earliestTime.IsZero() || t.Before(earliestTime) {
					earliestTime = t
				}
				if latestTime.IsZero() || t.After(latestTime) {
					latestTime = t
				}
			}
		}
	}

	prov.FirstReleaseDate = earliestTime
	prov.LatestReleaseDate = latestTime

	return prov, etag, nil
}
