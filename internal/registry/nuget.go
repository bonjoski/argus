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

// NuGetAdapter queries the NuGet v3 Registration API for .NET package provenance.
type NuGetAdapter struct {
	client      *http.Client
	registryURL string
}

// NewNuGetAdapter creates a new NuGetAdapter.
func NewNuGetAdapter(client *http.Client) *NuGetAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	return &NuGetAdapter{
		client:      client,
		registryURL: "https://api.nuget.org/v3/registration5-gz-semver",
	}
}

// SetRegistryURL overrides the base NuGet registration URL (used for testing).
func (a *NuGetAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// SetBaseURL provides an alias for SetRegistryURL.
func (a *NuGetAdapter) SetBaseURL(u string) {
	a.SetRegistryURL(u)
}

// Ecosystem returns model.EcosystemNuGet.
func (a *NuGetAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemNuGet
}

type nugetRegistrationIndex struct {
	Count int                     `json:"count"`
	Items []nugetRegistrationPage `json:"items"`
}

type nugetRegistrationPage struct {
	ID    string                      `json:"@id"`
	Count int                         `json:"count"`
	Items []nugetRegistrationLeafItem `json:"items"`
	Lower string                      `json:"lower"`
	Upper string                      `json:"upper"`
}

type nugetRegistrationLeafItem struct {
	ID             string                 `json:"@id"`
	CatalogEntry   *nugetLeafCatalogEntry `json:"catalogEntry"`
	PackageContent string                 `json:"packageContent"`
}

type nugetLeafCatalogEntry struct {
	ID                   string `json:"id"`
	Version              string `json:"version"`
	Authors              string `json:"authors"`
	Description          string `json:"description"`
	Published            string `json:"published"`
	ProjectURL           string `json:"projectUrl"`
	PackageContent       string `json:"packageContent"`
	PackageHash          string `json:"packageHash"`
	PackageHashAlgorithm string `json:"packageHashAlgorithm"`
	Listed               bool   `json:"listed"`
	Downloads            int64  `json:"downloads"`
}

// FetchProvenance retrieves package metadata, release timeline, and integrity hashes from NuGet.
func (a *NuGetAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return nil, "", fmt.Errorf("empty nuget package name")
	}

	lowerID := strings.ToLower(pkgName)
	pkgURL := fmt.Sprintf("%s/%s/index.json", a.registryURL, lowerID)

	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create nuget request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query nuget registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on nuget", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("nuget returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read nuget response: %w", err)
	}

	var index nugetRegistrationIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, "", fmt.Errorf("failed to parse nuget registration index: %w", err)
	}

	var allLeaves []nugetRegistrationLeafItem
	for _, page := range index.Items {
		if len(page.Items) > 0 {
			allLeaves = append(allLeaves, page.Items...)
		} else if page.ID != "" {
			// Page items are un-inlined; fetch individual page if needed
			pageReq, err := http.NewRequestWithContext(ctx, "GET", page.ID, nil)
			if err == nil {
				pageReq.Header.Set("Accept", "application/json")
				pageReq.Header.Set("User-Agent", "Argus/1.0")
				if pageResp, err := a.client.Do(pageReq); err == nil && pageResp.StatusCode == http.StatusOK {
					defer pageResp.Body.Close()
					var fetchedPage nugetRegistrationPage
					if pageBody, err := io.ReadAll(io.LimitReader(pageResp.Body, 5*1024*1024)); err == nil {
						if err := json.Unmarshal(pageBody, &fetchedPage); err == nil {
							allLeaves = append(allLeaves, fetchedPage.Items...)
						}
					}
				}
			}
		}
	}

	if len(allLeaves) == 0 {
		return nil, "", fmt.Errorf("no versions found for package %q on nuget", pkgName)
	}

	targetVersion := version
	var selectedEntry *nugetLeafCatalogEntry
	var selectedLeaf *nugetRegistrationLeafItem

	if targetVersion != "" && targetVersion != "latest" {
		for i := range allLeaves {
			entry := allLeaves[i].CatalogEntry
			if entry != nil && (strings.EqualFold(entry.Version, targetVersion) || strings.EqualFold(entry.Version, "v"+targetVersion)) {
				selectedEntry = entry
				selectedLeaf = &allLeaves[i]
				break
			}
		}
	}

	if selectedEntry == nil {
		// Pick last leaf (latest version)
		for i := len(allLeaves) - 1; i >= 0; i-- {
			if allLeaves[i].CatalogEntry != nil {
				selectedEntry = allLeaves[i].CatalogEntry
				selectedLeaf = &allLeaves[i]
				targetVersion = selectedEntry.Version
				break
			}
		}
	}

	if selectedEntry == nil {
		return nil, "", fmt.Errorf("could not resolve version for package %q on nuget", pkgName)
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemNuGet,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(allLeaves),
		AuthorName:      selectedEntry.Authors,
	}

	if strings.Contains(pkgName, ".") {
		prov.IsScoped = true
	}

	if selectedEntry.ProjectURL != "" {
		prov.RepositoryURL = selectedEntry.ProjectURL
	}

	if selectedLeaf != nil && selectedLeaf.PackageContent != "" {
		prov.TarballURL = selectedLeaf.PackageContent
	} else if selectedEntry.PackageContent != "" {
		prov.TarballURL = selectedEntry.PackageContent
	}

	if selectedEntry.PackageHash != "" {
		algo := strings.ToLower(selectedEntry.PackageHashAlgorithm)
		if algo == "" || algo == "sha512" {
			prov.IntegrityHash = "sha512-" + selectedEntry.PackageHash
		} else {
			prov.IntegrityHash = fmt.Sprintf("%s-%s", algo, selectedEntry.PackageHash)
		}
	}

	// Calculate release timeline
	var earliestTime, latestTime time.Time
	for _, leaf := range allLeaves {
		if leaf.CatalogEntry != nil && leaf.CatalogEntry.Published != "" {
			t, err := time.Parse(time.RFC3339, leaf.CatalogEntry.Published)
			if err != nil {
				// Try alternate ISO formats
				t, err = time.Parse("2006-01-02T15:04:05.9999999Z", leaf.CatalogEntry.Published)
			}
			if err == nil {
				// NuGet uses 1900-01-01 for unlisted packages
				if t.Year() <= 1900 {
					continue
				}
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
