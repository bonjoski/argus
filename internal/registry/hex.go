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

// HexAdapter queries Hex.pm for Elixir and Erlang package provenance.
type HexAdapter struct {
	client      *http.Client
	registryURL string
}

// NewHexAdapter creates a new HexAdapter.
func NewHexAdapter(client *http.Client) *HexAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	return &HexAdapter{
		client:      client,
		registryURL: "https://hex.pm/api/packages",
	}
}

// SetRegistryURL overrides the base Hex.pm API URL for unit testing.
func (a *HexAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// SetBaseURL provides an alias for SetRegistryURL.
func (a *HexAdapter) SetBaseURL(u string) {
	a.SetRegistryURL(u)
}

// Ecosystem returns model.EcosystemHex.
func (a *HexAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemHex
}

type hexPackageDoc struct {
	Name      string              `json:"name"`
	Meta      hexMetaDoc          `json:"meta"`
	Downloads hexDownloadsDoc     `json:"downloads"`
	Releases  []hexReleaseItemDoc `json:"releases"`
	CreatedAt string              `json:"inserted_at"`
	UpdatedAt string              `json:"updated_at"`
}

type hexMetaDoc struct {
	Description string            `json:"description"`
	Licenses    []string          `json:"licenses"`
	Links       map[string]string `json:"links"`
	Maintainers []string          `json:"maintainers"`
}

type hexDownloadsDoc struct {
	All    int64 `json:"all"`
	Recent int64 `json:"recent"`
	Week   int64 `json:"week"`
	Day    int64 `json:"day"`
}

type hexReleaseItemDoc struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	Checksum  string `json:"checksum"`
	CreatedAt string `json:"inserted_at"`
	UpdatedAt string `json:"updated_at"`
}

// FetchProvenance retrieves metadata and checksums for a Hex package.
func (a *HexAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return nil, "", fmt.Errorf("empty hex package name")
	}

	pkgURL := fmt.Sprintf("%s/%s", a.registryURL, pkgName)
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create hex.pm request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query hex.pm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on hex.pm", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("hex.pm returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read hex.pm response: %w", err)
	}

	var doc hexPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse hex.pm response: %w", err)
	}

	if len(doc.Releases) == 0 {
		return nil, "", fmt.Errorf("no releases found for package %q on hex.pm", pkgName)
	}

	targetVersion := version
	var selectedRelease *hexReleaseItemDoc

	if targetVersion != "" && targetVersion != "latest" {
		for i := range doc.Releases {
			if strings.EqualFold(doc.Releases[i].Version, targetVersion) || strings.EqualFold(doc.Releases[i].Version, "v"+targetVersion) {
				selectedRelease = &doc.Releases[i]
				break
			}
		}
	}

	if selectedRelease == nil {
		// Default to latest release (first in hex.pm releases array)
		selectedRelease = &doc.Releases[0]
		targetVersion = selectedRelease.Version
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemHex,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(doc.Releases),
		TarballURL:      fmt.Sprintf("https://repo.hex.pm/tarballs/%s-%s.tar", pkgName, targetVersion),
	}

	// Downloads
	if doc.Downloads.Week > 0 {
		prov.WeeklyDownloads = doc.Downloads.Week
	} else if doc.Downloads.All > 0 {
		prov.WeeklyDownloads = doc.Downloads.All / 52
	}

	// Author
	if len(doc.Meta.Maintainers) > 0 {
		prov.AuthorName = doc.Meta.Maintainers[0]
	}

	// VCS URL
	for k, v := range doc.Meta.Links {
		kLower := strings.ToLower(k)
		if kLower == "github" || kLower == "gitlab" || kLower == "repository" || kLower == "source" || kLower == "source code" {
			prov.RepositoryURL = v
			break
		}
		if prov.RepositoryURL == "" && (strings.Contains(v, "github.com") || strings.Contains(v, "gitlab.com")) {
			prov.RepositoryURL = v
		}
	}

	// Checksum
	if selectedRelease.Checksum != "" {
		prov.IntegrityHash = "sha256-" + selectedRelease.Checksum
	}

	// Release timeline
	var earliestTime, latestTime time.Time
	for _, rel := range doc.Releases {
		if rel.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, rel.CreatedAt); err == nil {
				if earliestTime.IsZero() || t.Before(earliestTime) {
					earliestTime = t
				}
				if latestTime.IsZero() || t.After(latestTime) {
					latestTime = t
				}
			}
		}
	}

	if earliestTime.IsZero() && doc.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.CreatedAt); err == nil {
			earliestTime = t
		}
	}
	if latestTime.IsZero() && doc.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.UpdatedAt); err == nil {
			latestTime = t
		}
	}

	prov.FirstReleaseDate = earliestTime
	prov.LatestReleaseDate = latestTime

	return prov, etag, nil
}
