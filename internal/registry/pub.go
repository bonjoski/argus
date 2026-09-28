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

// PubAdapter queries pub.dev for Dart / Flutter package provenance.
type PubAdapter struct {
	client      *http.Client
	registryURL string
}

// NewPubAdapter creates a new PubAdapter.
func NewPubAdapter(client *http.Client) *PubAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	return &PubAdapter{
		client:      client,
		registryURL: "https://pub.dev/api/packages",
	}
}

// SetRegistryURL overrides the base pub.dev API URL for unit testing.
func (a *PubAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// SetBaseURL provides an alias for SetRegistryURL.
func (a *PubAdapter) SetBaseURL(u string) {
	a.SetRegistryURL(u)
}

// Ecosystem returns model.EcosystemPub.
func (a *PubAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemPub
}

type pubPackageDoc struct {
	Name     string           `json:"name"`
	Latest   pubVersionItem   `json:"latest"`
	Versions []pubVersionItem `json:"versions"`
}

type pubVersionItem struct {
	Version       string     `json:"version"`
	ArchiveURL    string     `json:"archive_url"`
	ArchiveSha256 string     `json:"archive_sha256"`
	Published     string     `json:"published"`
	Pubspec       pubspecDoc `json:"pubspec"`
}

type pubspecDoc struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Homepage     string   `json:"homepage"`
	Repository   string   `json:"repository"`
	IssueTracker string   `json:"issue_tracker"`
	Author       string   `json:"author"`
	Authors      []string `json:"authors"`
	Description  string   `json:"description"`
}

// FetchProvenance retrieves metadata and integrity hashes for a Dart/Flutter package.
func (a *PubAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return nil, "", fmt.Errorf("empty pub package name")
	}

	pkgURL := fmt.Sprintf("%s/%s", a.registryURL, pkgName)
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pub.dev request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query pub.dev: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on pub.dev", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("pub.dev returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read pub.dev response: %w", err)
	}

	var doc pubPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse pub.dev response: %w", err)
	}

	if len(doc.Versions) == 0 && doc.Latest.Version == "" {
		return nil, "", fmt.Errorf("no versions found for package %q on pub.dev", pkgName)
	}

	targetVersion := version
	var selectedVersion *pubVersionItem

	if targetVersion != "" && targetVersion != "latest" {
		for i := range doc.Versions {
			if strings.EqualFold(doc.Versions[i].Version, targetVersion) || strings.EqualFold(doc.Versions[i].Version, "v"+targetVersion) {
				selectedVersion = &doc.Versions[i]
				break
			}
		}
	}

	if selectedVersion == nil {
		if doc.Latest.Version != "" {
			selectedVersion = &doc.Latest
			targetVersion = doc.Latest.Version
		} else if len(doc.Versions) > 0 {
			selectedVersion = &doc.Versions[len(doc.Versions)-1]
			targetVersion = selectedVersion.Version
		}
	}

	if selectedVersion == nil {
		return nil, "", fmt.Errorf("could not resolve version for package %q on pub.dev", pkgName)
	}

	totalReleases := len(doc.Versions)
	if totalReleases == 0 {
		totalReleases = 1
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemPub,
		ResolvedVersion: targetVersion,
		TotalReleases:   totalReleases,
	}

	// Author
	if selectedVersion.Pubspec.Author != "" {
		prov.AuthorName = selectedVersion.Pubspec.Author
	} else if len(selectedVersion.Pubspec.Authors) > 0 {
		prov.AuthorName = selectedVersion.Pubspec.Authors[0]
	}

	// Repository / VCS
	if selectedVersion.Pubspec.Repository != "" {
		prov.RepositoryURL = selectedVersion.Pubspec.Repository
	} else if selectedVersion.Pubspec.Homepage != "" {
		prov.RepositoryURL = selectedVersion.Pubspec.Homepage
	}

	// Tarball & Hash
	if selectedVersion.ArchiveURL != "" {
		prov.TarballURL = selectedVersion.ArchiveURL
	}
	if selectedVersion.ArchiveSha256 != "" {
		prov.IntegrityHash = "sha256-" + selectedVersion.ArchiveSha256
	}

	// Release timeline
	var earliestTime, latestTime time.Time
	for _, v := range doc.Versions {
		if v.Published != "" {
			if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
				if earliestTime.IsZero() || t.Before(earliestTime) {
					earliestTime = t
				}
				if latestTime.IsZero() || t.After(latestTime) {
					latestTime = t
				}
			}
		}
	}

	if earliestTime.IsZero() && selectedVersion.Published != "" {
		if t, err := time.Parse(time.RFC3339, selectedVersion.Published); err == nil {
			earliestTime = t
			latestTime = t
		}
	}

	prov.FirstReleaseDate = earliestTime
	prov.LatestReleaseDate = latestTime

	return prov, etag, nil
}
