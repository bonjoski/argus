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

// SwiftAdapter queries Swift Package Index (swiftpackageindex.com) for Swift package provenance.
type SwiftAdapter struct {
	client      *http.Client
	registryURL string
}

// NewSwiftAdapter creates a new SwiftAdapter.
func NewSwiftAdapter(client *http.Client) *SwiftAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	return &SwiftAdapter{
		client:      client,
		registryURL: "https://swiftpackageindex.com/api/packages",
	}
}

// SetRegistryURL overrides the base Swift Package Index API URL for unit testing.
func (a *SwiftAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// SetBaseURL provides an alias for SetRegistryURL.
func (a *SwiftAdapter) SetBaseURL(u string) {
	a.SetRegistryURL(u)
}

// Ecosystem returns model.EcosystemSwift.
func (a *SwiftAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemSwift
}

type swiftPackageDoc struct {
	Title          string            `json:"title"`
	Owner          string            `json:"owner"`
	RepositoryName string            `json:"repositoryName"`
	URL            string            `json:"url"`
	Summary        string            `json:"summary"`
	License        string            `json:"license"`
	History        swiftHistoryDoc   `json:"history"`
	Activity       swiftActivityDoc  `json:"activity"`
	Releases       []swiftReleaseDoc `json:"releases"`
	Authors        []swiftAuthorDoc  `json:"authors"`
}

type swiftHistoryDoc struct {
	FirstCommit   string `json:"firstCommit"`
	LatestCommit  string `json:"latestCommit"`
	FirstRelease  string `json:"firstRelease"`
	LatestRelease string `json:"latestRelease"`
	ReleaseCount  int    `json:"releaseCount"`
}

type swiftActivityDoc struct {
	Stars         int   `json:"stars"`
	RecentCommits int   `json:"recentCommits"`
	TotalCommits  int   `json:"totalCommits"`
	Downloads     int64 `json:"downloads"`
}

type swiftReleaseDoc struct {
	Version  string `json:"version"`
	Date     string `json:"date"`
	URL      string `json:"url"`
	Checksum string `json:"checksum"`
	TagName  string `json:"tag_name"`
}

type swiftAuthorDoc struct {
	Name string `json:"name"`
}

// FetchProvenance retrieves metadata and release history for a Swift package.
func (a *SwiftAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return nil, "", fmt.Errorf("empty swift package name")
	}

	// Swift package names can be owner/repo (e.g. apple/swift-algorithms) or standard package identifier
	cleanPkg := strings.TrimPrefix(pkgName, "https://github.com/")
	cleanPkg = strings.TrimSuffix(cleanPkg, ".git")

	pkgURL := fmt.Sprintf("%s/%s", a.registryURL, cleanPkg)
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create swift package request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query swift package index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("swift package %q not found", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("swift package index returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read swift response: %w", err)
	}

	var doc swiftPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse swift package response: %w", err)
	}

	targetVersion := version
	var selectedRelease *swiftReleaseDoc

	if targetVersion != "" && targetVersion != "latest" {
		for i := range doc.Releases {
			if strings.EqualFold(doc.Releases[i].Version, targetVersion) || strings.EqualFold(doc.Releases[i].Version, "v"+targetVersion) {
				selectedRelease = &doc.Releases[i]
				break
			}
		}
	}

	if selectedRelease == nil && len(doc.Releases) > 0 {
		selectedRelease = &doc.Releases[0]
		targetVersion = selectedRelease.Version
	}

	totalReleases := len(doc.Releases)
	if totalReleases == 0 && doc.History.ReleaseCount > 0 {
		totalReleases = doc.History.ReleaseCount
	}
	if totalReleases == 0 {
		totalReleases = 1
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemSwift,
		ResolvedVersion: targetVersion,
		TotalReleases:   totalReleases,
		IsScoped:        strings.Contains(pkgName, "/"),
	}

	// Repository URL
	if doc.URL != "" {
		prov.RepositoryURL = doc.URL
	} else if doc.Owner != "" && doc.RepositoryName != "" {
		prov.RepositoryURL = fmt.Sprintf("https://github.com/%s/%s", doc.Owner, doc.RepositoryName)
	} else if strings.Contains(pkgName, "/") {
		prov.RepositoryURL = fmt.Sprintf("https://github.com/%s", cleanPkg)
	}

	// Author
	if len(doc.Authors) > 0 && doc.Authors[0].Name != "" {
		prov.AuthorName = doc.Authors[0].Name
	} else if doc.Owner != "" {
		prov.AuthorName = doc.Owner
	}

	// Checksum / Tarball
	if selectedRelease != nil {
		if selectedRelease.Checksum != "" {
			prov.IntegrityHash = "sha256-" + selectedRelease.Checksum
		}
		if selectedRelease.URL != "" {
			prov.TarballURL = selectedRelease.URL
		}
	}

	// Release timeline
	var earliestTime, latestTime time.Time
	for _, rel := range doc.Releases {
		if rel.Date != "" {
			if t, err := time.Parse(time.RFC3339, rel.Date); err == nil {
				if earliestTime.IsZero() || t.Before(earliestTime) {
					earliestTime = t
				}
				if latestTime.IsZero() || t.After(latestTime) {
					latestTime = t
				}
			}
		}
	}

	if earliestTime.IsZero() && doc.History.FirstRelease != "" {
		if t, err := time.Parse(time.RFC3339, doc.History.FirstRelease); err == nil {
			earliestTime = t
		}
	}
	if latestTime.IsZero() && doc.History.LatestRelease != "" {
		if t, err := time.Parse(time.RFC3339, doc.History.LatestRelease); err == nil {
			latestTime = t
		}
	}

	prov.FirstReleaseDate = earliestTime
	prov.LatestReleaseDate = latestTime

	return prov, etag, nil
}
