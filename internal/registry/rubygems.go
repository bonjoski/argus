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

// RubyGemsAdapter queries the RubyGems.org REST API for gem provenance.
type RubyGemsAdapter struct {
	client      *http.Client
	registryURL string
}

// NewRubyGemsAdapter creates a new RubyGemsAdapter.
func NewRubyGemsAdapter(client *http.Client) *RubyGemsAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &RubyGemsAdapter{
		client:      client,
		registryURL: "https://rubygems.org",
	}
}

// SetRegistryURL overrides the base RubyGems URL for testing.
func (a *RubyGemsAdapter) SetRegistryURL(u string) {
	a.registryURL = strings.TrimRight(u, "/")
}

// Ecosystem returns model.EcosystemRubyGems.
func (a *RubyGemsAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemRubyGems
}

type rubyGemDoc struct {
	Name             string `json:"name"`
	Downloads        int64  `json:"downloads"`
	Version          string `json:"version"`
	VersionDownloads int64  `json:"version_downloads"`
	Authors          string `json:"authors"`
	Info             string `json:"info"`
	Sha              string `json:"sha"`
	GemURI           string `json:"gem_uri"`
	HomepageURI      string `json:"homepage_uri"`
	SourceCodeURI    string `json:"source_code_uri"`
	VersionCreatedAt string `json:"version_created_at"`
}

type rubyGemVersionItem struct {
	Number    string `json:"number"`
	CreatedAt string `json:"created_at"`
	Sha       string `json:"sha"`
	Downloads int64  `json:"downloads_count"`
}

// FetchProvenance retrieves metadata for a Ruby gem.
func (a *RubyGemsAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	gemURL := fmt.Sprintf("%s/api/v1/gems/%s.json", a.registryURL, pkgName)
	req, err := http.NewRequestWithContext(ctx, "GET", gemURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create rubygems request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query rubygems: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("gem %q not found on rubygems", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("rubygems returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read rubygems response: %w", err)
	}

	var doc rubyGemDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse rubygems response: %w", err)
	}

	targetVersion := version
	if targetVersion == "" || targetVersion == "latest" {
		targetVersion = doc.Version
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemRubyGems,
		ResolvedVersion: targetVersion,
		AuthorName:      doc.Authors,
		WeeklyDownloads: doc.Downloads / 52, // Approximate weekly from total if point not available
		TotalReleases:   1,
	}

	if doc.Sha != "" {
		prov.IntegrityHash = "sha256-" + doc.Sha
	}
	if doc.GemURI != "" {
		prov.TarballURL = doc.GemURI
	}

	// Determine VCS URL
	if doc.SourceCodeURI != "" {
		prov.RepositoryURL = doc.SourceCodeURI
	} else if strings.Contains(doc.HomepageURI, "github.com") || strings.Contains(doc.HomepageURI, "gitlab.com") {
		prov.RepositoryURL = doc.HomepageURI
	}

	// Fetch version history for accurate release counts and timestamps
	versionsURL := fmt.Sprintf("%s/api/v1/versions/%s.json", a.registryURL, pkgName)
	vReq, err := http.NewRequestWithContext(ctx, "GET", versionsURL, nil)
	if err == nil {
		vReq.Header.Set("Accept", "application/json")
		vReq.Header.Set("User-Agent", "Argus/1.0")
		if vResp, err := a.client.Do(vReq); err == nil && vResp.StatusCode == http.StatusOK {
			defer vResp.Body.Close()
			var versions []rubyGemVersionItem
			if vBody, err := io.ReadAll(io.LimitReader(vResp.Body, 5*1024*1024)); err == nil {
				if err := json.Unmarshal(vBody, &versions); err == nil && len(versions) > 0 {
					prov.TotalReleases = len(versions)

					// First release is last element in history
					firstVer := versions[len(versions)-1]
					if t, err := time.Parse(time.RFC3339, firstVer.CreatedAt); err == nil {
						prov.FirstReleaseDate = t
					}

					// Latest release is first element
					latestVer := versions[0]
					if t, err := time.Parse(time.RFC3339, latestVer.CreatedAt); err == nil {
						prov.LatestReleaseDate = t
					}

					// If target version was requested specifically, look up its SHA
					if targetVersion != doc.Version {
						for _, v := range versions {
							if v.Number == targetVersion {
								if v.Sha != "" {
									prov.IntegrityHash = "sha256-" + v.Sha
								}
								if t, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil {
									prov.LatestReleaseDate = t
								}
								break
							}
						}
					}
				}
			}
		}
	}

	// Fallback timestamps from gem doc if versions endpoint was unavailable
	if prov.FirstReleaseDate.IsZero() && doc.VersionCreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.VersionCreatedAt); err == nil {
			prov.FirstReleaseDate = t
			prov.LatestReleaseDate = t
		}
	}

	return prov, etag, nil
}
