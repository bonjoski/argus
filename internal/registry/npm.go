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

type NPMAdapter struct {
	client      *http.Client
	registryURL string
	downloadURL string
}

func NewNPMAdapter(client *http.Client) *NPMAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &NPMAdapter{
		client:      client,
		registryURL: "https://registry.npmjs.org",
		downloadURL: "https://api.npmjs.org/downloads/point/last-week",
	}
}

func (a *NPMAdapter) SetRegistryURL(u string) {
	a.registryURL = u
}

func (a *NPMAdapter) SetDownloadURL(u string) {
	a.downloadURL = u
}

func (a *NPMAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemNPM
}

type npmPackageDoc struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	DistTags    map[string]string        `json:"dist-tags"`
	Time        map[string]string        `json:"time"`
	Versions    map[string]npmVersionDoc `json:"versions"`
	Repository  any                      `json:"repository"`
	Author      any                      `json:"author"`
	Maintainers []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"maintainers"`
}

type npmVersionDoc struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
	Dist    struct {
		Integrity    string `json:"integrity"`
		Shasum       string `json:"shasum"`
		Tarball      string `json:"tarball"`
		Signatures   []any  `json:"signatures"`
		Attestations any    `json:"attestations"`
	} `json:"dist"`
}

func (a *NPMAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgURL := fmt.Sprintf("%s/%s", a.registryURL, urlEncodePkg(pkgName))
	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create npm request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query npm registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on npm", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("npm registry returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read npm response: %w", err)
	}

	var doc npmPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse npm response: %w", err)
	}

	targetVersion := version
	if targetVersion == "" || targetVersion == "latest" {
		if latest, ok := doc.DistTags["latest"]; ok {
			targetVersion = latest
		}
	}

	prov := &model.PackageProvenance{
		Name:            pkgName,
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(doc.Versions),
		IsScoped:        strings.HasPrefix(pkgName, "@"),
	}

	// Parse timestamps
	if createdStr, ok := doc.Time["created"]; ok {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			prov.FirstReleaseDate = t
		}
	}
	if modifiedStr, ok := doc.Time["modified"]; ok {
		if t, err := time.Parse(time.RFC3339, modifiedStr); err == nil {
			prov.LatestReleaseDate = t
		}
	}

	// Parse Version-specific details
	if verDoc, ok := doc.Versions[targetVersion]; ok {
		prov.IntegrityHash = verDoc.Dist.Integrity
		if prov.IntegrityHash == "" && verDoc.Dist.Shasum != "" {
			prov.IntegrityHash = "sha1-" + verDoc.Dist.Shasum
		}
		prov.TarballURL = verDoc.Dist.Tarball

		// Check for dangerous install scripts
		for scriptName := range verDoc.Scripts {
			if scriptName == "preinstall" || scriptName == "install" || scriptName == "postinstall" {
				prov.HasInstallScripts = true
				break
			}
		}

		// Check for npm --provenance (Sigstore / GitHub Actions OIDC)
		if len(verDoc.Dist.Signatures) > 0 || verDoc.Dist.Attestations != nil {
			prov.HasSigstoreProvenance = true
		}
	}

	// Parse Repository URL
	prov.RepositoryURL = parseRepoURL(doc.Repository)

	// Parse Author info
	if len(doc.Maintainers) > 0 {
		prov.AuthorName = doc.Maintainers[0].Name
	}

	// Query weekly downloads in parallel or directly
	downloads, _ := a.fetchWeeklyDownloads(ctx, pkgName)
	prov.WeeklyDownloads = downloads

	return prov, etag, nil
}

func (a *NPMAdapter) fetchWeeklyDownloads(ctx context.Context, pkgName string) (int64, error) {
	dlURL := fmt.Sprintf("%s/%s", a.downloadURL, urlEncodePkg(pkgName))
	req, err := http.NewRequestWithContext(ctx, "GET", dlURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil
	}

	var res struct {
		Downloads int64 `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return 0, err
	}

	return res.Downloads, nil
}

func urlEncodePkg(name string) string {
	// For scoped packages like @foo/bar, npm API expects @foo%2Fbar
	return strings.ReplaceAll(name, "/", "%2F")
}

func parseRepoURL(repo any) string {
	switch v := repo.(type) {
	case string:
		return v
	case map[string]any:
		if u, ok := v["url"].(string); ok {
			return u
		}
	}
	return ""
}
