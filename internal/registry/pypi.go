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

type PyPIAdapter struct {
	client  *http.Client
	baseURL string
}

func NewPyPIAdapter(client *http.Client) *PyPIAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &PyPIAdapter{
		client:  client,
		baseURL: "https://pypi.org/pypi",
	}
}

func (a *PyPIAdapter) SetBaseURL(u string) {
	a.baseURL = u
}

func (a *PyPIAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemPyPI
}

type pypiPackageDoc struct {
	Info struct {
		Name        string            `json:"name"`
		Version     string            `json:"version"`
		Author      string            `json:"author"`
		AuthorEmail string            `json:"author_email"`
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	Releases map[string][]pypiReleaseFile `json:"releases"`
	URLs     []pypiReleaseFile            `json:"urls"`
}

type pypiReleaseFile struct {
	Filename    string `json:"filename"`
	Packagetype string `json:"packagetype"` // bdist_wheel, sdist
	UploadTime  string `json:"upload_time_iso_8601"`
	URL         string `json:"url"`
	HasSigstore bool   `json:"has_sigstore"`
	Digests     struct {
		SHA256 string `json:"sha256"`
		MD5    string `json:"md5"`
	} `json:"digests"`
}

func (a *PyPIAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	pkgURL := fmt.Sprintf("%s/%s/json", a.baseURL, pkgName)
	if version != "" && version != "latest" {
		pkgURL = fmt.Sprintf("%s/%s/%s/json", a.baseURL, pkgName, version)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create PyPI request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query PyPI JSON API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("package %q not found on PyPI", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("PyPI returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read PyPI response: %w", err)
	}

	var doc pypiPackageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("failed to parse PyPI response: %w", err)
	}

	targetVersion := version
	if targetVersion == "" || targetVersion == "latest" {
		targetVersion = doc.Info.Version
	}

	prov := &model.PackageProvenance{
		Name:            doc.Info.Name,
		Ecosystem:       model.EcosystemPyPI,
		ResolvedVersion: targetVersion,
		TotalReleases:   len(doc.Releases),
		AuthorName:      doc.Info.Author,
	}

	// Calculate earliest and latest release dates across releases
	var earliest, latest time.Time
	for _, files := range doc.Releases {
		for _, f := range files {
			if f.UploadTime == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, f.UploadTime)
			if err != nil {
				continue
			}
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
			if latest.IsZero() || t.After(latest) {
				latest = t
			}
		}
	}
	prov.FirstReleaseDate = earliest
	prov.LatestReleaseDate = latest

	// Target version files
	targetFiles := doc.URLs
	if files, ok := doc.Releases[targetVersion]; ok && len(files) > 0 {
		targetFiles = files
	}

	for _, f := range targetFiles {
		if strings.HasSuffix(f.Filename, ".whl") || f.Packagetype == "bdist_wheel" {
			prov.HasBinaryWheels = true
		}
		if f.HasSigstore {
			prov.HasPEP740Attestation = true
		}
		if prov.IntegrityHash == "" && f.Digests.SHA256 != "" {
			prov.IntegrityHash = "sha256-" + f.Digests.SHA256
			prov.TarballURL = f.URL
		}
	}

	// Extract repository URL from project_urls or home_page
	prov.RepositoryURL = extractPyPIRepoURL(doc.Info.HomePage, doc.Info.ProjectURLs)

	return prov, etag, nil
}

func extractPyPIRepoURL(homePage string, projectURLs map[string]string) string {
	candidates := []string{
		"Repository", "Source", "Source Code", "Code", "GitHub", "GitLab", "Homepage",
	}

	for _, key := range candidates {
		for k, v := range projectURLs {
			if strings.EqualFold(k, key) && isVCSHost(v) {
				return v
			}
		}
	}

	if isVCSHost(homePage) {
		return homePage
	}

	for _, v := range projectURLs {
		if isVCSHost(v) {
			return v
		}
	}

	return ""
}

func isVCSHost(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "github.com") ||
		strings.Contains(lower, "gitlab.com") ||
		strings.Contains(lower, "bitbucket.org")
}
