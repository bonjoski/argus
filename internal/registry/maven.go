package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bonjoski/argus/internal/model"
)

// MavenAdapter queries the Maven Central Solr Search API for artifact provenance.
type MavenAdapter struct {
	client    *http.Client
	searchURL string
}

// NewMavenAdapter creates a new MavenAdapter.
func NewMavenAdapter(client *http.Client) *MavenAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &MavenAdapter{
		client:    client,
		searchURL: "https://search.maven.org/solrsearch/select",
	}
}

// SetSearchURL overrides the search API URL for unit testing.
func (a *MavenAdapter) SetSearchURL(u string) {
	a.searchURL = u
}

// Ecosystem returns model.EcosystemMaven.
func (a *MavenAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemMaven
}

type mavenSolrResponse struct {
	Response struct {
		NumFound int            `json:"numFound"`
		Docs     []mavenSolrDoc `json:"docs"`
	} `json:"response"`
}

type mavenSolrDoc struct {
	ID        string   `json:"id"`
	GroupID   string   `json:"g"`
	Artifact  string   `json:"a"`
	Version   string   `json:"v"`
	Timestamp int64    `json:"timestamp"`
	EC        []string `json:"ec"`
}

func parseMavenCoordinates(spec string) (groupID, artifactID string, err error) {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, ":") {
		parts := strings.SplitN(spec, ":", 2)
		return parts[0], parts[1], nil
	}
	if strings.Contains(spec, "/") {
		parts := strings.SplitN(spec, "/", 2)
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf("invalid maven coordinates %q (expected group:artifact or group/artifact)", spec)
}

// FetchProvenance retrieves metadata for a Maven Central artifact.
func (a *MavenAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	groupID, artifactID, err := parseMavenCoordinates(pkgName)
	if err != nil {
		return nil, "", err
	}

	query := fmt.Sprintf(`g:"%s" AND a:"%s"`, groupID, artifactID)
	reqURL := fmt.Sprintf("%s?q=%s&core=gav&rows=100&wt=json", a.searchURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create maven request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query maven central: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("artifact %q not found on maven central", pkgName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("maven central returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read maven response: %w", err)
	}

	var solrResp mavenSolrResponse
	if err := json.Unmarshal(body, &solrResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse maven central response: %w", err)
	}

	if solrResp.Response.NumFound == 0 || len(solrResp.Response.Docs) == 0 {
		return nil, "", fmt.Errorf("artifact %q not found on maven central", pkgName)
	}

	docs := solrResp.Response.Docs

	targetVersion := version
	if targetVersion == "" || targetVersion == "latest" {
		targetVersion = docs[0].Version
	}

	// Find the matching doc or default to the first
	var matchedDoc *mavenSolrDoc
	for i := range docs {
		if docs[i].Version == targetVersion {
			matchedDoc = &docs[i]
			break
		}
	}
	if matchedDoc == nil {
		matchedDoc = &docs[0]
		targetVersion = matchedDoc.Version
	}

	prov := &model.PackageProvenance{
		Name:            fmt.Sprintf("%s:%s", groupID, artifactID),
		Ecosystem:       model.EcosystemMaven,
		ResolvedVersion: targetVersion,
		TotalReleases:   solrResp.Response.NumFound,
		AuthorName:      groupID,
	}

	// Maven group IDs with verified domains are scoped / vendor protected
	if strings.HasPrefix(groupID, "org.") || strings.HasPrefix(groupID, "com.") || strings.HasPrefix(groupID, "io.") {
		prov.IsScoped = true
	}

	// Check for PGP / asc cryptographic signatures in artifact elements
	for _, ext := range matchedDoc.EC {
		if ext == ".asc" {
			prov.HasSigstoreProvenance = true // Cryptographic signature present
			break
		}
	}

	// Determine timestamps from docs
	var earliestTs int64 = 0
	var latestTs int64 = 0

	for _, d := range docs {
		if earliestTs == 0 || d.Timestamp < earliestTs {
			earliestTs = d.Timestamp
		}
		if d.Timestamp > latestTs {
			latestTs = d.Timestamp
		}
	}

	if earliestTs > 0 {
		prov.FirstReleaseDate = time.UnixMilli(earliestTs).UTC()
	}
	if latestTs > 0 {
		prov.LatestReleaseDate = time.UnixMilli(latestTs).UTC()
	}

	// Synthesize standard Central repository URL
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	prov.TarballURL = fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
		groupPath, artifactID, targetVersion, artifactID, targetVersion)

	// Attempt standard GitHub mapping if group is com.github.user or similar
	if strings.HasPrefix(groupID, "com.github.") {
		owner := strings.TrimPrefix(groupID, "com.github.")
		prov.RepositoryURL = fmt.Sprintf("https://github.com/%s/%s", owner, artifactID)
	}

	return prov, etag, nil
}
