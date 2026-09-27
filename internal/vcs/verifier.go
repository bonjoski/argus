package vcs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"bonjoski/argus/internal/model"
)

type Verifier interface {
	Verify(ctx context.Context, eco model.Ecosystem, pkgName, repoURL string) (*VCSResult, error)
}

type VCSResult struct {
	Status        model.VCSStatus
	RepoURL       string
	Owner         string
	Repo          string
	ManifestFound bool
	ManifestName  string
	AgeMonths     int
	CommitsCount  int
}

type HTTPVerifier struct {
	client *http.Client
}

func NewHTTPVerifier(client *http.Client) *HTTPVerifier {
	if client == nil {
		client = &http.Client{
			Timeout: 400 * time.Millisecond,
		}
	}
	return &HTTPVerifier{client: client}
}

// NormalizeRepoURL strips prefixes like git+, ssh://, .git suffix to return a clean URL.
func NormalizeRepoURL(raw string) (scheme, host, owner, repo string, err error) {
	clean := strings.TrimSpace(raw)
	clean = strings.TrimPrefix(clean, "git+")
	clean = strings.TrimPrefix(clean, "git://")
	clean = strings.TrimPrefix(clean, "ssh://")
	clean = strings.TrimSuffix(clean, ".git")

	// Handle scp-like git@host:owner/repo syntax
	if strings.HasPrefix(clean, "git@") {
		clean = strings.TrimPrefix(clean, "git@")
		clean = strings.Replace(clean, ":", "/", 1)
		clean = "https://" + clean
	}

	scheme = "https"
	if strings.HasPrefix(clean, "http://") {
		scheme = "http"
	} else if strings.HasPrefix(clean, "https://") {
		scheme = "https"
	} else {
		clean = "https://" + clean
	}

	u, err := url.Parse(clean)
	if err != nil {
		return "", "", "", "", err
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("invalid repository path structure: %s", u.Path)
	}

	return scheme, u.Host, parts[0], parts[1], nil
}

func (v *HTTPVerifier) Verify(ctx context.Context, eco model.Ecosystem, pkgName, repoURL string) (*VCSResult, error) {
	if strings.TrimSpace(repoURL) == "" {
		return &VCSResult{Status: model.VCSStatusNone}, nil
	}

	scheme, host, owner, repo, err := NormalizeRepoURL(repoURL)
	if err != nil {
		return &VCSResult{Status: model.VCSStatusMissing, RepoURL: repoURL}, nil
	}

	result := &VCSResult{
		RepoURL: fmt.Sprintf("%s://%s/%s/%s", scheme, host, owner, repo),
		Owner:   owner,
		Repo:    repo,
	}

	// Currently special-casing GitHub for deep reciprocal checks
	if strings.Contains(host, "github.com") {
		return v.verifyGitHub(ctx, eco, pkgName, owner, repo, result)
	}

	// Generic HTTP HEAD check for GitLab, Bitbucket, self-hosted
	req, err := http.NewRequestWithContext(ctx, "HEAD", result.RepoURL, nil)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	resp, err := v.client.Do(req)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		result.Status = model.VCSStatusVerified
	case http.StatusNotFound:
		result.Status = model.VCSStatusMissing
	case http.StatusForbidden, http.StatusTooManyRequests:
		result.Status = model.VCSStatusInconclusive
	default:
		result.Status = model.VCSStatusInconclusive
	}

	return result, nil
}

func (v *HTTPVerifier) verifyGitHub(ctx context.Context, eco model.Ecosystem, pkgName, owner, repo string, result *VCSResult) (*VCSResult, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.Status = model.VCSStatusMissing
		return result, nil
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	var ghRepo struct {
		CreatedAt time.Time `json:"created_at"`
		Archived  bool      `json:"archived"`
		Fork      bool      `json:"fork"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err == nil && !ghRepo.CreatedAt.IsZero() {
		months := int(time.Since(ghRepo.CreatedAt).Hours() / 24 / 30)
		result.AgeMonths = months
	}

	// Perform Reciprocal Linkage Check (Fetch raw manifest from repository)
	manifestMatched, manifestName := v.checkReciprocalManifest(ctx, eco, pkgName, owner, repo, token)
	if manifestMatched {
		result.Status = model.VCSStatusVerified
		result.ManifestFound = true
		result.ManifestName = manifestName
	} else if manifestName != "" && !manifestMatched {
		result.Status = model.VCSStatusMismatch
		result.ManifestFound = true
		result.ManifestName = manifestName
	} else {
		result.Status = model.VCSStatusVerified
	}

	return result, nil
}

func (v *HTTPVerifier) checkReciprocalManifest(ctx context.Context, eco model.Ecosystem, pkgName, owner, repo, token string) (bool, string) {
	var manifestPath string
	switch eco {
	case model.EcosystemNPM:
		manifestPath = "package.json"
	case model.EcosystemPyPI:
		manifestPath = "pyproject.toml"
	case model.EcosystemCargo:
		manifestPath = "Cargo.toml"
	case model.EcosystemGo:
		manifestPath = "go.mod"
	default:
		return false, ""
	}

	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/%s", owner, repo, manifestPath)
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return false, ""
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := v.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, ""
	}

	switch eco {
	case model.EcosystemNPM:
		var pkg struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &pkg); err == nil && pkg.Name != "" {
			return strings.EqualFold(pkg.Name, pkgName), pkg.Name
		}
	case model.EcosystemPyPI:
		re := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundName := string(matches[1])
			return strings.EqualFold(foundName, pkgName), foundName
		}
	case model.EcosystemCargo:
		re := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundName := string(matches[1])
			return strings.EqualFold(foundName, pkgName), foundName
		}
	case model.EcosystemGo:
		re := regexp.MustCompile(`(?m)^\s*module\s+([^\s]+)`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundMod := string(matches[1])
			return strings.EqualFold(foundMod, pkgName), foundMod
		}
	}

	return false, ""
}
