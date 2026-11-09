package vcs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
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
	client                  *http.Client
	allowInsecureTestClient bool
}

var safeRepoSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func NewHTTPVerifier(client *http.Client) *HTTPVerifier {
	if client == nil {
		return &HTTPVerifier{
			client:                  NewSafeHTTPClient(400 * time.Millisecond),
			allowInsecureTestClient: false,
		}
	}
	return &HTTPVerifier{
		client:                  client,
		allowInsecureTestClient: true,
	}
}

func isValidRepoSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." || len(seg) > 128 {
		return false
	}
	return safeRepoSegmentRe.MatchString(seg)
}

// NormalizeRepoURL strips prefixes like git+, ssh://, .git suffix to return a clean URL.
func NormalizeRepoURL(raw string) (scheme, host, owner, repo string, err error) {
	clean := strings.TrimSpace(raw)
	if strings.ContainsAny(clean, "\x00\r\n \t") {
		return "", "", "", "", fmt.Errorf("invalid whitespace or control characters in repository URL")
	}
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
	} else if strings.Contains(clean, "://") {
		return "", "", "", "", fmt.Errorf("unsupported repository URL scheme in %q", raw)
	} else {
		clean = "https://" + clean
	}

	u, err := url.Parse(clean)
	if err != nil {
		return "", "", "", "", err
	}
	if u.User != nil {
		return "", "", "", "", fmt.Errorf("userinfo credentials forbidden in repository URL")
	}
	if u.Hostname() == "" {
		return "", "", "", "", fmt.Errorf("missing hostname in repository URL")
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("invalid repository path structure: %s", u.Path)
	}
	if !isValidRepoSegment(parts[0]) || !isValidRepoSegment(parts[1]) {
		return "", "", "", "", fmt.Errorf("unsafe owner/repo characters in %s", u.Path)
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

	parsedHostURL, uErr := url.Parse(fmt.Sprintf("%s://%s", scheme, host))
	if uErr != nil {
		return &VCSResult{Status: model.VCSStatusMissing, RepoURL: repoURL}, nil
	}
	hostname := strings.ToLower(parsedHostURL.Hostname())

	// Production SSRF & HTTPS-only pre-flight checks before dispatching any outbound request
	if !v.allowInsecureTestClient {
		if scheme != "https" {
			return &VCSResult{Status: model.VCSStatusInconclusive, RepoURL: repoURL}, nil
		}
		if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".internal") {
			return &VCSResult{Status: model.VCSStatusInconclusive, RepoURL: repoURL}, nil
		}
		if ip, ipErr := netip.ParseAddr(hostname); ipErr == nil && !IsPublicAddr(ip) {
			return &VCSResult{Status: model.VCSStatusInconclusive, RepoURL: repoURL}, nil
		}
	}

	result := &VCSResult{
		RepoURL: fmt.Sprintf("%s://%s/%s/%s", scheme, host, owner, repo),
		Owner:   owner,
		Repo:    repo,
	}

	// Exact hostname matching ONLY (blocks evil-github.com / github.com.attacker.tld spoofing: ARG-05)
	switch hostname {
	case "github.com":
		return v.verifyGitHub(ctx, eco, pkgName, owner, repo, result)
	case "gitlab.com":
		return v.verifyGitLab(ctx, eco, pkgName, owner, repo, result)
	}

	// Generic VCS host check: verify repository reachability AND reciprocal root manifest
	req, err := http.NewRequestWithContext(ctx, "HEAD", result.RepoURL, nil)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		result.Status = model.VCSStatusMissing
		return result, nil
	case http.StatusOK:
		// Repository exists, but NEVER grant VCSStatusVerified (-25 pts) unless a root manifest matches pkgName!
		manifestPath := manifestPathForEcosystem(eco, pkgName)
		if manifestPath == "" {
			result.Status = model.VCSStatusInconclusive
			return result, nil
		}
		rawURL := fmt.Sprintf("%s/raw/HEAD/%s", result.RepoURL, manifestPath)
		matched, foundName, found := v.fetchAndMatchManifest(ctx, eco, pkgName, rawURL, "")
		if !found {
			result.Status = model.VCSStatusInconclusive
			return result, nil
		}
		result.ManifestFound = true
		result.ManifestName = foundName
		if matched {
			result.Status = model.VCSStatusVerified
		} else {
			result.Status = model.VCSStatusMismatch
		}
		return result, nil
	default:
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
}

func (v *HTTPVerifier) verifyGitHub(ctx context.Context, eco model.Ecosystem, pkgName, owner, repo string, result *VCSResult) (*VCSResult, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
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
	req.Header.Set("User-Agent", "Argus/1.0")

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

	if resp.StatusCode != http.StatusOK {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	var ghRepo struct {
		CreatedAt time.Time `json:"created_at"`
		Archived  bool      `json:"archived"`
		Fork      bool      `json:"fork"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&ghRepo); err == nil && !ghRepo.CreatedAt.IsZero() {
		months := int(time.Since(ghRepo.CreatedAt).Hours() / 24 / 30)
		result.AgeMonths = months
	}

	// Perform strict Reciprocal Linkage Check (never grant VCSStatusVerified without a matching root manifest!)
	manifestPath := manifestPathForEcosystem(eco, pkgName)
	if manifestPath == "" {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/%s",
		url.PathEscape(owner), url.PathEscape(repo), manifestPath)
	matched, manifestName, found := v.fetchAndMatchManifest(ctx, eco, pkgName, rawURL, token)
	if !found {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	result.ManifestFound = true
	result.ManifestName = manifestName
	if matched {
		result.Status = model.VCSStatusVerified
	} else {
		result.Status = model.VCSStatusMismatch
	}
	return result, nil
}

func (v *HTTPVerifier) verifyGitLab(ctx context.Context, eco model.Ecosystem, pkgName, owner, repo string, result *VCSResult) (*VCSResult, error) {
	projectID := url.PathEscape(owner + "/" + repo)
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}
	req.Header.Set("User-Agent", "Argus/1.0")

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
	if resp.StatusCode != http.StatusOK {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	manifestPath := manifestPathForEcosystem(eco, pkgName)
	if manifestPath == "" {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	rawURL := fmt.Sprintf("https://gitlab.com/%s/%s/-/raw/HEAD/%s",
		url.PathEscape(owner), url.PathEscape(repo), manifestPath)
	matched, manifestName, found := v.fetchAndMatchManifest(ctx, eco, pkgName, rawURL, "")
	if !found {
		result.Status = model.VCSStatusInconclusive
		return result, nil
	}

	result.ManifestFound = true
	result.ManifestName = manifestName
	if matched {
		result.Status = model.VCSStatusVerified
	} else {
		result.Status = model.VCSStatusMismatch
	}
	return result, nil
}

func manifestPathForEcosystem(eco model.Ecosystem, pkgName string) string {
	switch eco {
	case model.EcosystemNPM:
		return "package.json"
	case model.EcosystemPyPI:
		return "pyproject.toml"
	case model.EcosystemCargo:
		return "Cargo.toml"
	case model.EcosystemGo:
		return "go.mod"
	case model.EcosystemPackagist:
		return "composer.json"
	case model.EcosystemMaven:
		return "pom.xml"
	case model.EcosystemRubyGems:
		if !isValidRepoSegment(pkgName) {
			return ""
		}
		return pkgName + ".gemspec"
	default:
		return ""
	}
}

func (v *HTTPVerifier) fetchAndMatchManifest(ctx context.Context, eco model.Ecosystem, pkgName, rawURL, token string) (matched bool, manifestName string, found bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return false, "", false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "Argus/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, "", false
	}

	return matchManifestBody(eco, pkgName, body)
}

func matchManifestBody(eco model.Ecosystem, pkgName string, body []byte) (matched bool, manifestName string, found bool) {
	switch eco {
	case model.EcosystemNPM, model.EcosystemPackagist:
		var pkg struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &pkg); err == nil && strings.TrimSpace(pkg.Name) != "" {
			return strings.EqualFold(pkg.Name, pkgName), pkg.Name, true
		}
	case model.EcosystemPyPI, model.EcosystemCargo:
		re := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundName := string(matches[1])
			return strings.EqualFold(foundName, pkgName), foundName, true
		}
	case model.EcosystemGo:
		re := regexp.MustCompile(`(?m)^\s*module\s+([^\s]+)`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundMod := string(matches[1])
			return strings.EqualFold(foundMod, pkgName), foundMod, true
		}
	case model.EcosystemMaven:
		re := regexp.MustCompile(`(?s)<artifactId>\s*([^<\s]+)\s*</artifactId>`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundArtifact := string(matches[1])
			if strings.Contains(pkgName, ":") {
				parts := strings.Split(pkgName, ":")
				return strings.EqualFold(parts[1], foundArtifact), foundArtifact, true
			}
			return strings.EqualFold(pkgName, foundArtifact), foundArtifact, true
		}
	case model.EcosystemRubyGems:
		re := regexp.MustCompile(`(?m)\.name\s*=\s*["']([^"']+)["']`)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			foundName := string(matches[1])
			return strings.EqualFold(foundName, pkgName), foundName, true
		}
		// Never default to verified when .gemspec lacks an explicit .name declaration
		return false, "", false
	}

	return false, "", false
}
