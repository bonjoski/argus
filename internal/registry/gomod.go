package registry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"bonjoski/argus/internal/model"
)

// GoModAdapter queries the Go Proxy (proxy.golang.org) and Checksum DB (sum.golang.org).
type GoModAdapter struct {
	client   *http.Client
	proxyURL string
	sumURL   string
}

// NewGoModAdapter creates a new GoModAdapter with standard timeouts.
func NewGoModAdapter(client *http.Client) *GoModAdapter {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	return &GoModAdapter{
		client:   client,
		proxyURL: "https://proxy.golang.org",
		sumURL:   "https://sum.golang.org",
	}
}

// SetProxyURL overrides proxy.golang.org endpoint (for testing).
func (a *GoModAdapter) SetProxyURL(u string) {
	a.proxyURL = strings.TrimRight(u, "/")
}

// SetSumURL overrides sum.golang.org endpoint (for testing).
func (a *GoModAdapter) SetSumURL(u string) {
	a.sumURL = strings.TrimRight(u, "/")
}

// Ecosystem returns model.EcosystemGo.
func (a *GoModAdapter) Ecosystem() model.Ecosystem {
	return model.EcosystemGo
}

type goModInfoDoc struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// FetchProvenance inspects Go proxy metadata, checksum DB inclusion, and repository origin.
func (a *GoModAdapter) FetchProvenance(ctx context.Context, pkgName, version string) (*model.PackageProvenance, string, error) {
	escapedMod := escapeModulePath(pkgName)

	targetVersion := version
	var releaseTime time.Time

	// 1. Resolve Target Version and Timestamp
	if targetVersion == "" || targetVersion == "latest" {
		latestURL := fmt.Sprintf("%s/%s/@latest", a.proxyURL, escapedMod)
		req, err := http.NewRequestWithContext(ctx, "GET", latestURL, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create @latest request: %w", err)
		}
		req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

		resp, err := a.client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("failed to query go proxy @latest: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, "", fmt.Errorf("module %q not found on go proxy", pkgName)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("go proxy returned HTTP %d for @latest", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, "", fmt.Errorf("failed to read @latest body: %w", err)
		}

		var info goModInfoDoc
		if err := json.Unmarshal(body, &info); err != nil {
			return nil, "", fmt.Errorf("failed to parse @latest json: %w", err)
		}
		targetVersion = info.Version
		releaseTime = info.Time
	} else {
		// Normalise version tag if missing 'v'
		if !strings.HasPrefix(targetVersion, "v") {
			targetVersion = "v" + targetVersion
		}
		infoURL := fmt.Sprintf("%s/%s/@v/%s.info", a.proxyURL, escapedMod, escapeModulePath(targetVersion))
		req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create version info request: %w", err)
		}
		req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

		resp, err := a.client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("failed to query go proxy version info: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, "", fmt.Errorf("module %q version %q not found on go proxy", pkgName, targetVersion)
		}
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err == nil {
				var info goModInfoDoc
				if err := json.Unmarshal(body, &info); err == nil {
					releaseTime = info.Time
				}
			}
		}
	}

	// 2. Fetch Version List for Release Velocity
	totalReleases := 1
	var firstReleaseTime time.Time
	listURL := fmt.Sprintf("%s/%s/@v/list", a.proxyURL, escapedMod)
	if req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil); err == nil {
		req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")
		if resp, err := a.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				scanner := bufio.NewScanner(io.LimitReader(resp.Body, 2*1024*1024))
				count := 0
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" {
						count++
					}
				}
				if count > 0 {
					totalReleases = count
				}
			}
		}
	}

	prov := &model.PackageProvenance{
		Name:              pkgName,
		Ecosystem:         model.EcosystemGo,
		ResolvedVersion:   targetVersion,
		FirstReleaseDate:  firstReleaseTime,
		LatestReleaseDate: releaseTime,
		TotalReleases:     totalReleases,
		TarballURL:        fmt.Sprintf("%s/%s/@v/%s.zip", a.proxyURL, escapedMod, escapeModulePath(targetVersion)),
	}

	if prov.FirstReleaseDate.IsZero() {
		prov.FirstReleaseDate = releaseTime
	}

	// 3. Query Checksum Database (sum.golang.org)
	prov.InGoChecksumDB, prov.IntegrityHash = a.lookupChecksumDB(ctx, pkgName, targetVersion)

	// 4. Resolve VCS Repository URL and Author
	prov.RepositoryURL, prov.AuthorName = a.resolveVCS(ctx, pkgName)

	return prov, "", nil
}

// lookupChecksumDB queries sum.golang.org/lookup/{module}@{version} to verify cryptographic inclusion.
func (a *GoModAdapter) lookupChecksumDB(ctx context.Context, module, version string) (bool, string) {
	lookupURL := fmt.Sprintf("%s/lookup/%s@%s", a.sumURL, escapeModulePath(module), escapeModulePath(version))
	req, err := http.NewRequestWithContext(ctx, "GET", lookupURL, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, ""
	}

	// Extract go.sum entry hash
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	var integrityHash string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 3 && !strings.Contains(parts[1], "/go.mod") {
			integrityHash = parts[2]
			break
		}
	}

	return true, integrityHash
}

// resolveVCS extracts repository URL and maintainer author from module name or vanity import meta tags.
func (a *GoModAdapter) resolveVCS(ctx context.Context, module string) (string, string) {
	parts := strings.Split(module, "/")
	if len(parts) >= 3 {
		host := parts[0]
		if host == "github.com" || host == "gitlab.com" || host == "bitbucket.org" {
			repoURL := fmt.Sprintf("https://%s/%s/%s", host, parts[1], parts[2])
			return repoURL, parts[1]
		}
	}

	// For vanity imports (e.g. go.uber.org/zap), probe HTML with ?go-get=1
	vanityURL := fmt.Sprintf("https://%s?go-get=1", module)
	req, err := http.NewRequestWithContext(ctx, "GET", vanityURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Argus-Vetpkg/1.0")
		if resp, err := a.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				if err == nil {
					re := regexp.MustCompile(`<meta\s+name=["']go-import["']\s+content=["']([^"']+)["']`)
					matches := re.FindSubmatch(body)
					if len(matches) > 1 {
						fields := strings.Fields(string(matches[1]))
						if len(fields) >= 3 {
							return fields[2], parts[0]
						}
					}
				}
			}
		}
	}

	return "https://" + module, parts[0]
}

// escapeModulePath replaces uppercase ASCII characters with '!' followed by lowercase.
// Complies with Go proxy specification (golang.org/x/mod/module.EscapePath).
func escapeModulePath(path string) string {
	var sb strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			sb.WriteRune('!')
			sb.WriteRune(r + ('a' - 'A'))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
