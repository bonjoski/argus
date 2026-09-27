package vcs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestNormalizeRepoURL(t *testing.T) {
	cases := []struct {
		input      string
		wantScheme string
		wantHost   string
		wantOwner  string
		wantRepo   string
		wantErr    bool
	}{
		{"https://github.com/facebook/react", "https", "github.com", "facebook", "react", false},
		{"git+https://github.com/facebook/react.git", "https", "github.com", "facebook", "react", false},
		{"git@github.com:facebook/react.git", "https", "github.com", "facebook", "react", false},
		{"https://gitlab.com/owner/subrepo.git", "https", "gitlab.com", "owner", "subrepo", false},
	}

	for _, c := range cases {
		scheme, host, owner, repo, err := NormalizeRepoURL(c.input)
		if (err != nil) != c.wantErr {
			t.Errorf("NormalizeRepoURL(%q) err = %v, wantErr %v", c.input, err, c.wantErr)
			continue
		}
		if scheme != c.wantScheme || host != c.wantHost || owner != c.wantOwner || repo != c.wantRepo {
			t.Errorf("NormalizeRepoURL(%q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)", c.input, scheme, host, owner, repo, c.wantScheme, c.wantHost, c.wantOwner, c.wantRepo)
		}
	}
}

func TestHTTPVerifier_GenericEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/owner/ratelimited":
			w.WriteHeader(http.StatusForbidden)
		case "/owner/valid":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	v := NewHTTPVerifier(server.Client())
	ctx := context.Background()

	// 1. Missing repo
	res1, _ := v.Verify(ctx, model.EcosystemNPM, "my-pkg", server.URL+"/owner/missing")
	if res1.Status != model.VCSStatusMissing {
		t.Errorf("expected MISSING, got %v", res1.Status)
	}

	// 2. Rate-limited (403) -> Inconclusive (Not penalizing)
	res2, _ := v.Verify(ctx, model.EcosystemNPM, "my-pkg", server.URL+"/owner/ratelimited")
	if res2.Status != model.VCSStatusInconclusive {
		t.Errorf("expected INCONCLUSIVE on 403, got %v", res2.Status)
	}

	// 3. Valid repo
	res3, _ := v.Verify(ctx, model.EcosystemNPM, "my-pkg", server.URL+"/owner/valid")
	if res3.Status != model.VCSStatusVerified {
		t.Errorf("expected VERIFIED on 200, got %v", res3.Status)
	}
}
