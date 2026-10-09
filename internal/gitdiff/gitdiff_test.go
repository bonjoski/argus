package gitdiff

import (
	"context"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestParseDiffAndExtractImports(t *testing.T) {
	rawDiff := `diff --git a/app.py b/app.py
index abc..def 100644
--- a/app.py
+++ b/app.py
@@ -10,3 +10,6 @@ def init():
     pass
+import os
+import requests_jwt_validator
+from sklearn.cluster import KMeans
 def run():
     pass
diff --git a/server.js b/server.js
index 111..222 100644
--- a/server.js
+++ b/server.js
@@ -1,4 +1,6 @@
 const path = require('path');
+const phantom = require('express-auth-phantom');
+import express from 'express';
 function start() {}
diff --git a/cmd/main.go b/cmd/main.go
index 333..444 100644
--- a/cmd/main.go
+++ b/cmd/main.go
@@ -5,2 +5,4 @@ import (
 	"fmt"
+	"github.com/phantom/fake-pkg"
+	"github.com/gin-gonic/gin"
 )
`

	candidates, err := ExtractImportsFromDiff(strings.NewReader(rawDiff))
	if err != nil {
		t.Fatalf("unexpected diff extraction error: %v", err)
	}

	expected := map[string]model.Ecosystem{
		"requests_jwt_validator":      model.EcosystemPyPI,
		"scikit-learn":                model.EcosystemPyPI,
		"express-auth-phantom":        model.EcosystemNPM,
		"express":                     model.EcosystemNPM,
		"github.com/phantom/fake-pkg": model.EcosystemGo,
		"github.com/gin-gonic/gin":    model.EcosystemGo,
	}

	found := make(map[string]model.Ecosystem)
	for _, c := range candidates {
		found[c.PackageName] = c.Ecosystem
	}

	for pkg, eco := range expected {
		if gotEco, ok := found[pkg]; !ok {
			t.Errorf("expected import %q to be extracted from diff", pkg)
		} else if gotEco != eco {
			t.Errorf("expected package %q to have ecosystem %v, got %v", pkg, eco, gotEco)
		}
	}

	// Verify stdlib imports like 'os', 'path', 'fmt' were excluded
	if _, ok := found["os"]; ok {
		t.Errorf("stdlib 'os' must not be in extracted candidates")
	}
	if _, ok := found["path"]; ok {
		t.Errorf("stdlib 'path' must not be in extracted candidates")
	}
	if _, ok := found["fmt"]; ok {
		t.Errorf("stdlib 'fmt' must not be in extracted candidates")
	}
}

type mockGitRunner struct {
	diffData []byte
}

func (m *mockGitRunner) Diff(ctx context.Context, workDir string, cached bool) ([]byte, error) {
	return m.diffData, nil
}

func TestInspectDiffWithMockRunner(t *testing.T) {
	mockData := `diff --git a/script.py b/script.py
new file mode 100644
--- /dev/null
+++ b/script.py
@@ -0,0 +1,2 @@
+import requests_jwt_validator
+print("hi")
`
	runner := &mockGitRunner{diffData: []byte(mockData)}
	candidates, err := InspectDiff(context.Background(), runner, "", true)
	if err != nil {
		t.Fatalf("InspectDiff failed: %v", err)
	}

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	if candidates[0].PackageName != "requests_jwt_validator" {
		t.Errorf("expected requests_jwt_validator, got %s", candidates[0].PackageName)
	}
}
