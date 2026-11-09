package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bonjoski/argus/internal/model"
)

// ARG-01: Unwrap npm: package aliases and block direct VCS/tarball/URL/file bypass specs.
func TestAdversarial_ARG01_NPMAliasUnwrappingAndDirectVCSBlocking(t *testing.T) {
	name, ver, err := ParseAndValidatePackageSpec(model.EcosystemNPM, "benign-alias@npm:malicious-target@1.2.3")
	if err != nil {
		t.Fatalf("unexpected error unwrapping npm: alias: %v", err)
	}
	if name != "malicious-target" || ver != "1.2.3" {
		t.Fatalf("alias unwrap mismatch: got (%q, %q), want (\"malicious-target\", \"1.2.3\")", name, ver)
	}

	scopedName, scopedVer, err := ParseAndValidatePackageSpec(model.EcosystemNPM, "@safe/wrapper@npm:@evil/dropper@^2.0.0")
	if err != nil {
		t.Fatalf("unexpected error unwrapping scoped npm: alias: %v", err)
	}
	if scopedName != "@evil/dropper" || scopedVer != "^2.0.0" {
		t.Fatalf("scoped alias unwrap mismatch: got (%q, %q)", scopedName, scopedVer)
	}

	blockedSpecs := []struct {
		eco  model.Ecosystem
		spec string
	}{
		{model.EcosystemNPM, "git+ssh://git@github.com/evil/backdoor.git"},
		{model.EcosystemNPM, "git+https://github.com/evil/backdoor.git"},
		{model.EcosystemNPM, "https://attacker.tld/payload.tgz"},
		{model.EcosystemNPM, "http://attacker.tld/payload.tgz"},
		{model.EcosystemNPM, "github:evil/backdoor"},
		{model.EcosystemNPM, "evil/backdoor#main"},
		{model.EcosystemNPM, "file:../local-trojan"},
		{model.EcosystemNPM, "./trojan.tgz"},
		{model.EcosystemNPM, "alias@npm:https://attacker.tld/evil.tgz"},
		{model.EcosystemPyPI, "requests @ https://attacker.tld/requests-99.0-py3-none-any.whl"},
		{model.EcosystemPyPI, "git+https://github.com/evil/pytrojan.git"},
		{model.EcosystemCargo, "https://github.com/evil/crate.git"},
	}

	for _, tc := range blockedSpecs {
		if _, _, bErr := ParseAndValidatePackageSpec(tc.eco, tc.spec); bErr == nil {
			t.Errorf("FAIL-OPEN: expected %s spec %q to be blocked, but succeeded", tc.eco, tc.spec)
		}
	}
}

// ARG-02: Block custom registry/index flags and environment variable overrides in shim execution.
func TestAdversarial_ARG02_RegistryMismatchFlagsAndEnvBlocked(t *testing.T) {
	blockedInvocations := []struct {
		tool string
		args []string
		env  []string
	}{
		{"npm", []string{"install", "--registry", "https://evil-npm.org", "express"}, nil},
		{"npm", []string{"install", "--registry=https://evil-npm.org", "express"}, nil},
		{"npm", []string{"install", "express"}, []string{"NPM_CONFIG_REGISTRY=https://evil-npm.org"}},
		{"npm", []string{"install", "@corp/pkg"}, []string{"npm_config_@corp:registry=https://evil-npm.org"}},
		{"pip", []string{"install", "--index-url", "https://evil-pypi.org/simple", "requests"}, nil},
		{"pip", []string{"install", "-i", "https://evil-pypi.org/simple", "requests"}, nil},
		{"pip", []string{"install", "--extra-index-url", "https://evil-pypi.org/simple", "requests"}, nil},
		{"pip", []string{"install", "--find-links", "/tmp/wheels", "requests"}, nil},
		{"pip", []string{"install", "-f", "/tmp/wheels", "requests"}, nil},
		{"pip", []string{"install", "--trusted-host", "evil-pypi.org", "requests"}, nil},
		{"pip", []string{"install", "requests"}, []string{"PIP_INDEX_URL=https://evil-pypi.org/simple"}},
		{"pip", []string{"install", "requests"}, []string{"PIP_EXTRA_INDEX_URL=https://evil-pypi.org/simple"}},
		{"uv", []string{"pip", "install", "httpx"}, []string{"UV_INDEX_URL=https://evil-pypi.org/simple"}},
	}

	for _, tc := range blockedInvocations {
		if err := ValidateRegistryOverrides(tc.tool, tc.args, tc.env); err == nil {
			t.Errorf("FAIL-OPEN: expected ValidateRegistryOverrides(%s, %v, %v) to block custom registry", tc.tool, tc.args, tc.env)
		}
	}

	// Canonical public HTTPS registries must continue to pass
	if err := ValidateRegistryOverrides("npm", []string{"install", "--registry=https://registry.npmjs.org", "express"}, []string{"NPM_CONFIG_REGISTRY=https://registry.npmjs.org/"}); err != nil {
		t.Errorf("unexpected error for canonical npm registry: %v", err)
	}
	if err := ValidateRegistryOverrides("pip", []string{"install", "-i", "https://pypi.org/simple", "requests"}, []string{"PIP_INDEX_URL=https://pypi.org/simple"}); err != nil {
		t.Errorf("unexpected error for canonical PyPI index: %v", err)
	}
}

// ARG-02: Parse manifests when len(targets) == 0 and fail closed if -r <file> or manifest is missing/poisoned.
func TestAdversarial_ARG02_ManifestVettingAndFailClosed(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing -r requirements.txt MUST fail closed
	if _, _, triggered, err := ExtractManifestTargets("pip", []string{"install", "-r", "nonexistent.txt"}, tmpDir); !triggered || err == nil {
		t.Fatalf("FAIL-OPEN: expected missing -r requirements.txt to fail closed, got triggered=%v err=%v", triggered, err)
	}

	// 2. Embedded --extra-index-url inside requirements.txt MUST fail closed
	poisonedReq := filepath.Join(tmpDir, "poisoned.txt")
	if err := os.WriteFile(poisonedReq, []byte("--extra-index-url https://evil.org/simple\nrequests==2.31.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ExtractManifestTargets("pip", []string{"install", "-r", "poisoned.txt"}, tmpDir); err == nil {
		t.Fatalf("FAIL-OPEN: expected embedded --extra-index-url in requirements.txt to be blocked")
	}

	// 3. Valid requirements.txt extracts all targets
	cleanReq := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(cleanReq, []byte("requests==2.31.0\nflask>=3.0.0 # comment\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, reqSpecs, triggered, err := ExtractManifestTargets("pip", []string{"install", "-r", "requirements.txt"}, tmpDir)
	if err != nil || !triggered || len(reqSpecs) != 2 {
		t.Fatalf("expected 2 specs from requirements.txt, got %v (err=%v)", reqSpecs, err)
	}

	// 4. Bare npm install / npm ci parses package.json
	pkgJSON := `{"dependencies":{"express":"^4.18.2"},"devDependencies":{"mal-alias":"npm:slopsquat-pkg@1.0.0"}}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	_, npmSpecs, triggered, err := ExtractManifestTargets("npm", []string{"ci"}, tmpDir)
	if err != nil || !triggered || len(npmSpecs) != 2 {
		t.Fatalf("expected 2 specs from package.json on npm ci, got %v (err=%v)", npmSpecs, err)
	}

	// 5. cargo build parses Cargo.toml (including package rename aliases)
	cargoTOML := "[package]\nname = \"demo\"\n[dependencies]\nserde = \"1.0\"\n Sneaky = { version = \"0.1\", package = \"real-mal-crate\" }\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte(cargoTOML), 0600); err != nil {
		t.Fatal(err)
	}
	_, cargoSpecs, triggered, err := ExtractManifestTargets("cargo", []string{"build"}, tmpDir)
	if err != nil || !triggered || len(cargoSpecs) != 2 {
		t.Fatalf("expected 2 specs from Cargo.toml on cargo build, got %v (err=%v)", cargoSpecs, err)
	}
}

// ARG-02: Intercept ephemeral runners and hardcode absolute argus binary path in shim scripts.
func TestAdversarial_ARG02_EphemeralRunnersAndHardcodedShimBinary(t *testing.T) {
	ephemeralCases := []struct {
		tool    string
		args    []string
		wantEco model.Ecosystem
		wantPkg string
	}{
		{"npx", []string{"-y", "slopsquat-cli@1.0.0", "--port", "8080"}, model.EcosystemNPM, "slopsquat-cli@1.0.0"},
		{"pnpm", []string{"dlx", "create-evil-app"}, model.EcosystemNPM, "create-evil-app"},
		{"uvx", []string{"--from", "evil-runner", "entry"}, model.EcosystemPyPI, "evil-runner"},
		{"pipx", []string{"run", "hallucinated-tool"}, model.EcosystemPyPI, "hallucinated-tool"},
		{"go", []string{"run", "github.com/attacker/trojan@latest"}, model.EcosystemGo, "github.com/attacker/trojan@latest"},
		{"cargo", []string{"install", "evil-crate-cli"}, model.EcosystemCargo, "evil-crate-cli"},
	}

	for _, tc := range ephemeralCases {
		eco, targets, isInstall := ExtractTargets(tc.tool, tc.args)
		if !isInstall || eco != tc.wantEco || len(targets) == 0 || targets[0] != tc.wantPkg {
			t.Errorf("ExtractTargets(%s, %v) = (%s, %v, %v), want (%s, [%s], true)",
				tc.tool, tc.args, eco, targets, isInstall, tc.wantEco, tc.wantPkg)
		}
	}

	// Verify generated shim script hardcodes absolute path and NEVER honors caller ARGUS_BIN
	shimDir := t.TempDir()
	if err := Install(shimDir, "/usr/local/bin/argus"); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	scriptBytes, err := os.ReadFile(filepath.Join(shimDir, "npm"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)
	if strings.Contains(script, "ARGUS_BIN") || strings.Contains(script, "command -v") {
		t.Fatalf("SECURITY BYPASS: shim script still honors mutable ARGUS_BIN / PATH fallback:\n%s", script)
	}
	if !strings.Contains(script, "exec '/usr/local/bin/argus' shim exec npm \"$@\"") {
		t.Fatalf("expected immutable absolute exec line in shim script, got:\n%s", script)
	}
}
