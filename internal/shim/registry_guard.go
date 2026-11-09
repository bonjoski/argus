package shim

import (
	"fmt"
	"strings"
)

var canonicalPublicRegistries = map[string]bool{
	"https://registry.npmjs.org":          true,
	"https://registry.yarnpkg.com":        true,
	"https://pypi.org/simple":             true,
	"https://index.crates.io":             true,
	"sparse+https://index.crates.io":      true,
	"https://proxy.golang.org":            true,
	"https://proxy.golang.org,direct":     true,
	"https://rubygems.org":                true,
	"https://api.nuget.org/v3/index.json": true,
	"https://repo.packagist.org":          true,
}

func isCanonicalRegistryURL(raw string) bool {
	u := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), "/")
	if u == "" || u == "off" {
		return true
	}
	return canonicalPublicRegistries[u]
}

// ValidateRegistryOverrides blocks non-allowlisted custom registry/index flags and environment
// variables so an attacker cannot pass Argus vetting against public npm/PyPI while fetching
// malicious packages from an attacker-controlled registry (ARG-02 registry mismatch attack).
func ValidateRegistryOverrides(tool string, args []string, env []string) error {
	// 1. Inspect CLI arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		lower := strings.ToLower(arg)

		// Unconditionally forbidden flags (secondary index confusion, local wheel dir, TLS downgrade, custom npmrc)
		for _, hardBlocked := range []string{
			"--extra-index-url",
			"--find-links",
			"--trusted-host",
			"--userconfig",
			"--globalconfig",
		} {
			if lower == hardBlocked || strings.HasPrefix(lower, hardBlocked+"=") {
				return fmt.Errorf("registry override flag %q is blocked by Argus security policy", arg)
			}
		}

		// Short -f / -f<dir> on pip/pip3/uv (--find-links)
		if (tool == "pip" || tool == "pip3" || tool == "uv" || tool == "uvx" || tool == "pipx") &&
			(arg == "-f" || (strings.HasPrefix(arg, "-f") && !strings.HasPrefix(arg, "--"))) {
			return fmt.Errorf("registry override flag %q (--find-links) is blocked by Argus security policy", arg)
		}

		// Primary registry flags: allowed ONLY if explicitly pointing to canonical public HTTPS registry
		var flagName, flagVal string
		hasFlag := false

		for _, primary := range []string{
			"--registry",
			"--index-url",
			"--index",
			"--default-index",
			"--source",
			"-source",
		} {
			if lower == primary {
				flagName = arg
				if i+1 < len(args) {
					flagVal = args[i+1]
					i++
				}
				hasFlag = true
				break
			}
			if strings.HasPrefix(lower, primary+"=") {
				flagName = primary
				flagVal = arg[len(primary)+1:]
				hasFlag = true
				break
			}
		}

		if !hasFlag && (arg == "-i" || ((tool == "dotnet" || tool == "nuget" || tool == "bundle" || tool == "gem") && arg == "-s")) {
			flagName = arg
			if i+1 < len(args) {
				flagVal = args[i+1]
				i++
			}
			hasFlag = true
		} else if !hasFlag && (tool == "pip" || tool == "pip3" || tool == "uv" || tool == "uvx" || tool == "pipx") &&
			strings.HasPrefix(arg, "-i") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			flagName = "-i"
			flagVal = arg[2:]
			hasFlag = true
		}

		if hasFlag {
			if flagVal == "" || !isCanonicalRegistryURL(flagVal) {
				return fmt.Errorf("non-allowlisted custom registry %q via %s is blocked by Argus policy", flagVal, flagName)
			}
		}
	}

	// 2. Inspect ambient environment variables
	alwaysBlockedEnv := map[string]bool{
		"PIP_EXTRA_INDEX_URL":   true,
		"UV_EXTRA_INDEX_URL":    true,
		"PIP_FIND_LINKS":        true,
		"UV_FIND_LINKS":         true,
		"PIP_TRUSTED_HOST":      true,
		"NPM_CONFIG_USERCONFIG": true,
		"GONOSUMDB":             true,
	}

	primaryRegistryEnv := map[string]bool{
		"NPM_CONFIG_REGISTRY":              true,
		"YARN_REGISTRY":                    true,
		"YARN_NPM_REGISTRY_SERVER":         true,
		"BUN_CONFIG_REGISTRY":              true,
		"PIP_INDEX_URL":                    true,
		"UV_INDEX_URL":                     true,
		"UV_DEFAULT_INDEX":                 true,
		"CARGO_REGISTRIES_CRATES_IO_INDEX": true,
		"GOPROXY":                          true,
	}

	for _, kv := range env {
		eqIdx := strings.IndexByte(kv, '=')
		if eqIdx <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(kv[:eqIdx]))
		val := strings.TrimSpace(kv[eqIdx+1:])
		if val == "" {
			continue
		}

		if alwaysBlockedEnv[key] {
			return fmt.Errorf("registry override environment variable %s is blocked by Argus policy", key)
		}
		if primaryRegistryEnv[key] && !isCanonicalRegistryURL(val) {
			return fmt.Errorf("non-allowlisted registry override %s=%q is blocked by Argus policy", key, val)
		}
		// npm also honors npm_config_<scope>:registry
		if strings.HasPrefix(key, "NPM_CONFIG_") && strings.HasSuffix(key, "REGISTRY") && !isCanonicalRegistryURL(val) {
			return fmt.Errorf("non-allowlisted scoped npm registry override %s=%q is blocked by Argus policy", key, val)
		}
	}

	return nil
}
