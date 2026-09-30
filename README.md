<p align="center">
  <img src="https://raw.githubusercontent.com/bonjoski/argus/main/docs/assets/argus-banner.png" alt="Argus Banner" width="600" onerror="this.style.display='none'"/>
</p>

<h1 align="center">Argus (vetpkg)</h1>

<p align="center">
  <strong>Zero-SaaS Pre-Flight Dependency Provenance Interceptor & AI Slopsquatting Defense</strong>
</p>

<p align="center">
  <a href="https://github.com/bonjoski/argus/actions/workflows/ci.yml"><img src="https://github.com/bonjoski/argus/actions/workflows/ci.yml/badge.svg" alt="CI Pipeline Status"/></a>
  <a href="https://github.com/bonjoski/argus/releases/latest"><img src="https://img.shields.io/github/v/release/bonjoski/argus?color=blue&label=release" alt="Latest Release"/></a>
  <a href="https://github.com/bonjoski/argus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"/></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.27.1-blue.svg" alt="Go Version"/></a>
  <a href="https://sigstore.dev"><img src="https://img.shields.io/badge/cosign-keyless--signed-blueviolet.svg" alt="Cosign Keyless Signed"/></a>
</p>

---

## 📖 Table of Contents

- [What is Argus?](#-what-is-argus)
- [Why is Argus Needed? The Threat Landscape](#-why-is-argus-needed-the-threat-landscape)
- [How Argus Works (Architecture)](#-how-argus-works-architecture)
- [Supported Ecosystems (11 Registries)](#-supported-ecosystems-11-registries)
- [Installation](#-installation)
  - [Pre-Built Binaries (Recommended)](#1-pre-built-binaries-recommended)
  - [Cryptographic Verification via Sigstore Cosign](#2-cryptographic-verification-via-sigstore-cosign)
  - [Via Go Toolchain](#3-via-go-toolchain)
  - [Build from Source](#4-build-from-source)
- [Quickstart Guide](#-quickstart-guide)
  - [1. Single Package Provenance Vetting](#1-single-package-provenance-vetting)
  - [2. Lockfile Transitive Scan (CI/CD)](#2-lockfile-transitive-scan-cicd)
  - [3. Agent Subshell Protection via PATH Shims](#3-agent-subshell-protection-via-path-shims)
  - [4. Sub-Millisecond Resident IPC Daemon](#4-sub-millisecond-resident-ipc-daemon)
  - [5. Transparent Inline Registry Mirror Proxy](#5-transparent-inline-registry-mirror-proxy)
  - [6. Dynamic Install-Script Sanitization & Quarantine](#6-dynamic-install-script-sanitization--quarantine)
  - [7. Hardware-Isolated Process & Network Sandboxing](#7-hardware-isolated-process--network-sandboxing)
- [Scoring Heuristics & Offsets](#-scoring-heuristics--offsets)
- [Enterprise Policy Configuration (`.argusrc.yaml`)](#-enterprise-policy-configuration-argusrcyaml)
- [CI/CD & GitHub Actions Integration](#-cicd--github-actions-integration)
- [Adversarial Verification Suite](#-adversarial-verification-suite)
- [Contributing & Development](#-contributing--development)
- [License](#-license)

---

## 👁️ What is Argus?

**Argus (`vetpkg`)** is a fast, sovereign, zero-SaaS CLI security engine, resident daemon, and transparent network interceptor designed to evaluate package provenance and halt malicious, hallucinated, or slopsquatted dependencies **before** package managers write them to disk or execute dangerous install-time lifecycle hooks.

Unlike traditional Software Composition Analysis (SCA) tools that look up known CVEs in stale vulnerability databases, Argus analyzes **real-time provenance and behavioural signals** directly from authoritative package registries (npm, PyPI, Crates.io, Go Proxy, NuGet, etc.) and upstream VCS repositories.

### 🛡️ Core Tenets

* 🌐 **Zero-SaaS & Sovereign Execution:** Zero telemetry, no proprietary cloud APIs, and zero metadata leakage. All intelligence is computed locally from upstream registries and cryptographic trust roots.
* ⚡ **Sub-Millisecond Vetting:** Hot in-memory SQLite and trie caches resolve warm queries in **<1ms** (~220µs over local IPC socket); cold upstream probes complete in **<800ms**.
* 🛡️ **Autonomous Agent Armor:** Intercepts both interactive terminal commands and headless subshell invocations (`sh -c "npm install ..."` or `pip install ...`) initiated by AI coding assistants.
* 🔒 **Hardware-Enforced Isolation:** Enforces Apple Seatbelt (`sandbox-exec`) and Linux Landlock LSM security boundaries during unvetted executions.

---

## 🎯 Why is Argus Needed? The Threat Landscape

The emergence of AI pair-programmers and autonomous coding agents (Claude Code, Cursor, Copilot, Cline, Codex) has triggered a fundamental shift in software supply chain vulnerabilities:

```
+------------------------------------+
|  Autonomous AI Coding Agent / Dev  |
| "I'll install 'fast-jwt-helper'..."|
+------------------------------------+
                  |
                  | 1. LLM Hallucinates Non-Existent Package
                  v
+------------------------------------+
|     Adversarial Slopsquatting      |
|  Attacker scrapes LLM outputs and  |
|  registers 'fast-jwt-helper' with  |
|     malicious postinstall hook     |
+------------------------------------+
                  |
                  | 2. Agent runs: npm install fast-jwt-helper
                  v
+------------------------------------+        +----------------------------------+
|           WITHOUT ARGUS            |        |            WITH ARGUS            |
| • Package manager fetches tarball  |   vs   | • Argus interceptor computes     |
| • Malicious install script runs    |        |   risk score: 90/100 (CRITICAL)  |
| • ~/.ssh & env secrets exfiltrated |        | • INSTALL HALTED PRE-FLIGHT      |
| • Machine compromised              |        | • Tarball quarantined & stripped |
+------------------------------------+        +----------------------------------+
```

### 1. AI Package Hallucinations
Large Language Models frequently hallucinate package names that sound plausible (e.g., `flask-jwt-auth-helper`, `react-dropzone-uploader-v2`, `crypto-token-utils`).

### 2. Deterministic Slopsquatting
Adversaries run automated honeypots and scrapers to capture common LLM package hallucination patterns, rapidly registering these empty or weaponized names on public registries.

### 3. Install-Time Execution Vulnerabilities
Package managers execute arbitrary shell scripts immediately upon package download (`preinstall`, `postinstall`, `setup.py`, `build.rs`). By the time a traditional static analyzer or linter inspects `node_modules/`, the attacker's payload has already executed and exfiltrated developer credentials, SSH keys, and cloud tokens.

**Argus stops this entire attack chain at the boundary before code is ever downloaded or extracted.**

---

## 🏗️ How Argus Works (Architecture)

Argus offers multiple layers of defense depending on your development environment:

```
                            +------------------------------------+
                            |    Developer / Autonomous Agent    |
                            | (sh -c "npm/pip/cargo/gem/composer")|
                            +------------------------------------+
                                              |
                     +------------------------+------------------------+
                     | (PATH Interception)                             | (HTTP Proxy)
                     v                                                 v
    +------------------------------------+            +------------------------------------+
    |      PATH-Prepend Proxy Shims      |            |    Inline Registry Mirror Proxy    |
    |  (~/.argus/bin/npm, pip, gem ...)  |            |   (localhost:8080/npm, /pypi ...)  |
    +------------------------------------+            +------------------------------------+
                     |                                                 |
                     +------------------------+------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |   Enterprise Policy Engine    |
                              |  (.argusrc Allow/Blocklists)  |
                              +-------------------------------+
                                              |
                     +------------------------+------------------------+
                     | (Daemon Active: <1ms)                           | (Standalone Fallback)
                     v                                                 v
      +-----------------------------+                   +-----------------------------+
      |  Resident IPC Daemon Server |                   |      Local SQLite Cache     |
      | (~/.argus/argus.sock 0600)  |                   | (TTL 24h, Seed/Export)      |
      +-----------------------------+                   +-----------------------------+
                     \                                                 /
                      +-----------------------+-----------------------+
                                              | (Cache Miss)
                                              v
                              +-------------------------------+
                              |  Upstream Registry Adapters   |
                              |    (11 Supported Registries)  |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    Reciprocal VCS Verifier    |
                              |  (Two-Way Manifest Matching)  |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |   Pre-Flight AST Inspector    |
                              |  (In-Memory Stream Scanning)  |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |   Lexical Conflation Engine   |
                              | (Trie + 11 Ecosystem Corpora) |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    Scoring Engine (0 - 100)   |
                              | Penalties (HR) - Offsets (MO) |
                              +-------------------------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
          [Score < 30: ALLOW]                             [Score >= 80: HARD BLOCK]
```

---

## 📦 Supported Ecosystems (11 Registries)

Argus supports **11 package ecosystems** natively with dedicated ground-truth registry adapters and lockfile parsers:

| Ecosystem | Toolchain Commands | Registry Queried | Lockfile Formats Supported | Key Telemetry Verified |
| :--- | :--- | :--- | :--- | :--- |
| **NPM** | `npm`, `npx`, `pnpm`, `yarn`, `bun` | `registry.npmjs.org` | `package-lock.json`, `npm-shrinkwrap.json` | Sigstore OIDC, Weekly Downloads, Release Velocity, Install Scripts |
| **PyPI** | `pip`, `pip3`, `poetry`, `uv` | `pypi.org` | `poetry.lock`, `Pipfile.lock` | PEP 740 Attestations, Binary Wheel Distributions, Upload Timestamps |
| **Crates.io** | `cargo`, `cargo-add` | `crates.io/api/v1` | `Cargo.lock` | Token-bucket rate limiting (1 req/sec), Exact crate hash, Downloads |
| **Go Modules** | `go get`, `go install` | `proxy.golang.org`, `sum.golang.org` | `go.sum` | Cryptographic Checksum DB transparency, Vanity import redirection |
| **RubyGems** | `gem`, `bundle` | `rubygems.org` | `Gemfile.lock` | SHA-256 digests, Version chronology, Author profiles |
| **Maven Central** | `mvn`, `gradle` | `repo1.maven.org/maven2` | `pom.xml`, `gradle.lockfile` | PGP signatures, Group ID naming structure, Solr search indexing |
| **Packagist** | `composer` | `repo.packagist.org` | `composer.lock` | Composer v2 metadata, GitHub security advisories, Vendor namespaces |
| **NuGet** | `dotnet add`, `nuget` | `api.nuget.org/v3` | `packages.lock.json` | Semver registration catalogs, Total downloads, Project URLs |
| **Pub** | `dart pub`, `flutter pub` | `pub.dev/api` | `pubspec.lock` | Package popularity score, Verified publisher badge, Dart/Flutter SDK constraints |
| **Hex** | `mix hex`, `mix deps.get` | `hex.pm/api` | `mix.lock` | Hex package checksums, Download counters, GitHub repo binding |
| **Swift (SPM)** | `swift package` | Swift Package Index / Git | `Package.resolved` (v1, v2, v3) | Release tags, Semantic version pins, Package manifests |

---

## 📥 Installation

### 1. Pre-Built Binaries (Recommended)

Download the latest pre-compiled binary for your operating system and architecture from the [Releases Page](https://github.com/bonjoski/argus/releases/latest):

```bash
# macOS (Apple Silicon - M1/M2/M3/M4)
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/argus_0.5.0_darwin_arm64.tar.gz
tar -xzf argus_0.5.0_darwin_arm64.tar.gz
sudo mv argus /usr/local/bin/

# macOS (Intel)
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/argus_0.5.0_darwin_amd64.tar.gz
tar -xzf argus_0.5.0_darwin_amd64.tar.gz
sudo mv argus /usr/local/bin/

# Linux (x86_64)
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/argus_0.5.0_linux_amd64.tar.gz
tar -xzf argus_0.5.0_linux_amd64.tar.gz
sudo mv argus /usr/local/bin/

# Linux (ARM64 / Graviton / Raspberry Pi)
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/argus_0.5.0_linux_arm64.tar.gz
tar -xzf argus_0.5.0_linux_arm64.tar.gz
sudo mv argus /usr/local/bin/
```

### 2. Cryptographic Verification via Sigstore Cosign

All official Argus release binaries are keylessly signed via **Sigstore Cosign** using GitHub Actions OIDC identity. You can cryptographically verify that the binary was compiled directly by the official workflow without importing any keys:

```bash
# Download checksum and signature files
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/checksums.txt
curl -LO https://github.com/bonjoski/argus/releases/download/v0.5.0/checksums.txt.sig

# Verify signature against Sigstore transparency log (Rekor / Fulcio)
cosign verify-blob \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "^https://github.com/bonjoski/argus/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# Verify archive integrity
sha256sum -c checksums.txt --ignore-missing
```

### 3. Via Go Toolchain

```bash
go install bonjoski/argus/cmd/argus@v0.5.0
```

### 4. Build from Source

```bash
git clone https://github.com/bonjoski/argus.git
cd argus
make all
sudo make install
```

---

## 🚀 Quickstart Guide

### 1. Single Package Provenance Vetting

Inspect any package across all 11 ecosystems before installing:

```bash
# Vet an npm package
argus vet npm express

# Vet a specific version with strict threshold
argus vet npm @angular/core@17.0.0 --strict

# Vet PyPI package and output OASIS SARIF v2.1.0 report
argus vet pypi requests --sarif

# Vet Crates.io crate with JSON diagnostics
argus vet cargo serde --json

# Vet Go module
argus vet go github.com/gin-gonic/gin

# Vet .NET NuGet package
argus vet nuget Newtonsoft.Json

# Vet Dart/Flutter Pub package
argus vet pub flutter_bloc

# Vet Elixir Hex package
argus vet hex phoenix
```

#### Example Output:
```
 ARGUS VET  npm : fast-jwt-auth-helper@1.0.0

  Risk Score:    85/100 (CRITICAL)
  Recommendation: HARD BLOCK

  Threat Penalties:
    [+35] Fresh Release (HR-01): Package published 2 days ago (peak hallucination window)
    [+15] Single Version Trap (HR-03): Only 1 release published lifetime
    [+15] Negligible Adoption (HR-04): 12 weekly downloads (<100 threshold)
    [+20] Detached VCS Repo (HR-05A): Declared repository returned HTTP 404

  Mitigating Offsets:
    None

⛔ Package risk score meets or exceeds blocking threshold (85 >= 50).
```

---

### 2. Lockfile Transitive Scan (CI/CD)

Scan your entire project lockfile (including deeply nested transitive dependencies) for hallucinated or malicious components:

```bash
# Scan npm package-lock.json
argus scan package-lock.json

# Scan Cargo.lock in strict mode
argus scan Cargo.lock --strict

# Scan go.sum and export SARIF report for GitHub Code Scanning
argus scan go.sum --sarif > argus-results.sarif

# Scan Python poetry.lock, NuGet packages.lock.json, or mix.lock
argus scan poetry.lock
argus scan packages.lock.json
argus scan mix.lock
```

---

### 3. Agent Subshell Protection via PATH Shims

Autonomous AI coding agents (such as Cursor, Claude Code, or local LLM wrappers) execute package managers inside subshells (`sh -c "npm install <pkg>"`).

Install Argus PATH proxy shims to intercept package manager commands transparently:

```bash
# Install shims to ~/.argus/bin/ and prepend to shell PATH
argus shim install

# Check active interception shims
argus shim status
```

Now, when any developer or AI subshell runs:
```bash
npm install suspicious-hallucinated-package
```
The Argus shim intercepts the command, vets the package pre-flight, and halts execution if the risk score exceeds policy thresholds.

To remove shims:
```bash
argus shim remove
```

---

### 4. Sub-Millisecond Resident IPC Daemon

Keep an Argus SQLite connection pool and in-memory trie structures hot in RAM to achieve **sub-millisecond (<1ms)** pre-flight vetting:

```bash
# Start background resident daemon
argus daemon start

# Check daemon health and response latency
argus daemon ping
argus daemon status

# Stop daemon
argus daemon stop
```

When the daemon is active, shims and CLI queries automatically route through `~/.argus/argus.sock` (`0600` permissions) with seamless fallback to in-process execution if the daemon is offline.

---

### 5. Transparent Inline Registry Mirror Proxy

Intercept package manager traffic directly at the HTTP layer. Ideal for local development, Docker containers, and CI runners:

```bash
# Start mirror proxy server on port 8080 (as a background daemon)
argus mirror start --port 8080 --daemon

# Point your package managers to the mirror:
npm config set registry http://localhost:8080/npm
pip config set global.index-url http://localhost:8080/pypi/simple/

# Check mirror metrics and intercepted requests:
argus mirror status

# Stop mirror proxy
argus mirror stop
```

**Zero-Leak Invariant:** When a blocked package is requested, Argus immediately returns **`HTTP 403 Forbidden`** with a structured diagnostic payload. The malicious tarball is **never requested from upstream or streamed to the client**.

---

### 6. Dynamic Install-Script Sanitization & Quarantine

Neutralize dangerous lifecycle execution hooks (`preinstall`, `postinstall`, `build.rs`, `setup.py`) from package archives before extraction:

```bash
# Sanitize an npm package tarball, stripping malicious install hooks
argus sanitize malicious-pkg.tgz --out safe-pkg.tgz --quarantine

# Inspect quarantined archives in the forensics store (~/.argus/quarantine/)
argus quarantine list
argus quarantine inspect <quarantine-id>

# Safely purge quarantine store
argus quarantine purge
```

---

### 7. Hardware-Isolated Process & Network Sandboxing

Execute untrusted commands, build scripts, or agent sub-processes inside hardware-enforced system sandboxes (Apple Seatbelt on macOS, Landlock LSM on Linux):

```bash
# Run untrusted install script inside sandbox (blocks ~/.ssh, /etc, .git, and env secrets)
argus sandbox run -- npm install

# Allow temporary workdir writes while blocking all outbound network traffic
argus sandbox run --workdir ./workspace -- node test.js

# Allow network access explicitly
argus sandbox run --allow-net -- pip install requests

# View the generated platform sandbox profile
argus sandbox profile
```

---

## ⚖️ Scoring Heuristics & Offsets

Argus computes a balanced risk score on a scale of `0 – 100`:

$$\text{Final Risk Score} = \text{clamp}\left(0, 100, \sum \text{Penalties} - \sum \text{Offsets}\right)$$

### 🚨 Threat Penalties

| Rule ID | Rule Name | Points | Condition & Description |
| :--- | :--- | :---: | :--- |
| `HR-01` | **Fresh Release** | `+35` | Package first published $\le 7$ days ago (peak slopsquatting window). |
| `HR-02` | **Infant Package** | `+20` | Package first published between 8 and 30 days ago. |
| `HR-03` | **Single Version Trap** | `+15` | Package has published exactly 1 version lifetime (common for squat payloads). |
| `HR-04` | **Negligible Adoption** | `+15` | Low weekly downloads, unindexed crate, or missing binary wheel distribution. |
| `HR-05A` | **Detached VCS Repo** | `+20` | Declared repository link is missing, returns HTTP 404, or is empty. |
| `HR-05B` | **Spoofed VCS Impersonation** | `+35` | Points to a valid repository, but reciprocal manifest names a different package. |
| `HR-06` | **Lexical Conflation** | `+25` | Synthesizes high-reputation ecosystem names or typosquats top packages. |
| `HR-07` | **Author Ephemerality** | `+15` | Maintainer account created $<30$ days before package publication. |
| `HR-08` | **Sudden Sleeper** | `+25` | Inactive/dormant package suddenly publishes an unexpected release. |
| `HR-09` | **Install Lifecycle Hooks** | `+30` | Declares `preinstall`/`postinstall` scripts in unvetted package. |
| `HR-10` | **Suspicious Static AST** | `+35` | AST inspection detects obfuscated `eval()`, `execSync()`, or network reverse shells. |

### 🛡️ Reputational Mitigating Offsets

| Offset ID | Offset Name | Credits | Condition & Description |
| :--- | :--- | :---: | :--- |
| `MO-01` | **Cryptographic Attestation** | `-40` | Sigstore OIDC, GitHub Actions provenance, or PEP 740 digital attestation present. |
| `MO-02` | **Established Author Anchor** | `-30` | Maintainer account established $>1$ year with $\ge 3$ active packages. |
| `MO-03` | **Reciprocal VCS Match** | `-25` | Two-way verified source repository with $\ge 6$ months history and matching manifest. |
| `MO-04` | **Approved Namespace** | `-20` | Standard ecosystem extension convention (e.g. `pytest-*`, `@types/*`, `System.*`). |
| `MO-05` | **Clean Provenance Profile** | `-10` | Conforms to modern distribution standards (no scripts, binary wheels, in Checksum DB). |

---

## ⚙️ Enterprise Policy Configuration (`.argusrc.yaml`)

Place an `.argusrc.yaml` file in your repository root or home directory (`~/.argusrc.yaml`) to enforce organization-wide governance:

```yaml
version: 1
threshold: 50
strict: false

# Approved internal scopes and trusted third-party dependencies
allowlist:
  packages:
    - "@mycorp/*"
    - "mycorp-internal-*"
    - "express"
    - "react"
  authors:
    - "google"
    - "microsoft"
    - "torvalds"

# Immediate hard-blocks regardless of computed score
blocklist:
  packages:
    - "malicious-crypto-miner"
    - "flatmap-stream"
  patterns:
    - "*cryptominer*"
    - "*-exfiltrator"
```

---

## 🤖 CI/CD & GitHub Actions Integration

Use the official composite GitHub Action in `.github/workflows/security.yml`:

```yaml
name: Supply Chain Pre-Flight Gate

on: [push, pull_request]

jobs:
  argus-gate:
    name: Argus Dependency Provenance Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Argus Scan
        uses: bonjoski/argus@v0.5.0
        with:
          lockfile: package-lock.json
          threshold: 50
          strict: true
          comment-pr: true
          export-sarif: true
          sarif-file: argus-results.sarif

      - name: Upload SARIF to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: argus-results.sarif
```

---

## 🧪 Adversarial Verification Suite

Argus maintains a **20-point Red Team Adversarial Suite** (`ADV-01` through `ADV-20`) to guarantee that edge-case exploits and evasion techniques are blocked:

| Test ID | Adversarial Bypass Target | Verification Strategy |
| :--- | :--- | :--- |
| `ADV-01` | The 31-Day Sleeper | Multi-signal velocity thresholding |
| `ADV-02` | Fake VCS Impersonation | Reciprocal 2-way manifest checking |
| `ADV-03` | GitHub 403 Secondary Rate Limiting | Graceful degradation to registry signals |
| `ADV-04` | Day-One Legitimate False-Positive | Author reputation offset crediting |
| `ADV-05` | Non-Interactive Agent Subshell | Headless PATH proxy interception |
| `ADV-06` | PyPI Signals Without Phantom Download API | Release chronology & wheel ratio heuristics |
| `ADV-07` | Go Checksum DB Tampering | Cryptographic `sum.golang.org` lookup |
| `ADV-08` | Crates.io API Throttling | Token-bucket client-side rate limiter |
| `ADV-09` | Plugin Prefix Typosquat Collision | Approved namespace prefix exemptions |
| `ADV-10` | Transitive Dependency Hiding | Full lockfile closure tree inspection |
| `ADV-11` | TOCTOU Pinned Version Mutation | Exact hash and immutable tag locking |
| `ADV-12` | Cache Poisoning Exploitation | Composite `(pkg, version, hash)` cache key |
| `ADV-13` | Private Scope Typosquatting | Scope isolation boundary enforcement |
| `ADV-14` | Static AST Obfuscated Payloads | In-memory stream parser flagging `eval`/`execSync` |
| `ADV-15` | Enterprise Policy Hard-Block Bypass | Instant allow/blocklist evaluation |
| `ADV-16` | IPC Daemon Pre-Flight & Failover | `<1ms` socket round-trip + in-process fallback |
| `ADV-17` | Inline Registry Mirror Interception | HTTP 403 pre-flight leak prevention |
| `ADV-18` | Malicious Install-Script Neutralization | Tarball de-weaponization & quarantine |
| `ADV-19` | Extended Ecosystems & Lockfiles | NuGet, Pub, Hex, Swift registry & lockfile verification |
| `ADV-20` | System Sandbox Isolation Boundary | Seatbelt & Landlock permission-denied enforcement |

Run the full adversarial test suite locally:
```bash
make test-adversarial
```

---

## 🛠️ Contributing & Development

We welcome contributions from security researchers, language ecosystem maintainers, and agent tool developers.

### Development Prerequisites
- Go `1.27.1+`
- Python `3.11+` (for architectural sentinel audits)
- `make`

### Common Make Targets
```bash
# Run complete CI gate (formatting, vet, sentinel audit, vulncheck, tests, binary build)
make all

# Run unit tests with race detector
make test

# Run 20-point adversarial red team regression suite
make test-adversarial

# Run security and architecture sentinel audit
make sentinel

# Cross-compile for all operating systems (macOS, Linux, Windows)
make cross-build
```

---

## 📄 License

Argus is open-source software licensed under the [MIT License](LICENSE).
