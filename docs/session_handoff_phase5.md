# Session Handoff: Next Phase Execution (Argus / vetpkg — Phase 5)

**Date:** September 28, 2026  
**Repository:** `bonjoski/argus`  
**Current Branch:** `main`  
**Toolchain:** Go `1.27.1 darwin/arm64` (`CGO_ENABLED=0`)  
**License:** MIT  
**Milestones Completed:**
- ✅ **Milestone 1:** Hardened Core (NPM/PyPI, Reciprocal VCS, SQLite Cache, Heuristics, CI/CD)
- ✅ **Milestone 2:** Multi-Ecosystem Expansion (Crates.io, Go Modules, Lexical Conflation Engine, TTY Interactive Confirmation)
- ✅ **Milestone 3:** Agent Subshell Protection & Production Engine (PATH Shims, Lockfile Scanner, SARIF Exporter, Adversarial Suite ADV-01..13)
- ✅ **Milestone 4:** Production GA, Extended Adapters, AST Inspector & Policy (RubyGems, Maven Central, Packagist, In-Memory AST Inspector, Enterprise `.argusrc.yaml` Policy, Air-Gapped Cache Seed/Export, ADV-14..15, GoReleaser Cosign & Homebrew Tap)
- ✅ **Milestone 5 (Phase 5 Delivery):** High-Speed Resident IPC Daemon (`argus daemon`, sub-millisecond IPC socket), GitHub Action Composite (`action.yml`), Enterprise CI/CD Templates (GitLab CI, Bitbucket Pipelines, GitHub Actions Example), ADV-16 Daemon Interception & Failover Suite

---

## 1. Executive Summary & Verified Architecture State

Argus (`vetpkg`) is a zero-SaaS, high-performance CLI and subshell pre-flight dependency interceptor designed to evaluate package provenance and halt malicious, hallucinated, or slopsquatted dependencies before package managers write them to disk or execute install scripts.

Phases 1 through 4 have completed with **100% test pass rate**, zero data races (`go test -race ./...`), zero security sentinel findings, zero CVE vulnerabilities (`govulncheck`), and support for **7 package ecosystems**:
1. **NPM** (`npm`, `npx`, `pnpm`, `yarn`, `bun`)
2. **PyPI** (`pip`, `pip3`, `poetry`)
3. **Crates.io** (`cargo`)
4. **Go Modules** (`go get`, `go.sum`)
5. **RubyGems** (`gem`, `bundle`)
6. **Maven Central** (`mvn`, `gradle`)
7. **Packagist** (`composer`)

```
                                  +------------------------------------+
                                  |    Developer / Autonomous Agent    |
                                  | (sh -c "npm/pip/cargo/gem/composer")|
                                  +------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |    PATH-Prepend Proxy / CLI        |
                                  |   (~/.argus/bin/npm, pip, gem ...) |
                                  +------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |   Enterprise Policy (.argusrc)    |
                                  | (Allowlist / Blocklist / Strict)   |
                                  +------------------------------------+
                                                    |
                         +--------------------------+--------------------------+
                         |                                                     |
                         v                                                     v
          +-----------------------------+                       +-----------------------------+
          |      Local SQLite Cache     |<--(Hit: <5ms)         | Upstream Registry Adapters  |
          | (TTL 24h, Seed/Export)      |                       | (7 Supported Ecosystems)    |
          +-----------------------------+                       +-----------------------------+
                                                                               |
                                            +----------------------------------+----------------------------------+
                                            |                                  |                                  |
                                            v                                  v                                  v
                                    +---------------+                  +---------------+                  +---------------+
                                    | npm / PyPI    |                  | crates / Go   |                  | gem/mvn/pack  |
                                    | • Downloads   |                  | • Rate Limit  |                  | • Solr / p2   |
                                    | • Sigstore    |                  | • Checksum DB |                  | • PGP / SHA   |
                                    +---------------+                  +---------------+                  +---------------+
                                            \                                  |                                  /
                                             \                                 |                                 /
                                              +--------------------------------+--------------------------------+
                                                                               |
                                                                               v
                                                                +-----------------------------+
                                                                | Reciprocal VCS Verifier     |
                                                                | (manifest check on GitHub)  |
                                                                +-----------------------------+
                                                                               |
                                                                               v
                                                                +-----------------------------+
                                                                | Pre-Flight AST Inspector    |
                                                                | (tarball/zip stream scan)   |
                                                                +-----------------------------+
                                                                               |
                                                                               v
                                                                +-----------------------------+
                                                                | Lexical Conflation Engine   |
                                                                | (Trie + 7 Ecosystem Corpora)|
                                                                +-----------------------------+
                                                                               |
                                                                               v
                                                                +-----------------------------+
                                                                | Scoring Engine (0 - 100)    |
                                                                | Penalties (HR) - Offsets(MO)|
                                                                +-----------------------------+
                                                                               |
                                          +------------------------------------+-----------------------------------+
                                          |                                    |                                   |
                                          v                                    v                                   v
                             [Score < 30: ALLOW]                  [Score 30-79: WARN / PROMPT]            [Score >= 80: BLOCK]
```

---

## 2. Core Invariants & Engineering Constraints

Every subsequent enhancement must preserve these fundamental invariants:

1. **Zero-SaaS & Sovereign Execution**:
   Argus MUST NEVER transmit dependency names, package metadata, or telemetry to proprietary external services. All intelligence is derived exclusively from authoritative registries, upstream VCS, and local policies.
2. **Sub-800ms Latency Budget**:
   Cold upstream network probes must complete in $<800\text{ms}$; cache hits must resolve in $<5\text{ms}$.
3. **Pure Go Toolchain**:
   All storage uses pure Go (`modernc.org/sqlite`) without CGo dependencies (`CGO_ENABLED=0`).
4. **Strict Gate Enforcement**:
   - `make all` must pass 100% cleanly (includes formatting, `go vet`, `sentinel_audit.py`, `govulncheck`, `go test -race ./...`, binary build).
   - Adversarial Red Team Suite (`ADV-01`..`ADV-15`) must maintain 100% pass rate.

---

## 3. Phase 5 Roadmap: Operational Scale, IPC Daemon & Enterprise CI

### Workstream 1: High-Speed IPC Daemon Mode (`argus daemon`) [COMPLETED]
- [x] **UNIX Domain Socket Server**:
  - Implemented `argus daemon run` listening on `~/.argus/argus.sock` with strict 0600 file permissions.
  - Keeps SQLite connection pool and in-memory trie structures hot in resident RAM.
  - Reduces shim interception invocation latency to $<1\text{ms}$ (measured ~220µs).
- [x] **Daemon Management Commands**:
  - `argus daemon start`, `argus daemon stop`, `argus daemon status`, `argus daemon ping`.
- [x] **Transparent Failover**:
  - Shims and CLI `vet` commands query daemon socket first, gracefully falling back to in-process service if daemon is offline.
- [x] **Adversarial Verification (`ADV-16`)**:
  - Pre-flight interception and failover verification under adversarial conditions.

### Workstream 2: Inline Registry Mirror Proxy (`argus mirror`)
- [ ] **Zero-Config Transparent HTTP Caching & Vetting Proxy**:
  - Lightweight embedded HTTP proxy (`argus mirror start --port 8080`).
  - Intercepts outbound package manager traffic (`npm config set registry http://localhost:8080/npm`, `pip config set global.index-url http://localhost:8080/pypi`).
  - Performs inline pre-flight vetting at HTTP layer, returning HTTP 403 Forbidden with SARIF/JSON diagnostic payloads for blocked packages before payload transmission.

### Workstream 3: GitHub Action & CI/CD Ecosystem Integration [COMPLETED]
- [x] **Dedicated GitHub Action (`action.yml`)**:
  - Composite action supporting lockfile / directory scanning, strict gating, and failure on risk.
  - Automatically posts sticky GitHub PR summary comments with risk score breakdown.
  - Generates and exports OASIS SARIF v2.1.0 security reports for GitHub Advanced Security Code Scanning.
- [x] **GitLab CI & Bitbucket Pipelines Templates**:
  - `templates/gitlab-ci.yml`: SAST artifact integration with security report generation.
  - `templates/bitbucket-pipelines.yml`: Pull request and main branch scanning template.
  - `templates/github-action-example.yml`: Turnkey GitHub Actions workflow.
- [x] **Dogfooding CI Integration**:
  - Self-scanning supply chain verification step in `.github/workflows/ci.yml`.

### Workstream 4: Dynamic Install-Script Sandboxing & Quarantine
- [ ] **Install Script Neutralization / Quarantine**:
  - Provide `--sanitize` flag in `argus vet` and `argus shim` to strip `preinstall`/`postinstall` hooks from downloaded packages before package manager extraction.
  - Quarantine suspicious tarballs into `~/.argus/quarantine/` for post-incident security analysis.

---

## 4. Verification & Quick-Start Commands for Next Session

```bash
# 1. Run complete verification gate locally
cd /Users/benskolmoski/supplychain/argus
make all

# 2. Run Adversarial Red Team Suite (ADV-01..ADV-16)
go test -race -v ./test/adversarial/...

# 3. Run Sentinel Architecture & Security Audit
python3 scripts/sentinel_audit.py

# 4. Check status of shims and local cache
./bin/argus shim status
./bin/argus cache stats

# 5. Vet packages across supported ecosystems
./bin/argus vet npm express
./bin/argus vet pypi requests
./bin/argus vet cargo tokio
./bin/argus vet go github.com/gin-gonic/gin
./bin/argus vet rubygems rails
./bin/argus vet maven org.apache.commons:commons-lang3
./bin/argus vet packagist guzzlehttp/guzzle
```
