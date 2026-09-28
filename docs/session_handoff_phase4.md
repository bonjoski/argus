# Session Handoff: Next Phase Execution (Argus / vetpkg)

**Date:** September 28, 2026  
**Repository:** `bonjoski/argus`  
**Current Branch:** `main`  
**Latest Verified Commit:** `e1b5746` (GitHub CI 100% Green)  
**Toolchain:** Go `1.27.1 darwin/arm64`  
**License:** MIT  
**Milestones Completed:**
- ✅ **Milestone 1:** Hardened Core (NPM/PyPI, Reciprocal VCS, SQLite Cache, Heuristics, CI/CD)
- ✅ **Milestone 2:** Multi-Ecosystem Expansion (Crates.io, Go Modules, Lexical Conflation Engine, TTY Interactive Confirmation)
- ✅ **Milestone 3:** Agent Subshell Protection & Production Engine (PATH Shims, Lockfile Scanner, SARIF Exporter, Full Adversarial Suite ADV-01..13)

---

## 1. Executive Summary & Complete Architecture State

Argus (`vetpkg`) is a zero-SaaS, high-performance CLI pre-flight dependency interceptor designed to evaluate package provenance and halt malicious, hallucinated, or slopsquatted packages before package managers write them to disk or execute install scripts.

Phases 1, 2, and 3 have been completed with **100% test pass rate**, zero data races (`go test -race ./...`), zero security sentinel findings, zero CVE vulnerabilities (`govulncheck`), and all GitHub Actions CI checks passing across Ubuntu and macOS.

```
                                  +------------------------------------+
                                  |    Developer / Autonomous Agent    |
                                  | (sh -c "npm/pip/cargo/go install") |
                                  +------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |    PATH-Prepend Proxy / CLI        |
                                  |   (~/.argus/bin/npm, pip, cargo)   |
                                  +------------------------------------+
                                                    |
                 +----------------------------------+----------------------------------+
                 |                                                                     |
                 v                                                                     v
  +-----------------------------+                                       +-----------------------------+
  |      Local SQLite Cache     |<--(Hit: <5ms)                         | Upstream Registry Adapters  |
  | (TTL 24h, Schema v2)        |                                       | (NPM, PyPI, Crates, GoMod)  |
  +-----------------------------+                                       +-----------------------------+
                                                                                       |
                                           +-------------------------------------------+-------------------------------------------+
                                           |                           |                               |                           |
                                           v                           v                               v                           v
                                   +---------------+           +---------------+               +---------------+           +---------------+
                                   | npm Registry  |           | PyPI JSON API |               | crates.io API |           | Go Proxy & Sum|
                                   | • Downloads   |           | • Wheels/Sdist|               | • 1 req/s     |           | • sum.golang  |
                                   | • OIDC / Sig  |           | • PEP 740 Sig |               | • Ownership   |           | • Tag Maturity|
                                   +---------------+           +---------------+               +---------------+           +---------------+
                                           \                           |                               |                           /
                                            \                          |                               |                          /
                                             +-------------------------+-------------------------------+-------------------------+
                                                                                       |
                                                                                       v
                                                                        +-----------------------------+
                                                                        | Reciprocal VCS Verifier     |
                                                                        | • Two-way link validation   |
                                                                        | • GitHub Token / 403 bypass |
                                                                        +-----------------------------+
                                                                                       |
                                                                                       v
                                                                        +-----------------------------+
                                                                        | Lexical Conflation Engine   |
                                                                        | • Top 5k Trie + Tokenizer   |
                                                                        | • Plugin Namespace Exemption|
                                                                        +-----------------------------+
                                                                                       |
                                                                                       v
                                                                        +-----------------------------+
                                                                        |   Scoring Engine (0 - 100)  |
                                                                        |   Penalties - Offsets       |
                                                                        +-----------------------------+
                                                                                       |
                                  +----------------------------------------------------+---------------------------------------------------+
                                  |                                                    |                                                   |
                                  v                                                    v                                                   v
                     [Score < 30: ALLOW]                                  [Score 30-79: WARN / PROMPT]                         [Score >= 80: BLOCK]
```

### Key Components Implemented

1. **CLI Commands (`internal/cli/`)**:
   - `argus vet <ecosystem> <package>[@version]`: Inspects single package provenance with TTY, JSON, or SARIF output. Interactive prompt on 30-79 scores; hard block on $\ge 80$ without `--force`.
   - `argus scan <lockfile>`: Parallel 5-worker scanner for lockfiles (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `go.sum`).
   - `argus shim [install|uninstall|status|exec]`: Generates transparent multi-call executable shims in `~/.argus/bin/` to intercept non-interactive agent subshells (`sh -c "npm install ..."`).
   - `argus cache [stats|prune]`: Inspects and purges local SQLite cache entries.

2. **Registry Adapters (`internal/registry/`)**:
   - `NPMAdapter`: Metadata, download volume trends (`api.npmjs.org`), and Sigstore/OIDC `--provenance` verification.
   - `PyPIAdapter`: Wheel vs sdist distribution parser, release cadence, and PEP 740 attestation validation.
   - `CratesAdapter`: Thread-safe token bucket rate limiter (1 req/sec) conforming to crates.io crawler policies.
   - `GoModAdapter`: Evaluates `proxy.golang.org` and `sum.golang.org` checksum DB records with uppercase path escaping (`!azure` for `Azure`).

3. **Reciprocal VCS Verification (`internal/vcs/`)**:
   - Manifest check on upstream GitHub/GitLab repositories (`package.json`, `Cargo.toml`, `pyproject.toml`) to defeat fake VCS impersonation (`HR-05B`).
   - Graceful HTTP 403/429 bypass returning `INCONCLUSIVE_VCS` (0 pt penalty) in unauthenticated CI environments.

4. **Lexical Conflation Engine (`internal/conflation/`)**:
   - Embedded top corpora for `npm`, `pypi`, `cargo`, and `go` via Go `//go:embed`.
   - Trie-based prefix/suffix matching, Levenshtein distance, and plugin namespace exemptions (`eslint-plugin-*`, `pytest-*`, `mkdocs-*`, `django-*`, `cargo-*`).

5. **Heuristics Scoring Engine (`internal/heuristics/`)**:
   - **Penalties:** `HR-01` (Fresh Release), `HR-02` (Infant Package), `HR-03` (Single Version), `HR-04` (Negligible Adoption), `HR-05A` (Detached VCS), `HR-05B` (Spoofed VCS), `HR-06` (Lexical Conflation), `HR-07` (Author Ephemerality), `HR-08` (Sudden Sleeper Activation), `HR-09` (Dangerous Install Scripts).
   - **Offsets:** `MO-01` (Cryptographic Attestation), `MO-02` (Established Author), `MO-03` (Two-Way Reciprocal VCS Match), `MO-04` (Approved Ecosystem Namespace), `MO-05` (Clean Provenance Profile).

6. **Lockfile Engine (`internal/lockfile/`)**:
   - Parsers for `package-lock.json` (v1/v2/v3), `Cargo.lock`, `poetry.lock`, and `go.sum`. Surfaces transitive dependencies for deep supply chain inspection.

7. **Output Reporters (`internal/output/`)**:
   - `TTYReporter`: Color-coded LipGloss cards with penalty/offset breakdowns.
   - `JSONReporter`: Normalized JSON report for machine consumption.
   - `SARIFReporter`: SARIF v2.1.0 report for GitHub Advanced Security and GitLab CI integration.

8. **Adversarial Red Team Suite (`test/adversarial/`)**:
   - 13-point suite passing under `go test -race`: `ADV-01` (31-Day Sleeper), `ADV-02` (Fake VCS), `ADV-03` (GitHub 403), `ADV-04` (Day-One Mitigation), `ADV-05` (Agent Subshell Interception), `ADV-06` (PyPI Signals), `ADV-07` (Go Checksum DB), `ADV-08` (Crates.io Rate Limiting), `ADV-09` (Plugin Whitelisting), `ADV-10` (Transitive Lockfile Inspection), `ADV-11` (TOCTOU Pinned Versioning), `ADV-12` (Cache Poisoning Defense), `ADV-13` (Private Scope Isolation).

---

## 2. Invariants & Development Protocols

All future work on Argus must strictly adhere to these core invariants:

1. **Zero-SaaS Mandate**:
   Argus must NEVER transmit telemetry or metadata to proprietary cloud backends. All intelligence is evaluated directly against authoritative registry APIs, VCS repositories, and local caches.
2. **Sub-800ms Latency Budget**:
   Cold network evaluation must complete in $<800\text{ms}$; SQLite cache hits must resolve in $<10\text{ms}$.
3. **Strict Gate Enforcement**:
   - `make all` must pass 100% cleanly before any commit (includes `tidy`, `fmt-check`, `vet`, `sentinel`, `vulncheck`, `test -race`, `build`).
   - `scripts/sentinel_audit.py` must report 0 findings.
4. **Pure Go Toolchain**:
   All database and storage operations must use pure Go (`modernc.org/sqlite`) without CGo dependencies (`CGO_ENABLED=0`).

---

## 3. Next Phase Scope & Roadmap (Phase 4 / Production GA & Extensions)

### Workstream 1: v1.0.0 GA Tagging & Distribution
- [ ] **GoReleaser v1.0.0 Tagging**: Create git tag `v1.0.0` and trigger `.github/workflows/release.yml` with Cosign keyless binary signing.
- [ ] **Homebrew Tap Formula**: Create and publish `bonjoski/homebrew-tap/argus` formula with automated updates from GoReleaser artifacts.
- [ ] **Shell Auto-Completion**: Implement `argus completion [bash|zsh|fish]` in Cobra CLI.

### Workstream 2: Additional Registry Adapters
- [ ] **RubyGems Adapter (`internal/registry/rubygems.go`)**:
  - API: `https://rubygems.org/api/v1/gems/{gem}.json`
  - Signals: Total downloads, version release cadence, verified owners, SHA256 gem checksum.
- [ ] **Maven Central Adapter (`internal/registry/maven.go`)**:
  - API: `https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}`
  - Signals: Group ID verification, PGP artifact signatures, Central Repository publish timeline.
- [ ] **Packagist / PHP Adapter (`internal/registry/packagist.go`)**:
  - API: `https://repo.packagist.org/p2/{vendor}/{package}.json`
  - Signals: GitHub stars, maintainers, composer release cadence.

### Workstream 3: Static AST Pre-Flight Inspector
- [ ] **Install Script AST Scanner**:
  - Inspect extracted tarball payload without running scripts: detect obfuscated `eval()`, `child_process.exec`, network socket connections in `setup.py` / `package.json` hooks before package manager handoff.

### Workstream 4: Enterprise Policy & Air-Gapped Bundles
- [ ] **Argus Policy File (`.argusrc.yaml`)**:
  - Allow organizations to configure custom risk thresholds, approved vendor namespaces, required attestation rules, and offline-mode mirrors.
- [ ] **Offline / Air-Gapped Mode**:
  - Pre-seeded corpora and local checksum caches for sovereign, air-gapped CI/CD runners.

---

## 4. Quick-Start Commands for Next Agent

```bash
# 1. Verify working tree and CI compliance locally
cd /Users/benskolmoski/supplychain/argus
make all

# 2. Run Adversarial Red Team Suite
make test-adversarial

# 3. Check GitHub Actions CI status
gh run list --limit 5
gh run view --log-failed

# 4. Run interactive demo across all 4 ecosystems
make demo
```
