# Session Handoff: Phase 2 Execution (Argus / vetpkg)

**Date:** September 27, 2026  
**Repository:** `bonjoski/argus`  
**Current Branch:** `main`  
**Toolchain:** Go `1.27.1 darwin/arm64`  
**License:** MIT  
**Current Milestone Completed:** Milestone 1 (Hardened Core, NPM & PyPI Ground Truth, Reciprocal VCS, Heuristics Engine, SQLite Cache, CI/CD Pipeline)  
**Next Milestone:** Milestone 2 (Full Ecosystem Expansion: Crates.io, Go Modules, Embedded Lexical Conflation Engine, Interactive UX)

---

## 1. Executive Summary & Current Architecture State

Argus (`vetpkg`) is a zero-SaaS, high-performance CLI pre-flight dependency interceptor designed to prevent developer environments and autonomous coding agents from installing hallucinated, slopsquatted, or hijacked third-party dependencies.

Phase 1 has been completed with **100% test pass rate**, zero data races (`go test -race ./...`), an automated adversarial security sentinel, and full GitHub Actions CI/CD workflows.

### Phase 1 Deliverables Summary
* **CLI Entrypoint (`cmd/argus`, `internal/cli`)**:
  * Root command `argus` with alias `vetpkg`.
  * `argus vet <ecosystem> <package>` with `--json`, `--strict`, and `--threshold` flags.
  * `argus cache stats` and `argus cache prune`.
* **Domain Model (`internal/model`)**:
  * Unified `PackageProvenance`, `HeuristicFinding`, `MitigatingOffsetFinding`, and `RiskReport`.
* **Pure Go SQLite Storage (`internal/cache`)**:
  * Backed by `modernc.org/sqlite` (no CGo required).
  * WAL mode, foreign keys, schema migrations, and millisecond TTL expiration keying on `(eco:pkg@ver:hash)`.
* **Registry Ground Truth Adapters (`internal/registry`)**:
  * `NPMAdapter`: Metadata, release cadence, download evaluation via `api.npmjs.org`, and Sigstore/OIDC `--provenance` attestation verification.
  * `PyPIAdapter`: Wheel vs sdist distribution parser, release cadence, and PEP 740 digital attestation validation.
* **Reciprocal VCS Verification (`internal/vcs`)**:
  * Solves the **Fake VCS Impersonation** attack vector by fetching upstream repository manifests (`package.json`, `pyproject.toml`) and verifying reciprocal ownership.
  * GitHub token integration (`$GITHUB_TOKEN`) with graceful HTTP 403/429 rate-limit bypass returning `INCONCLUSIVE_VCS` (0 pt penalty).
* **Heuristics & Scoring Engine (`internal/heuristics`)**:
  * Standardized rules (`HR-01` to `HR-09`) and mitigating offsets (`MO-01` to `MO-03`).
  * Clamped scoring algorithm:
    $$\text{Score} = \max\left(0, \min\left(100, \sum \text{Penalties} - \sum \text{Offsets}\right)\right)$$
* **Terminal & JSON Output (`internal/output`)**:
  * LipGloss-styled visual cards with transparent penalty and offset breakdowns.
  * Machine-readable JSON output for agent pipeline integration.
* **Adversarial Test Suite (`test/adversarial`)**:
  * 13-point test suite covering `ADV-01` through `ADV-13` (typosquatting, unverified VCS, day-one offsets, sleeper activation, rate-limit resilience, bounded readers, cache invalidation).
* **Tooling & CI/CD**:
  * Root `Makefile` (`all`, `build`, `cross-build`, `test`, `test-adversarial`, `test-cover`, `sentinel`, `vulncheck`, `lint`, `fmt`, `tidy`).
  * `.github/workflows/ci.yml` (multi-OS matrix, race detection, coverage, lint, sentinel, vulncheck).
  * `.github/workflows/release.yml` and `.goreleaser.yaml` (automated cross-compilation and Cosign keyless signing).
  * `scripts/sentinel_audit.py` (architectural and security compliance linter).

---

## 2. Invariants & Architectural Rules

All future contributions must respect the following non-negotiable principles:

1. **Zero-SaaS Mandate**:
   Argus must NEVER rely on proprietary SaaS backends, cloud databases, or centralized telemetry. All intelligence is computed locally from registry APIs, VCS repositories, and local caches.
2. **Strict Go Idioms & SOLID Principles**:
   * Single Responsibility Principle (SRP) per heuristic and adapter.
   * Interface-driven design (Dependency Inversion) in `internal/service`.
   * Bounded I/O (`io.LimitReader`) on all network responses (10MB on registry payloads, 64KB on VCS manifests).
3. **Sub-800ms Latency Budget**:
   * Remote queries must be budgeted at $<500\text{ms}$ with parallel execution using `sync.WaitGroup` or `golang.org/x/sync/errgroup`.
4. **Adversarial Regression Gate**:
   * No code may be committed if `go test -race ./...` or `make sentinel` fails.

---

## 3. Phase 2 Scope & Work Breakdown

Phase 2 focuses on **Full Ecosystem Expansion & Intelligence (Weeks 4–6)**.

```
                    ┌────────────────────────────────────────────────────────┐
                    │                      argus vet                         │
                    └──────────────────────────┬─────────────────────────────┘
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
       Existing Adapters               New Phase 2 Adapters          Lexical Intelligence
     ┌───────────────────┐          ┌─────────────────────┐        ┌───────────────────────┐
     │  - NPM Adapter    │          │  - Crates.io        │        │  - Tokenizer          │
     │  - PyPI Adapter   │          │  - Go Modules       │        │  - Trie Corpus Engine │
     │  - Reciprocal VCS │          │  - Rate Limiter     │        │  - Namespace Exemption│
     └───────────────────┘          └─────────────────────┘        └───────────────────────┘
```

### Task 1: Crates.io Registry Adapter (`internal/registry/crates.go`)
* **Objective**: Implement `Adapter` interface for `model.EcosystemCargo`.
* **API Endpoints**:
  * Metadata: `https://crates.io/api/v1/crates/{crate}`
  * Version details: `https://crates.io/api/v1/crates/{crate}/{version}`
* **Rate Limiting Requirements**:
  * Crates.io strictly requires a descriptive `User-Agent` header (e.g., `argus/1.0.0 (https://github.com/bonjoski/argus)`).
  * Enforce a thread-safe 1 req/sec rate limiter using `golang.org/x/time/rate` to prevent HTTP 429 errors.
* **Extracted Ground Truth**:
  * Package age (`created_at`), release cadence, download counts (`downloads`), repository URL.
  * Verified publisher / GitHub owners (mapped to `PublisherVerified`).

### Task 2: Go Modules Adapter (`internal/registry/gomod.go`)
* **Objective**: Implement `Adapter` interface for `model.EcosystemGo`.
* **API Endpoints**:
  * Version listing: `https://proxy.golang.org/{module}/@v/list`
  * Latest version info: `https://proxy.golang.org/{module}/@latest`
  * Checksum verification: `https://sum.golang.org/lookup/{module}@{version}`
* **Extracted Ground Truth**:
  * Go packages lack centralized download statistics. Instead, validity is established via:
    1. Presence in `proxy.golang.org`.
    2. Inclusion in the cryptographic `sum.golang.org` database (`InGoChecksumDB = true`).
    3. Direct VCS reciprocal probe for domain vanity imports (e.g. `go.uber.org/zap`).

### Task 3: Embedded Lexical Conflation Engine (`internal/conflation/`)
* **Objective**: Detect typosquatting and slopsquatting without SaaS calls using embedded local corpora.
* **Implementation Plan**:
  * Curate top 5,000 package names for NPM, PyPI, Cargo, and Go.
  * Embed package lists into binary using Go `//go:embed`.
  * Implement Trie-based prefix/suffix matching and Levenshtein distance $\le 2$.
  * **Approved Namespace Exemptions (`MO-04`)**:
    * Deduct `-30` points for recognized ecosystem plugin patterns:
      * `pytest-*`
      * `eslint-plugin-*` / `@types/*`
      * `mkdocs-*`
      * `django-*`
      * `cargo-*`

### Task 4: Interactive TTY UI Prompts
* **Objective**: Intercept suspicious packages in interactive terminal sessions.
* **Behavior Matrix**:
  * Score $< 30$: Clean (Green) $\to$ proceed silently.
  * Score $30 - 79$: Suspicious (Yellow) $\to$ display risk card, prompt `[y/N]` confirmation in interactive TTY.
  * Score $\ge 80$: Critical Threat (Red) $\to$ hard block; requires `--force` or explicit override.
  * If non-interactive (CI / subshell): exit code 1 on score $\ge \text{threshold}$ (default 50).

---

## 4. Key Files to Create / Modify in Phase 2

| File Path | Action | Description |
|-----------|--------|-------------|
| `internal/registry/crates.go` | **Create** | Crates.io adapter with rate limiting and metadata parsing |
| `internal/registry/crates_test.go` | **Create** | Unit and mock integration tests for Crates.io |
| `internal/registry/gomod.go` | **Create** | Go Proxy and Checksum DB adapter |
| `internal/registry/gomod_test.go` | **Create** | Unit tests for Go module vetting |
| `internal/conflation/engine.go` | **Create** | Lexical tokenizer and Trie distance engine |
| `internal/conflation/data/*.txt` | **Create** | Top 5,000 package corpora per ecosystem (embedded via `embed.FS`) |
| `internal/heuristics/rules.go` | **Modify** | Wire `HR-06` (Lexical Conflation) and `MO-04` (Approved Namespace) |
| `internal/cli/vet.go` | **Modify** | Support `cargo` and `go` ecosystems, wire interactive confirmation prompt |
| `test/adversarial/adversarial_test.go` | **Modify** | Add test cases `ADV-06` through `ADV-09` |

---

## 5. Quick Start for the Resuming Engineer

To resume work on Phase 2 immediately, execute:

```bash
# 1. Verify clean repository state and toolchain
go version # must be 1.27.1 or compatible
git status

# 2. Run full regression suite to verify baseline
make all

# 3. Begin Task 1: Create Crates.io adapter
touch internal/registry/crates.go internal/registry/crates_test.go
```

Argus is in a clean, fully verified state on branch `main` with all Phase 1 requirements met. Phase 2 can be executed seamlessly starting with the Crates.io and Go module adapters.
