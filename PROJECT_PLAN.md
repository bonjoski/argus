# Project Plan: Argus (`vetpkg`)
## Pre-Flight Dependency Provenance & Slopsquatting Interceptor
### Hardened Architectural Specification & Adversarial Mitigation Blueprint

---

## 1. Executive Summary & Threat Model

Argus (`vetpkg`) is a zero-SaaS, ecosystem-agnostic pre-flight CLI interceptor designed to inspect package provenance and halt malicious, hallucinated, or slopsquatted dependencies before package managers write them to disk or execute post-install hooks.

### 1.1 Threat Model & Adversarial Reality
An adversarial review of dependency supply chain attacks demonstrates that naive heuristic scanning fails in production due to three distinct failure modes:
1. **Adversarial Gaming:** Attackers actively study public scoring rules. They age packages past arbitrary time windows ("31-Day Sleeper" attack), forge upstream repository links to high-reputation projects without ownership validation, and wash-trade download numbers.
2. **Upstream API Realities:** Key registries do not expose uniform metrics. PyPI permanently deprecated REST download stats in 2013; Go Module Proxies only maintain cryptographic module hashes and timestamps; crates.io enforces strict 1 req/sec rate limits; unauthenticated GitHub HEAD requests hit shared IP rate limits (HTTP 403) in CI environments.
3. **The Day-One False-Positive Trap:** Scoring engines that only accumulate penalties inevitably categorize legitimate new open-source packages (e.g., `fastapi-surrealdb`, `pytest-tempo`) as critical security threats (scoring 90–100/100) purely because they are newly published, have 1 version, low downloads, and match ecosystem keywords.

Argus resolves these challenges through **Reciprocal Provenance Verification**, **Reputational Anchors (Mitigating Offsets)**, **Ecosystem-Specific Ground-Truth Telemetry**, **Lockfile-First Resolution**, and **PATH-Prepended Process Shims**.

---

## 2. Core Architectural Principles & Adversarial Defenses

```
                                      +------------------------------------+
                                      |   Developer / Autonomous Agent     |
                                      |  (Interactive or Non-Interactive)  |
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
      |      Local SQLite Cache     |<--(Hit: <5ms)                         | Upstream Registry Resolvers |
      | (TTL 24h, Schema v2)        |                                       | (Ecosystem-Specific APIs)   |
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

### 2.1 Adversarial Defenses

#### 1. Two-Way Reciprocal VCS Ownership Verification
* **Vulnerability:** Anyone can put `"repository": "https://github.com/facebook/react"` into an untrusted `package.json`. A naive HTTP HEAD probe returns 200 OK, clearing fake repository checks.
* **Defense:** Argus enforces **Reciprocal Linkage Verification**:
  1. Inspect package metadata for declared VCS URL.
  2. Perform targeted check against the upstream repository manifest (e.g., fetch raw `package.json`, `Cargo.toml`, or `pyproject.toml` from the repository's default branch).
  3. Verify that the repository's internal manifest declares the identical package name.
  4. If metadata declares a repository that exists (200 OK) but the repository manifest names a completely different package, trigger **`HR-05B` (Spoofed VCS Impersonation: `+35` points)**.
  5. Check for cryptographic publisher attestations (GitHub Actions OIDC, Sigstore / npm provenance, PyPI PEP 740).
* **CI Rate-Limit Immunity:** Read `$GITHUB_TOKEN` or `$GH_TOKEN` from the environment if present. If unauthenticated requests return HTTP 403 or 429, categorize the VCS check as `INCONCLUSIVE_VCS` (`0` points penalty), **never** penalizing the package as a fake repo.

#### 2. Ecosystem-Realistic Signals (No Phantom APIs)
* **PyPI:** Discontinue requests for non-existent REST download counts. Evaluate:
  - Presence of pre-compiled binary wheel distributions vs raw `.tar.gz` sdist-only payloads.
  - Release cadence velocity and timestamp spread across releases.
  - PEP 740 / Sigstore cryptographic digital attestations.
* **Go Modules:** Discontinue download volume assumptions. Evaluate:
  - Inclusion and verification in the Go Checksum Database (`sum.golang.org`).
  - Semantic import versioning and tag history maturity.
  - Domain reputation: vanity/custom domains (`go.uber.org/*`, `google.golang.org/*`) vs raw public forge URLs (`github.com/temp-user/*`).
* **Crates.io:** Integrate a thread-safe token bucket rate limiter (1 req/sec sustained) with connection caching to strictly adhere to crates.io crawler policies without triggering Cloudflare blocks.
* **npm:** Utilize `api.npmjs.org` download points with wash-trading mitigation (check historical trend vs single-day spike), and verify npm `--provenance` Sigstore attestations.

#### 3. Reputational Anchors & Mitigating Offsets (Solving the Day-One Trap)
To prevent legitimate new packages from being blocked by default, Argus implements a dual-sided scoring engine: **Threat Penalties** balanced by **Reputational Offsets**:
* A verified cryptographic attestation (Sigstore / GitHub OIDC) grants a `-40` point credit.
* An established author identity ($>3$ existing packages with $>1$ year ecosystem age) grants a `-30` point credit.
* A verified two-way reciprocal repository match with established commit history ($>6$ months, $>20$ commits) grants a `-25` point credit.
* Result: A legitimate day-one library (`pytest-tempo` or `fastapi-surrealdb`) published by an established developer with a verified repository earns a net score $\le 15$ (ALLOW), while an unanchored slopsquat hits $\ge 85$ (BLOCK).

#### 4. The Anti-Sleeper Decaying Hazard Model
* **Vulnerability:** Attackers pre-register hallucinated names and let them sit dormant for 31 days to bypass static 7-day and 30-day checks.
* **Defense:** Replace binary age thresholds with a continuous hazard curve:
  - `HR-01`: Publish age $\le 7$ days (`+35` pts).
  - `HR-02`: Publish age $8 - 30$ days (`+20` pts).
  - `HR-08`: **Dormant Sleeper / Sudden Activation (`+25` pts):** Package was created $>30$ days ago but remained dormant with 0 maintenance, single initial stub, negligible adoption, and suddenly pushed its first substantive code version within the last 14 days.

#### 5. Subshell-Proof Interception: PATH-Prepend Proxy Shims
* **Vulnerability:** Autonomous coding agents (Cursor, Claude Code, Antigravity) run non-interactive subshells: `sh -c "npm install <pkg>"` or `/bin/bash -c "pip install <pkg>"`. These do **not** load shell aliases or rc files (`~/.zshrc`, `~/.bashrc`).
* **Defense:** Argus creates a dedicated shim directory: `~/.argus/bin/`.
  - Generates lightweight executable wrapper binaries (`npm`, `npx`, `pip`, `pip3`, `cargo`, `go`).
  - Prepends `~/.argus/bin` to the global system `$PATH` (or exports via agent environment configs).
  - Any subshell invocation executing `npm` or `pip` hits the Argus proxy wrapper.
  - The proxy extracts package targets, invokes `argus vet` in $<800\text{ms}$, and either invokes the real underlying binary via `syscall.Exec` or aborts execution with a high-visibility terminal alert.

#### 6. Lockfile-First & Transitive Dry-Run Resolution
* **Vulnerability:** Manifest scanning (`package.json`, `requirements.txt`) only evaluates loose version ranges (`^1.0.0`) and completely misses nested, hallucinated transitive dependencies whose `postinstall` scripts trigger remote code execution.
* **Defense:**
  - `argus scan` prioritizes lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `go.sum`) to evaluate exact, pinned dependency graphs.
  - `argus exec` supports `--dry-run-inspect`: for commands like `npm install foo`, Argus performs an isolated resolution check (`npm install --package-lock-only --dry-run` or synthetic tree resolution) to ensure all newly introduced transitive packages are vetted before scripts run.

#### 7. TOCTOU & CDN Eventual Consistency Protection
* **Vulnerability:** Argus inspects unpinned `foo` at $T_0$, which resolves to benign metadata on Fastly/Cloudflare edge node A. When the package manager runs at $T_1$, it hits edge node B or a newly published malicious release, introducing Time-of-Check to Time-of-Use execution.
* **Defense:**
  - During the pre-flight check, Argus resolves and pins the concrete version and cryptographic integrity hash (e.g. SHA-512 tarball or wheel digest).
  - When delegating to the package manager, Argus passes the pinned version argument (`npm install foo@1.2.3 --integrity=sha512-...`) or enforces lockfile synchronization, preventing downstream drift.

#### 8. Cache Poisoning & Stale TTL Defense
* **Vulnerability:** An attacker publishes a benign package, runs `argus vet` to seed a clean score into the local SQLite cache with a 24-hour TTL, and pushes a weaponized patch 5 minutes later.
* **Defense:**
  - Cache entries are strictly keyed by `(ecosystem, package, version, integrity_hash)`.
  - Mutable queries (e.g., unversioned `npm install foo` or "latest" alias) **never** trust blind 24-hour TTLs. Instead, Argus uses conditional HTTP `ETag` and `If-Modified-Since` validation headers. Over HTTP/2 persistent connections, upstream registries return `304 Not Modified` in $<40\text{ms}$, preventing stale cache exploitation while preserving sub-second speed.

#### 9. Private Registries & Dependency Confusion Leakage Prevention
* **Vulnerability:** Querying public registries (`registry.npmjs.org`, PyPI) for proprietary internal packages (`@company/auth-client`) leaks confidential internal package names over the wire and triggers false 404 blocks (`HR-05A`).
* **Defense:**
  - Automatic configuration discovery: Argus parses `.npmrc` (`@scope:registry=...`), `pip.conf` / `pyproject.toml` (`index-url`), `~/.cargo/config.toml`, and environment variables (`GOPRIVATE`, `GONOPROXY`, `NO_PROXY`).
  - Scoped packages mapped to private mirrors or matching internal namespace rules are quarantined from public lookups.
  - Transparent support for corporate authentication headers and self-hosted registries (Artifactory, Nexus, Verdaccio, AWS CodeArtifact).

#### 10. Broad Package Manager & Python Module Coverage
* **Vulnerability:** Modern development workflows and autonomous agents frequently bypass standard `npm` or `pip` invocations via alternatives (`pnpm`, `yarn`, `bun`, `uv`, `poetry`, `pixi`, `pipx`) or module invocations (`python -m pip install`).
* **Defense:**
  - `~/.argus/bin/` generates proxy interceptor shims for: `npm`, `npx`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `poetry`, `cargo`, `go`.
  - The process wrapper inspects child subshell argument strings, extracting targets from `python -m pip install <pkg>` or `python3 -m pip`.

---

## 3. Heuristic Scoring Engine: Penalties & Mitigating Offsets

$$\text{Final Risk Score} = \text{clamp}\left(0, 100, \sum_{i=1}^{n} w_i \cdot \mathbb{I}(\text{Penalty}_i) - \sum_{j=1}^{m} m_j \cdot \mathbb{I}(\text{Offset}_j)\right)$$

### 3.1 Threat Penalties ($+w_i$)

| Rule ID | Heuristic Factor | Trigger Condition | Points ($+w_i$) | Threat Context |
| :--- | :--- | :--- | :---: | :--- |
| `HR-01` | **Fresh Release** | First release published $\le 7$ days ago | `+35` | Peak window for opportunistic slopsquatting after novel LLM queries. |
| `HR-02` | **Infant Package** | First release published $8 - 30$ days ago | `+20` | Elevated risk window prior to public vetting. |
| `HR-03` | **Single Version Trap** | Total releases across all versions $== 1$ | `+15` | Typical of malicious one-off drop payloads or unmaintained placeholders. |
| `HR-04` | **Negligible Adoption** | npm/crates.io: $< 100$ weekly downloads<br/>PyPI: No binary wheels + no releases in 60d<br/>Go: Not indexed in `sum.golang.org` | `+15` | Zero real-world adoption or ecosystem verification. |
| `HR-05A`| **Detached VCS Repo** | No repository URL declared in metadata, or URL returns 404 | `+20` | Claims open-source provenance but source code is completely missing. |
| `HR-05B`| **Spoofed VCS Repo** | VCS exists (200 OK) but reciprocal manifest check fails (impersonation) | `+35` | **High Severity:** Attacker maliciously linked to a high-reputation repo they do not own. |
| `HR-06` | **Lexical Conflation** | Blends tokens from top 5,000 packages (excluding approved plugin namespaces) | `+25` | Hallucination pattern: synthesizing adjacent popular primitives (e.g. `jwt-auth-token`). |
| `HR-07` | **Author Ephemerality** | Maintainer account age $< 30$ days or first-time publisher | `+15` | Disposable burner account registered specifically to deploy squats. |
| `HR-08` | **Sudden Sleeper Activation**| Dormant $>30$ days with 0 maintenance, sudden first update $\le 14$ days | `+25` | Anti-aging bypass: detects awakened sleeper squat packages. |
| `HR-09` | **Dangerous Install Scripts**| npm package containing `preinstall`, `install`, or `postinstall` lifecycle hooks | `+15` | Vector for immediate code execution upon `npm install`. |

### 3.2 Reputational Mitigating Offsets ($-m_j$)

| Offset ID | Mitigating Factor | Condition | Credits ($-m_j$) | Rationale |
| :--- | :--- | :--- | :---: | :--- |
| `MO-01` | **Cryptographic Attestation** | Valid Sigstore / GitHub Actions OIDC provenance attestation (e.g. npm `--provenance`, PEP 740) | `-40` | Cryptographically links the published artifact to a verified build pipeline and commit SHA. |
| `MO-02` | **Established Author Anchor** | Publisher account $> 1$ year old with $\ge 3$ other established packages | `-30` | High-reputation maintainer identity with established track record. |
| `MO-03` | **Two-Way Reciprocal VCS Match** | VCS manifest matches package name, repo age $> 6$ months, $\ge 20$ commits | `-25` | Legitimate open-source project with authentic development history. |
| `MO-04` | **Approved Ecosystem Namespace** | Standard plugin naming convention (`pytest-*`, `eslint-plugin-*`, `mkdocs-*`) OR verified scope | `-20` | Eliminates false positives on idiomatic community plugins. |
| `MO-05` | **Clean Provenance Profile** | No install lifecycle hooks, multi-file binary wheels present, clean AST | `-10` | Package conforms to modern secure packaging standards. |

### 3.3 Score Simulation & Validation Examples

```
Scenario A: Legitimate Day-One Library (fastapi-surrealdb by established author)
──────────────────────────────────────────────────────────────────────────────────────────
Penalties:  HR-01 Fresh Release (+35) + HR-03 Single Version (+15) + HR-04 Negligible (+15) = +65
Offsets:    MO-02 Author Anchor (-30) + MO-03 Reciprocal VCS Match (-25) + MO-04 Approved Namespace (-20) = -75
Net Score:  max(0, 65 - 75) = 0  --> [ALLOW] (Passes cleanly without false alarm)

Scenario B: The "31-Day Sleeper" Attack
──────────────────────────────────────────────────────────────────────────────────────────
Penalties:  HR-04 Negligible (+15) + HR-06 Conflation (+25) + HR-08 Sudden Sleeper (+25) + HR-09 Install Hooks (+15) = +80
Offsets:    None (No OIDC, burner author, no reciprocal repo) = 0
Net Score:  80  --> [BLOCK] (Halts installation deterministically)

Scenario C: Fake VCS Impersonator (react-ai-auth claiming github.com/facebook/react)
──────────────────────────────────────────────────────────────────────────────────────────
Penalties:  HR-01 Fresh (+35) + HR-05B Spoofed VCS (+35) + HR-06 Conflation (+25) + HR-07 Author (+15) = +110
Offsets:    None = 0
Net Score:  min(100, 110) = 100 --> [BLOCK] (Hard abort)
```

---

## 4. Technical Architecture & System Design

### 4.1 Internal Package Structure

```
bonjoski/argus/
  ├── cmd/
  │     ├── argus/                  # Primary CLI application
  │     └── argus-shim/             # Ultra-low-overhead C/Go proxy shim for PATH
  ├── internal/
  │     ├── cli/                    # Cobra command declarations (vet, scan, exec, shim)
  │     ├── model/                  # Domain types: Provenance, Finding, RiskReport
  │     ├── registry/               # Ecosystem-specific registry adapters
  │     │     ├── adapter.go        # RegistryAdapter interface
  │     │     ├── npm.go            # npm registry + downloads + provenance API
  │     │     ├── pypi.go           # PyPI JSON API + wheel inspector + PEP 740
  │     │     ├── crates.go         # crates.io adapter with 1 req/s token bucket
  │     │     └── gomod.go          # Go proxy, sum.golang.org, and tag evaluator
  │     ├── vcs/                    # Reciprocal VCS verification service
  │     │     ├── verifier.go       # Two-way manifest matching & GitHub/GitLab parser
  │     │     └── token.go          # GITHUB_TOKEN reader & 403/429 bypass handler
  │     ├── conflation/             # Lexical conflation engine
  │     │     ├── tokenizer.go      # Name splitter (kebab, snake, camel)
  │     │     ├── matcher.go        # Trie matcher against embedded top 5,000 corpora
  │     │     └── exemptions.go     # Whitelist for legitimate plugin prefixes
  │     ├── lockfile/               # Lockfile parsers for accurate dependency trees
  │     │     ├── parser.go         # Lockfile parser interface
  │     │     ├── npm_lock.go       # package-lock.json v2/v3
  │     │     ├── cargo_lock.go     # Cargo.lock
  │     │     ├── poetry_lock.go    # poetry.lock
  │     │     └── go_sum.go         # go.sum
  │     ├── heuristics/             # Scoring engine
  │     │     ├── engine.go         # Evaluates penalties and mitigating offsets
  │     │     ├── penalties/        # HR-01 through HR-09
  │     │     └── offsets/          # MO-01 through MO-05
  │     ├── cache/                  # Local persistence
  │     │     └── sqlite.go         # Pure Go SQLite (TTL-based storage)
  │     ├── shim/                   # PATH-prepend shim installer & generator
  │     │     └── manager.go        # ~/.argus/bin bootstrap & management
  │     └── output/                 # Terminal UI & CI reporters
  │           ├── tty.go            # LipGloss color-coded findings card
  │           ├── json.go           # Machine-readable output
  │           └── sarif.go          # SARIF v2.1.0 report generator
  └── test/
        ├── adversarial/            # Red Team test suite
        └── fixtures/               # Recorded VCR HTTP fixtures & mock lockfiles
```

### 4.2 Sub-Second Latency Budget (<800ms Target)

Because the VCS repository URL is extracted from the registry metadata, the network evaluation pipeline is structured into a strictly coordinated **Two-Stage Execution Model**:

```
Stage 1: Registry Metadata Resolution (Sequential Dependency)
0ms               100ms             200ms             300ms             400ms             500ms
├─────────────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤
[CLI Boot: 8ms]
[Cache Check: 3ms]
[Registry Metadata API: 210ms ───────────────────────>|
                                                      |
Stage 2: Parallel Fan-Out Probes (errgroup concurrency)
                                                      ├─ [VCS Reciprocal Manifest Probe: 220ms ──────>|]
                                                      ├─ [Downloads / Checksum DB Probe: 130ms ─>]
                                                      └─ [Author Profile Probe: 95ms ─>]
                                                                                                      |
Stage 3: Local In-Memory Scoring & Output
                                                                                                      ├─ [Trie Matcher: 4ms]
                                                                                                      ├─ [Scoring Engine: 1ms]
                                                                                                      └─ [TTY Render: 12ms]
Total Latency (Cache Miss): ~420ms - 520ms (Comfortably below the 800ms threshold)
Total Latency (Cache Hit):  ~12ms - 20ms
```

---

## 5. Adversarial Red Team Test Suite Specification

Prior to releasing Phase 1, Argus will implement an explicit **Adversarial Regression Test Suite** (`test/adversarial/`):

1. **Test `ADV-01`: The 31-Day Sleeper Attack**
   - Fixture: Package published 35 days ago, 1 version, 12 downloads, updated 2 days ago.
   - Assertion: Rule `HR-08` triggers; final score $\ge 80$ (BLOCK).
2. **Test `ADV-02`: Fake VCS Impersonation**
   - Fixture: Malicious package `express-auth-helpers` specifying `"repository": "https://github.com/expressjs/express"`.
   - Assertion: Reciprocal manifest check detects package name mismatch; `HR-05B` triggers (`+35` pts); final score $\ge 85$ (BLOCK).
3. **Test `ADV-03`: GitHub 403 Rate-Limit Handling**
   - Fixture: GitHub returns HTTP 403 Forbidden on repo probe.
   - Assertion: VCS result marked `INCONCLUSIVE_VCS`; `HR-05A` does **not** trigger; 0 false penalty points added.
4. **Test `ADV-04`: Legitimate Day-One Package (False Positive Guard)**
   - Fixture: Newly released package ($< 24$ hours old) by established maintainer with matching reciprocal repository and OIDC provenance.
   - Assertion: Penalties neutralized by `MO-01`, `MO-02`, and `MO-03`; final score $\le 15$ (ALLOW).
5. **Test `ADV-05`: Non-Interactive Agent Subshell Interception**
   - Test: Spawn child process `sh -c "npm install <test-pkg>"` with `PATH="~/.argus/bin:$PATH"`.
   - Assertion: Subshell intercepts call, executes vetting, and exits with code 1 before `/usr/bin/npm` is spawned.
6. **Test `ADV-06`: PyPI Ground-Truth Signal Verification**
   - Fixture: PyPI JSON response without download metrics.
   - Assertion: Evaluates wheel distribution, PEP 740 attestations, and release velocity; zero crashes or phantom penalties.
7. **Test `ADV-07`: Go Checksum Database Verification**
   - Fixture: Go module not present in `sum.golang.org`.
   - Assertion: `HR-04` flags missing checksum entry; authentic modules pass with zero penalty.
8. **Test `ADV-08`: Crates.io Token Bucket Rate Limiting**
   - Test: Rapid sequential vetting of 50 crates.
   - Assertion: Client enforces 1 req/sec rate limit without receiving HTTP 429 Too Many Requests.
9. **Test `ADV-09`: Plugin Prefix Whitelisting**
   - Fixture: Legitimate new plugin `pytest-fastapi-deps`.
   - Assertion: Recognized namespace prefix exempt from `HR-06` Lexical Conflation.
10. **Test `ADV-10`: Transitive Lockfile Inspection**
    - Fixture: Clean root package declaring a hallucinated transitive dependency in `package-lock.json`.
    - Assertion: `argus scan package-lock.json` flags the nested dependency before install hooks run.
11. **Test `ADV-11`: TOCTOU Pinned Version Enforcement**
    - Test: Vetting an unpinned package manager invocation (`npm i unpinned-pkg`).
    - Assertion: Argus extracts upstream version and SHA-512 integrity hash, and delegates using pinned immutable arguments (`unpinned-pkg@x.y.z --integrity=...`).
12. **Test `ADV-12`: Cache Poisoning & Conditional ETag Validation**
    - Fixture: Stored cache entry for mutable tag. Upstream publishes a new release.
    - Assertion: Client sends `If-None-Match` ETag; registry returns 200 with new metadata; cache updates immediately without serving stale clean score.
13. **Test `ADV-13`: Private Registry & Scope Isolation**
    - Fixture: Internal company package `@mycorp/auth` defined in `.npmrc`.
    - Assertion: Argus isolates the scoped request to the configured internal mirror, leaking zero telemetry to public registries and preventing false 404 penalties.

---

## 6. Revised 8-Week Implementation Roadmap & Status Tracking

### Current Execution Status: Phase 1, Phase 2 & Phase 3 Completed (100%)

```
┌──────────────────────────────────────┬──────────────────────────────────────┬──────────────────────────────────────┐
│       PHASE 1: HARDENED CORE         │     PHASE 2: FULL ECOSYSTEM & AI     │     PHASE 3: SHIMS, CI & RELEASE     │
│             (Weeks 1–3)              │             (Weeks 4–6)              │             (Weeks 7–8)              │
│          STATUS: COMPLETED           │          STATUS: COMPLETED           │          STATUS: COMPLETED           │
├──────────────────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┤
│ [x] Go 1.27.1 scaffold & SQLite cache│ [x] Crates.io adapter (1 req/s bucket│ [x] PATH-prepend proxy shims         │
│ [x] npm adapter (Sigstore & download)│ [x] Go Proxy & sum.golang adapter    │ [x] Non-interactive subshell handling│
│ [x] PyPI adapter (wheels & PEP 740)  │ [x] Lexical conflation + exemptions  │ [x] Lockfile parser (npm/Cargo/poetr)│
│ [x] Reciprocal VCS validator         │ [x] Reputational Mitigating Offsets  │ [x] SARIF v2.1.0 generator           │
│ [x] GITHUB_TOKEN & 403 bypass logic  │ [x] LipGloss interactive TTY card    │ [x] Adversarial benchmark CI gates   │
│ [x] Adversarial Test Suite (ADV-01..)│ [x] Milestone 2: Multi-Ecosystem Beta│ [x] ADV-05 & ADV-10 passing          │
│ [x] Full CI/CD & GoReleaser Pipeline │                                      │ [x] Milestone 3: Agent shim protect. │
└──────────────────────────────────────┴──────────────────────────────────────┴──────────────────────────────────────┘
```

### Detailed Week-by-Week Work Breakdown

#### Phase 1: Hardened Core & Primary Registries (Weeks 1–3) — COMPLETED
* **Week 1: Foundations & SQLite Storage** `[COMPLETED - Commit 59038ca]`
  - [x] Initialized Go module (`bonjoski/argus`) with Go 1.27.1 and Cobra CLI framework (`cmd/argus`, `internal/cli/`).
  - [x] Implemented domain models (`PackageProvenance`, `HeuristicFinding`, `MitigatingOffset`, `RiskReport`).
  - [x] Implemented pure Go SQLite cache (`modernc.org/sqlite`) with WAL mode, schema migrations, and millisecond TTL.
  - [x] Configured CI pipeline with `golangci-lint`, `govulncheck`, and Adversarial Architecture Sentinel.
* **Week 2: npm & PyPI Ground-Truth Clients** `[COMPLETED - Commit 59038ca]`
  - [x] Implemented `internal/registry/npm.go`: metadata parser, `api.npmjs.org` download evaluator, and Sigstore/OIDC `--provenance` verification.
  - [x] Implemented `internal/registry/pypi.go`: wheel vs sdist distribution parser, release cadence tracker, and PEP 740 attestation validator.
  - [x] Built concurrent HTTP pipeline with connection reuse, bounded readers (`io.LimitReader`), and sub-second timeout contexts.
* **Week 3: Reciprocal VCS Verification & Anti-False-Positive Engine** `[COMPLETED - Commit 59038ca]`
  - [x] Implemented two-way VCS verification: parses manifests (`package.json`, `pyproject.toml`) from upstream repositories to verify ownership.
  - [x] Implemented GitHub token reader (`$GITHUB_TOKEN`) and graceful 403/429 bypass (`INCONCLUSIVE_VCS`).
  - [x] Built heuristics engine with penalties (`HR-01` to `HR-09`) and mitigating offsets (`MO-01` to `MO-03`).
  - [x] Implemented 13-point Adversarial Regression Suite (`test/adversarial`) passing with `-race`.
  - [x] Added production Makefile (`build`, `cross-build`, `test`, `vulncheck`, `sentinel`, `test-cover`).
  - [x] Configured GitHub Actions CI/CD (`.github/workflows/ci.yml`, `release.yml`, `.goreleaser.yaml`) `[Commit 3a592a9]`.
  - [x] Added MIT License `[Commit 5cbbc88]`.
  - [x] **Delivered Milestone 1**: `argus vet npm <pkg>` and `argus vet pypi <pkg>` passing in production with <800ms latency.

#### Phase 2: Full Ecosystem Expansion & Intelligence (Weeks 4–6) — COMPLETED
* **Week 4: Crates.io & Go Checksum Adapters** `[COMPLETED]`
  - [x] Implement crates.io adapter with thread-safe 1 req/sec token bucket rate limiter (`internal/registry/crates.go`).
  - [x] Implement Go adapter: query `proxy.golang.org` and `sum.golang.org` checksum database for authenticity validation (`internal/registry/gomod.go`).
  - [x] Standardize error classifications across all 4 registries (Not Found vs Timeout vs Rate Limited).
* **Week 5: Lexical Conflation Engine & Namespace Exemptions** `[COMPLETED]`
  - [x] Compile and embed top package corpora per ecosystem via Go `embed.FS` (`internal/conflation/`).
  - [x] Implement tokenizer and Trie prefix/suffix matcher.
  - [x] Implement plugin namespace exemption engine (`eslint-plugin-*`, `pytest-*`, `mkdocs-*`, `django-*`, `cargo-*`).
  - [x] Wire `HR-06` Lexical Conflation rule and `MO-04` Approved Namespace Offset into engine.
* **Week 6: Offsets Integration & Rich Terminal UX** `[COMPLETED]`
  - [x] Finalize mitigating offsets (`MO-01` to `MO-05`) to eliminate the Day-One False Positive Trap.
  - [x] Build interactive confirmation prompt: prompt user when score is between 30 and 79; block when $\ge 80$.
  - [x] Implement CLI flags (`--strict`, `--threshold`, `--json`, `--force`).
  - [x] Deliver **Milestone 2**: Multi-ecosystem CLI passing `ADV-06` through `ADV-09`.

#### Phase 3: Agent Shims, Lockfiles & Production Release (Weeks 7–8) — COMPLETED
* **Week 7: PATH-Prepend Proxy Shims & Lockfile Engine** `[COMPLETED]`
  - [x] Implement `argus shim install`: generates proxy binaries in `~/.argus/bin/` to intercept non-interactive agent subshells (`sh -c "npm install ..."`).
  - [x] Implement lockfile parsers (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `go.sum`) for exact dependency graph vetting.
  - [x] Implement `argus scan <lockfile>` command with concurrent 5-worker pool and SARIF/JSON/TTY output.
  - [x] Deliver **Milestone 3**: Full agent subshell protection passing `ADV-05` and `ADV-10`.
* **Week 8: SARIF CI Integration, Benchmarks & GA Release** `[COMPLETED]`
  - [x] Implement SARIF v2.1.0 exporter (`internal/output/sarif.go`) for GitHub Advanced Security and GitLab CI integration.
  - [x] Full Adversarial Benchmark Suite: `ADV-01` through `ADV-13` — 100% pass rate, 0 sentinel findings, 0 vulnerabilities.
  - [x] `make all` CI gate green: tidy → fmt → vet → sentinel → vulncheck → test -race → build.

---

## 7. Deliverables & Definition of Done (DoD)

1. **Adversarial Resilience:** 100% pass rate on all 10 Adversarial Suite specifications (`ADV-01` to `ADV-10`).
2. **False Positive Ceiling:** $< 2\%$ false positive rate when evaluated against the top 1,000 established open-source packages and a benchmark set of 50 legitimate day-one packages.
3. **Detection Recall:** $> 95\%$ detection rate on confirmed historical hallucination and slopsquatting packages.
4. **Latency Ceiling:** p95 latency $< 800\text{ms}$ on cold network lookups; $< 20\text{ms}$ on cache hits.
5. **Zero-SaaS Guarantee:** Zero outbound traffic to proprietary analytics servers or unauthenticated centralized proxies.
