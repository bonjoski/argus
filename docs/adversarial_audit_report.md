# RED TEAM AUDIT: PROJECT ARGUS
**Adversarial Review & Supply Chain Defense Vulnerability Analysis**  
**Auditor:** Independent Third-Party Reviewer (AppSec & Supply Chain Architecture)  
**Date:** September 2026  
**Target:** [`PROJECT_PLAN.md`](file:///Users/benskolmoski/supplychain/argus/PROJECT_PLAN.md) / [`README.md`](file:///Users/benskolmoski/supplychain/argus/README.md)  
**Verdict:** **REJECT IN INITIAL STATE / REMEDIATION REQUIRED** (Critical Architecture, Security, & Operational Deficiencies)

---

## Executive Summary

Project Argus proposes a pre-flight CLI interceptor to block hallucinated dependencies and slopsquatting before package managers install them. While the threat vector is real and urgent, the initial architectural specification suffered from **fundamental design fallacies, trivially exploitable heuristic loopholes, non-existent upstream API dependencies, and runtime blind spots**.

In its initial naive form, Argus created a dangerous **illusion of security**:
1. Sophisticated threat actors could bypass the heuristic scoring engine with simple automated aging and metadata spoofing.
2. Legitimate developers and modern plugin ecosystems experienced near-100% false-positive block rates during package launches.
3. Key technical claims (such as sub-second zero-SaaS PyPI download queries and concurrent VCS HEAD verification) were physically or architecturally impossible under current registry designs.

---

## 1. Threat Model & Adversarial Bypass Vectors

```
                                 ATTACKER EXPLOIT FLOW: THE 31-DAY SLEEPER
+-------------------------+      +-------------------------+      +-------------------------+
|  Harvest Hallucination  | ---> |   Register Dummy Stubs  | ---> |   Wait 31 Days (Aging)  |
|  (LLM Prompt Scraping)  |      |   (v0.0.1 + v0.0.2)     |      |   (Accounts & Repos)    |
+-------------------------+      +-------------------------+      +-------------------------+
                                                                               |
                                                                               v
+-------------------------+      +-------------------------+      +-------------------------+
|     PAYLOAD EXECUTES    | <--- |   ARGUS SCORE: 40/100   | <--- | Point to Facebook Repo  |
|   (Bypasses CI & Agent) |      | (MEDIUM: Auto-Permitted)|      | (HEAD 200 OK -> HR-05=0)|
+-------------------------+      +-------------------------+      +-------------------------+
```

### 1.1 The "31-Day Sleeper" Exploit (Heuristic Gaming)
* **The Vulnerability:** Rules `HR-01` ($\le 7$ days, $+35$) and `HR-02` ($8-30$ days, $+20$) cap temporal risk at 30 days. `HR-03` flags single releases ($==1$, $+15$).
* **Adversarial Procedure:**
  1. An attacker scrapes hallucinated package names from LLM logs or runs automated prompts against OpenAI/Anthropic/Google models.
  2. The attacker registers the names on npm/PyPI, publishing an empty `v0.0.1` and `v0.0.2` stub using a maintainer account older than 30 days.
  3. The attacker waits 31 days.
* **Scoring Breakdown:**
  * Age $>30$ days: `HR-01` = 0, `HR-02` = 0.
  * Two versions published: `HR-03` = 0.
  * Maintainer $>30$ days: `HR-07` = 0.
  * Upstream repo specified: `HR-05` = 0.
  * Residual Penalties: `HR-04` ($<100$ downloads, $+15$) + `HR-06` (Lexical conflation, $+25$) = **Total Score: 40**.
* **Impact:** 40 points is classified as **MEDIUM / CAUTION** (30–59). In automated agent loops and non-interactive CI pipelines, Argus **allows the package to install by default**. The sleeper package triggers without friction.

### 1.2 The "Fake VCS Link" Metadata Impersonation
* **The Vulnerability:** `HR-05` penalizes missing repos or repos returning HTTP 404/403 ($+20\text{ pts}$). Section 4.3 planned an HTTP `HEAD` probe ($<350\text{ms}$) to verify existence.
* **Adversarial Procedure:**
  * Public package registries do not verify that a package author owns the repository declared in `package.json` or `pyproject.toml`.
  * The attacker sets `"repository": "https://github.com/facebook/react"` or `"https://github.com/psf/requests"`.
* **Impact:** Argus's HTTP `HEAD` probe returns **HTTP 200 OK**. Argus awards 0 penalty points, granting an attacker full credit for a tier-1 open-source repository they have zero affiliation with.

### 1.3 Time-of-Check to Time-of-Use (TOCTOU) & CDN Eventual Consistency
* **The Vulnerability:** Argus vets packages at time $T_0$, then delegates to `npm install` / `pip install` at time $T_1$.
* **Adversarial Procedure:**
  * If the package version is unpinned (e.g. `npm install pkg-name`), Argus queries the registry edge node.
  * Due to CDN replication lag (Fastly on npm, Cloudflare on PyPI), the vetting query may hit edge node A (serving benign metadata or an older cached payload), while the subsequent package manager resolution hits edge node B (serving a newly published malicious release).
  * Alternatively, an attacker publishes a malicious release in the sub-second window between Argus verification and package manager download.

### 1.4 Cache Poisoning via Local SQLite Stale TTL
* **The Vulnerability:** Argus caches evaluation results in a local SQLite database with a 24-hour TTL (Section 6 & 7).
* **Adversarial Procedure:**
  * An attacker registers a benign package and runs `argus vet` on developer machines or test environments. Argus scores it 0 and caches the result for 24 hours.
  * Minutes later, the attacker pushes a malicious patch or payload.
  * For the next 24 hours, `argus exec` and `argus vet` return an instant cache hit (<5ms) with a clean bill of health, blinding the developer to the poisoned version.

---

## 2. Broken Architectural & Upstream Registry Assumptions

| Ecosystem / Component | Architectural Assumption in Plan | Real-World Upstream Reality | Fatal Failure Mode |
| :--- | :--- | :--- | :--- |
| **PyPI Download Metric** (`internal/registry/pypi.go`) | Fetch weekly downloads directly from PyPI API in $<300\text{ms}$ (Section 4.3). | PyPI **permanently disabled download counts in its JSON API in 2013**. Fields are hardcoded to `-1`/`null`. | Download count is uncomputable via zero-SaaS REST. BigQuery requires GCP credentials and multi-second batch queries. |
| **Go Module Downloads** (`internal/registry/gomod.go`) | Evaluates `HR-04` ($<100$ weekly downloads) for Go modules. | Go proxy (`proxy.golang.org`) and index **do not record or expose download metrics**. | `HR-04` cannot be calculated for Go modules, breaking the 0-100 scoring scale for 25% of supported ecosystems. |
| **Crates.io Rate Limits** (`internal/registry/crates.go`) | Concurrently queries crates metadata and download counts in parallel via `errgroup`. | crates.io enforces a **strict crawling limit of 1 request/second** with mandatory contact User-Agent. | Manifest scanning (`argus scan Cargo.toml`) on a 40-dependency project triggers **HTTP 429** and Cloudflare IP bans. |
| **GitHub Unauthenticated HEAD Probes** (`internal/vcs/verifier.go`) | Unauthenticated HTTP `HEAD` probes to verify repo existence in $<350\text{ms}$. | GitHub unauthenticated IP rate limit is **60 requests per hour per IP**. | In shared CI runners or corporate networks, GitHub returns **HTTP 403**, triggering `HR-05` (+20 pts) and falsely blocking legitimate builds. |
| **Latency Budget Dependency Pipeline** (Section 4.3) | Registry metadata and VCS probe run concurrently to finish within $<800\text{ms}$. | **VCS URL is inside the registry metadata**. VCS check cannot start until registry metadata is fully returned. | The calls are strictly sequential: $T_{\text{registry}} (450\text{ms}) + T_{\text{vcs}} (350\text{ms}) = 800\text{ms}$, leaving zero budget for TLS handshakes, redirects, or DNS. |

---

## 3. High False-Positive Trap: The Day-One Release Penalty

The scoring matrix introduces an extreme false-positive rate for legitimate open-source development:

### 3.1 The Framework Plugin Scenario
Suppose an engineer publishes a legitimate new plugin: `fastapi-mongodb-relay` or `pytest-isolated-network`.

```
HR-01: Fresh Release (<7 days)              = +35 points
HR-03: Single Version Trap (v0.1.0)         = +15 points
HR-04: Negligible Downloads (<100 downloads) = +15 points
HR-06: Lexical Conflation (fastapi/pytest)  = +25 points
HR-07: Author Ephemerality (new registry id)= +15 points
---------------------------------------------------------
TOTAL RISK SCORE                            = 105 -> 100 (CRITICAL / BLOCK)
```

* **Outcome:** Every single legitimate framework extension or plugin published in its first week is **guaranteed a 100/100 Hard Block**.
* **Operational Consequence:** Developers and autonomous agents will face relentless alert fatigue, leading engineering teams to bypass Argus entirely or systematically pass `--force`.

### 3.2 Private Registries & Dependency Confusion Leakage
* Enterprises use internal scopes and private mirrors (Artifactory, Nexus, Verdaccio) e.g., `@internal/auth-client`.
* If Argus queries public registries (`registry.npmjs.org`, PyPI) for internal packages:
  1. **Confidentiality Breach:** Internal proprietary package names are leaked over the wire to public registries.
  2. **False Block:** Public registry returns 404, triggering `HR-05` and blocking internal company builds.
  3. Argus makes no provision for reading `.npmrc`, `pip.conf`, or `~/.cargo/config.toml` auth tokens.

---

## 4. Execution Interception & Agent Runtime Blind Spots

```
                              THE AGENT RUNTIME BYPASS
                                 
                     Autonomous Agent (Claude / Cursor / SWE-bench)
                                          |
                                          | spawns non-interactive subshell
                                          v
                                   sh -c "npm i bad-pkg"
                                          |
                         +----------------+----------------+
                         |                                 |
                         v                                 v
                 ~/.zshrc / ~/.bashrc               Direct Binary Exec
                  (Argus Shim Skipped!)             (Bypasses Argus)
```

### 4.1 Shell Shims Do Not Intercept Autonomous AI Agents
* Section 6 proposes `argus shim install` to append wrapper functions to `~/.zshrc` or `~/.bashrc`.
* **The Reality:** Autonomous coding agents (Cursor background agent, Claude Code, Antigravity, SWE-bench containers) execute tool commands in **non-interactive, non-login subshells**:
  ```bash
  /bin/sh -c "npm install hallucinated-pkg"
  ```
* Non-interactive subshells **do not source `~/.zshrc` or `~/.bashrc`**. Shell function shims are completely inert in AI agent workflows.

### 4.2 Trivial Invocation Evasion
Argus’s proposed CLI parser expects conventional invocations like `npm install <pkg>`. It fails on:
* Shell built-in bypasses: `command npm install`, `\npm install`, `env npm install`.
* Python module syntax: `python -m pip install <pkg>`, `python3 -m pip install`.
* Modern package managers: `pnpm`, `yarn`, `bun`, `uv`, `poetry`, `pixi`, `pipx`.
* Script wrappers: `npm run setup`, `make install`, `docker build`.

### 4.3 The Transitive Dependency Blind Spot
* `argus exec -- npm install foo` inspects only the CLI arguments passed to `npm`.
* If `foo` is legitimate but has a malicious slopsquat declared in its own `dependencies`, npm resolves and downloads the entire transitive tree.
* npm executes `preinstall` and `postinstall` lifecycle scripts on all transitive packages before Argus ever inspects them, allowing arbitrary code execution on the developer machine.

---

## 5. Lockfile vs. Manifest Semantics

* Section 6 specifies `argus scan [manifest-path]` targeting `package.json`, `requirements.txt`, `Cargo.toml`, and `go.mod`.
* **The Problem:** Manifests declare **unresolved version constraints** (`^1.2.0`, `>=2.0.0`), not concrete releases.
  * If Argus evaluates `latest`, but the project's lockfile resolves `1.2.0`, Argus evaluates the wrong code.
  * If an attacker publishes a malicious `1.2.9` matching `^1.2.0`, scanning `package.json` without resolving the dependency tree will never detect the attack.
* **The Requirement:** Supply chain pre-flight validation must inspect **lockfiles** (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `go.sum`), where pinned releases, cryptographic hashes, and exact tree topologies are recorded.

---

## 6. Project Roadmap & Resource Reality Check

The 8-week timeline (Section 7) is severely compressed for the committed scope:

```
[Week 1-3] Core CLI, SQLite, npm/PyPI, VCS, Rules 1-5  <-- Underestimates VCS 403 & PyPI API reality
[Week 4-6] Cargo, Go Proxy, Lexical Trie, LipGloss TUI  <-- Underestimates Go download absence & Crates 1req/s
[Week 7-8] Shell shims, CI SARIF, Benchmarks, SLSA L3   <-- Underestimates Agent subshell realities & TOCTOU
```

A solo developer or small team cannot build production-grade, rate-limit-compliant, cross-platform adapters for 4 disparate package ecosystems, manifest parsers, AST CLI introspectors, and SLSA L3 pipelines in 40 working days without accumulating massive technical debt.

---

## Remediation Roadmap: How to Fix the Architecture

To make Argus viable, resilient, and enterprise-grade, apply the following structural redesign:

### Step 1: Replace Flawed Metrics with Verifiable Provenance
1. **Drop PyPI & Go Download Metrics:** Replace download counts with **cryptographic and structural signals**:
   * Presence of Sigstore / GitHub Actions OIDC publisher attestations (PEP 740 on PyPI, npm provenance).
   * Binary distribution health: Presence of pre-built wheels vs bare `setup.py`.
   * Release velocity: Frequency of releases over time rather than raw download counts.
2. **Cryptographic VCS Verification:** Rather than a naive `HEAD` check:
   * Verify whether the package manifest's Git commit SHA exists in the linked GitHub repository via GitHub archive URLs.
   * Provide an optional `GITHUB_TOKEN` to prevent 403 rate-limit bans. If unauthenticated rate limits hit, record VCS status as `INCONCLUSIVE` (0 points), never `FAKE_REPO` (+20 points).

### Step 2: Fix the Day-One False-Positive Trap
Introduce **Mitigating Reputation Offsets**:
* If an author has $\ge 3$ existing packages $>1\text{ year}$ old with active downloads: **$-30\text{ points}$**.
* If package contains valid provenance attestations (SLSA/Sigstore): **$-40\text{ points}$**.
* Create namespace whitelists for known plugin patterns (`eslint-plugin-*`, `pytest-*`, `babel-preset-*`, `@angular/*`).

### Step 3: Implement True Agent-Level Interception
* Abandon fragile `.bashrc` / `.zshrc` shell function shims.
* Implement a **Binary Proxy Shim Directory**:
  * Generate lightweight compiled wrapper binaries for `npm`, `pip`, `cargo`, `go` located in `~/.argus/bin/`.
  * Prepend `~/.argus/bin` to the global system `$PATH` (or container `ENV PATH`).
  * When any process or non-interactive subshell calls `npm`, the Argus proxy interceptor executes first, runs the pre-flight check, and invokes the real `/usr/local/bin/npm`.

### Step 4: Shift from Manifest to Lockfile & Dry-Run Resolution
* For interactive installs (`npm install foo`), use `--dry-run` or `--package-lock-only` to resolve the full transitive dependency graph to memory, vet all resolved package-version pairs in parallel, and only then proceed with physical disk installation.
* Update `argus scan` to parse `package-lock.json`, `poetry.lock`, `Cargo.lock`, and `go.sum`.

---

## Conclusion

The core vision of Argus is timely and critical for defending against AI-generated hallucinations and slopsquatting. However, without addressing the **31-Day Sleeper bypass**, the **VCS impersonation loophole**, the **uncomputable PyPI/Go metrics**, and the **agent subshell interception failures**, Argus will fail against real attackers while breaking the daily workflow of legitimate developers. Implementing the mitigations above will position Argus as a robust, industry-standard supply chain gatekeeper.
