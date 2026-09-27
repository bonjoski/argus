# Argus

> **Pre-Flight Dependency Provenance & Slopsquatting Interceptor**

Argus (`vetpkg`) is a fast, zero-SaaS CLI tool designed to inspect package provenance and detect hallucinated or slopsquatted dependencies before they are installed by developers or autonomous AI coding agents.

---

## 1. Executive Summary & Problem Statement

Modern development workflows increasingly incorporate LLM coding tools (Cursor, Copilot, Claude Code). While accelerating velocity, they introduce critical software supply chain attack surfaces:

* **AI Package Hallucination:** LLMs consistently invent plausible-sounding, non-existent package names.
* **Deterministic Slopsquatting:** Attackers harvest hallucinated import names and register them on public package registries (npm, PyPI, crates.io, Go Proxy).
* **Automated Ingestion:** Developers and autonomous agents run package installs without verifying provenance, pulling down malicious code with zero warning.

---

## 2. Goals & Core Principles

* **Zero-SaaS Architecture:** Direct queries to authoritative upstream registries without relying on commercial feeds or third-party servers.
* **Sub-Second Latency:** Evaluates package metadata in `<800ms` to preserve CLI ergonomics.
* **Ecosystem Agnostic:** Unified support for **npm**, **pip**, **Go modules**, and **cargo**.

---

## 3. Adversarial-Hardened Scoring Model (0 – 100)

Argus computes a balanced risk score combining **Threat Penalties** ($+w_i$) and **Reputational Mitigating Offsets** ($-m_j$):

$$\text{Final Risk Score} = \text{clamp}\left(0, 100, \sum \text{Penalties} - \sum \text{Offsets}\right)$$

### Threat Penalties
| Heuristic Factor | Condition | Points | Description |
| :--- | :--- | :---: | :--- |
| **Fresh Release** (`HR-01`) | $\le$ 7 days old | `+35` | Highest hallucination / squat risk window |
| **Infant Package** (`HR-02`) | 8 – 30 days old | `+20` | Elevated risk window of unverified code |
| **Sudden Sleeper** (`HR-08`) | Dormant >30 days, updated $\le 14$ days | `+25` | Awakened dormant squat package |
| **Single Version Trap** (`HR-03`) | Total releases == 1 | `+15` | Common for placeholder / slopsquat payloads |
| **Negligible Adoption** (`HR-04`) | Low downloads or unindexed | `+15` | Lacks organic ecosystem adoption |
| **Detached VCS Repo** (`HR-05A`) | No VCS link or 404 repo | `+20` | Claims open source but repository is missing |
| **Spoofed VCS Repo** (`HR-05B`) | VCS exists but package mismatch | `+35` | Maliciously masquerading as existing open source |
| **Lexical Conflation** (`HR-06`) | Blends top 5k package names | `+25` | Synthesizes popular keywords (excluding plugins) |
| **Author Ephemerality** (`HR-07`) | Maintainer age < 30 days | `+15` | Burner account registered to push squat |

### Reputational Mitigating Offsets (Anti-False-Positive Guard)
| Mitigating Factor | Condition | Credits | Description |
| :--- | :--- | :---: | :--- |
| **Cryptographic Attestation** (`MO-01`) | Sigstore / GitHub OIDC / PEP 740 | `-40` | Provenance cryptographically tied to source build |
| **Established Author Anchor** (`MO-02`) | Maintainer >1 yr, $\ge 3$ packages | `-30` | High-reputation maintainer identity |
| **Reciprocal VCS Match** (`MO-03`) | Repo manifest matches, >6 mo old | `-25` | Two-way verified open-source repository |
| **Approved Namespace** (`MO-04`) | Known plugin prefix (e.g. `pytest-*`) | `-20` | Standard ecosystem extension conventions |

---

## 4. Implementation Roadmap (8 Weeks)

* **Phase 1 (Weeks 1–3):** Hardened Go CLI scaffold, SQLite cache, npm & PyPI ground-truth adapters (OIDC/wheels), reciprocal VCS verifier, and Adversarial Test Suite.
* **Phase 2 (Weeks 4–6):** Crates.io (token-bucket throttled) & Go checksum database adapters, lexical conflation engine with namespace exemptions, and LipGloss interactive TTY.
* **Phase 3 (Weeks 7–8):** PATH-prepend proxy shims for non-interactive agent subshells, lockfile dependency tree inspection, SARIF v2.1.0 generator, and v1.0.0 GA release.

---

## Project Specification & Security Audits

* Full engineering project plan: [PROJECT_PLAN.md](PROJECT_PLAN.md)
* Adversarial Red Team audit: [docs/adversarial_audit_report.md](docs/adversarial_audit_report.md)
* Initial PDF specification: [project_plan.pdf](project_plan.pdf)
