# ADR-0001: Pre-Flight Package Verification & Project Quarry Runtime

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/verifier`, `pkg/quarry`
- **Deciders:** Lead Supply Chain Architect & Package Security Engineer

---

## 1. Context & Problem Statement

LLMs frequently hallucinate package names that do not exist in package registries ("slopsquatting").
- Attackers register hallucinated package names with malicious payloads waiting for automated agents to install them.
- Package managers (`npm`, `pip`) execute post-install hooks immediately upon download, compromising developer workstations.

---

## 2. Decision Outcome

We built **Argus**, a pre-flight package interceptor:

1. **Local Pre-Check CLI:**
   - Evaluates requested dependency names against known registry databases and Cisco Project Quarry datasets.
2. **Slopsquatting & Age Verification:**
   - Flags newly registered packages (< 72 hours old) or packages with high Levenshtein distance to popular libraries.
3. **Execution Circuit Breaker:**
   - Halts installation commands and alerts the developer before the package manager initiates network download.

---

## 3. Consequences

- **Positive:** Neutralizes slopsquatting and hallucinated dependency poisoning attacks before code executes.
- **Negative:** Adds a brief pre-check lookup (< 15ms local cache, < 200ms remote check) during package addition.
