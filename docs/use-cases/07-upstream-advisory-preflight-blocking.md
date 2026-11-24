# Recipe: Upstream Advisory Pre-Flight Blocking (Project Quarry SemVer Gate)

> **Use Case ID:** `ARG-UC-07`  
> **Mitigated Advisories:** `GHSA-qh76-45cr-8xrc`, `GHSA-f9h7-4mmq-vgcq`, `GHSA-p3j5-5hrq-p75h`, `GHSA-x72p-hmqp-46hw`  
> **Mechanism:** Project Quarry `package_name_matches` + SemVer `vulnerable_versions` Pre-Flight Enforcement  

---

## 1. Problem Statement

Autonomous coding agents frequently install Go, Rust, npm, and PyPI dependencies on demand without consulting fresh vulnerability advisories. Installing unpinned or vulnerable ranges (e.g. `sevenz-rust2 < 0.21.1`, `klever-go < 1.7.20`, `nats-server < 2.12.8`, or `git-lfs < 3.8.1`) introduces Zip-Slip, cryptographic quorum bypass, or config RCE risks directly into the developer workstation.

## 2. Fail-Closed Quarry Rule Enforcement

Argus evaluates declarative Quarry rules under `rules/quarry/*.yaml` with full SemVer range matching (`<`, `<=`, `>`, `>=`, comma-AND, and `||`-OR disjunctions):

- **Vulnerable Version -> Blocked (`action: kill`)**
- **Unpinned / Floating Version (`latest`, omitted) -> Fail-Closed Blocked**
- **Explicitly Patched Version (e.g., `sevenz-rust2@0.21.1`, `git-lfs/v3@v3.8.1`) -> Allowed**

## 3. Verification

```bash
go test ./pkg/quarry -run TestLoadAndEvaluateUpstreamAdvisoryRules -v
```
