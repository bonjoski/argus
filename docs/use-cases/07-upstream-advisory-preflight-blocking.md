# Recipe: Upstream Advisory Pre-Flight Blocking (Project Quarry SemVer Gate)

> **Use Case ID:** `ARG-UC-07`  
> **Mitigated Advisories:** `GHSA-qh76-45cr-8xrc`, `GHSA-f9h7-4mmq-vgcq`, `GHSA-p3j5-5hrq-p75h`, `GHSA-x72p-hmqp-46hw`, `GHSA-8cg3-r6g9-fpg2`, `GHSA-3wh4-j44w-pg92` (plus automated Spanreed Radar rules in `rules/quarry/radar_*.yaml`)  
> **Mechanism:** Project Quarry `package_name_matches` + SemVer `vulnerable_versions` Pre-Flight Enforcement  

---

## 1. Problem Statement

Autonomous coding agents frequently install Go, Rust, npm, and PyPI dependencies on demand without consulting fresh vulnerability advisories. Installing unpinned or vulnerable ranges (e.g. `sevenz-rust2 < 0.21.1`, `klever-go < 1.7.20`, `nats-server < 2.12.8`, `git-lfs < 3.8.1`, `github.com/cli/cli/v2 < 2.96.0`, or `go.etcd.io/etcd/v3 < 3.5.32 / < 3.6.13`) introduces Zip-Slip, cryptographic quorum bypass, CRL bypass, or URL-scheme RCE risks directly into the developer workstation.

## 2. Fail-Closed Quarry Rule Enforcement & Automated Radar Synthesis

Argus evaluates declarative Quarry rules under `rules/quarry/*.yaml` with full SemVer range matching (`<`, `<=`, `>`, `>=`, comma-AND, and `||`-OR disjunctions):

- **Vulnerable Version -> Blocked (`action: kill`)**
- **Unpinned / Floating Version (`latest`, omitted) -> Fail-Closed Blocked**
- **Explicitly Patched Version (e.g., `sevenz-rust2@0.21.1`, `git-lfs/v3@v3.8.1`, `cli/cli/v2@2.96.0`, `etcd/v3@3.6.13`) -> Allowed**

Spanreed's daily threat radar (`daily_radar.py --sync --validate --auto-fix`, `RFC-2026-11-25-59`) automatically synthesizes ReDoS-safe `rules/quarry/radar_<ghsa>.yaml` rules and updates `rules/quarry/radar_auto_manifest.json`, gating every new rule through `TestRadarAutoAdvisoryRules` with atomic rollback on failure.

## 3. Verification

```bash
go test ./pkg/quarry -run "TestLoadAndEvaluateUpstreamAdvisoryRules|TestRadarAutoAdvisoryRules" -v
```
