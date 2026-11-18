# Argus Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, package verification invariants, and telemetry models governing [`bonjoski/argus`](https://github.com/bonjoski/argus).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-pre-flight-package-verification-project-quarry.md)** | **Pre-Flight Package Verification & Project Quarry Runtime** | `Accepted` | 2026-10-30 | `pkg/verifier`, `pkg/quarry` |

---

## Architectural Principles

1. **Pre-Flight Interception:** Verifies package integrity, typosquatting, and slopsquatting before download managers (`npm install`, `pip install`, `go get`) touch external registries.
2. **Local Research Dataset Integration:** Uses open research datasets (e.g. Cisco Project Quarry) and local cache heuristics without commercial dependency.
3. **Unified OpenTelemetry Tracing:** Emits OpenTelemetry spans correlating git commits, tool executions, and security events under a unified trace ID.
