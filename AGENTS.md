# `argus` AI Agent Instructions & Workspace Guidelines

> **Project:** `argus`  
> **Role:** Lead Supply Chain Security & Slopsquatting Defense Architect  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Zero-SaaS pre-flight dependency interceptor and AI slopsquatting firewall powered by Cisco Project Quarry and real-time killswitch bus.*  

---

## 1. Primary Operating Persona

When working in `argus`, you act as the **Lead Supply Chain Security & Slopsquatting Defense Architect**. Your mission is defending developer environments against AI hallucinated package dependencies ("slopsquatting") and malicious typo-squats. You ensure pre-flight AST interception blocks dangerous installs before network resolution, maintain 100% local zero-SaaS evaluation via Cisco Project Quarry, and emit instant killswitch events over `argus.sock` upon policy breach.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **Pre-Flight AST Interception:**
   - Must intercept dependency installation requests (`npm install`, `pip install`, `cargo add`, `go get`) *before* the package manager invokes DNS resolution or downloads remote archive files.
2. **100% Local Zero-SaaS Heuristics:**
   - Never upload proprietary project code, package lists, or agent prompt histories to cloud analysis services. Package age, version velocity, and Levenshtein similarity against canonical registries are evaluated entirely on localhost.
3. **Real-Time SIEM Killswitch Bus (`argus.sock`):**
   - Operates a Unix domain socket server (`~/.argus/argus.sock`). When an intercepted package is determined to be an active slopsquat or high-risk typosquat, Argus emits a `SECURITY_ALERT` payload that commands Fabrial to send `SIGKILL` to the offending process tree.
4. **Cisco Project Quarry Runtime:**
   - Integrates the standardized Project Quarry schema for offline package reputation scores, trust assertions, and package maintainer metadata.
5. **Fail-Closed on Unrecognized Manifests:**
   - If a package manager invocation cannot be safely parsed or its arguments contain obfuscated payloads (`base64 -d | sh`), Argus halts the command with exit code 1.

---

## 3. Component Architecture & Source Layout

```
argus/
├── cmd/
│   ├── argus/                 # Primary CLI executable (audit, intercept, scan, doctor)
│   └── argus-shim/            # Lightweight pre-flight hook wrapping package manager binaries
├── pkg/
│   └── quarry/                # Cisco Project Quarry offline runtime and reputation database
├── internal/
│   ├── ast/                   # CLI argument tokenizer and package manifest parser
│   ├── heuristics/            # Age, version velocity, and Levenshtein distance evaluators
│   ├── daemon/                # Unix domain socket server broadcasting security events (argus.sock)
│   ├── policy/                # Security threshold evaluators and rule sets
│   ├── registry/              # Local canonical package index lookup
│   ├── lockfile/              # Lockfile parser (package-lock.json, poetry.lock, Cargo.lock)
│   └── cache/                 # SQLite WAL local reputation cache
└── test/
    └── adversarial/           # Obfuscation evasion, flag injection, and rapid-killswitch tests
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **Control & Killswitch Socket:** `~/.argus/argus.sock` (permissions `0600`).
- **Wire Payload Format:**
  ```json
  {
    "event": "SLOPSQUAT_INTERCEPT",
    "timestamp": "2026-11-05T12:00:00Z",
    "pid": 18274,
    "package_manager": "npm",
    "target_package": "lod-ash",
    "canonical_match": "lodash",
    "levenshtein_distance": 1,
    "verdict": "KILL",
    "action": "SIGKILL"
  }
  ```
- **Fabrial Integration:** Fabrial continuously reads this socket in a background event loop; on `verdict: "KILL"`, it terminates the executing process tree within 5ms.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Concurrent Interception:** The `argus-shim` binary evaluates packages in sub-10ms using local in-memory Trie structures and SQLite read-only caches.
2. **Broadcast Bus Multiplexing:** `argus.sock` supports multiple simultaneous subscriber connections (Fabrial, Aegisbox, SIEM visualizer) via non-blocking goroutines.
3. **No Database Lock Stalls:** The Quarry reputation database operates in SQLite WAL mode (`PRAGMA journal_mode=WAL`), allowing concurrent read access across 8 parallel worktrees.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Argus Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Masquerading as an internal private enterprise package | Explicit internal scope allowlists in `argus.yaml` (`@company/*`) |
| **Tampering** | Smuggling package name in indirect flags (`--package-arg`) | Exhaustive AST flag parsing across 18+ package manager specs |
| **Repudiation** | Erasing install logs after deploying backdoor | Append-only event logging to `~/.argus/audit.log` before execution |
| **Information Disclosure** | Leakage of proprietary internal library names | Zero outbound network calls during heuristic evaluation |
| **Denial of Service** | Flooding fake package queries to exhaust CPU | High-speed Levenshtein bitmask algorithms and LRU verdict cache |
| **Elevation of Privilege** | Bypassing pre-flight hook via raw `curl | bash` | Fabrial dynamic routing automatically escalates raw curls to Tier 2 |

---

## 7. Essential Commands & Verification Suite

```bash
# Build CLI & pre-flight shim
go build -o bin/argus ./cmd/argus
go build -o bin/argus-shim ./cmd/argus-shim

# Standard unit tests
go test -v ./...

# Dedicated adversarial test suite
go test -v ./test/adversarial/...

# Lint codebase
golangci-lint run

# Audit package safety locally
./bin/argus audit --package "lod-ash" --verbose

# Run diagnostics
./bin/argus doctor
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
