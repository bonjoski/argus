# Session Handoff: Milestone 7 — Source AST & Pre-Commit Slop Sentinel (`argus diff`)

**Date:** October 8, 2026  
**Repository:** `bonjoski/argus`  
**Current Branch:** `main`  
**Base Commit:** `ba35e19` (`feat(windows): wire native Windows Airlock bridge, .cmd shims, and binary discovery`)  
**Toolchain:** Go `1.27.1 darwin/arm64` (`CGO_ENABLED=0`)  
**License:** MIT  
**Milestones Completed:**
- ✅ **Milestone 1:** Hardened Core (NPM/PyPI, Reciprocal VCS, SQLite Cache, Heuristics, CI/CD)
- ✅ **Milestone 2:** Multi-Ecosystem Expansion (Crates.io, Go Modules, Lexical Conflation Engine, TTY Interactive Confirmation)
- ✅ **Milestone 3:** Agent Subshell Protection & Production Engine (PATH Shims, Lockfile Scanner, SARIF Exporter, Adversarial Suite ADV-01..13)
- ✅ **Milestone 4:** Production GA, Extended Adapters, AST Inspector & Policy (RubyGems, Maven Central, Packagist, In-Memory AST Inspector, Enterprise `.argusrc.yaml` Policy, Air-Gapped Cache Seed/Export, ADV-14..15, GoReleaser Cosign & Homebrew Tap)
- ✅ **Milestone 5:** High-Speed Resident IPC Daemon (`argus daemon`, sub-millisecond IPC socket), GitHub Action Composite (`action.yml`), Enterprise CI/CD Templates (GitLab CI, Bitbucket Pipelines, GitHub Actions Example), Dogfooding CI Gate, Adversarial Suite ADV-16.
- ✅ **Milestone 6:** Inline Registry Mirror Proxy (`argus mirror`), Dynamic Install-Script Neutralization (`argus sanitize`), Forensics Quarantine Store (`argus quarantine`), Adversarial Suite ADV-17 & ADV-18.
- 🎯 **Milestone 7 (In Scope):** Source AST & Pre-Commit Slop Sentinel (`argus diff`, `argus scan --ast`, phantom dependency detection before package manager invocation).

---

## 1. Executive Summary & Problem Formulation

### The Shift-Left Threat
Autonomous coding agents (OpenCode, Claude Code, Gemini CLI, Cursor, Copilot) frequently hallucinate non-existent package dependencies or suggest newly-registered "slopsquat" packages during code generation.
While Argus's PATH shims, inline mirror proxy, and lockfile scanner catch these during `npm install` or `pip install`, attackers can exploit the gap where developers commit or stage code before running package manager syncs, or when AI agents generate code directly into workspace files.

### Architectural Solution
Fold the source-level AST firewall capability directly into **Argus** as **Milestone 7**:
1. **`argus diff`**: Inspects staged changes (`git diff --cached`) or uncommitted workspace modifications, parses added import statements across Python, JS/TS, and Go, normalizes package names, and checks provenance before commit.
2. **`argus scan --ast <paths...>`**: Recursively extracts imports from source files in a directory or workspace without requiring an existing lockfile.
3. **Pure Go Implementation (`CGO_ENABLED=0`)**: Maintains Argus's invariant of zero CGo dependencies, utilizing native parsers and tokenizers.
4. **Direct Pipeline Reuse**: Pipes extracted package specifiers directly into Argus's existing `VettingService` (querying the local SQLite cache, resident daemon IPC socket, and authoritative registries).

```
   [ Git Staged Diff / Source Files ]
                   │
                   ▼
       [ internal/ast & gitdiff ]
   ├── Git Diff Chunk Parser (added lines: +)
   ├── Pure-Go AST Parsers (Python, JS/TS, Go)
   ├── Stdlib Whitelist Filter (Python, Node, Go)
   └── Import-to-Distribution Normalizer (e.g. sklearn -> scikit-learn)
                   │ (Extracted candidate packages)
                   ▼
         [ internal/service ]
   ├── Local SQLite Cache (<5ms) / Daemon IPC (<1ms)
   ├── Upstream Registries (PyPI, npm, Go Proxy)
   └── Heuristics Engine (404 Phantom, Age < 7d, Typosquatting)
                   │
                   ▼
     [ Verdict: ALLOW / WARN / BLOCK ] (Exit 0 / 1 / 2)
```

---

## 2. Core Invariants & Engineering Constraints

1. **Pure Go Toolchain (`CGO_ENABLED=0`)**:
   Zero CGo dependencies. Do NOT use C-based Tree-sitter libraries. Use Go standard library (`go/parser`, `go/token`) for Go, and dedicated pure-Go tokenizers/parsers for Python and JS/TS.
2. **Zero-SaaS & Sovereign Execution**:
   Never send source code, diffs, or file paths outside the local host. Only normalized package names are queried against local cache, daemon IPC, or public registries.
3. **Sub-Millisecond Cache / Daemon Budget**:
   Diff parsing and AST extraction must run in $<50\text{ms}$ on typical git diffs (<10,000 LOC); warm package vetting via daemon IPC must resolve in $<1\text{ms}$ per dependency.
4. **Strict Gate Enforcement**:
   - `make all` must pass 100% cleanly (`gofmt`, `go vet`, `sentinel_audit.py`, `govulncheck`, `go test -race ./...`).
   - All errors wrapped with `%w`.
   - Adversarial test suite `ADV-19` added and passing.

---

## 3. Milestone 7 Component Breakdown

### Component A: `internal/ast/` — Source AST & Import Extraction
* **`golang.go`**: Uses `go/parser` and `go/token` to extract import paths from Go files or code chunks. Discards stdlib packages using `go/build` / stdlib index.
* **`python.go`**: Pure-Go tokenizer/scanner that parses `import <name>` and `from <name> import <submodule>`. Handles multi-line parenthesized imports and ignores comments/strings.
* **`javascript.go`**: Pure-Go lexer extracting ESM `import ... from "pkg"`, dynamic `import("pkg")`, and CJS `require("pkg")`.
* **`stdlib.go`**: Statically embedded hash sets of standard library modules:
  - Python: All 3.9–3.13 stdlib modules (e.g. `sys`, `os`, `json`, `pathlib`, `typing`, etc.).
  - Node.js: Built-in modules (`fs`, `path`, `http`, `crypto`, including `node:` prefix).
  - Go: Standard library root packages.
* **`normalizer.go`**: Maps import identifiers to public registry package distribution names:
  - Python mappings: `sklearn` $\rightarrow$ `scikit-learn`, `PIL` $\rightarrow$ `Pillow`, `yaml` $\rightarrow$ `PyYAML`, `bs4` $\rightarrow$ `beautifulsoup4`, `cv2` $\rightarrow$ `opencv-python`, `google.protobuf` $\rightarrow$ `protobuf`, etc.
  - JS/TS mappings: Handles scoped packages (e.g. `@angular/core`), subpath imports (`lodash/get` $\rightarrow$ `lodash`).
  - Go mappings: Extracts module roots from URL paths (e.g. `github.com/gin-gonic/gin/binding` $\rightarrow$ `github.com/gin-gonic/gin`).

### Component B: `internal/gitdiff/` — Diff Stream Parser
* Runs `git diff --cached` (or uncommitted `git diff`) or accepts a diff stream from `io.Reader`.
* Parses unified diff format:
  - Identifies added/modified filenames and matches language by file extension (`.py`, `.js`, `.ts`, `.mjs`, `.cjs`, `.go`).
  - Filters strictly for added lines (`+` prefix, ignoring `+++` header).
  - Extracts newly introduced import statements without scanning untouched lines.

### Component C: `internal/cli/diff.go` & `scan.go` Updates
* New command **`argus diff`**:
  ```bash
  argus diff              # Scans uncommitted working tree changes
  argus diff --cached     # Scans staged git changes (standard pre-commit hook mode)
  argus diff --json       # Machine-readable output for IDE/agent tooling
  argus diff --strict     # Fails (exit 2) on warnings in addition to blocks (exit 1)
  ```
* Updates to **`argus scan`**:
  ```bash
  argus scan --ast ./src  # Scans raw source files across directories without requiring a lockfile
  ```

### Component D: Adversarial Verification (`ADV-19`)
* `test/adversarial/adv19_diff_sentinel_test.go`:
  - Simulates git commit introducing hallucinated Python package (e.g. `import requests_jwt_validator`).
  - Verifies `argus diff --cached` detects 404 on PyPI and halts with Exit Code 1.
  - Verifies valid imports (`import requests`, `import os`) pass cleanly with Exit Code 0.
  - Verifies JS/TS hallucinated package (`require("express-auth-phantom")`) is caught.
  - Verifies Go hallucinated module (`import "github.com/phantom/fake-pkg"`) is caught.

---

## 4. Quick Verification Commands for the Session

```bash
# 1. Switch to Argus repository
cd /Users/benskolmoski/supplychain/argus

# 2. Verify baseline passes cleanly
make all

# 3. Run sentinel audit
python3 scripts/sentinel_audit.py --path .

# 4. Verify existing adversarial suite
go test -race -v ./test/adversarial/...
```

---

## 5. Execution Instructions for the AI Agent

When executing in the `argus` workspace, follow these steps in order:

1. **Create `internal/ast/`**:
   - Implement `stdlib.go` with embedded stdlib lookup tables for Python, Node.js, and Go.
   - Implement `normalizer.go` with unit tests for Python/JS/Go import-to-package resolution.
   - Implement `golang.go`, `python.go`, and `javascript.go` parsers with comprehensive test cases for single-line, multi-line, and aliased imports.
2. **Create `internal/gitdiff/`**:
   - Implement diff parser in `gitdiff.go` that runs `git diff` or consumes an `io.Reader`.
   - Write unit tests with real git diff snippets covering Python, JS, and Go files.
3. **Wire CLI in `internal/cli/diff.go`**:
   - Register `diffCmd` in `root.go`.
   - Wire with `service.VettingService` and lipgloss reporting.
4. **Add Adversarial Suite `ADV-19`**:
   - Create `test/adversarial/adv19_diff_sentinel_test.go`.
5. **Verify Gate**:
   - Run `make all` and ensure zero linter warnings, zero sentinel findings, and 100% passing tests.
