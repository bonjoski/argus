# Use Case 06: Autonomous 1-Turn Agent Self-Healing via `argus mcp` (`argus_vet`)

> **Goal:** Stop AI coding agents from installing hallucinated or typosquatted packages and let them self-correct in 1 turn using structured `UB-MCP-v1` Fix-Forward payloads and signed `BLPR-v1` receipts.

## Starting the Canonical MCP Server
```bash
# Wired automatically via `fabrial init --mcp --apply`, or run directly over STDIO:
argus mcp
```

## Example Agent Loop (`tools/call` → `argus_vet`)
1. **Agent vets an install command before execution:**
   ```json
   {
     "command": "npm install open-ai-sdk",
     "workspace": "/path/to/repo",
     "strict": true,
     "session_id": "sess_01JDX9J00...",
     "emit_receipt": true
   }
   ```
2. **Argus blocks the slopsquat and returns calm human text + structured `UB-MCP-v1` self-heal guidance (`exit_code: 20`):**
   * `content[0].text`: ≤3 calm ANSI-stripped lines explaining what paused, the verified `Fix: npm install openai`, and a 1-line `Why:`.
   * `structuredContent`: Machine-parseable `ub-cli-v2` payload with allowlisted `self_heal.suggested_args` (strictly validated against `^[a-zA-Z0-9@._/-]+$` to block shell or prompt injection).
   * `BLPR-v1` receipt: Atomically written to `FABRIAL_RECEIPT_DIR` (`stage: "scaffolding_deps"`), signed via `LOCKSMITH_SOCKET` `sign_dsse` when active, and verifiable via `fabrial receipt verify`.
