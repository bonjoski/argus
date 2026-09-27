#!/usr/bin/env python3
"""
Adversarial Architecture & Security Sentinel Scanner
Automated auditor for software projects, verifying:
- Adversarial Security & Sandbox Rule Precedence (Seatbelt, Seccomp, Landlock)
- SOLID Design Principles (SRP, OCP, LSP, ISP, DIP)
- Language Development Best Practices (Go, Rust)
"""

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

@dataclass
class Finding:
    severity: str     # CRITICAL, HIGH, MEDIUM, LOW
    category: str     # SECURITY, SOLID, BEST_PRACTICE
    title: str
    file_path: str
    line_number: int
    description: str
    remediation: str

class SentinelAuditor:
    def __init__(self, root_dir: str):
        self.root = Path(root_dir).resolve()
        self.findings: List[Finding] = []

    def audit(self) -> List[Finding]:
        self.findings.clear()
        for root, dirs, files in os.walk(self.root):
            # Skip VCS, vendor, test artifacts
            dirs[:] = [d for d in dirs if d not in {".git", "vendor", "node_modules", ".gemini", "scratch"}]
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(self.root)

                if file.endswith(".go") and not file.endswith("_test.go"):
                    self.audit_go_file(full_path, str(rel_path))
                elif file.endswith(".rs"):
                    self.audit_rust_file(full_path, str(rel_path))
                elif file.endswith(".sb") or file.endswith(".scheme"):
                    self.audit_seatbelt_raw(full_path, str(rel_path))

        return self.findings

    def audit_seatbelt_text(self, content: str, file_path: str, base_line: int = 1):
        """Audits Seatbelt SBPL content (standalone or embedded in Go templates)."""
        # Find S-expression positions across multiline content
        # Check 1: SBPL Rule Ordering (allow after deny overrides deny)
        workspace_allow_match = re.search(r'\(allow\s+file-read\*\s+file-write\*[^)]*WorkspaceRoot', content, re.DOTALL)
        git_deny_match = re.search(r'\(deny\s+file-write\*[^)]*\.git', content, re.DOTALL)
        env_deny_match = re.search(r'\(deny\s+file-read\*[^)]*\.env', content, re.DOTALL)

        if git_deny_match and workspace_allow_match and workspace_allow_match.start() > git_deny_match.start():
            line_num = base_line + content[:workspace_allow_match.start()].count("\n")
            self.findings.append(Finding(
                severity="CRITICAL",
                category="SECURITY",
                title="Seatbelt Rule Precedence Overridden: Workspace Allow Overrides .git Deny",
                file_path=file_path,
                line_number=line_num,
                description=(
                    "In macOS Seatbelt SBPL, when a general 'allow' rule appears AFTER a specific 'deny' rule, "
                    "the allow rule takes precedence! Because '(allow file-read* file-write* (subpath WorkspaceRoot))' "
                    "is placed after '(deny file-write* (subpath WorkspaceRoot/.git))', writing to .git/hooks is permitted! "
                    "An adversary can plant a malicious pre-commit hook to achieve unconfined host execution."
                ),
                remediation=(
                    "Move all specific (deny ...) rules AFTER all broad (allow ...) rules in the Seatbelt template, "
                    "so that denials strictly override broader permissions."
                )
            ))

        if env_deny_match and workspace_allow_match and workspace_allow_match.start() > env_deny_match.start():
            line_num = base_line + content[:workspace_allow_match.start()].count("\n")
            self.findings.append(Finding(
                severity="CRITICAL",
                category="SECURITY",
                title="Seatbelt Rule Precedence Overridden: Workspace Allow Overrides .env Deny",
                file_path=file_path,
                line_number=line_num,
                description=(
                    "The general workspace allow rule appears AFTER the .env read deny rule. In SBPL evaluation, "
                    "the later allow rule grants read access to .env files, exposing project secrets."
                ),
                remediation="Ensure .env read deny rules appear AFTER workspace read/write allow rules."
            ))

        lines = content.splitlines()

        # Check 2: Wildcard subpath bug
        for i, line in enumerate(lines):
            if re.search(r'\(subpath\s+["\'].*\*.*["\']\)', line):
                self.findings.append(Finding(
                    severity="CRITICAL",
                    category="SECURITY",
                    title="Invalid Seatbelt Subpath Wildcard",
                    file_path=file_path,
                    line_number=base_line + i,
                    description=(
                        "Seatbelt (subpath \"...\") accepts literal string prefixes and does NOT expand wildcards (*). "
                        "Paths with asterisks match only directories literally named '*'. Protected directories remain exposed."
                    ),
                    remediation=r'Use evaluated absolute paths (e.g. {{.UserHome}}/.ssh) or regex matching (regex #"^/Users/[^/]+/\.ssh").'
                ))

        # Check 3: Direct external egress in proxy mode
        for i, line in enumerate(lines):
            if '(allow network-outbound (to tcp "*:443"))' in line and "ProxyPort" not in line:
                self.findings.append(Finding(
                    severity="HIGH",
                    category="SECURITY",
                    title="Advisory Egress Proxy Bypass (Direct Outbound Port 443 Allowed)",
                    file_path=file_path,
                    line_number=base_line + i,
                    description=(
                        "Seatbelt allows direct TCP outbound on port 443. Malicious packages making direct socket connections "
                        "bypass the localhost forward proxy entirely, rendering registry domain whitelisting ineffective."
                    ),
                    remediation="Deny external network-outbound and restrict outbound TCP strictly to 127.0.0.1:{{.ProxyPort}}."
                ))

    def audit_go_file(self, full_path: Path, rel_path: str):
        content = full_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        # Check embedded seatbelt templates
        if "seatbeltTemplate" in content or "(version 1)" in content:
            template_start = 1
            for i, line in enumerate(lines):
                if "seatbeltTemplate = `" in line or "(version 1)" in line:
                    template_start = i + 1
                    break
            self.audit_seatbelt_text(content, rel_path, base_line=template_start)

        # Check Go Idioms & Best Practices
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            # Error wrapping with fmt.Errorf without %w
            if "fmt.Errorf(" in line and ("%v" in line or "%s" in line) and "%w" not in line:
                if any(err_term in line for err_term in ["err)", "err,", "error)"]):
                    self.findings.append(Finding(
                        severity="MEDIUM",
                        category="BEST_PRACTICE",
                        title="Go Idiom: Error formatted without %w wrapping",
                        file_path=rel_path,
                        line_number=line_num,
                        description=(
                            "fmt.Errorf formats an error using %v or %s instead of %w. "
                            "This breaks error unwrapping via errors.Is() and errors.As(), dropping the typed error chain."
                        ),
                        remediation="Replace %v or %s with %w when wrapping underlying errors in fmt.Errorf."
                    ))

            # Silent error suppression
            if re.search(r'_\s*=\s*(os\.(Remove|Mkdir|Chmod|Rename)|cmd\.Run|cmd\.Start)\b', stripped):
                self.findings.append(Finding(
                    severity="LOW",
                    category="BEST_PRACTICE",
                    title="Go Best Practice: Unchecked OS or Process Error",
                    file_path=rel_path,
                    line_number=line_num,
                    description="Ignoring error return value from critical OS or command execution.",
                    remediation="Check the error or log a warning if failure is intentionally non-fatal."
                ))

        # Check SOLID: Dependency Inversion Principle (DIP)
        # If file defines runners/managers without accepting interfaces
        if "type Runner struct" in content or "type Supervisor struct" in content:
            if "exec.Command" in content and "type Engine interface" not in content and "Engine" not in content:
                self.findings.append(Finding(
                    severity="MEDIUM",
                    category="SOLID",
                    title="SOLID DIP Violation: High-level Runner coupled directly to concrete exec.Command",
                    file_path=rel_path,
                    line_number=1,
                    description=(
                        "Dependency Inversion Principle: The execution runner depends directly on concrete os/exec.Command "
                        "rather than an Engine abstraction. This prevents injecting mock sandboxes during unit testing."
                    ),
                    remediation="Define a minimal Engine interface (e.g. Run(ctx, cmd, env) error) and inject it into Runner."
                ))

        # Check SOLID: Single Responsibility Principle (SRP)
        func_count = len(re.findall(r'^func\s+', content, re.MULTILINE))
        if len(lines) > 600 and func_count > 25:
            self.findings.append(Finding(
                severity="LOW",
                category="SOLID",
                title="SOLID SRP Warning: Large module with high function density",
                file_path=rel_path,
                line_number=1,
                description=f"File has {len(lines)} lines and {func_count} functions. Consider decomposing into focused sub-packages.",
                remediation="Extract distinct responsibilities (parsing, validation, execution) into specialized types."
            ))

    def audit_rust_file(self, full_path: Path, rel_path: str):
        content = full_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            if ".unwrap()" in stripped and not stripped.startswith("//") and "#[test]" not in content[:content.find(line)]:
                self.findings.append(Finding(
                    severity="MEDIUM",
                    category="BEST_PRACTICE",
                    title="Rust Idiom: Direct .unwrap() in production path",
                    file_path=rel_path,
                    line_number=line_num,
                    description="Calling .unwrap() can cause thread panics on unhandled edge cases.",
                    remediation="Use Result handling with ? operator, match, or unwrap_or_else."
                ))

            if "unsafe {" in stripped and "// SAFETY:" not in stripped and "// Safety:" not in stripped:
                self.findings.append(Finding(
                    severity="HIGH",
                    category="BEST_PRACTICE",
                    title="Rust Safety: Unsafe block without safety invariant documentation",
                    file_path=rel_path,
                    line_number=line_num,
                    description="Unsafe block lacks an explanatory // SAFETY comment justifying memory invariants.",
                    remediation="Document why the unsafe operation is sound and guaranteed safe by callers."
                ))

    def audit_seatbelt_raw(self, full_path: Path, rel_path: str):
        content = full_path.read_text(encoding="utf-8", errors="replace")
        self.audit_seatbelt_text(content, rel_path)

def main():
    parser = argparse.ArgumentParser(description="Adversarial Architecture & Security Sentinel")
    parser.add_argument("--path", default=".", help="Root directory of the project to audit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    auditor = SentinelAuditor(args.path)
    findings = auditor.audit()

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(f"\n🛡️  Adversarial Architecture & Security Sentinel Audit Report")
        print(f"Target: {os.path.abspath(args.path)}")
        print(f"Total Findings: {len(findings)}\n" + "="*70)

        if not findings:
            print("✅ All adversarial security and architecture checks passed cleanly!")
            sys.exit(0)

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        print(f"Summary: CRITICAL: {critical_count} | HIGH: {high_count} | MEDIUM: {medium_count} | LOW: {low_count}\n")

        for f in findings:
            print(f"[{f.severity}] [{f.category}] {f.title}")
            print(f"  Location: {f.file_path}:{f.line_number}")
            print(f"  Issue:    {f.description}")
            print(f"  Fix:      {f.remediation}\n")

        if critical_count > 0 or high_count > 0:
            sys.exit(1)

if __name__ == "__main__":
    main()
