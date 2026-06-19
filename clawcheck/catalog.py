"""Check catalog: severity weights and metadata for every ClawCheck check.

Grounded on docs/specs/openclaw-audit-skill-spec.md (v2). Pure stdlib, no deps.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# severity -> score weight
WEIGHT = {CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1}

# finding statuses
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"        # partial / likely-insecure default; counts half, does not hard-cap
UNKNOWN = "UNKNOWN"  # not determinable from config -> excluded from score denominator


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: str
    block: str           # "trifecta" | "hardening" | "advisory"
    framework: str       # human-facing taxonomy tag
    scored: bool = True


# Block A — Lethal Trifecta (headline correlation check)
# Block B — Hardening ring (scored)
# Block C — advisory (reported, NOT in score denominator)
CATALOG: list[CheckMeta] = [
    CheckMeta("A1", "Lethal Trifecta (untrusted input × sensitive data × outbound)",
              CRITICAL, "trifecta", "Lethal Trifecta"),
    CheckMeta("B1", "Secrets in plaintext config / bootstrap files",
              CRITICAL, "hardening", "Secrets Vault"),
    CheckMeta("B2", "Gateway exposure & channel authentication",
              CRITICAL, "hardening", "Zero Trust / Gateway"),
    CheckMeta("B3", "Least privilege (elevated tools / allowlists)",
              HIGH, "hardening", "Least Privilege"),
    CheckMeta("B4", "Execution sandbox",
              HIGH, "hardening", "Least Privilege / Sandbox"),
    CheckMeta("B5", "Plugin / skill supply-chain integrity",
              HIGH, "hardening", "Supply Chain"),
    CheckMeta("B6", "Bootstrap-file injection surface (SOUL.md/AGENTS.md/TOOLS.md)",
              HIGH, "hardening", "Untrusted↔Trusted separation"),
    CheckMeta("B7", "Memory poisoning surface (MEMORY.md / memory dir)",
              HIGH, "hardening", "Memory integrity"),
    CheckMeta("B8", "Human approval on destructive actions",
              HIGH, "hardening", "Human Approval"),
    CheckMeta("B9", "System-prompt / secret leak in tool output",
              MEDIUM, "hardening", "Egress / Leak"),
    CheckMeta("B10", "Audit log & sensitive redaction",
              MEDIUM, "hardening", "Audit Log"),
    CheckMeta("B11", "Transport TLS & at-rest protection",
              MEDIUM, "hardening", "TLS & Encryption"),
    CheckMeta("B12", "Local-first & model hygiene",
              LOW, "hardening", "Local First"),
    CheckMeta("B13", "Installed skill / plugin safety (downloaded, not self-made)",
              HIGH, "hardening", "Supply Chain / ClawHavoc"),
    CheckMeta("B14", "Egress surface (where the agent can reach out)",
              MEDIUM, "hardening", "Egress Control", scored=False),
    CheckMeta("B15", "MCP server trust boundaries",
              HIGH, "hardening", "MCP Trust"),
    CheckMeta("B16", "Threat monitoring / detection in place",
              MEDIUM, "hardening", "Monitoring"),
    CheckMeta("B17", "Autonomy / heartbeat actions",
              MEDIUM, "hardening", "Autonomy Control"),
    CheckMeta("B18", "Subagent delegation",
              MEDIUM, "hardening", "Least Privilege / Subagents"),
    CheckMeta("B19", "Data at-rest protection (memory/logs)",
              MEDIUM, "hardening", "Data Protection"),
    CheckMeta("B20", "Bootstrap / memory write protection",
              MEDIUM, "hardening", "Write Integrity"),
    CheckMeta("B21", "Tool-output / retrieved-content trust boundary",
              MEDIUM, "hardening", "Prompt Injection / Trust Boundary"),
    CheckMeta("B22", "Self-modification risk (identity/skill files writable + tools enabled)",
              HIGH, "hardening", "Write Integrity / Self-Modification"),
    CheckMeta("B23", "Approval-bypass directives in bootstrap",
              HIGH, "hardening", "Human Approval"),
    CheckMeta("B24", "MCP server hardening",
              HIGH, "hardening", "MCP Trust"),
    CheckMeta("B25", "Update / pinning hygiene",
              MEDIUM, "hardening", "Supply Chain"),
    # advisory (not scored)
    CheckMeta("C3", "Backups of SOUL.md / memory", LOW, "advisory", "Backups", scored=False),
    CheckMeta("C4", "OpenClaw version / update hygiene", LOW, "advisory", "Patch hygiene", scored=False),
    CheckMeta("C5", "Native binary PATH safety", LOW, "advisory", "Binary Integrity", scored=False),
]

BY_ID = {c.id: c for c in CATALOG}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    detail: str
    fix: str
    framework: str
    scored: bool = True
    evidence: list[str] = field(default_factory=list)
    suppressed: bool = False
