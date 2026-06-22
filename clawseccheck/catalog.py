"""Check catalog: severity weights and metadata for every ClawSecCheck check.

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

# Confidence tiers (orthogonal to severity/status). A self-report from the audited
# agent is WEAKER evidence than a config fact — the agent may be compromised or
# prompt-injected — so attestation-derived findings carry ATTESTED, below MEDIUM.
ATTESTED = "ATTESTED"


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: str
    block: str           # "trifecta" | "hardening" | "advisory"
    framework: str       # human-facing taxonomy tag
    scored: bool = True
    # How sure we are a finding is correct: HIGH = a deterministic config-field fact;
    # MEDIUM = a heuristic match on free text / filesystem that may need a human look.
    confidence: str = "HIGH"


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
              HIGH, "hardening", "Untrusted↔Trusted separation", confidence="MEDIUM"),
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
              HIGH, "hardening", "Supply Chain / ClawHavoc", confidence="MEDIUM"),
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
              MEDIUM, "hardening", "Prompt Injection / Trust Boundary", confidence="MEDIUM"),
    CheckMeta("B22", "Self-modification risk (identity/skill files writable + tools enabled)",
              HIGH, "hardening", "Write Integrity / Self-Modification"),
    CheckMeta("B23", "Approval-bypass directives in bootstrap",
              HIGH, "hardening", "Human Approval", confidence="MEDIUM"),
    CheckMeta("B24", "MCP server hardening",
              HIGH, "hardening", "MCP Trust"),
    CheckMeta("B25", "Update / pinning hygiene",
              MEDIUM, "hardening", "Supply Chain"),
    CheckMeta("B30", "Sender identity strength (name-matching / mutable-ID bypass)",
              MEDIUM, "hardening", "Sender Identity"),
    CheckMeta("B31", "Effective-tools bypass (illusory deny — write blocked but apply_patch/exec still write)",
              MEDIUM, "hardening", "Least Privilege / Tool Policy"),
    CheckMeta("B32", "Control-plane mutation reachability via gateway",
              HIGH, "hardening", "Control Plane"),
    CheckMeta("B38", "Browser control / cookie & SSRF exposure",
              HIGH, "hardening", "Browser / SSRF"),
    CheckMeta("B39", "Session visibility / cross-user transcript leak",
              MEDIUM, "hardening", "Session Isolation"),
    CheckMeta("B26", "Untrusted-context exposure (channels.contextVisibility)",
              MEDIUM, "hardening", "Injection Surface"),
    CheckMeta("B33", "Known-vulnerable OpenClaw version gate",
              HIGH, "hardening", "Patch hygiene"),
    CheckMeta("B41", "Credential blast-radius assessment",
              MEDIUM, "advisory", "Credential / Blast Radius", scored=True),
    CheckMeta("B42", "Skill/plugin install-time policy (postinstall hooks, writable skill dirs)",
              MEDIUM, "hardening", "Supply Chain / Install Policy", confidence="MEDIUM"),
    # Attestation layer (v0.26.0) — enriched by the agent's self-report (--attest).
    # ATTESTED confidence: weaker than a config fact; advisory (not scored) so the
    # static grade is unaffected when no attestation is supplied (finding -> UNKNOWN).
    CheckMeta("B43", "Capability blast-radius / dangerous-verb inventory",
              HIGH, "advisory", "Least Privilege / Blast Radius",
              scored=False, confidence=ATTESTED),
    CheckMeta("B44", "Attestation ⇄ config mismatch (undisclosed capability)",
              MEDIUM, "advisory", "Trust Boundary / Drift",
              scored=False, confidence=ATTESTED),
    # Multi-agent privilege separation (v1.4.0).
    # B45 reads the attested agent roster (config has no per-agent tool allowlist), so
    # it is ATTESTED + advisory like B43/B44 — UNKNOWN without --attest, no score impact.
    # B46 is config-only (grounded multi-agent topology + global trifecta + no gate); it
    # is scored but capped at WARN so it can never introduce a new FAIL on real configs.
    CheckMeta("B45", "Per-agent privilege separation (trifecta decomposition)",
              HIGH, "advisory", "Privilege Separation / Lethal Trifecta",
              scored=False, confidence=ATTESTED),
    CheckMeta("B46", "Multi-agent trifecta exposure",
              MEDIUM, "hardening", "Least Privilege / Agents"),
    # B47 (v1.5.0): cross-agent reassembly over the attested delegation graph. ATTESTED +
    # advisory like B45 — config has no delegation graph, so UNKNOWN without --attest.
    CheckMeta("B47", "Cross-agent trifecta reassembly (delegation graph)",
              HIGH, "advisory", "Privilege Separation / Delegation",
              scored=False, confidence=ATTESTED),
    # Host Watch Posture — is anyone watching the machine the agent runs on?
    # Read-only host-monitor detection (hostwatch.detect). LOW + WARN-only (never
    # FAIL): the absence of host monitoring is flagged only when the agent is
    # high-privilege, so it never hard-caps the grade.
    CheckMeta("B50", "Host network monitoring / IDS",
              LOW, "hardening", "Host Watch / Network IDS"),
    CheckMeta("B51", "Host audit / syscall logging",
              LOW, "hardening", "Host Watch / Audit"),
    CheckMeta("B52", "Host file-integrity monitoring",
              LOW, "hardening", "Host Watch / FIM"),
    CheckMeta("B53", "Host endpoint protection / EDR",
              LOW, "hardening", "Host Watch / EDR"),
    CheckMeta("B54", "Host firewall active",
              LOW, "hardening", "Host Watch / Firewall"),
    # advisory (not scored)
    CheckMeta("C3", "Backups of SOUL.md / memory", LOW, "advisory", "Backups", scored=False),
    CheckMeta("C4", "OpenClaw version / update hygiene", LOW, "advisory", "Patch hygiene", scored=False),
    CheckMeta("C5", "Native binary PATH safety", LOW, "advisory", "Binary Integrity",
              scored=False, confidence="MEDIUM"),
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
    confidence: str = "HIGH"
