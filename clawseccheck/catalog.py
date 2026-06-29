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


# ── Surface taxonomy (additive metadata; no verdict/score impact) ─────────────
# 13 canonical OpenClaw security surfaces + "trifecta" (cross-cutting).
# Grounded against docs/research/output-redesign-dashboard.md (2026-06-27).
SURFACES: tuple[str, ...] = (
    "gateway", "tools", "agents", "mcp", "skills",
    "bootstrap", "channels", "sessions", "secrets",
    "monitoring", "hooks", "host", "update",
    "trifecta",   # cross-cutting: A1 headline check only — not a bucket surface
)

# 13-surface → 7-family roll-up (dashboard grouping; unblocks F-029).
# "trifecta" is intentionally absent: it is a cross-cutting chip, never a family bucket.
FAMILY_OF: dict[str, str] = {
    "gateway":    "exposure",           # Exposure & Network
    "channels":   "exposure",
    "sessions":   "exposure",
    "tools":      "privilege",          # Privilege & Execution
    "agents":     "privilege",
    "skills":     "supply_chain",       # Supply Chain
    "mcp":        "supply_chain",
    "bootstrap":  "content_integrity",  # Content & Memory Integrity
    "secrets":    "secrets",            # Secrets & Data
    "monitoring": "detection",          # Detection & Host
    "host":       "detection",
    "hooks":      "automation",         # Automation & Maintenance
    "update":     "automation",
}


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
    # OpenClaw surface this check belongs to. One of the 13 surface slugs or "trifecta".
    # Empty string only if constructed without assignment; every CATALOG entry sets this.
    surface: str = ""


# Block A — Lethal Trifecta (headline correlation check)
# Block B — Hardening ring (scored)
# Block C — advisory (reported, NOT in score denominator)
CATALOG: list[CheckMeta] = [
    CheckMeta("A1", "Lethal Trifecta (untrusted input × sensitive data × outbound)",
              CRITICAL, "trifecta", "Lethal Trifecta",
              surface="trifecta"),
    CheckMeta("B1", "Secrets in plaintext config / bootstrap files",
              CRITICAL, "hardening", "Secrets Vault",
              surface="secrets"),
    CheckMeta("B2", "Gateway exposure & channel authentication",
              CRITICAL, "hardening", "Zero Trust / Gateway",
              surface="gateway"),
    CheckMeta("B3", "Least privilege (elevated tools / allowlists)",
              HIGH, "hardening", "Least Privilege",
              surface="tools"),
    CheckMeta("B4", "Execution sandbox",
              HIGH, "hardening", "Least Privilege / Sandbox",
              surface="agents"),
    CheckMeta("B5", "Plugin / skill supply-chain integrity",
              HIGH, "hardening", "Supply Chain",
              surface="skills"),
    CheckMeta("B6", "Bootstrap-file injection surface (SOUL.md/AGENTS.md/TOOLS.md)",
              HIGH, "hardening", "Untrusted↔Trusted separation", confidence="MEDIUM",
              surface="bootstrap"),
    CheckMeta("B7", "Memory poisoning surface (MEMORY.md / memory dir)",
              HIGH, "hardening", "Memory integrity",
              surface="bootstrap"),
    CheckMeta("B8", "Human approval on destructive actions",
              HIGH, "hardening", "Human Approval",
              surface="tools"),
    CheckMeta("B9", "System-prompt / secret leak in tool output",
              MEDIUM, "hardening", "Egress / Leak",
              surface="secrets"),
    CheckMeta("B10", "Audit log & sensitive redaction",
              MEDIUM, "hardening", "Audit Log",
              surface="monitoring"),
    CheckMeta("B11", "Transport TLS & at-rest protection",
              MEDIUM, "hardening", "TLS & Encryption",
              surface="gateway"),
    CheckMeta("B12", "Local-first & model hygiene",
              LOW, "hardening", "Local First",
              surface="secrets"),
    CheckMeta("B13", "Installed skill / plugin safety (downloaded, not self-made)",
              HIGH, "hardening", "Supply Chain / ClawHavoc", confidence="MEDIUM",
              surface="skills"),
    CheckMeta("B14", "Egress surface (where the agent can reach out)",
              MEDIUM, "hardening", "Egress Control", scored=False,
              surface="monitoring"),
    CheckMeta("B15", "MCP server trust boundaries",
              HIGH, "hardening", "MCP Trust",
              surface="mcp"),
    CheckMeta("B16", "Threat monitoring / detection in place",
              MEDIUM, "hardening", "Monitoring",
              surface="monitoring"),
    CheckMeta("B17", "Autonomy / heartbeat actions",
              MEDIUM, "hardening", "Autonomy Control",
              surface="tools"),
    CheckMeta("B18", "Subagent delegation",
              MEDIUM, "hardening", "Least Privilege / Subagents",
              surface="agents"),
    CheckMeta("B19", "Data at-rest protection (memory/logs)",
              MEDIUM, "hardening", "Data Protection",
              surface="secrets"),
    CheckMeta("B20", "Bootstrap / memory write protection",
              MEDIUM, "hardening", "Write Integrity",
              surface="bootstrap"),
    CheckMeta("B21", "Tool-output / retrieved-content trust boundary",
              MEDIUM, "hardening", "Prompt Injection / Trust Boundary", confidence="MEDIUM",
              surface="bootstrap"),
    CheckMeta("B22", "Self-modification risk (identity/skill files writable + tools enabled)",
              HIGH, "hardening", "Write Integrity / Self-Modification",
              surface="agents"),
    CheckMeta("B23", "Approval-bypass directives in bootstrap",
              HIGH, "hardening", "Human Approval", confidence="MEDIUM",
              surface="bootstrap"),
    CheckMeta("B24", "MCP server hardening",
              HIGH, "hardening", "MCP Trust",
              surface="mcp"),
    CheckMeta("B25", "Update / pinning hygiene",
              MEDIUM, "hardening", "Supply Chain",
              surface="skills"),
    CheckMeta("B30", "Sender identity strength (name-matching / mutable-ID bypass)",
              MEDIUM, "hardening", "Sender Identity",
              surface="channels"),
    CheckMeta("B31", "Effective-tools bypass (illusory deny — write blocked but apply_patch/exec still write)",
              MEDIUM, "hardening", "Least Privilege / Tool Policy",
              surface="tools"),
    CheckMeta("B32", "Control-plane mutation reachability via gateway",
              HIGH, "hardening", "Control Plane",
              surface="gateway"),
    CheckMeta("B38", "Browser control / cookie & SSRF exposure",
              HIGH, "hardening", "Browser / SSRF",
              surface="sessions"),
    CheckMeta("B39", "Session visibility / cross-user transcript leak",
              MEDIUM, "hardening", "Session Isolation",
              surface="sessions"),
    CheckMeta("B26", "Untrusted-context exposure (channels.contextVisibility)",
              MEDIUM, "hardening", "Injection Surface",
              surface="channels"),
    CheckMeta("B33", "Known-vulnerable OpenClaw version gate",
              HIGH, "hardening", "Patch hygiene",
              surface="update"),
    CheckMeta("B41", "Credential blast-radius assessment",
              MEDIUM, "advisory", "Credential / Blast Radius", scored=True,
              surface="secrets"),
    CheckMeta("B42", "Skill/plugin install-time policy (postinstall hooks, writable skill dirs)",
              MEDIUM, "hardening", "Supply Chain / Install Policy", confidence="MEDIUM",
              surface="skills"),
    # Attestation layer (v0.26.0) — enriched by the agent's self-report (--attest).
    # ATTESTED confidence: weaker than a config fact; advisory (not scored) so the
    # static grade is unaffected when no attestation is supplied (finding -> UNKNOWN).
    CheckMeta("B43", "Capability blast-radius / dangerous-verb inventory",
              HIGH, "advisory", "Least Privilege / Blast Radius",
              scored=False, confidence=ATTESTED,
              surface="tools"),
    CheckMeta("B44", "Attestation ⇄ config mismatch (undisclosed capability)",
              MEDIUM, "advisory", "Trust Boundary / Drift",
              scored=False, confidence=ATTESTED,
              surface="tools"),
    # Multi-agent privilege separation (v1.4.0).
    # B45 reads the attested agent roster (config has no per-agent tool allowlist), so
    # it is ATTESTED + advisory like B43/B44 — UNKNOWN without --attest, no score impact.
    # B46 is config-only (grounded multi-agent topology + global trifecta + no gate); it
    # is scored but capped at WARN so it can never introduce a new FAIL on real configs.
    CheckMeta("B45", "Per-agent privilege separation (trifecta decomposition)",
              HIGH, "advisory", "Privilege Separation / Lethal Trifecta",
              scored=False, confidence=ATTESTED,
              surface="agents"),
    CheckMeta("B46", "Multi-agent trifecta exposure",
              MEDIUM, "hardening", "Least Privilege / Agents",
              surface="agents"),
    # B47 (v1.5.0): cross-agent reassembly over the attested delegation graph. ATTESTED +
    # advisory like B45 — config has no delegation graph, so UNKNOWN without --attest.
    CheckMeta("B47", "Cross-agent trifecta reassembly (delegation graph)",
              HIGH, "advisory", "Privilege Separation / Delegation",
              scored=False, confidence=ATTESTED,
              surface="agents"),
    # B48 (v1.8.0): grounded registry of OpenClaw "dangerously*/allowUnsafe*" break-glass
    # toggles. Scored: FAIL on sandbox-escape / control-plane-auth-disable, WARN on the rest.
    CheckMeta("B48", "Dangerous break-glass overrides enabled",
              HIGH, "hardening", "Least Privilege / Break-Glass",
              surface="tools"),
    # Host Watch Posture — is anyone watching the machine the agent runs on?
    # Read-only host-monitor detection (hostwatch.detect). LOW + WARN-only (never
    # FAIL): the absence of host monitoring is flagged only when the agent is
    # high-privilege, so it never hard-caps the grade.
    CheckMeta("B50", "Host network monitoring / IDS",
              LOW, "hardening", "Host Watch / Network IDS",
              surface="host"),
    CheckMeta("B51", "Host audit / syscall logging",
              LOW, "hardening", "Host Watch / Audit",
              surface="host"),
    CheckMeta("B52", "Host file-integrity monitoring",
              LOW, "hardening", "Host Watch / FIM",
              surface="host"),
    CheckMeta("B53", "Host endpoint protection / EDR",
              LOW, "hardening", "Host Watch / EDR",
              surface="host"),
    CheckMeta("B54", "Host firewall active",
              LOW, "hardening", "Host Watch / Firewall",
              surface="host"),
    # B55 (C-013): filesystem-write tool exposure. Advisory (scored=False) — it names
    # the fs-write capability and feeds RISK-12 (write + untrusted ingress = tamper /
    # persistence); the scored write/least-privilege dimensions stay with B3/B22/B31 so
    # this never introduces a new scored FAIL on real configs.
    CheckMeta("B55", "Filesystem-write tool exposure (broad fs-write without scoping)",
              HIGH, "hardening", "Least Privilege / Filesystem Write", scored=False,
              surface="tools"),
    # B56 (NC-4) / B57 (NC-8): real config-fact misconfigurations grounded against
    # docs.openclaw.ai/gateway/security. Both FAIL only on an explicit dangerous value
    # (allowedOrigins contains "*"; permissionMode=="approve-all"); a default/absent
    # config is UNKNOWN/PASS, so neither introduces a false-positive FAIL on real configs.
    CheckMeta("B56", "Control-UI cross-origin allow-all (allowedOrigins \"*\")",
              HIGH, "hardening", "Zero Trust / Control-UI Origin",
              surface="gateway"),
    CheckMeta("B57", "Plugin auto-approve (permissionMode=approve-all)",
              HIGH, "hardening", "Least Privilege / Plugin Approval",
              surface="skills"),
    # B58 (v1.17.0): Unicode de-obfuscation pre-pass — detects injections hidden behind
    # Cyrillic/Greek confusables, zero-width chars, and bidi-override controls.
    # FAIL only on a confirmed evasion delta (injection visible post-norm, invisible raw);
    # WARN on obfuscation presence without a confirmed injection (never a false-positive FAIL).
    CheckMeta("B58", "Unicode-obfuscated injection / hidden-text evasion",
              HIGH, "hardening", "Prompt Injection / Unicode Evasion", confidence="MEDIUM",
              surface="bootstrap"),
    # B59 (v1.17.0): Markdown/HTML image URLs with data-bearing query params — potential
    # exfiltration channel (image fetch carries context as query params to remote server).
    # WARN only — query-param images are common in legit docs; FAIL would risk FP.
    CheckMeta("B59", "Markdown-image data-exfil via remote URL",
              MEDIUM, "hardening", "Data Exfiltration / Markdown Injection", confidence="MEDIUM",
              surface="bootstrap"),
    # B60 (v1.17.0): Prompt self-replication / propagation directive (ATLAS AML.T0061).
    # WARN only — highest FP risk among content checks; requires verb + target proximity.
    CheckMeta("B60", "Prompt self-replication / propagation directive",
              HIGH, "hardening", "Agentic Worm / Self-Replication", confidence="MEDIUM",
              surface="bootstrap"),
    # B61 (v1.17.0): Cross-agent config snooping / credential theft (F-006 / SkillSpector
    # AS1–AS3). FAIL when a foreign-agent config path co-occurs with a read/exfil verb;
    # WARN on path-alone. Conservative gating (path + verb) prevents false-positive FAILs.
    CheckMeta("B61", "Cross-agent config snooping / credential theft",
              HIGH, "hardening", "Credential Theft / Supply Chain", confidence="MEDIUM",
              surface="bootstrap"),
    # B62 (F-019): Capability–intent mismatch — declared purpose (SKILL.md name/description)
    # conflicts with actual reachable capabilities (effect_profiles + import-family scan).
    # The HIGHEST false-positive risk check in the project — WARN-only, MEDIUM, advisory.
    # UNKNOWN when no SKILL.md description, no Python, or a vague/permissive category.
    # Only fires when the declared category is CLEAR+NARROW and the surprising capability
    # is MEANINGFUL (high-surprise single family OR ≥2 co-occurring surprising families).
    CheckMeta("B62", "Capability–intent mismatch (declared purpose vs actual behaviour)",
              MEDIUM, "advisory", "Excessive Agency / Inaccurate Capability Declaration",
              scored=False, confidence="MEDIUM",
              surface="skills"),
    # B63 (C-075): Silent-instruction detector — directives that hide agent actions
    # from the user.  Always malicious (no legit skill says "don't tell the user").
    # FAIL on secrecy + action co-occurrence; WARN on bare secrecy phrase.
    CheckMeta("B63", "Silent-instruction directive (hidden actions from user)",
              HIGH, "hardening", "Human Oversight / Transparency",
              confidence="HIGH",
              surface="bootstrap"),
    # B64 (C-076): Scan bootstrap files, installed skills, and MCP tool descriptions
    # for authority override phrases. FAIL on high confidence, WARN on weaker signals.
    CheckMeta("B64", "Instruction-hierarchy override detector",
              HIGH, "hardening", "Prompt Injection / Instruction Hierarchy",
              confidence="MEDIUM",
              surface="bootstrap"),
    # B65 (C-080): conditional / sleeper-trigger detector.
    # Detects prompts that gate hidden actions behind a user-query trigger.
    CheckMeta("B65", "Conditional sleeper-trigger detector",
              HIGH, "hardening", "Prompt Injection / Conditional Trigger",
              confidence="MEDIUM",
              surface="bootstrap"),
    # B66 (C-078): persona / role jailbreak detector.
    # Detects role-play instructions like "pretend you are DAN" that weaken policy
    # hierarchy and can reset trust assumptions.
    CheckMeta("B66", "Persona / role jailbreak detector",
              HIGH, "hardening", "Prompt Injection / Persona Injection",
              confidence="MEDIUM",
              surface="bootstrap"),
    # B67 (C-092): per-source tool-output trust contracts.
    # Complements B21 (generic trust boundary): checks that bootstrap has
    # channel-specific DATA/instruction declarations for each active high-risk
    # channel (browser, email, MCP, search, docs).
    CheckMeta("B67", "Per-source tool-output trust contracts",
              MEDIUM, "hardening", "Prompt Injection / Trust Boundary",
              confidence="MEDIUM",
              surface="bootstrap"),
    # B68–B73 (v1.20.0): advisory WARN-only config-fact checks. scored=False so they
    # never move the A–F grade. Each fires only on the explicit dangerous value;
    # default/absent → UNKNOWN or PASS (zero false-positive FAILs on real configs).
    CheckMeta("B68", "apply_patch workspace-only restriction disabled",
              MEDIUM, "hardening", "Least Privilege / Filesystem Write", scored=False,
              surface="tools"),
    CheckMeta("B69", "exec inline-eval gate missing when exec enabled",
              MEDIUM, "hardening", "Least Privilege / Inline Eval", scored=False,
              surface="tools"),
    CheckMeta("B70", "trustedProxy allowLoopback on non-loopback bind (header-spoof surface)",
              LOW, "hardening", "Zero Trust / Proxy Headers", scored=False,
              surface="gateway"),
    CheckMeta("B71", "gateway.nodes.denyCommands ineffective patterns (non-exact entries)",
              MEDIUM, "hardening", "Least Privilege / Node Commands", scored=False,
              surface="gateway"),
    CheckMeta("B72", "subagents.allowAgents wildcard (any agent as spawn target)",
              LOW, "hardening", "Least Privilege / Subagents", scored=False,
              surface="agents"),
    CheckMeta("B73", "mDNS full advertisement on non-loopback gateway bind",
              LOW, "hardening", "Least Privilege / Discovery", scored=False,
              surface="gateway"),
    CheckMeta("B74", "Forged role/system block or false-provenance attribution in content",
              HIGH, "hardening", "Prompt Injection / Provenance Forgery",
              surface="bootstrap"),
    CheckMeta("B75", "MCP tool-inheritance bypass — per-agent filter circumvented (attested)",
              MEDIUM, "hardening", "Least Privilege / MCP Tool Inheritance",
              scored=False, confidence=ATTESTED,
              surface="agents"),
    CheckMeta("B76", "High-blast MCP tool-inheritance bypass (attested)",
              HIGH, "hardening", "Least Privilege / MCP Tool Inheritance",
              scored=True, confidence=ATTESTED,
              surface="agents"),
    CheckMeta("B77", "Config-write audit log review (suspicious / unexpected writer)",
              MEDIUM, "hardening", "Audit Log / Config Provenance",
              scored=False, confidence="MEDIUM",
              surface="monitoring"),
    CheckMeta("B78", "Config-health integrity alert (observed suspicious signature)",
              HIGH, "hardening", "Config Integrity / Tamper Detection",
              scored=False, confidence="MEDIUM",
              surface="monitoring"),
    CheckMeta("B79", "Codex session approval-policy posture (approval=never)",
              MEDIUM, "hardening", "Human Approval",
              scored=False, confidence="MEDIUM",
              surface="tools"),
    # advisory (not scored)
    CheckMeta("C3", "Backups of SOUL.md / memory", LOW, "advisory", "Backups", scored=False,
              surface="bootstrap"),
    CheckMeta("C4", "OpenClaw version / update hygiene", LOW, "advisory", "Patch hygiene", scored=False,
              surface="update"),
    CheckMeta("C5", "Native binary PATH safety", LOW, "advisory", "Binary Integrity",
              scored=False, confidence="MEDIUM",
              surface="host"),
    # C6 (C-052): pre-v2026.6.10 hook-composition could silently drop trusted tool
    # policies. Runtime evaluation-order effect, no static config field — an honest
    # UNKNOWN nudge, never a FAIL. Advisory (not scored).
    CheckMeta("C6", "Hook-composition tool-policy drop (pre-v2026.6.10)",
              LOW, "advisory", "Patch hygiene", scored=False,
              surface="update"),
    CheckMeta("C032", "Proxy header trust when real-IP fallback is enabled",
              LOW, "advisory", "Gateway / Proxy Header Trust", scored=False,
              surface="gateway"),
    CheckMeta("C014", "Egress inventory (outbound-capable surface enumeration)",
              LOW, "advisory", "Egress Inventory", scored=False,
              surface="monitoring"),
    CheckMeta("C015", "Secrets-at-rest scan of the OpenClaw home",
              MEDIUM, "advisory", "Secrets / Filesystem", scored=False, confidence="MEDIUM",
              surface="secrets"),
    CheckMeta("C047", "Non-local MCP server endpoint (manual review)",
              LOW, "advisory", "MCP / External Endpoint Review", scored=False,
              surface="mcp"),
    # C048: top-level cron scheduler persistence surface. Advisory UNKNOWN-only when
    # the real OpenClaw `cron` field is present; config alone cannot distinguish a
    # legitimate schedule from attacker-planted persistence, so this never FAILs.
    CheckMeta("C048", "Cron scheduler persistence surface (top-level cron)",
              LOW, "advisory", "Persistence / Scheduled Execution", scored=False,
              surface="hooks"),
    CheckMeta("C074", "Injection-like text in HTML image attributes",
              MEDIUM, "advisory", "Prompt Injection / HTML Attribute", scored=False,
              surface="bootstrap"),
]

BY_ID = {c.id: c for c in CATALOG}


# ── OWASP framework mapping (additive metadata; no verdict/score impact) ──────────
# OWASP Top 10 for LLM Applications 2025 — grounded against genai.owasp.org (the 2025
# list reordered vs 2023: Sensitive-Info-Disclosure is LLM02, Improper-Output-Handling
# LLM05, Excessive-Agency LLM06, System-Prompt-Leakage LLM07 is new).
OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Agentic Skills Top 10 (2026 Edition) — agent-SKILL-specific threat classes.
# Grounded against owasp.org/www-project-agentic-skills-top-10 (v1.0 2026, status:
# "candidate / active development"). Titles verbatim from the published list.
OWASP_AST_2026 = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}

# Each skill-relevant check -> OWASP Agentic Skills Top 10 (2026) class(es). Only clean
# fits are tagged; agent-/network-only or pure-config-hygiene checks are intentionally
# left out (ast_for returns ()). AST10 Cross-Platform Reuse has no catalog member
# (single-install scope) — a documented coverage gap.
AST_MAP = {
    "B13": ("AST01", "AST02"),
    "C048": ("AST01",),
    "B5": ("AST02",),
    "B15": ("AST02",),
    "B24": ("AST02",),
    "B42": ("AST02",),
    "C5": ("AST02",),
    "C047": ("AST02",),
    "B3": ("AST03",),
    "B8": ("AST03",),
    "B17": ("AST03",),
    "B18": ("AST03",),
    "B31": ("AST03",),
    "B32": ("AST03",),
    "B41": ("AST03",),
    "B43": ("AST03",),
    "B45": ("AST03",),
    "B46": ("AST03",),
    "B47": ("AST03",),
    "B55": ("AST03",),
    "B68": ("AST03",),
    "B69": ("AST03",),
    "B71": ("AST03",),
    "B72": ("AST03",),
    "B75": ("AST03",),
    "B6": ("AST04", "AST05"),
    "B44": ("AST03", "AST04"),
    "B62": ("AST04",),
    "B7": ("AST05",),
    "B20": ("AST05",),
    "B21": ("AST05",),
    "B23": ("AST05", "AST03"),
    "B26": ("AST05",),
    "B30": ("AST05",),
    "B58": ("AST05",),
    "B59": ("AST05",),
    "B60": ("AST01", "AST05"),
    "B61": ("AST05",),
    "B63": ("AST01", "AST05"),
    "B64": ("AST05",),
    "B65": ("AST01", "AST05"),
    "B66": ("AST05",),
    "B67": ("AST05",),
    "C074": ("AST05",),
    "B4": ("AST06",),
    "B22": ("AST03", "AST06"),
    "B39": ("AST06",),
    "B48": ("AST06", "AST03"),
    "B70": ("AST06",),
    "B25": ("AST02", "AST07"),
    "B33": ("AST07",),
    "C4": ("AST07",),
    "C6": ("AST07",),
    "B16": ("AST08", "AST09"),
    "B10": ("AST09",),
    "B50": ("AST09",),
    "B51": ("AST09",),
    "B52": ("AST09",),
    "B53": ("AST09",),
    "B54": ("AST09",),
    "B57": ("AST02", "AST03"),
}

# Each check mapped to the OWASP-LLM-2025 category/categories it addresses ON THE AGENT
# surface. Only clear fits are tagged; checks with no clean LLM-Top-10 analog (host-watch
# B50–B54, logging B10, monitoring B16, SSRF B38, backups C3) are intentionally left
# unmapped rather than stretched — their coverage is the agent-specific OWASP Agentic
# (ASI) threat classes, documented in docs/THREAT_COVERAGE.md. LLM08 (vector/embedding)
# and LLM09 (misinformation) have no agent-config surface here, so nothing maps to them.
OWASP_MAP = {
    "A1": ("LLM01", "LLM06"),
    "B1": ("LLM02",),
    "B2": ("LLM01",),
    "B3": ("LLM06",),
    "B4": ("LLM06",),
    "B5": ("LLM03",),
    "B6": ("LLM01",),
    "B7": ("LLM04",),
    "B8": ("LLM06",),
    "B9": ("LLM07", "LLM02"),
    "B11": ("LLM02",),
    "B13": ("LLM03",),
    "B14": ("LLM02",),
    "B15": ("LLM03",),
    "B17": ("LLM06", "LLM10"),
    "B18": ("LLM06",),
    "B19": ("LLM02",),
    "B20": ("LLM04",),
    "B21": ("LLM01", "LLM05"),
    "B22": ("LLM04", "LLM06"),
    "B23": ("LLM01", "LLM06"),
    "B24": ("LLM03",),
    "B25": ("LLM03",),
    "B26": ("LLM01",),
    "B30": ("LLM01",),
    "B31": ("LLM06",),
    "B32": ("LLM06",),
    "B33": ("LLM03",),
    "B39": ("LLM02",),
    "B41": ("LLM02", "LLM06"),
    "B42": ("LLM03",),
    "B43": ("LLM06",),
    "B44": ("LLM06",),
    "B45": ("LLM06",),
    "B46": ("LLM06",),
    "B47": ("LLM05", "LLM06"),
    "B48": ("LLM01", "LLM06"),
    "B55": ("LLM06", "LLM04"),
    "B56": ("LLM01",),
    "B57": ("LLM06", "LLM03"),
    # B62: Excessive Agency (LLM06) — skill acts beyond its declared scope.
    "B62": ("LLM06",),
    # B63: Improper Output Handling (LLM09) / Excessive Agency (LLM06) — hiding
    # actions from the user undermines transparency and human oversight.
    "B63": ("LLM09", "LLM06"),
    # B65: conditional/sleeper trigger instructions — hidden conditional malware-like
    # behavior under a user-query gate.
    "B65": ("LLM06", "LLM09"),
    # B66: persona / role jailbreak patterns that aim to reset safety constraints.
    "B66": ("LLM06", "LLM09"),
    # B67: per-source trust contracts — prompt injection via channel-specific gaps.
    "B67": ("LLM01", "LLM02"),
    "C4": ("LLM03",),
    "C5": ("LLM03",),
    # Gap-fill additions (E-013): content-injection and config-hygiene checks now mapped.
    "B58": ("LLM01",),
    "B59": ("LLM02", "LLM01"),
    "B60": ("LLM01",),
    "B61": ("LLM02", "LLM01"),
    "B64": ("LLM01",),
    "B68": ("LLM06",),
    "B69": ("LLM06",),
    "B71": ("LLM06",),
    "B72": ("LLM06",),
    "C074": ("LLM01",),
    "C047": ("LLM03",),
}


def owasp_for(check_id: str) -> tuple:
    """OWASP-LLM-2025 code(s) a check maps to, or () if it has no clean LLM-Top-10 analog."""
    return OWASP_MAP.get(check_id, ())


def ast_for(check_id: str) -> tuple:
    """OWASP Agentic Skills Top 10 (2026) code(s) a check maps to, or () if it has
    no clean agent-skill analog (agent-/network-only or pure config hygiene)."""
    return AST_MAP.get(check_id, ())


# ── Paste-ready remediation (additive; surfaced by --fix / --json / SARIF) ────────
# Authored ONLY for checks with a safe, deterministic, paste-ready fix. ClawSecCheck
# never applies these — it prints them; the user reviews and runs them (§2 read-only).
#   commands: exact shell, allowlisted verbs only (chmod / openclaw); <placeholders>
#             for workspace-specific paths are documented forms, not auto-substituted
#             (never chmod a path guessed from evidence — §5).
#   config:   path+value GUIDANCE for openclaw.json (grounded dotted paths only, §4) —
#             "set <path> -> <value>", NOT a paste-over JSON blob (a blob would clobber
#             neighbouring keys). set=None means the value is descriptive (see note).
REMEDIATION = {
    "B1": {"commands": ["openclaw secrets configure",
                        "chmod 600 ~/.openclaw/openclaw.json",
                        "chmod 700 ~/.openclaw"]},
    "B2": {"config": [{"path": "gateway.auth", "set": None,
                       "note": "enable gateway auth and restrict channels to an allowlist"}]},
    "B3": {"config": [{"path": "tools.elevated.allowFrom", "set": None,
                       "note": "restrict to an explicit allowlist (no wildcards)"}]},
    "B4": {"config": [{"path": "agents.defaults.sandbox.mode", "set": "non-main",
                       "note": "run exec tools in a sandbox"}]},
    "B8": {"config": [{"path": "tools.exec.mode", "set": "ask",
                       "note": "require human approval before exec"}]},
    "B19": {"commands": ["chmod 700 ~/.openclaw"]},
    "B20": {"commands": ["chmod 700 <workspace>",
                         "chmod 600 <workspace>/SOUL.md <workspace>/AGENTS.md "
                         "<workspace>/TOOLS.md <workspace>/MEMORY.md"]},
    "B22": {"commands": ["chmod 600 <workspace>/SOUL.md", "chmod 700 <workspace>/skills"]},
    "B23": {"config": [{"path": "tools.exec.mode", "set": "ask",
                        "note": "enforce the approval gate; do not let bootstrap text weaken it"}]},
    "B30": {"config": [{"path": "channels.<provider>.dangerouslyAllowNameMatching", "set": None,
                        "note": "remove this flag — a mutable display-name allowlist is "
                                "trivially bypassed"}]},
    "B38": {"config": [{"path": "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", "set": False,
                        "note": "block private-network requests from the browser tool"}]},
    "B39": {"config": [{"path": "session.dmScope", "set": None,
                        "note": "isolate DM sessions per user; do not use \"main\""}]},
    "C5": {"commands": ["chmod o-w,g-w <dir>"]},
}


def remediation_for(check_id: str) -> dict:
    """Paste-ready remediation for a check, normalized to {"commands": [...], "config": [...]}.

    Empty lists when the check has no deterministic paste-ready fix (its prose `fix` leads).
    """
    r = REMEDIATION.get(check_id, {})
    return {"commands": list(r.get("commands", ())),
            "config": [dict(c) for c in r.get("config", ())]}


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
    # PASS-specific confidence tier: 'verified' = check found positive evidence of security;
    # 'no_signal' = PASS by absence of a bad signal (config absent/default).
    # None for FAIL/WARN/UNKNOWN findings (not meaningful there).
    pass_confidence: str | None = None
