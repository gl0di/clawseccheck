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
WARN = "WARN"  # partial / likely-insecure default; counts half, does not hard-cap
UNKNOWN = "UNKNOWN"  # not determinable from config -> excluded from score denominator

# Confidence tiers (orthogonal to severity/status). A self-report from the audited
# agent is WEAKER evidence than a config fact — the agent may be compromised or
# prompt-injected — so attestation-derived findings carry ATTESTED, below MEDIUM.
ATTESTED = "ATTESTED"


# ── Surface taxonomy (additive metadata; no verdict/score impact) ─────────────
# 13 canonical OpenClaw security surfaces + "trifecta" (cross-cutting).
# Grounded against docs/research/output-redesign-dashboard.md (2026-06-27).
SURFACES: tuple[str, ...] = (
    "gateway",
    "tools",
    "agents",
    "mcp",
    "skills",
    "bootstrap",
    "channels",
    "sessions",
    "secrets",
    "monitoring",
    "hooks",
    "host",
    "update",
    "trifecta",  # cross-cutting: A1 headline check only — not a bucket surface
)

# 13-surface → 7-family roll-up (dashboard grouping; unblocks F-029).
# "trifecta" is intentionally absent: it is a cross-cutting chip, never a family bucket.
FAMILY_OF: dict[str, str] = {
    "gateway": "exposure",  # Exposure & Network
    "channels": "exposure",
    "sessions": "exposure",
    "tools": "privilege",  # Privilege & Execution
    "agents": "privilege",
    "skills": "supply_chain",  # Supply Chain
    "mcp": "supply_chain",
    "bootstrap": "content_integrity",  # Content & Memory Integrity
    "secrets": "secrets",  # Secrets & Data
    "monitoring": "detection",  # Detection & Host
    "host": "detection",
    "hooks": "automation",  # Automation & Maintenance
    "update": "automation",
}

# Human-facing family labels, in the fixed order the Dashboard renders them.
# "trifecta" (A1) is routed to "privilege" by the report renderer — it's an
# agent-behavior signal, not its own bucket (unblocks F-044).
FAMILY_LABEL: dict[str, str] = {
    "exposure": "Exposure & Network",
    "privilege": "Privilege & Execution",
    "supply_chain": "Supply Chain",
    "content_integrity": "Content & Memory Integrity",
    "secrets": "Secrets & Data",
    "detection": "Detection & Host",
    "automation": "Automation & Maintenance",
}
FAMILY_ORDER: tuple[str, ...] = tuple(FAMILY_LABEL.keys())

# 14-surface -> 5-subject roll-up (F-131 Phase 1: owner-facing "Inventory by subject").
# Additive metadata only, next to FAMILY_OF — no verdict/score impact. Distinct from
# FAMILY_OF (analyst-facing security categories): this groups findings the way an owner
# actually owns things — "my system", "my agents", "each of my skills" — per the approved
# design docs/design/2026-07-17-subject-inventory-block-design.md (workspace-root only,
# not shipped). Every SURFACES slug (incl. "trifecta") maps to exactly one subject; a
# coherence test asserts completeness, mirroring FAMILY_OF's own contract.
SUBJECT_OF: dict[str, str] = {
    "gateway": "system",
    "tools": "system",
    "secrets": "system",
    "monitoring": "system",
    "hooks": "system",
    "host": "system",
    "update": "system",
    "sessions": "system",
    "agents": "agents",
    "bootstrap": "agents",
    "trifecta": "agents",  # A1: an agent-behavior signal, not a standalone bucket
    "skills": "skills",
    "mcp": "mcp",
    "channels": "channels",
}

# Human-facing subject labels, in the fixed order the Inventory block renders them.
SUBJECT_LABEL: dict[str, str] = {
    "system": "System (OpenClaw core)",
    "agents": "Agents",
    "skills": "Skills",
    "mcp": "MCP servers",
    "channels": "Channels",
}
SUBJECT_ORDER: tuple[str, ...] = ("system", "agents", "skills", "mcp", "channels")


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: str
    block: str  # "trifecta" | "hardening" | "advisory"
    framework: str  # human-facing taxonomy tag
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
    CheckMeta(
        "A1",
        "Lethal Trifecta (untrusted input × sensitive data × outbound)",
        CRITICAL,
        "trifecta",
        "Lethal Trifecta",
        surface="trifecta",
    ),
    CheckMeta(
        "B1",
        "Secrets in plaintext config / bootstrap files",
        CRITICAL,
        "hardening",
        "Secrets Vault",
        surface="secrets",
    ),
    CheckMeta(
        "B2",
        "Gateway exposure & channel authentication",
        CRITICAL,
        "hardening",
        "Zero Trust / Gateway",
        surface="gateway",
    ),
    CheckMeta(
        "B3",
        "Least privilege (elevated tools / allowlists)",
        HIGH,
        "hardening",
        "Least Privilege",
        surface="tools",
    ),
    CheckMeta(
        "B4", "Execution sandbox", HIGH, "hardening", "Least Privilege / Sandbox", surface="agents"
    ),
    CheckMeta(
        "B5",
        "Plugin / skill supply-chain integrity",
        HIGH,
        "hardening",
        "Supply Chain",
        surface="skills",
    ),
    CheckMeta(
        "B6",
        "Bootstrap-file injection surface (SOUL.md/AGENTS.md/TOOLS.md)",
        HIGH,
        "hardening",
        "Untrusted↔Trusted separation",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    CheckMeta(
        "B7",
        "Memory poisoning surface (MEMORY.md / memory dir)",
        HIGH,
        "hardening",
        "Memory integrity",
        surface="bootstrap",
    ),
    CheckMeta(
        "B8",
        "Human approval on destructive actions",
        HIGH,
        "hardening",
        "Human Approval",
        surface="tools",
    ),
    CheckMeta(
        "B9",
        "System-prompt / secret leak in tool output",
        LOW,
        "hardening",
        "Egress / Leak",
        surface="secrets",
    ),
    CheckMeta(
        "B10",
        "Audit log & sensitive redaction",
        MEDIUM,
        "hardening",
        "Audit Log",
        surface="monitoring",
    ),
    CheckMeta(
        "B11",
        "Transport TLS & at-rest protection",
        MEDIUM,
        "hardening",
        "TLS & Encryption",
        surface="gateway",
    ),
    CheckMeta(
        "B12", "Local-first & model hygiene", LOW, "hardening", "Local First", surface="secrets"
    ),
    CheckMeta(
        "B13",
        "Installed skill / plugin safety (downloaded, not self-made)",
        HIGH,
        "hardening",
        "Supply Chain / ClawHavoc",
        confidence="MEDIUM",
        surface="skills",
    ),
    CheckMeta(
        "B14",
        "Egress surface (where the agent can reach out)",
        MEDIUM,
        "hardening",
        "Egress Control",
        scored=False,
        surface="monitoring",
    ),
    CheckMeta("B15", "MCP server trust boundaries", HIGH, "hardening", "MCP Trust", surface="mcp"),
    CheckMeta(
        "B16",
        "Threat monitoring / detection in place",
        MEDIUM,
        "hardening",
        "Monitoring",
        surface="monitoring",
    ),
    CheckMeta(
        "B17",
        "Autonomy / heartbeat actions",
        MEDIUM,
        "hardening",
        "Autonomy Control",
        surface="tools",
    ),
    CheckMeta(
        "B18",
        "Subagent delegation",
        MEDIUM,
        "hardening",
        "Least Privilege / Subagents",
        surface="agents",
    ),
    CheckMeta(
        "B19",
        "Data at-rest protection (memory/logs)",
        MEDIUM,
        "hardening",
        "Data Protection",
        surface="secrets",
    ),
    CheckMeta(
        "B20",
        "Bootstrap / memory write protection",
        MEDIUM,
        "hardening",
        "Write Integrity",
        surface="bootstrap",
    ),
    CheckMeta(
        "B21",
        "Tool-output / retrieved-content trust boundary",
        MEDIUM,
        "hardening",
        "Prompt Injection / Trust Boundary",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    CheckMeta(
        "B22",
        "Self-modification risk (identity/skill files writable + tools enabled)",
        HIGH,
        "hardening",
        "Write Integrity / Self-Modification",
        surface="agents",
    ),
    CheckMeta(
        "B23",
        "Approval-bypass directives in bootstrap",
        HIGH,
        "hardening",
        "Human Approval",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    CheckMeta("B24", "MCP server hardening", HIGH, "hardening", "MCP Trust", surface="mcp"),
    CheckMeta(
        "B25", "Update / pinning hygiene", MEDIUM, "hardening", "Supply Chain", surface="skills"
    ),
    CheckMeta(
        "B30",
        "Sender identity strength (name-matching / mutable-ID bypass)",
        MEDIUM,
        "hardening",
        "Sender Identity",
        surface="channels",
    ),
    CheckMeta(
        "B31",
        "Effective-tools bypass (illusory deny — write blocked but apply_patch/exec still write)",
        MEDIUM,
        "hardening",
        "Least Privilege / Tool Policy",
        surface="tools",
    ),
    CheckMeta(
        "B32",
        "Control-plane mutation reachability via gateway",
        HIGH,
        "hardening",
        "Control Plane",
        surface="gateway",
    ),
    CheckMeta(
        "B38",
        "Browser control / cookie & SSRF exposure",
        HIGH,
        "hardening",
        "Browser / SSRF",
        surface="sessions",
    ),
    CheckMeta(
        "B155",
        "Outbound proxy hardening (credential leak / TLS-verify / SSRF-guard bypass)",
        HIGH,
        "hardening",
        "Proxy / Egress Hardening",
        surface="tools",
    ),
    # B178 (B-241, child of E-047): models.providers.<id>.baseUrl is the one sibling
    # field B155 never dig()s on the same provider object. Grounded: ModelProviderSchema
    # .baseUrl (zod-schema.core-DviqqtPj.js) — optional, per-provider, repoints the
    # agent's LLM endpoint. Dual-use caveat (explicit in the originating task): a custom
    # https:// baseUrl (self-hosted gateway / corporate proxy) is legitimate and
    # indistinguishable from an attacker repoint by static inspection alone, so it is
    # NEVER flagged. A cleartext http:// scheme to a public IP or unrecognized dotted
    # hostname is sound, unambiguous positive evidence — FAIL. A cleartext http:// to a
    # private/CGNAT-range IP or a bare single-label hostname (e.g. a docker-compose
    # sibling service) is on-LAN-only exposure, indistinguishable from a benign local
    # model runtime (Ollama/LM Studio, which carry no API key at all) — WARN, not FAIL
    # (B-241 adversarial review, confirmed FP: OpenClaw's own
    # LMSTUDIO_DOCKER_HOST_BASE_URL / LOCAL_OLLAMA_HOSTNAMES / isLoopbackOllamaBaseUrl
    # treat host.docker.internal, 0.0.0.0, and 10/8+172.16/12+192.168/16+100.64.0.0/10
    # as local — those FAILed before this fix). FAIL-capable but scoped tight (HIGH
    # confidence, deterministic field read) to hold Golden Rule #5.
    CheckMeta(
        "B178",
        "Cleartext http:// baseUrl on a model provider (API-key + traffic leak)",
        HIGH,
        "hardening",
        "Proxy / Egress Hardening",
        surface="tools",
    ),
    CheckMeta(
        "B39",
        "Session visibility / cross-user transcript leak",
        MEDIUM,
        "hardening",
        "Session Isolation",
        surface="sessions",
    ),
    CheckMeta(
        "B26",
        "Untrusted-context exposure (channels.contextVisibility)",
        MEDIUM,
        "hardening",
        "Injection Surface",
        surface="channels",
    ),
    # B140 (B-139): a channel provider's groups["*"] wildcard entry with no allowFrom
    # (channel-level or per-group) means the bot answers in any group anyone adds it
    # to. Advisory only — a public/community bot may accept this deliberately.
    CheckMeta(
        "B140",
        "Wildcard group ingress with no allowFrom restriction",
        MEDIUM,
        "hardening",
        "Injection Surface",
        confidence="MEDIUM",
        surface="channels",
    ),
    CheckMeta(
        "B33",
        "Known-vulnerable OpenClaw version gate",
        HIGH,
        "hardening",
        "Patch hygiene",
        surface="update",
    ),
    CheckMeta(
        "B41",
        "Credential blast-radius assessment",
        MEDIUM,
        "advisory",
        "Credential / Blast Radius",
        scored=True,
        surface="secrets",
    ),
    CheckMeta(
        "B42",
        "Skill/plugin install-time policy (postinstall hooks, writable skill dirs)",
        MEDIUM,
        "hardening",
        "Supply Chain / Install Policy",
        confidence="MEDIUM",
        surface="skills",
    ),
    # B174 (B-238): the operator-facing install GATE itself -- security.installPolicy.*
    # (enabled + the exec hook's allowInsecurePath/allowSymlinkCommand/trustedDirs/passEnv
    # escape surface) -- distinct from B42, which only scans a skill's own postinstall
    # hook content and skill-dir perms. FAIL is reserved for an unrestrained
    # allowInsecurePath (no trustedDirs); trustedDirs narrows it to WARN, a bare
    # allowSymlinkCommand alone doesn't bypass the resolved-target's own permission checks
    # and is not a finding trigger, and the bare "not enabled" default state is WARN-only
    # (C-135 adversarial re-pass, B-238: ground truth is install-policy-Barp1EUw.js
    # assertSecureCommandPath()).
    CheckMeta(
        "B174",
        "security.installPolicy.* operator gate + exec-hook escape flags",
        HIGH,
        "hardening",
        "Supply Chain / Install Policy",
        confidence="HIGH",
        surface="skills",
    ),
    # Attestation layer (v0.26.0) — enriched by the agent's self-report (--attest).
    # ATTESTED confidence: weaker than a config fact; advisory (not scored) so the
    # static grade is unaffected when no attestation is supplied (finding -> UNKNOWN).
    CheckMeta(
        "B43",
        "Capability blast-radius / dangerous-verb inventory",
        HIGH,
        "advisory",
        "Least Privilege / Blast Radius",
        scored=False,
        confidence=ATTESTED,
        surface="tools",
    ),
    CheckMeta(
        "B44",
        "Attestation ⇄ config mismatch (undisclosed capability)",
        MEDIUM,
        "advisory",
        "Trust Boundary / Drift",
        scored=False,
        confidence=ATTESTED,
        surface="tools",
    ),
    # Multi-agent privilege separation (v1.4.0).
    # B45 reads the attested agent roster (config has no per-agent tool allowlist), so
    # it is ATTESTED + advisory like B43/B44 — UNKNOWN without --attest, no score impact.
    # B46 is config-only (grounded multi-agent topology + global trifecta + no gate); it
    # is scored but capped at WARN so it can never introduce a new FAIL on real configs.
    CheckMeta(
        "B45",
        "Per-agent privilege separation (trifecta decomposition)",
        HIGH,
        "advisory",
        "Privilege Separation / Lethal Trifecta",
        scored=False,
        confidence=ATTESTED,
        surface="agents",
    ),
    CheckMeta(
        "B46",
        "Multi-agent trifecta exposure",
        MEDIUM,
        "hardening",
        "Least Privilege / Agents",
        surface="agents",
    ),
    # B47 (v1.5.0): cross-agent reassembly over the attested delegation graph. ATTESTED +
    # advisory like B45 — config has no delegation graph, so UNKNOWN without --attest.
    CheckMeta(
        "B47",
        "Cross-agent trifecta reassembly (delegation graph)",
        HIGH,
        "advisory",
        "Privilege Separation / Delegation",
        scored=False,
        confidence=ATTESTED,
        surface="agents",
    ),
    # B48 (v1.8.0): grounded registry of OpenClaw "dangerously*/allowUnsafe*" break-glass
    # toggles. Scored: FAIL on sandbox-escape / control-plane-auth-disable, WARN on the rest.
    CheckMeta(
        "B48",
        "Dangerous break-glass overrides enabled",
        HIGH,
        "hardening",
        "Least Privilege / Break-Glass",
        surface="tools",
    ),
    # Host Watch Posture — is anyone watching the machine the agent runs on?
    # Read-only host-monitor detection (hostwatch.detect). LOW + WARN-only (never
    # FAIL): the absence of host monitoring is flagged only when the agent is
    # high-privilege, so it never hard-caps the grade.
    CheckMeta(
        "B50",
        "Host network monitoring / IDS",
        LOW,
        "hardening",
        "Host Watch / Network IDS",
        surface="host",
    ),
    CheckMeta(
        "B51",
        "Host audit / syscall logging",
        LOW,
        "hardening",
        "Host Watch / Audit",
        surface="host",
    ),
    CheckMeta(
        "B52",
        "Host file-integrity monitoring",
        LOW,
        "hardening",
        "Host Watch / FIM",
        surface="host",
    ),
    CheckMeta(
        "B53",
        "Host endpoint protection / EDR",
        LOW,
        "hardening",
        "Host Watch / EDR",
        surface="host",
    ),
    CheckMeta(
        "B54", "Host firewall active", LOW, "hardening", "Host Watch / Firewall", surface="host"
    ),
    # B101 (F-084): outbound (egress) filtering posture — a firewall can be present
    # and active (B54) while still defaulting to allow-all outbound. WARN-only when
    # confirmed default-allow AND the agent is high-privilege; UNKNOWN when the
    # policy can't be read (the expected result on most systems, never fabricated).
    CheckMeta(
        "B101",
        "Outbound (egress) filtering posture",
        LOW,
        "hardening",
        "Host Watch / Egress Posture",
        surface="host",
    ),
    # B55 (C-013): filesystem-write tool exposure. Advisory (scored=False) — it names
    # the fs-write capability and feeds RISK-12 (write + untrusted ingress = tamper /
    # persistence); the scored write/least-privilege dimensions stay with B3/B22/B31 so
    # this never introduces a new scored FAIL on real configs.
    CheckMeta(
        "B55",
        "Filesystem-write tool exposure (broad fs-write without scoping)",
        HIGH,
        "hardening",
        "Least Privilege / Filesystem Write",
        scored=False,
        surface="tools",
    ),
    # B56 (NC-4) / B57 (NC-8): real config-fact misconfigurations grounded against
    # docs.openclaw.ai/gateway/security. Both FAIL only on an explicit dangerous value
    # (allowedOrigins contains "*"; permissionMode=="approve-all"); a default/absent
    # config is UNKNOWN/PASS, so neither introduces a false-positive FAIL on real configs.
    CheckMeta(
        "B56",
        'Control-UI cross-origin allow-all (allowedOrigins "*")',
        HIGH,
        "hardening",
        "Zero Trust / Control-UI Origin",
        surface="gateway",
    ),
    CheckMeta(
        "B57",
        "Plugin auto-approve (permissionMode=approve-all)",
        HIGH,
        "hardening",
        "Least Privilege / Plugin Approval",
        surface="skills",
    ),
    # B58 (v1.17.0): Unicode de-obfuscation pre-pass — detects injections hidden behind
    # Cyrillic/Greek confusables, zero-width chars, and bidi-override controls.
    # FAIL only on a confirmed evasion delta (injection visible post-norm, invisible raw);
    # WARN on obfuscation presence without a confirmed injection (never a false-positive FAIL).
    CheckMeta(
        "B58",
        "Unicode-obfuscated injection / hidden-text evasion",
        HIGH,
        "hardening",
        "Prompt Injection / Unicode Evasion",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B59 (v1.17.0): Markdown/HTML image URLs with data-bearing query params — potential
    # exfiltration channel (image fetch carries context as query params to remote server).
    # WARN only — query-param images are common in legit docs; FAIL would risk FP.
    CheckMeta(
        "B59",
        "Markdown-image data-exfil via remote URL",
        MEDIUM,
        "hardening",
        "Data Exfiltration / Markdown Injection",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B60 (v1.17.0): Prompt self-replication / propagation directive (ATLAS AML.T0061).
    # WARN only — highest FP risk among content checks; requires verb + target proximity.
    CheckMeta(
        "B60",
        "Prompt self-replication / propagation directive",
        HIGH,
        "hardening",
        "Agentic Worm / Self-Replication",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B61 (v1.17.0): Cross-agent config snooping / credential theft (F-006 / SkillSpector
    # AS1–AS3). FAIL when a foreign-agent config path co-occurs with a read/exfil verb;
    # WARN on path-alone. Conservative gating (path + verb) prevents false-positive FAILs.
    CheckMeta(
        "B61",
        "Cross-agent config snooping / credential theft",
        HIGH,
        "hardening",
        "Credential Theft / Supply Chain",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B62 (F-019): Capability–intent mismatch — declared purpose (SKILL.md name/description)
    # conflicts with actual reachable capabilities (effect_profiles + import-family scan).
    # The HIGHEST false-positive risk check in the project — WARN-only, MEDIUM, advisory.
    # UNKNOWN when no SKILL.md description, no Python, or a vague/permissive category.
    # Only fires when the declared category is CLEAR+NARROW and the surprising capability
    # is MEANINGFUL (high-surprise single family OR ≥2 co-occurring surprising families).
    CheckMeta(
        "B62",
        "Capability–intent mismatch (declared purpose vs actual behaviour)",
        MEDIUM,
        "advisory",
        "Excessive Agency / Inaccurate Capability Declaration",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B63 (C-075): Silent-instruction detector — directives that hide agent actions
    # from the user.  Always malicious (no legit skill says "don't tell the user").
    # FAIL on secrecy + action co-occurrence; WARN on bare secrecy phrase.
    # C-192 (Option C targeted promote, clean C-135 pass): FAIL severity CRITICAL — a
    # co-located secrecy+action directive is near-zero-FP and structurally always
    # malicious. The WARN branch (bare secrecy phrase) stays pinned at its own explicit
    # severity=MEDIUM in check_silent_instruction, unaffected by this bump.
    CheckMeta(
        "B63",
        "Silent-instruction directive (hidden actions from user)",
        CRITICAL,
        "hardening",
        "Human Oversight / Transparency",
        confidence="HIGH",
        surface="bootstrap",
    ),
    # B64 (C-076): Scan bootstrap files, installed skills, and MCP tool descriptions
    # for authority override phrases. FAIL on high confidence, WARN on weaker signals.
    CheckMeta(
        "B64",
        "Instruction-hierarchy override detector",
        HIGH,
        "hardening",
        "Prompt Injection / Instruction Hierarchy",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B65 (C-080): conditional / sleeper-trigger detector.
    # Detects prompts that gate hidden actions behind a user-query trigger.
    CheckMeta(
        "B65",
        "Conditional sleeper-trigger detector",
        HIGH,
        "hardening",
        "Prompt Injection / Conditional Trigger",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B66 (C-078): persona / role jailbreak detector.
    # Detects role-play instructions like "pretend you are DAN" that weaken policy
    # hierarchy and can reset trust assumptions.
    CheckMeta(
        "B66",
        "Persona / role jailbreak detector",
        HIGH,
        "hardening",
        "Prompt Injection / Persona Injection",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B156 (B-188, corroborated FAIL added C-093): overt unconditional secret-exfil — a
    # secret shipped to an external/second-party destination with no secrecy (B63),
    # override (B64) or trigger (B65) framing. FAILs when the destination itself names a
    # KNOWN paste/exfil/tunneling host (_KNOWN_EXFIL_HOST_RE — pastebin.com, webhook.site,
    # ngrok, transfer.sh, …), a concrete low-FP drop-point list reused from B166;
    # otherwise stays the original WARN (a vague destination, or a legitimate auth skill
    # POSTing its own token to its own declared backend, per the own-host safety valve —
    # see check_overt_secret_exfil / _b156_scan). No longer WARN-only: the metadata HIGH
    # ceiling now matches the runtime's full range, same as its B63/B65 content-ring
    # siblings.
    CheckMeta(
        "B156",
        "Overt secret-exfil to external/second-party destination",
        HIGH,
        "hardening",
        "Data Exfiltration / Credential Leak",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B165 (C-200, hex-key leg of the crypto-wallet VALUE detection split off C-198):
    # a bare 0x + 64 hex-char value is shape-identical between an Ethereum private key
    # and a transaction/block hash — co-occurrence gated (wallet/key wording nearby,
    # tx/block-hash wording absent) rather than a bare shape-only regex. Advisory:
    # acknowledged residual risk on both sides, never scored, never escalated to FAIL.
    CheckMeta(
        "B165",
        "Possible exposed crypto private-key value (hex-shaped, wallet-context gated)",
        HIGH,
        "advisory",
        "Data Exfiltration / Credential Leak",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B166 (C-211): a known paste/exfiltration host (webhook.site, ngrok, pastebin,
    # *.onion, ...) named in an MCP server's own command/args -- the server's
    # identity-level startup config itself references an untrusted drop point, before
    # the server is ever run. Grounded against the real OASB corpus (v2.0, 2988 benign
    # / 166 malicious mcp_tool samples): 0 benign false positives. C-230: scored, because
    # a very-narrow FAIL tier (webhook.site / .onion, `_B166_FAIL_HOST_RE`) has no
    # legitimate startup use; the broader dual-use hosts stay WARN inside the same check.
    CheckMeta(
        "B166",
        "MCP server command/args references a known paste/exfiltration host",
        HIGH,
        "hardening",
        "Data Exfiltration / Credential Leak",
        scored=True,
        confidence="MEDIUM",
        surface="mcp",
    ),
    # B167 (B-231): plugins.entries.<name>.config.appServer.command is an in-process
    # plugin's own launch command -- executed automatically whenever the plugin loads.
    # Reuses the same remote-fetch/pipe-to-shell detector B100/B103 use for skill install
    # directives (curl|bash, wget|sh, bash <(curl), iwr|iex, npx -y https://, pip install
    # https://), including the B-118 first-party-installer allowlist so a legitimate
    # documented installer host does not false-FAIL.
    CheckMeta(
        "B167",
        "Plugin appServer launch command is a remote-fetch/pipe-to-shell pattern",
        HIGH,
        "hardening",
        "Supply Chain",
        scored=True,
        confidence="MEDIUM",
        surface="skills",  # matches B57's plugins.entries.<name>.config.* precedent
    ),
    # B168 (B-231 sub-item 1): the cron job store (~/.openclaw/cron/jobs.json, or the
    # SQLite-backed cron_jobs table when the JSON file is absent) was never collected --
    # an entire unattended-execution surface was invisible. Reuses the same content-ring
    # directive/install detectors B169 reuses over each job's payload.message /
    # trigger.script, plus a structural deleteAfterRun+exec (self-erasing job) signal.
    # UNKNOWN when the cron store is absent or unreadable -- a genuine "cannot determine",
    # not a fake clean PASS (Golden Rule #4 / the B-228 _config_unreadable pattern).
    CheckMeta(
        "B168",
        "Cron job store payload.message / trigger.script carries an embedded directive",
        HIGH,
        "hardening",
        "Prompt Injection / Trust Boundary",
        scored=True,
        confidence="MEDIUM",
        surface="hooks",
    ),
    # B169 (B-231 sub-item 2): hooks.mappings[].messageTemplate / textTemplate carry an
    # untrusted external webhook payload into a live agent turn, but were never
    # content-scanned -- only allowUnsafeExternalContent (B48) is checked. Reuses the
    # content ring's own directive/install detectors (B64 instruction-hierarchy override,
    # B63 silent-instruction/secrecy framing, and the ClickFix remote-fetch/pipe-to-shell
    # pattern already reused by B167) over the template strings themselves.
    CheckMeta(
        "B169",
        "Hook mapping messageTemplate/textTemplate carries an embedded directive",
        HIGH,
        "hardening",
        "Prompt Injection / Trust Boundary",
        scored=True,
        confidence="MEDIUM",
        surface="hooks",
    ),
    # B170 (B-232 item 4): PRESENCE detector for a tool-output trust-boundary-inversion
    # directive -- text telling the agent to treat fetched web/MCP/tool/API output as
    # authoritative operator/system instructions. Mirrors B67 (which flags the ABSENCE
    # of the correct "tool output is data" declaration) from the opposite direction.
    # WARN-only (never FAIL) -- highest-FP surface in the project (content ring).
    CheckMeta(
        "B170",
        "Tool-output trust-boundary-inversion directive",
        HIGH,
        "hardening",
        "Prompt Injection / Trust Boundary",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B171 (B-235): root-level commands.* in-chat privileged-command surface
    # (bash/config/mcp/plugins) was entirely uncovered -- enabling raw-shell chat commands
    # plus an open channel scored identically to a closed-channel baseline (differential
    # test, 2026-07-17 coverage-map campaign). FAIL only on positive evidence (wildcard
    # owner/allow-from gate, or an empty gate on a channel already known to be open);
    # WARN on an empty gate elsewhere / useAccessGroups disabled; UNKNOWN when reachability
    # genuinely can't be assessed (no channels configured at all). Base severity HIGH,
    # escalates to CRITICAL in-check for bash/config (see check_privileged_commands_exposure).
    CheckMeta(
        "B171",
        "In-chat privileged command surface (commands.bash/config/mcp/plugins) weakly gated",
        HIGH,
        "hardening",
        "Least Privilege / Break-Glass",
        scored=True,
        confidence="HIGH",
        surface="tools",
    ),
    # B172 (B-236, re-scoped): inventory of standing ~/.openclaw/exec-approvals.json
    # "allow-always" grants -- a persisted per-command exec approval that lives entirely
    # outside openclaw.json and, before this check, no check ever read (grep for
    # "exec-approvals" across clawseccheck/ was zero hits). Originally filed as a
    # suspected tools.exec gate BYPASS (a standing grant making B8/B22/B23/B48 give a
    # lying-PASS); B-236's own adversarial review REFUTED that: OpenClaw computes the
    # effective exec policy as minSecurity(tools.exec.security, execApprovals.security)
    # + maxAsk(tools.exec.ask, execApprovals.ask) (bash-tools*.js:581-582;
    # exec-approvals-BIKWP8_V.js:1126-1140), so a standing grant can only TIGHTEN the
    # gate, never loosen it -- B8/B22/B23/B48's PASS was already correct. This check is
    # therefore a pure visibility/inventory advisory (WARN-only, never FAIL, scored=False):
    # it surfaces a standing grant the user may have forgotten about, it does not claim
    # the grant defeats any other check's verdict.
    CheckMeta(
        "B172",
        "Standing exec-approvals.json allow-always grant (uninventoried persisted authority)",
        MEDIUM,
        "hardening",
        "Least Privilege / Exec Approvals",
        scored=False,
        confidence="HIGH",
        surface="tools",
    ),
    # B158 (F-119): a declared skill/plugin load source (skills.load.extraDirs,
    # plugins.load.paths, or a .clawhub/lock.json skillFile) resolves to nothing on disk —
    # an unaudited auto-load gap. Advisory, WARN-only, unscored (declared-but-absent is
    # legitimate on a fresh host).
    CheckMeta(
        "B158",
        "Declared skill-load source not present on disk (unaudited auto-load surface)",
        MEDIUM,
        "advisory",
        "Supply Chain",
        scored=False,
        confidence="HIGH",
        surface="skills",
    ),
    # B157 (F-117): a skill's package.json declares a dependency VALUE that is a non-registry /
    # remote-code source (git URL, remote tarball, github shorthand, file:/link:/npm: alias).
    # FAIL only for unverifiable provenance (plaintext http / raw public IP / .onion); else
    # WARN. Scored since C-229: the FAIL shape is identical to B103's (already scored), and
    # the promised real-fleet C-135 pass confirmed zero false-positive FAILs.
    CheckMeta(
        "B157",
        "Non-registry / remote-code dependency source in a skill package.json",
        HIGH,
        "hardening",
        "Supply Chain",
        scored=True,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B159 (C-207): skill prose instructs the AGENT to widen its own permissions —
    # write an allow-all/wildcard tool grant (allowedTools, Bash(*), permissionMode:
    # approve-all) into settings.json/openclaw.json — corroborated with a fabricated-
    # consent claim ("the user has already approved this"). Distinct from B96 (which
    # looks at VALUES already present in a bundled config file): this looks at PROSE
    # directing the agent to WRITE such a value itself. Strong signal (overt
    # capability-widening + a false justification to skip asking) -> FAIL-capable.
    CheckMeta(
        "B159",
        "Self-privilege-escalation directive in skill prose",
        CRITICAL,
        "hardening",
        "Prompt Injection / Privilege Escalation",
        confidence="MEDIUM",
        surface="skills",
    ),
    # B160 (C-210): natural-language description of collecting BULK/PII data and
    # sending it to an external (non-first-party) endpoint -- a prose-intent exfil
    # directive, distinct from C-203's code-shaped host-info telemetry. WARN for a
    # bulk-data object (all records / complete dataset / SELECT * / PII); FAIL only
    # when the object is credential/secret-shaped (a much stronger, less ambiguous
    # signal). Reuses the B-132 first-party-host allowlist so "send to the skill's
    # own configured endpoint" (report generators, legitimate sync/backup targets)
    # stays clean.
    CheckMeta(
        "B160",
        "Prose-intent bulk-data exfiltration directive",
        HIGH,
        "hardening",
        "Data Exfiltration / Prompt Injection",
        confidence="MEDIUM",
        surface="skills",
    ),
    # B161 (C-217): identity-file injection -- an override/jailbreak directive planted
    # in the agent's OWN identity/bootstrap files (SOUL.md, AGENTS.md, system-prompt
    # equivalents), distinct from B64 (generic override phrases across bootstrap +
    # skills + MCP) and B66 (persona/DAN jailbreak): this targets the specific
    # staleness-framing ("the above instructions are outdated") + fake-authorization-
    # code combo neither existing check covers. WARN on staleness/safety-disable
    # framing alone; FAIL only when corroborated by a fabricated admin/auth code.
    CheckMeta(
        "B161",
        "Identity-file injection (override/jailbreak directive in bootstrap files)",
        CRITICAL,
        "hardening",
        "Prompt Injection / Identity Rewrite",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B163 (C-209): skill prose instructs the HUMAN READER to act on a fabricated
    # urgent/authoritative pretext and hand over a credential or take an out-of-band
    # action -- corroborated triad (urgency + authority-claim + credential-solicitation
    # OR OOB-action), per the ratified prose-intent design (C-208). Distinct from B159
    # (targets the AGENT's own permission config) and B160 (bulk-data exfil to a URL):
    # this is the classic phishing/social-engineering pattern aimed at the human. C-135
    # found a bare credential ask (e.g. "confirm your password") is common in ordinary
    # account-recovery/2FA/support prose -- FAIL requires the ask ALSO be paired with a
    # concrete external (non-first-party) URL destination nearby (a "credential-exfil
    # sink," mirrors B160's is_cred); a bare ask or an out-of-band-action alone -> WARN.
    # (B162 intentionally skipped -- reserved for the log-threat-hunting epic's F-127.)
    CheckMeta(
        "B163",
        "Social-engineering / credential-phishing prose directive",
        CRITICAL,
        "hardening",
        "Prompt Injection / Social Engineering",
        confidence="MEDIUM",
        surface="skills",
    ),
    # B164 (F-124/E-044 Phase 1): content-scan the agent's OWN log/transcript corpus
    # (trajectory sidecars, logging.file, cacheTrace, session transcripts, config-audit
    # log, memory files, install backups) for threat signals against the agent
    # (injected instructions) and against its environment (exfil evidence, dangerous
    # capability use, compromise IOCs, tamper/anomaly, at-rest secrets) — see
    # clawseccheck/logdiscovery.py + logscan.py. Quiet-by-default (base-rate discipline,
    # §5.1 of the design doc): WARN only when >=2 signal classes co-occur in one sink, or
    # a single class with inherent same-line/perm corroboration fires (exfil_evidence is
    # already secret+exfil-host paired; secrets_at_rest also needs a world-readable sink).
    # Isolated single-class hits are suppressed to a quiet report hint, never a WARN.
    # Advisory (scored=False) — a content heuristic over an attacker-influenced corpus
    # must never move the A-F grade (Golden Rule #5). Never FAILs.
    CheckMeta(
        "B164",
        "Threats surfaced in agent logs (content scan)",
        MEDIUM,
        "advisory",
        "Log Threat Intel",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
    # B67 (C-092): per-source tool-output trust contracts.
    # Complements B21 (generic trust boundary): checks that bootstrap has
    # channel-specific DATA/instruction declarations for each active high-risk
    # channel (browser, email, MCP, search, docs).
    CheckMeta(
        "B67",
        "Per-source tool-output trust contracts",
        MEDIUM,
        "hardening",
        "Prompt Injection / Trust Boundary",
        confidence="MEDIUM",
        surface="bootstrap",
    ),
    # B68–B73 (v1.20.0): advisory WARN-only config-fact checks. scored=False so they
    # never move the A–F grade. Each fires only on the explicit dangerous value;
    # default/absent → UNKNOWN or PASS (zero false-positive FAILs on real configs).
    CheckMeta(
        "B68",
        "apply_patch workspace-only restriction disabled",
        MEDIUM,
        "hardening",
        "Least Privilege / Filesystem Write",
        scored=False,
        surface="tools",
    ),
    CheckMeta(
        "B69",
        "exec inline-eval gate missing when exec enabled",
        MEDIUM,
        "hardening",
        "Least Privilege / Inline Eval",
        scored=False,
        surface="tools",
    ),
    CheckMeta(
        "B70",
        "trusted-proxy auth without identity constraints on non-loopback bind "
        "(header-spoof surface)",
        HIGH,
        "hardening",
        "Zero Trust / Proxy Headers",
        scored=False,
        surface="gateway",
    ),
    CheckMeta(
        "B71",
        "gateway.nodes.denyCommands ineffective patterns (non-exact entries)",
        MEDIUM,
        "hardening",
        "Least Privilege / Node Commands",
        scored=False,
        surface="gateway",
    ),
    CheckMeta(
        "B72",
        "subagents.allowAgents wildcard (any agent as spawn target)",
        LOW,
        "hardening",
        "Least Privilege / Subagents",
        scored=False,
        surface="agents",
    ),
    CheckMeta(
        "B73",
        "mDNS full advertisement on non-loopback gateway bind",
        LOW,
        "hardening",
        "Least Privilege / Discovery",
        scored=False,
        surface="gateway",
    ),
    # C-192 (Option C targeted promote, clean C-135 pass): FAIL severity CRITICAL — a
    # forged role/system block requires a co-located override directive to FAIL at all
    # (B-184 removed the bare-marker FP surface entirely), so the remaining FAIL case is
    # near-zero-FP and structural. The WARN branch (bare false-provenance phrase) stays
    # pinned at its own explicit severity=HIGH in check_forged_provenance, unaffected.
    CheckMeta(
        "B74",
        "Forged role/system block or false-provenance attribution in content",
        CRITICAL,
        "hardening",
        "Prompt Injection / Provenance Forgery",
        surface="bootstrap",
    ),
    CheckMeta(
        "B75",
        "MCP tool-inheritance bypass — per-agent filter circumvented (attested)",
        MEDIUM,
        "hardening",
        "Least Privilege / MCP Tool Inheritance",
        scored=False,
        confidence=ATTESTED,
        surface="agents",
    ),
    CheckMeta(
        "B76",
        "High-blast MCP tool-inheritance bypass (attested)",
        HIGH,
        "hardening",
        "Least Privilege / MCP Tool Inheritance",
        scored=True,
        confidence=ATTESTED,
        surface="agents",
    ),
    CheckMeta(
        "B77",
        "Config-write audit log review (suspicious / unexpected writer)",
        MEDIUM,
        "hardening",
        "Audit Log / Config Provenance",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
    CheckMeta(
        "B78",
        "Config-health integrity alert (observed suspicious signature)",
        HIGH,
        "hardening",
        "Config Integrity / Tamper Detection",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
    CheckMeta(
        "B79",
        "Codex session approval-policy posture (approval=never)",
        MEDIUM,
        "hardening",
        "Human Approval",
        scored=False,
        confidence="MEDIUM",
        surface="tools",
    ),
    CheckMeta(
        "B80",
        "Gateway auth without rate limiting on a non-loopback bind",
        LOW,
        "hardening",
        "Least Privilege / Rate Limiting",
        scored=False,
        surface="gateway",
    ),
    CheckMeta(
        "B81",
        "Subagent spawn limits raised beyond recommended defaults",
        LOW,
        "hardening",
        "Least Privilege / Subagents",
        scored=False,
        surface="agents",
    ),
    CheckMeta(
        "B82",
        "cacheTrace transcripts persisted without tool-output redaction",
        MEDIUM,
        "hardening",
        "Secrets / At-Rest Redaction",
        scored=False,
        surface="secrets",
    ),
    CheckMeta(
        "B83",
        "Web-fetch tool allows excessive redirect following",
        LOW,
        "hardening",
        "SSRF / Redirect Hardening",
        scored=False,
        surface="tools",
    ),
    # B84 extends B44 with a THIRD column: PROVEN behavior (runtime/log evidence of
    # actual invocation), not just declared (config grant) vs effective (self-reported
    # inventory). ATTESTED confidence, advisory (not scored) — UNKNOWN without --attest
    # citing proven_tools, so the static grade is unaffected by default.
    CheckMeta(
        "B84",
        "Declared vs. effective vs. proven tool use",
        HIGH,
        "advisory",
        "Least Privilege / Blast Radius",
        scored=False,
        confidence=ATTESTED,
        surface="tools",
    ),
    # B85 (C-093 / E-014 S3) — incident readiness. OpenClaw's trajectory sidecar (recon
    # §9.1) is the attributable on-disk tool-call record; this is a filesystem-grounded
    # HIGH-confidence presence + tamper (group/world-writable) check, NOT attestation.
    # Advisory (scored=False); UNKNOWN when no sidecar exists so the static grade is
    # unaffected. Mirrors B50 (host-audit governance) → AST09, no clean LLM analog.
    CheckMeta(
        "B85",
        "Incident readiness — tool-use trail present and tamper-resistant",
        MEDIUM,
        "hardening",
        "Incident Response / Audit Trail",
        scored=False,
        surface="monitoring",
    ),
    # B86 (defensibility axis — D1) — import-path hijack surface. A benign skill that
    # extends sys.path with a relative / writable / env-derived location can be weaponized
    # by its environment: anyone able to write that path drops a module the skill imports.
    # Skill-as-target (confused deputy), not skill-as-attacker. Heuristic (MEDIUM),
    # advisory (scored=False) so it never perturbs the static grade; WARN-only.
    CheckMeta(
        "B86",
        "Import-path hijack surface (sys.path from writable/relative location)",
        MEDIUM,
        "advisory",
        "Defensibility / Supply-Chain Tamper",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A skill/workspace symlink whose realpath resolves into a sensitive host path
    # (~/.ssh, ~/.aws, keychains, browser profiles, .env, credential files) is a
    # data-exfiltration primitive (TAM-07 symlink escape). F-061 already traverses
    # such links *safely* (never followed); B87 turns the link itself into a verdict.
    # Scored since C-228: the FAIL condition is a deterministic realpath-into-secret-store
    # fact with no dual-use ambiguity once it fires (reading through the link hands the
    # target's contents to the skill), so it belongs in the grade denominator. The verdict
    # stays dynamic (FAIL sensitive / WARN escape / PASS intra-tree / UNKNOWN dangling).
    CheckMeta(
        "B87",
        "Symlink escape to sensitive host path (skill / workspace)",
        HIGH,
        "hardening",
        "Weak Isolation / Path Escape",
        scored=True,
        confidence="HIGH",
        surface="skills",
    ),
    # SKILL.md frontmatter authoring hygiene (F-082 a + e-gap): an HTML/XML-tag-shaped
    # value inside a frontmatter value (metadata-injection surface) and cross-skill
    # trigger-squatting in the description. Coordinates with B58 (invisible unicode) and
    # F-051 (broad-trigger family) — B88 covers only what those don't. WARN-only advisory.
    CheckMeta(
        "B88",
        "SKILL.md frontmatter authoring hygiene (tag-shaped values / cross-skill squatting)",
        MEDIUM,
        "advisory",
        "Authoring Hygiene / Insecure Metadata",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A skill that is unreachable by BOTH the user (user-invocable:false) AND the model
    # (disable-model-invocation:true) yet still ships executable code is a dormant-capability
    # shape: inert code nobody can trigger, staged for later activation. WARN-only heuristic
    # (F-092 (b), narrowed from the raw "both disabled" signal so legit doc-only unreachable
    # skills don't fire). Reads both invocation-flag forms (top-level + metadata.openclaw).
    CheckMeta(
        "B89",
        "Dormant-capability skill (unreachable by user and model, yet ships code)",
        MEDIUM,
        "advisory",
        "Dormant Capability / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A base64 payload deliberately SPLIT across string literals (in different files) so no
    # single-pass scan sees the whole blob — the documented ClawHavoc split-by-file evasion.
    # B13 reassembles within one blob; B90 reassembles across a skill's source string
    # literals and fires only when the join decodes to a shell/download payload AND the skill
    # carries a base64-decode sink. WARN-only heuristic (F-092/I-019, narrowed for zero-FP).
    CheckMeta(
        "B90",
        "Cross-file split base64 payload (reassembled from string literals)",
        MEDIUM,
        "advisory",
        "Obfuscation / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A base64 payload embedded directly in prose/markdown (not a code string literal)
    # whose two halves sit in adjacent files, joining only across the `# file:`
    # section-boundary marker our own concatenation inserts — a narrower residual
    # distinct from B90 (which covers code string literals anywhere in a skill, not
    # specifically at a boundary). WARN-only heuristic (F-086).
    CheckMeta(
        "B102",
        "Base64 payload split exactly at a file-section boundary",
        MEDIUM,
        "advisory",
        "Obfuscation / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A skill's metadata.openclaw.install[] directive fetches an installer artifact over
    # plaintext HTTP/FTP, or from a raw IP / .onion host — an unverified supply-chain source
    # with no legitimate form in the real schema. Deterministic config-field facts (scored),
    # zero-FP-verified against the full bundled fleet (B-099).
    CheckMeta(
        "B103",
        "Install-directive supply-chain (plaintext/IP/onion fetch in metadata.openclaw.install[])",
        HIGH,
        "hardening",
        "Supply Chain / ClawHavoc",
        scored=True,
        confidence="HIGH",
        surface="skills",
    ),
    # Decommissioning debt: the same skill installed in >1 location (stale auto-loadable
    # copy) or a configured MCP server whose absolute command path is gone (dead entry).
    # Advisory host-hygiene (NHI1 improper offboarding); orphaned-skill detection is
    # UNKNOWN-by-design because OpenClaw auto-loads skills by directory presence (§5).
    CheckMeta(
        "B104",
        "Offboarding hygiene (duplicate skill installs / dead MCP command paths)",
        LOW,
        "advisory",
        "Decommissioning / NHI Offboarding",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A sink reached via a COMPUTED name (getattr(os, 'sy'+'stem'), import_module(cfg['mod']))
    # rather than a literal token defeats a simple text/keyword scan. Reuses the existing
    # skillast.py AST rules (GETATTR_INDIRECTION, DYNAMIC_IMPORT_EXEC) — pure wiring, no new
    # AST logic (L1-5 / F-102). Advisory (scored=False); WARN-only.
    CheckMeta(
        "B91",
        "Dynamic-dispatch sink obfuscation (computed getattr/import_module name)",
        MEDIUM,
        "advisory",
        "Obfuscation / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # An unsafe deserialization sink (pickle/marshal/dill/torch.load, or yaml.load without a
    # safe Loader) executes arbitrary code from what looks like "just data" — RCE from a
    # bundled model/config file (L1-1 / F-098). json.load / yaml.safe_load never reach this
    # rule at all (different attribute name) and stay clean automatically. Advisory
    # (scored=False); WARN-only.
    CheckMeta(
        "B92",
        "Unsafe deserialization sink (pickle/marshal/dill/torch.load, unsafe yaml.load)",
        HIGH,
        "advisory",
        "Supply-Chain Tamper / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A confusable/mixed-script character in a skill's frontmatter DESCRIPTION (the actual
    # trigger-phrase surface) can register as a distinct near-duplicate for preferential
    # routing while looking identical to a human reader. F-022 already covers the skill NAME;
    # this covers the description text (L1-6 / F-103). Reuses textnorm.py's existing
    # confusable-canonicalization wholesale — no new detection logic. Advisory (scored=False).
    CheckMeta(
        "B93",
        "Confusable/mixed-script characters in a skill's trigger description",
        MEDIUM,
        "advisory",
        "Obfuscation / Trigger-Squatting",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # npm's prepare/preversion/postversion/prepublish(Only)/pretest/posttest scripts run on
    # install/version/publish/test just as reliably as postinstall (B42's existing scope), but
    # a reviewer scanning only for "postinstall" misses them; a Python setup.py cmdclass
    # override runs at pip-install time (L1-2 / F-099). Advisory (scored=False); WARN-only.
    CheckMeta(
        "B94",
        "Extended lifecycle hooks (npm prepare/preversion/..., setup.py cmdclass override)",
        HIGH,
        "advisory",
        "Supply-Chain Tamper / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # An UNPINNED dependency whose name also resembles a well-known package is the classic
    # dependency-confusion combination: a wide version range lets the resolver silently pick
    # up a release of a name chosen to look trusted (L1-4 / F-101). B13 already flags unpinned
    # (C-044) and typosquat (F-022) separately; this is the co-occurrence on the SAME name, a
    # materially higher-risk combination. Pure correlation, no new fuzzy-matching. Advisory.
    CheckMeta(
        "B95",
        "Dependency confusion (unpinned version + name resembling a well-known package)",
        HIGH,
        "advisory",
        "Supply-Chain Tamper / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B105 (B-096): cross-skill combined effect — one co-installed skill supplies secrecy
    # framing (bare B63 Signal-B), a DIFFERENT one supplies credential-read + network exfil
    # (Signal A); neither reaches FAIL alone but together they form a silent-exfil pattern
    # per-skill vetting cannot see. Full-audit scope only. Pure correlation, WARN-only,
    # advisory (scored=False) — remote-sink discriminator keeps benign cred→local-log out.
    CheckMeta(
        "B105",
        "Cross-skill combined effect (secrecy framing + credential exfil split across skills)",
        MEDIUM,
        "advisory",
        "Human Oversight / Transparency",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A skill that ships hooks/openclaw/*.mjs installs a PER-TURN event handler — a real,
    # documented OpenClaw tool-registration mechanism, not a hidden backdoor, but it fires on
    # EVERY turn (persistent point of review), distinct from B42's install-time hook scan
    # (L1-7 / F-104). Presence = WARN (reviewer should read it); escalate on network sink /
    # process.env / turn-object mutation. Advisory (scored=False); UNKNOWN on minified bodies.
    CheckMeta(
        "B97",
        "Per-turn event-hook file shipped in a skill (hooks/openclaw/*)",
        HIGH,
        "advisory",
        "Persistent Review Surface / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A skill-bundled config value shaped like an approve-all/auto-approve setting, or a
    # telemetry/callback-named key holding a URL, is the wording a compromised or careless
    # skill would use to quietly widen its own trust (L1-3 / F-100). GROUNDING-GATED (§4):
    # no such skill-bundled field is documented anywhere, so this is deliberately
    # heuristic/wording-shape only — never a claim about a real, live-read OpenClaw config
    # path. Advisory (scored=False); WARN-only.
    CheckMeta(
        "B96",
        "Config-driven trust widening (approve-all wording / telemetry-callback URL)",
        MEDIUM,
        "advisory",
        "Insecure Metadata / Excessive Agency",
        scored=False,
        confidence="LOW",
        surface="skills",
    ),
    # A skill that reaches fs-write / network / exec effects but declares no
    # allowed-tools/tools manifest is exercising undeclared privilege — a reviewer reading
    # only the manifest would under-estimate the skill's real capability. Reuses B62's
    # declared-tools parser and actual-capability extraction. Advisory (scored=False);
    # WARN-only, never FAIL; UNKNOWN when no Python sources exist to profile.
    CheckMeta(
        "B98",
        "Undeclared capabilities (risky effects, no allowed-tools manifest)",
        MEDIUM,
        "advisory",
        "Least Privilege / Excessive Agency",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # A shipped `.pth` file with an executable `import` line, or a bundled
    # sitecustomize.py/usercustomize.py, auto-runs on every Python interpreter start
    # (CPython `site` module behavior) — even without anyone ever importing the
    # package. The TeamPCP/LiteLLM v1.82.8 supply-chain payload used exactly this
    # vector. Advisory (scored=False); WARN-only, never FAIL.
    CheckMeta(
        "B99",
        "Executable .pth file / sitecustomize auto-execution persistence",
        HIGH,
        "advisory",
        "Defensibility / Supply-Chain Tamper",
        scored=False,
        confidence="HIGH",
        surface="skills",
    ),
    # A Prerequisites/Setup/Installation heading whose body instructs the reader to
    # paste a remote-fetch shell command into a terminal is the ClickFix 2.0 / ClawHavoc
    # delivery technique (standard §2.1) — distinct from B13's bare remote-fetch WARN,
    # this looks at the natural-language paste-into-terminal framing itself. Advisory
    # (scored=False); WARN-only, never FAIL.
    CheckMeta(
        "B100",
        "ClickFix-style paste-into-terminal setup instruction",
        HIGH,
        "advisory",
        "Supply Chain / ClawHavoc",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # advisory (not scored)
    CheckMeta(
        "C3",
        "Backups of SOUL.md / memory",
        LOW,
        "advisory",
        "Backups",
        scored=False,
        surface="bootstrap",
    ),
    CheckMeta(
        "C4",
        "OpenClaw version / update hygiene",
        LOW,
        "advisory",
        "Patch hygiene",
        scored=False,
        surface="update",
    ),
    CheckMeta(
        "C5",
        "Native binary PATH safety",
        LOW,
        "advisory",
        "Binary Integrity",
        scored=False,
        confidence="MEDIUM",
        surface="host",
    ),
    # C6 (C-052): pre-v2026.6.10 hook-composition could silently drop trusted tool
    # policies. Runtime evaluation-order effect, no static config field — an honest
    # UNKNOWN nudge, never a FAIL. Advisory (not scored).
    CheckMeta(
        "C6",
        "Hook-composition tool-policy drop (pre-v2026.6.10)",
        LOW,
        "advisory",
        "Patch hygiene",
        scored=False,
        surface="update",
    ),
    CheckMeta(
        "C032",
        "Proxy header trust when real-IP fallback is enabled",
        LOW,
        "advisory",
        "Gateway / Proxy Header Trust",
        scored=False,
        surface="gateway",
    ),
    CheckMeta(
        "C014",
        "Egress inventory (outbound-capable surface enumeration)",
        LOW,
        "advisory",
        "Egress Inventory",
        scored=False,
        surface="monitoring",
    ),
    CheckMeta(
        "C015",
        "Secrets-at-rest scan of the OpenClaw home",
        MEDIUM,
        "advisory",
        "Secrets / Filesystem",
        scored=False,
        confidence="MEDIUM",
        surface="secrets",
    ),
    CheckMeta(
        "C047",
        "Non-local MCP server endpoint (manual review)",
        LOW,
        "advisory",
        "MCP / External Endpoint Review",
        scored=False,
        surface="mcp",
    ),
    # C048: top-level cron scheduler persistence surface. Advisory UNKNOWN-only when
    # the real OpenClaw `cron` field is present; config alone cannot distinguish a
    # legitimate schedule from attacker-planted persistence, so this never FAILs.
    CheckMeta(
        "C048",
        "Cron scheduler persistence surface (top-level cron)",
        LOW,
        "advisory",
        "Persistence / Scheduled Execution",
        scored=False,
        surface="hooks",
    ),
    CheckMeta(
        "C074",
        "Injection-like text in HTML image attributes",
        MEDIUM,
        "advisory",
        "Prompt Injection / HTML Attribute",
        scored=False,
        surface="bootstrap",
    ),
    # B136: Codex CLI project trust_level="trusted" (codex-home/config.toml) disables
    # Codex's own approval/sandbox gating for everything run under that project path.
    # Hardening advisory, never FAIL — a trusted project may be entirely legitimate;
    # this is awareness of a broad, security-relevant setting, matching B79's precedent
    # (Codex approval-policy posture) which is also scored=False / surface="tools".
    CheckMeta(
        "B136",
        "Codex CLI project trust_level=\"trusted\" (codex-home/config.toml)",
        MEDIUM,
        "advisory",
        "Human Approval",
        scored=False,
        confidence="MEDIUM",
        surface="tools",
    ),
    # B138: dangling high-scope pending device pairing (devices/pending.json). A pending
    # isRepair=true request with an operator.admin/operator.write scope is awaiting human
    # approval — informational awareness, not proof of compromise. Hardening advisory,
    # never FAIL; surface="agents" (control-plane device/identity onboarding).
    CheckMeta(
        "B138",
        "Dangling high-scope pending device pairing (devices/pending.json)",
        MEDIUM,
        "advisory",
        "Control Plane / Human Approval",
        scored=False,
        confidence="MEDIUM",
        surface="agents",
    ),
    # B176 (B-243): standing operator authority in the paired-device store
    # (devices/paired.json). B138 audits a *pending* pairing request; nothing
    # previously read the *approved* store a pairing lands in once granted, which
    # carries a live standing operator token + granted scopes (schema recon
    # docs/research/openclaw-schema-recon.md §14.3: scopes/approvedScopes/tokens/
    # lastSeenAtMs). >=1 paired operator-scope device is the EXPECTED state for every
    # normal install (the user's own phone/laptop) — never FAIL; matches B138's
    # advisory precedent exactly (a pending high-scope request is also common/expected
    # and still only WARNs). Never reads the `tokens` field's value.
    CheckMeta(
        "B176",
        "Standing operator authority in paired device store (devices/paired.json)",
        MEDIUM,
        "advisory",
        "Identity / Standing Authority",
        scored=False,
        confidence="MEDIUM",
        surface="agents",
    ),
    # B135: a skill installed despite ClawHub's own verification rejecting it
    # (.clawhub/lock.json verification.ok=false / decision="fail"). Deterministic
    # config-field fact (the lock file explicitly records the registry's own
    # decision), but advisory/scored=False: a legitimate reason to keep a
    # rejected install can exist (e.g. a security researcher's own test skill),
    # so this is awareness of an accepted-despite-rejection state, not proof of
    # compromise — matches B136/B138's precedent in the same E-030 epic.
    CheckMeta(
        "B135",
        "Accepted-despite-failed-verification skill install (.clawhub/lock.json)",
        MEDIUM,
        "advisory",
        "Supply Chain / Human Approval",
        scored=False,
        confidence="HIGH",
        surface="skills",
    ),
    # B150: OpenClaw-related systemd user-unit Restart=always persistence
    # (~/.config/systemd/user/*.service). Legitimate, common infrastructure for a
    # long-running gateway service that also happens to be a durable autonomy/
    # persistence substrate worth disclosing. Advisory, never FAIL — matches B136's
    # precedent (a broad, security-relevant OS-level setting, informational only).
    CheckMeta(
        "B150",
        "Systemd user-unit Restart=always persistence (OpenClaw-related)",
        LOW,
        "advisory",
        "Persistence / Host Watch",
        scored=False,
        confidence="MEDIUM",
        surface="host",
    ),
    # B151: third-party Codex CLI connector caches (agents/*/agent/codex-home/.tmp/
    # plugins/plugins/*/hooks.json) that wire a shell script to a tool-use/lifecycle
    # event. Informational disclosure of an upload-shaped surface in a third-party
    # connector cache — not proof of malice. Advisory, never FAIL.
    CheckMeta(
        "B151",
        "Codex connector shell hooks in the plugin doc-cache",
        LOW,
        "advisory",
        "Supply Chain / Connector Hooks",
        scored=False,
        confidence="MEDIUM",
        surface="mcp",
    ),
    # B152: on-disk plugin cache directories (npm/projects/, agents/*/agent/plugins/)
    # not declared under plugins.entries — may be stale/uninstalled, mid-install, or
    # declared under a different key. Hygiene/disclosure signal, never FAIL.
    CheckMeta(
        "B152",
        "Orphaned plugin cache not declared in plugins.entries",
        LOW,
        "advisory",
        "Supply Chain / Plugin Hygiene",
        scored=False,
        confidence="MEDIUM",
        surface="mcp",
    ),
    # B153: an untrusted shell variable spliced unescaped into a
    # double-quoted python -c / node -e / bun -e one-liner — quote-breakout injection risk
    # independent of whether the body also names a dangerous import. WARN-only heuristic
    # (the variable's real trust/origin isn't provable from static text alone).
    CheckMeta(
        "B153",
        "Untrusted interpolation into an interpreter one-liner (python -c / node -e / bun -e)",
        MEDIUM,
        "advisory",
        "Command Injection",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B154: the split-across-files scanner-evasion vector for a payload that is never
    # base64-encoded — B90 reassembles base64 fragments behind a decode sink; this
    # reassembles PLAINTEXT fragments and tests the joined text directly against the same
    # strong runnable-payload shape. WARN-only heuristic (reassembly at runtime is an
    # inference, same as B90).
    CheckMeta(
        "B154",
        "Cross-file split plaintext payload (reassembled from string literals)",
        MEDIUM,
        "advisory",
        "Obfuscation / Malicious Skill",
        scored=False,
        confidence="MEDIUM",
        surface="skills",
    ),
    # B173 (B-237): security.audit.suppressions[] permanently silences specific findings of
    # OpenClaw's OWN built-in `openclaw security audit` -- and since native.py's fold-in only
    # ever sees what that CLI already returns, a suppression blindfolds BOTH the native audit
    # AND ClawSecCheck's fold-in of it, with nothing previously flagging that a suppression
    # list even exists. Grounded: zod-schema-O9ml_nmo.js SecuritySchema.audit.suppressions[]
    # = { checkId (required), titleIncludes?, detailIncludes?, reason? }. A non-empty list is
    # not itself a vulnerability -- legitimate, knowingly-accepted native findings get
    # suppressed -- so the default is WARN (disclosure), scored like B41/B48. FAIL only when a
    # suppressed checkId is one of a small, grounded set audit-UjVvFwCi.js's own
    # runSecurityAudit gives an UNCONDITIONAL severity:"critical" (no runtime-state ternary).
    CheckMeta(
        "B173",
        "OpenClaw native-audit suppression list (security.audit.suppressions)",
        MEDIUM,
        "advisory",
        "Transparency / Audit Suppression",
        scored=True,
        confidence="HIGH",
        surface="monitoring",
    ),
    # B175 (E-047): Skill Workshop autonomous authoring + no-review
    # install. Grounded 2026-07-18 against the installed dist
    # (config-XlfFMqhc.js:resolveSkillWorkshopConfig, zod-schema-O9ml_nmo.js:1510-1516)
    # AFTER the originating bug report's assumed field shape turned out wrong: the report
    # nested approvalPolicy/allowSymlinkTargetWrites under .autonomous and assumed a
    # "manual" policy value. The real schema has them as SIBLINGS of `autonomous` directly
    # under skills.workshop, and the only two literals it accepts are "pending" (the safe
    # default) and "auto" — anything else, including an omitted key, resolves to "pending".
    # skills.workshop.autonomous.enabled=true lets the agent author brand-new executable
    # skill proposals from conversation signals with no user request
    # (get-reply-OTG64ybi.js: autonomous mode replaces the normal suggest-then-ask flow).
    # approvalPolicy="auto" removes the human confirmation step for every skill_workshop
    # lifecycle call (propose/apply/reject/quarantine) —
    # agent-tools.before-tool-call-C95DXQXZ.js:608 short-circuits the approval-gate builder
    # before it ever runs. The combination is the full unattended self-modification
    # pipeline the bug names: conceive, author, AND install new executable code from a
    # single conversation turn, zero human review. HIGH confidence — a deterministic
    # config-field fact, not a heuristic.
    CheckMeta(
        "B175",
        "Skill Workshop autonomous authoring + no-review install (approvalPolicy=auto)",
        HIGH,
        "hardening",
        "Write Integrity / Self-Modification",
        surface="skills",
    ),
    # B179 (B-250): hooks.webhooks / hooks.internal(.load.extraDirs) enable-toggle
    # inventory. The originating bug report's field name "hooks.webhooks" is NOT a real
    # config path -- grounded against the dist, the native audit's own inventory line
    # (audit.nondeep.runtime-C3y1Q5Fi.js:205-212) computes its "hooks.webhooks: enabled/
    # disabled" DISPLAY LABEL from the real field `hooks.enabled`
    # (`cfg.hooks?.enabled === true`), there is no separate `hooks.webhooks` key anywhere
    # in schema-DRyO1XBt.js. The real internal-hooks surface is `hooks.internal.enabled`,
    # `.entries`, `.installs`, and `.load.extraDirs` (schema-DRyO1XBt.js:1063-1068,
    # mirrored by hasConfiguredInternalHooks() in configured-pV8SaeM2.js:20-28). Before
    # this check, clawseccheck had zero references to any of these five fields.
    # `hooks.internal.load.extraDirs` is the sharpest signal -- it names extra
    # directories OpenClaw searches for internal hook MODULES at startup, i.e. a
    # startup arbitrary-module-load / persistence surface, not just an enable flag.
    # Severity LOW and WARN-only (never FAIL), scored=False (pure attack-surface
    # inventory, advisory block): the real fleet config has no `hooks` key at all (no
    # live miss today), and the native audit itself treats this as "info", not
    # WARN/FAIL. The higher-risk adjacent hooks.* surfaces already have dedicated
    # checks -- hooks.token (B1), hooks.mappings[].allowUnsafeExternalContent (B48),
    # hooks.mappings[] template content (B169), hooks.gmail.allowUnsafeExternalContent
    # (B48) -- this check only fills the toggle-visibility gap next to them.
    CheckMeta(
        "B179",
        "Hooks enable-toggle attack-surface inventory (hooks.enabled / hooks.internal.load.extraDirs)",
        LOW,
        "advisory",
        "Attack Surface / Hook Exposure",
        scored=False,
        confidence="HIGH",
        surface="hooks",
    ),
    # B177 (B-240): OpenClaw's OWN persisted per-plugin ClawHub trust verdict
    # (installed_plugin_index.install_records_json.<pluginId>.clawhubTrustDisposition, in
    # the shared state SQLite DB ~/.openclaw/state/openclaw.sqlite) was never read (grep
    # for "clawhubTrust"/"openclaw.sqlite" across clawseccheck/ was zero hits before this)
    # -- a free, high-precision plugin-trust signal OpenClaw already computed and
    # persisted itself. Grounded against the installed dist (installed-plugin-index-store-
    # CWgFGnm0.js, installed-plugin-index-records-C_n191FN.js, types.openclaw-CXjMEWAQ.d.ts,
    # clawhub-install-trust-DdnykQnp.js) and against the real file
    # (~/.openclaw/state/openclaw.sqlite: table present, schema matches exactly). FAIL only
    # on the unambiguous "blocked" disposition (OpenClaw's own moderation explicitly
    # blocked the install); WARN on any other non-clean disposition ("review-required",
    # "review-recommended", or a future value) and on clawhubTrustPending/Stale (an
    # unverified/outdated verdict). UNKNOWN when the state DB, the index row, or the
    # column is absent/locked/unreadable (Golden Rule #4) -- never a fake PASS. Read-only
    # (file:...?mode=ro + PRAGMA query_only=1), never writes to the shared state DB.
    CheckMeta(
        "B177",
        "OpenClaw's own persisted ClawHub trust verdict for an installed plugin",
        HIGH,
        "hardening",
        "Supply Chain / Third-Party Trust Verdict",
        scored=True,
        confidence="HIGH",
        surface="mcp",
    ),
    # E-032 v1 — behavioral trajectory audit (--behavioral mode only, never part of the
    # main audit()/CHECKS list or the A-F score). Reads OpenClaw's trajectory sidecar
    # (agents/*/sessions/*.trajectory.jsonl, §9.1 grounded) and finds sequences PROVEN by
    # the log, complementing the static config/skill-content checks (what the agent could
    # do vs what it actually did). Metadata-only (§8): never reads
    # arguments/output/result/contentItems. WARN-only, scored=False (Golden Rule #5) —
    # ingress/sensitive/egress role is classified by VERB NAME (a heuristic, MEDIUM
    # confidence), not by the untouched payload content.
    #
    # T1: behavioral trifecta — an ingress-verb, then a sensitive-verb, then an
    # egress-verb, in that order, within one thread. Mirrors A1's static
    # ingress/sensitive/egress leg model (INPUT_TOOL_HINTS/SENSITIVE_TOOL_HINTS/
    # OUTBOUND_TOOL_HINTS, checks/_shared.py) applied to observed runtime order instead
    # of declared config — proof-by-log of the same pattern A1 flags by capability.
    CheckMeta(
        "T1",
        "Behavioral trifecta (observed ingress -> sensitive -> egress verb sequence)",
        MEDIUM,
        "advisory",
        "Lethal Trifecta (behavioral)",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
    # T2: outcome anomaly — a fail -> fail -> success series on a sensitive verb within
    # one thread (from tool.result status/isError/success). Conservative on purpose: only
    # a repeated-failure-then-success shape on a sensitive-classified verb counts, never
    # a bare isolated failure (isolated failures are the overwhelming common case and
    # would blow the zero-false-positive bar on any real fleet).
    CheckMeta(
        "T2",
        "Outcome anomaly (fail→fail→success series on a sensitive verb)",
        MEDIUM,
        "advisory",
        "Anomalous Behavior",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
    # T3: runtime capability drift — a HIGH-BLAST verb PROVEN in the trajectory log that is
    # NOT in the declared (tools.allow / gateway.tools.allow) ∪ attested grant. Complements
    # B84 (proven-high-blast + UNGATED posture); T3 is proven-high-blast + UNDECLARED,
    # regardless of gating. The high-blast gate is load-bearing: built-ins and MCP tools are
    # auto-available beyond tools.allow (B44), so reversible/unknown verbs never reach the
    # alert — only EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG drift does. WARN-only, unscored,
    # --behavioral only (never audit()/CHECKS/A-F).
    CheckMeta(
        "T3",
        "Runtime capability drift (proven high-blast verb never declared)",
        MEDIUM,
        "advisory",
        "Excessive Agency (behavioral)",
        scored=False,
        confidence="MEDIUM",
        surface="monitoring",
    ),
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
    "B174": ("AST02",),
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
    "B170": ("AST05",),  # trust-inversion directive — presence-mirror of B67
    "C074": ("AST05",),
    "B4": ("AST06",),
    "B22": ("AST03", "AST06"),
    "B175": ("AST03", "AST06"),  # skill workshop auto-author + no-review install = over-privileged self-modification (cf. B22)
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
    "B101": ("AST09",),  # host-level egress posture = governance/no-isolation gap (cf. B50-B54)
    "B57": ("AST02", "AST03"),
    # Orphan-check fills (coverage-map P3): each mirrors a named sibling's AST class.
    "B38": ("AST06",),  # headless browser without OS sandbox = Weak Isolation (cf. B4)
    "B73": ("AST06",),  # mDNS full advertise on non-loopback exposes the agent (cf. B70)
    "B74": ("AST05",),  # forged role/provenance = untrusted external instructions (cf. B64)
    "B76": ("AST03",),  # MCP tool-inheritance bypass = over-privileged reach (cf. B75)
    "B77": ("AST09",),  # config-write audit review = governance / audit-trail (cf. B10)
    "B78": ("AST09",),  # config-integrity tamper detection = governance (cf. B10)
    "B79": ("AST03",),  # approval_policy=never = over-autonomous agency (cf. B8)
    "C032": ("AST06",),  # trusting spoofable forwarded headers = weak boundary (cf. B70)
    "B80": ("AST06",),  # no rate limiting on an exposed auth'd gateway = weak isolation (cf. B70)
    "B81": ("AST03",),  # raised subagent spawn limits = over-privileged delegation (cf. B72)
    "B82": ("AST02",),  # unredacted transcripts at rest = supply-chain/secret exposure (cf. C5)
    "B83": ("AST06",),  # excessive redirect-follow on fetch = weak isolation/SSRF (cf. B38)
    "B84": (
        "AST03",
        "AST04",
    ),  # declared/effective/proven drift = over-privileged + insecure self-report (cf. B44)
    "B85": ("AST09",),  # tamperable/absent tool-use audit trail = weak governance (cf. B50/B77)
    "B86": ("AST02",),  # import-path hijack via writable sys.path = supply-chain tamper (cf. B5)
    "B87": ("AST06",),  # symlink escape to a sensitive host path = boundary violation (cf. B38 SSRF)
    "B88": ("AST04",),  # tag-shaped frontmatter value / cross-skill squat = insecure metadata (cf. B62)
    "B89": ("AST01",),  # unreachable-yet-code-bearing skill = staged/dormant malicious shape (cf. B13)
    "B90": ("AST01",),  # cross-file split base64 payload = hidden malicious code / scanner evasion (cf. B13)
    "B102": ("AST01",),  # base64 split at a file-section boundary = hidden malicious code (cf. B90)
    "B103": ("AST02",),  # install[] plaintext/IP/onion fetch = ML supply-chain compromise (cf. B13/B95)
    "B91": ("AST01",),  # dynamic-dispatch sink obfuscation = hidden malicious code / scanner evasion (cf. B89/B90)
    "B92": ("AST02",),  # unsafe deserialization sink = RCE-from-data supply-chain tamper (cf. B86)
    "B93": ("AST04",),  # confusable trigger description = insecure metadata / trigger-squat (cf. B88)
    "B94": ("AST02",),  # extended lifecycle hooks = supply-chain tamper on install/version/publish (cf. B42)
    "B95": ("AST02",),  # dependency confusion (unpinned + typosquat name) = supply-chain tamper (cf. B13)
    "B105": ("AST05",),  # cross-skill combined effect = excessive agency across co-installed skills
    "T1": ("AST05",),  # behavioral trifecta = untrusted external instructions, proven by log (cf. B105)
    "T3": ("AST04",),  # runtime capability drift = over-privileged + insecure self-report (cf. B84)
    "B97": ("AST09",),  # per-turn event-hook file = persistent review/audit surface (cf. B77/B85)
    "B96": ("AST04",),  # config-driven trust widening (heuristic) = insecure metadata (cf. B62/B88)
    "B98": ("AST04",),  # missing capability declaration = insecure/absent least-privilege metadata (cf. B62/B88/B96)
    "B99": ("AST02",),  # .pth/sitecustomize auto-execution persistence = supply-chain tamper (cf. B86/B94)
    "B100": ("AST01", "AST02"),  # ClickFix paste-into-terminal + remote-fetch = malicious skill / supply-chain (cf. B13)
    "B135": ("AST02",),  # accepted-despite-failed-verification install = supply-chain trust bypass (cf. B103/B95)
    "B136": ("AST06",),  # codex trust_level="trusted" disables approval/sandbox gating = weak isolation (cf. B4/B48/B70)
    "B138": ("AST03",),  # dangling high-scope pending device pairing = over-privileged-skill risk awaiting approval (cf. B79)
    "B176": ("AST03",),  # standing operator.admin/write authority in paired-device store = over-privileged control-plane grant (cf. B138)
    "B140": ("AST05",),  # wildcard group ingress, no allowFrom = untrusted external instructions (cf. B26/B67)
    "B150": ("AST03",),  # systemd Restart=always persistence = durable over-privileged autonomy substrate (cf. B17)
    "B151": ("AST02",),  # codex connector shell hooks in the plugin doc-cache = supply-chain tamper (cf. B42/B94)
    "B152": ("AST02",),  # orphaned plugin cache not declared in plugins.entries = supply-chain visibility gap (cf. C5/C047)
    "B177": ("AST02",),  # OpenClaw's own persisted ClawHub trust verdict = supply-chain compromise signal (cf. B5/B15/B24/B42)
}

# Each check mapped to the OWASP-LLM-2025 category/categories it addresses ON THE AGENT
# surface. Only clear fits are tagged; checks with no clean LLM-Top-10 analog (host-watch
# B50–B54, logging B10, monitoring B16/B77/B78, SSRF B38, backups C3) are intentionally left
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
    "B103": ("LLM03",),  # install[] plaintext/IP/onion fetch = supply-chain (cf. B13/B95)
    "B14": ("LLM02",),
    "B15": ("LLM03",),
    "B17": ("LLM06", "LLM10"),
    "B18": ("LLM06",),
    "B19": ("LLM02",),
    "B20": ("LLM04",),
    "B21": ("LLM01", "LLM05"),
    "B22": ("LLM04", "LLM06"),
    "B175": ("LLM04", "LLM06"),  # skill workshop auto-author + no-review install = Data/Model Poisoning + Excessive Agency (cf. B22)
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
    "B174": ("LLM03",),
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
    # B88: a tag-shaped value hidden in SKILL.md frontmatter is a prompt-injection surface
    # (Prompt Injection, LLM01); the cross-skill-squat half is metadata hygiene (AST04 only).
    "B88": ("LLM01",),
    # B63: Excessive Agency (LLM06) — instructing the agent to hide its actions
    # undermines human oversight. NOT LLM09 "Misinformation" (a model-output/RAG concern
    # the agent config can't see; LLM09 is out of scope per docs/THREAT_COVERAGE.md).
    "B63": ("LLM06",),
    "B105": ("LLM06",),  # combined-effect disclosure suppression (cross-skill) — cf. B63
    "T1": ("LLM06",),  # behavioral trifecta = Excessive Agency, proven by log — cf. B105
    "T3": ("LLM06",),  # runtime capability drift = Excessive Agency, proven by log — cf. B84
    # B65: conditional/sleeper trigger instructions — hidden conditional malware-like
    # behavior under a user-query gate (Excessive Agency, not Misinformation).
    "B65": ("LLM06",),
    # B66: persona / role jailbreak patterns that aim to reset safety constraints.
    "B66": ("LLM06",),
    # B67: per-source trust contracts — prompt injection via channel-specific gaps.
    "B67": ("LLM01", "LLM02"),
    # B170: presence of a trust-boundary-inversion directive — prompt injection enabler.
    "B170": ("LLM01", "LLM02"),
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
    # Orphan-check fills (coverage-map P3): each mirrors a named sibling's LLM class.
    # SSRF B38, backups C3 and monitoring B77/B78 stay unmapped (no clean LLM analog).
    "B12": ("LLM02",),  # cloud-model use = data egress to a 3rd party (cf. B14)
    "B74": ("LLM01",),  # forged role/provenance = prompt injection (cf. B64)
    "B76": ("LLM06",),  # MCP tool-inheritance bypass = Excessive Agency (cf. B31)
    "B79": ("LLM06",),  # approval_policy=never = Excessive Agency (cf. B8)
    "C014": ("LLM02",),  # outbound-surface inventory = data-disclosure surface (cf. B14)
    "C015": ("LLM02",),  # secrets-at-rest scan = Sensitive Info Disclosure (cf. B1)
    "B80": ("LLM10",),  # no rate limiting on an exposed auth'd gateway = Unbounded Consumption
    "B81": ("LLM06",),  # raised subagent spawn limits = Excessive Agency (cf. B72)
    "B82": ("LLM02",),  # unredacted transcripts persisted at rest = Sensitive Info Disclosure
    "B83": (
        "LLM02",
    ),  # excessive redirect-follow on fetch = SSRF data-disclosure surface (cf. B38)
    "B84": (
        "LLM06",
    ),  # proven high-blast verb with an ungated posture = Excessive Agency (cf. B43/B44)
    "B135": ("LLM03",),  # accepted-despite-failed-verification install = Supply Chain (cf. B103)
    "B136": ("LLM06",),  # codex trust_level="trusted" disables approval/sandbox = Excessive Agency (cf. B4/B8)
    "B138": ("LLM06",),  # dangling high-scope pending device pairing = Excessive Agency (cf. B79)
    "B176": ("LLM06",),  # standing operator.admin/write authority in paired-device store = Excessive Agency (cf. B138)
    "B140": ("LLM01",),  # wildcard group ingress, no allowFrom = Prompt Injection surface (cf. B21/B67)
    "B150": ("LLM06", "LLM10"),  # systemd Restart=always = durable autonomy substrate (cf. B17)
    "B151": ("LLM03",),  # codex connector shell hooks in the plugin doc-cache = Supply Chain
    "B152": ("LLM03",),  # orphaned plugin cache not declared in plugins.entries = Supply Chain
    "B177": ("LLM03",),  # OpenClaw's own persisted ClawHub trust verdict = Supply Chain
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
    "B1": {
        "commands": [
            "openclaw secrets configure",
            "chmod 600 ~/.openclaw/openclaw.json",
            "chmod 700 ~/.openclaw",
        ]
    },
    "B2": {
        "config": [
            {
                "path": "gateway.auth",
                "set": None,
                "note": "enable gateway auth and restrict channels to an allowlist",
            }
        ]
    },
    "B3": {
        "config": [
            {
                "path": "tools.elevated.allowFrom",
                "set": None,
                "note": "restrict to an explicit allowlist (no wildcards)",
            }
        ]
    },
    "B4": {
        "config": [
            {
                "path": "agents.defaults.sandbox.mode",
                "set": "non-main",
                "note": "run exec tools in a sandbox",
            }
        ]
    },
    "B8": {
        "config": [
            {"path": "tools.exec.mode", "set": "ask", "note": "require human approval before exec"}
        ]
    },
    "B19": {"commands": ["chmod 700 ~/.openclaw"]},
    "B20": {
        "commands": [
            "chmod 700 <workspace>",
            "chmod 600 <workspace>/SOUL.md <workspace>/AGENTS.md "
            "<workspace>/TOOLS.md <workspace>/MEMORY.md",
        ]
    },
    "B22": {"commands": ["chmod 600 <workspace>/SOUL.md", "chmod 700 <workspace>/skills"]},
    "B23": {
        "config": [
            {
                "path": "tools.exec.mode",
                "set": "ask",
                "note": "enforce the approval gate; do not let bootstrap text weaken it",
            }
        ]
    },
    "B30": {
        "config": [
            {
                "path": "channels.<provider>.dangerouslyAllowNameMatching",
                "set": None,
                "note": "remove this flag — a mutable display-name allowlist is trivially bypassed",
            }
        ]
    },
    "B38": {
        "config": [
            {
                "path": "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
                "set": False,
                "note": "block private-network requests from the browser tool",
            }
        ]
    },
    "B39": {
        "config": [
            {
                "path": "session.dmScope",
                "set": None,
                "note": 'isolate DM sessions per user; do not use "main"',
            }
        ]
    },
    "C5": {"commands": ["chmod o-w,g-w <dir>"]},
}


def remediation_for(check_id: str) -> dict:
    """Paste-ready remediation for a check, normalized to {"commands": [...], "config": [...]}.

    Empty lists when the check has no deterministic paste-ready fix (its prose `fix` leads).
    """
    r = REMEDIATION.get(check_id, {})
    return {
        "commands": list(r.get("commands", ())),
        "config": [dict(c) for c in r.get("config", ())],
    }


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
    # vet_skill() attaches per-check ring findings here (content-ring checks B59–B67, B74,
    # B42) so callers can inspect individual check results without changing the return type.
    # Not used by the full audit (stays empty); not rendered by report.py / sarif.py
    # (those iterate the outer finding list, not this field).
    ring_findings: list = field(default_factory=list)
    # vet_mcp() attaches per-axis reasons here so the risk dossier can split a single
    # multi-reason MCP verdict across its axes (danger/build/behavior/connections) with the
    # right per-axis severity. Shape: {axis: [[status, reason], ...]}. Empty for every other
    # producer; not part of the frozen public JSON shape (internal to dossier bucketing).
    axis_reasons: dict = field(default_factory=dict)
