# Threat coverage matrix

Honest map of what ClawSecCheck checks today, what it does **not** yet check, and where
the gaps are. `UNKNOWN` is never counted as `PASS`; gaps below are areas with no check at
all (so they can't even surface as a finding). Updated 2026-06-22 for v1.8.1.

Current catalog: `A1, B1–B26, B30–B33, B38, B39, B41–B48, B50–B54, C3–C5`, plus the
combinational risk engine `RISK-01..RISK-11`, the install-time vetters `--vet` (B13 on
an uninstalled skill, now AST- and injection-aware) / `--vet-mcp`, and the **attestation
layer** (`--ask` / `--attest`, with a guided interrogation protocol so the agent self-builds
the report; `--attest -` reads stdin) that feeds the agent's self-report into B43/B44.

## Covered

| Threat | Covered by | Notes |
|---|---|---|
| Plaintext secrets in config / bootstrap | B1 | Reports key paths, not values |
| Gateway exposure & channel auth | B2, B11 | IPv6-aware bind parsing (v0.17.0) |
| Least privilege / dangerous tools | B3, B7, B8 | Approval gate via real `tools.exec.mode` (v0.17.0) |
| Execution sandbox present | B4 | Depth is partial — see gaps (B35) |
| Bootstrap-file injection surface | B6 | Prompt-injection-prone directives in SOUL/AGENTS/TOOLS |
| Trusted-output boundary policy | B21 | Is external content treated as data, not instructions |
| Installed-skill malware (ClawHavoc class) | B13, `--vet` | curl\|sh, base64/PS-encoded, split-stage exfil, paste hosts; **AST obfuscation** (`exec(b64decode)`, `getattr(os,…)()`, `__import__(…).system`) + injection directives in skill prose (v0.21); **AST taint** cred-file→network (`CRED_EXFIL_FLOW`, v0.23) |
| Egress surface | B14 | Where the agent can reach out |
| MCP server trust | B15, B24, `--vet-mcp` | Unpinned installs, plaintext transport, env/secret passthrough, broad scopes |
| Threat monitoring present | B16, `--monitor` | Detects absence; **Agent Watch** (`--monitor`, v0.24) gives severity-tagged drift on skills/bootstrap/score **and connections** (new MCP server / channel / gateway-exposed / host-monitor lost) + a local event journal (`--watch-log`) |
| Autonomy / heartbeat | B17 | Self-acting agent steerable by untrusted input |
| Subagent delegation | B18 | Elevated/exec inheritance w/o approval (real gate, v0.17.0) |
| Data at-rest perms | B19 | Group/world-readable memory/log dirs |
| Bootstrap/memory write protection | B20 | Identity-file writability |
| Self-modification risk | B22 | Writable identity + tools + no approval |
| Approval-bypass directives | B23 | "do X without asking" in bootstrap |
| Update / pinning hygiene | B25, C4 | Pinned releases |
| Untrusted-context exposure | B26 | `channels.<p>.contextVisibility` — untrusted group/quote/history context injected into the model (config side; B21 is the policy side) |
| Known-vulnerable version gate | B33 | `meta.lastTouchedVersion` vs a maintained advisory table (seeded: GHSA-g8p2-7wf7-98mq, fixed 2026.1.29) |
| Credential blast-radius | B41 | `auth.profiles.*` + gateway token vs reachability; PII-safe (provider names only) |
| **Capability blast-radius (verb-level least privilege)** | B43 | Attested via `--attest`. Classifies the agent's REAL held verbs: `MAILBOX_CONFIG` (auto-forward/filter/delegation), `DESTRUCTIVE` (delete-forever), `EGRESS` (send/forward), `REVERSIBLE`. Reversible-only ⇒ PASS; high-blast + ungated ⇒ FAIL. `ATTESTED` confidence |
| **Self-report ⇄ config drift** | B44 | Attested. Config grants a high-blast verb the agent omitted ⇒ WARN (drift / blind-spot / injection-mask). Impossible for a static-only scan |
| Effective-tools bypass | B31 | `tools.deny`/`toolsBySender`/per-agent deny vs the `deny write` ⇏ `deny apply_patch`/`exec` footgun |
| Sender identity strength | B30 | Mutable display-name allowlists, group history injection |
| Control-plane mutation reachability | B32 | cron/config.apply/update.run exposed over gateway |
| Browser / SSRF exposure | B38 | Metadata-IP, no-sandbox, hostname allowlist |
| Session visibility / cross-user leak | B39 | `session.dmScope`, `tools.sessions.visibility` |
| Backups of identity/memory | C3 | |
| Native binary PATH safety | C5 | |
| **Host defensive posture** | B50–B54 | Is the agent's *host* watched: network IDS, host audit, file-integrity, EDR/AV, firewall — read-only, WARN only for a high-privilege agent, never FAIL (v0.20). A self-reported `host_monitors` entry (attestation) upgrades a gap to an `ATTESTED` PASS for a monitor the scan can't see; static detection still wins (v0.28) |
| **Combinational attack chains** | RISK-01..10 | Lethal trifecta, untrusted→exec, control-plane takeover, malicious-skill→exfil, powerful-agent-on-unmonitored-host (RISK-10), etc. |

## Framework mapping (OWASP)

ClawSecCheck audits the **agent**, so it maps the OWASP categories onto the agent surface
(not app code). The machine-readable mapping is `catalog.OWASP_MAP` / `owasp_for(id)` and is
surfaced per finding in `--json` (`"owasp": [...]`); this table is its human view. Only clear
fits are tagged — checks with no clean LLM-Top-10 analog are covered by the agent-specific
OWASP Agentic (ASI) classes below, not stretched into a category they don't fit.

### OWASP Top 10 for LLM Applications (2025)

| Code | Category | ClawSecCheck checks |
|---|---|---|
| LLM01 | Prompt Injection | A1, B2, B6, B21, B23, B26, B30, B48 |
| LLM02 | Sensitive Information Disclosure | B1, B9, B11, B14, B19, B39, B41 |
| LLM03 | Supply Chain | B5, B13, B15, B24, B25, B33, B42, C4, C5 |
| LLM04 | Data and Model Poisoning | B7, B20, B22 |
| LLM05 | Improper Output Handling | B21, B47 |
| LLM06 | Excessive Agency | A1, B3, B4, B8, B17, B18, B22, B23, B31, B32, B41, B43, B44, B45, B46, B47, B48 |
| LLM07 | System Prompt Leakage | B9 |
| LLM08 | Vector and Embedding Weaknesses | — (no agent-config surface; RAG/embedding concern) |
| LLM09 | Misinformation | — (model output / overreliance; out of scope) |
| LLM10 | Unbounded Consumption | B17 |

LLM08/LLM09 are honest non-coverage: they live in the model/RAG layer, not the agent config
ClawSecCheck reads. **Excessive Agency (LLM06)** is where the tool is densest — the whole
multi-agent privilege-separation arc (B45/B46/B47) lands here, exactly the agent-specific
surface a web/code reviewer never sees.

### OWASP Agentic (ASI) threat classes — by name

The agent-specific framework is the **OWASP Agentic Security Initiative (ASI)** taxonomy.
Mapped by threat *name* (the exact ASI numbering should be reconciled against the published
ASI Top 10 / Agentic Threats & Mitigations doc before being treated as canonical — not
stamped here):

| ASI threat class | ClawSecCheck checks |
|---|---|
| Goal hijacking / prompt injection | A1, B6, B21, B23, B26; B28 is an unshipped provenance gap |
| Tool misuse (unsafe delegation / parameter injection) | B3, B18, B31, B45, B46, B47 |
| Identity & privilege abuse (multi-agent delegation chains) | B30, B45, B46, B47 |
| Runtime supply chain (dynamic tool/plugin composition) | B5, B13, B25, B33, B42 |
| Unexpected RCE (sandboxing failures) | B4, B48, C5 |
| Memory & context poisoning | B7, B20; B28 is an unshipped provenance gap |
| Insecure inter-agent communication | B47, B2, B32 |
| Cascading failures / blast-radius amplification | B41, B43, B45, B46, B47 |
| Human-agent trust / decision-fatigue | B8, B18, B23 |
| Rogue agent misalignment | B17, B22 (partial) |

This is the honest positioning: ClawSecCheck covers the **agent-specific** OWASP classes —
tool misuse, multi-agent identity/privilege abuse, inter-agent communication, cascading
blast-radius — that an app-code / OWASP-web reviewer does not touch at all.

**Sources (grounded):** OWASP Top 10 for LLM Applications 2025
(<https://genai.owasp.org/llm-top-10/>); OWASP Agentic Security Initiative
(<https://genai.owasp.org/initiatives/agentic-security-initiative/>) and Agentic AI — Threats
and Mitigations (<https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>).

## Gaps (no check today)

| Gap | Intended ID | Why it matters | Status |
|---|---|---|---|
| Dirty-input **content sanitizer** (HTML/bidi/zero-width normalization, hidden-text stripping) | (part of B26) | OpenClaw exposes no sanitizer config field; the context-exposure side ships as B26 (`contextVisibility`), the policy side is B21. Deeper normalization has no config surface to check | Partial / no config surface |
| Dirty-input → **action gate** (block exec/send/write/memory-write influenced by untrusted data w/o approval) | B27 | Stops injection from reaching side-effects | **No config surface** (`tools.confirm`/`requireApproval` are phantom; the real gate `tools.exec.mode` is B8/B22/B23). Covered combinationally by RISK-01/02/03 + B21, and now **partially via attestation** — B43 FAILs when the agent self-reports `untrusted_to_action: ungated` while holding a high-blast verb (v0.26) |
| **Taint / provenance** labels (summaries inherit source trust) | B28 | "sanitized ≠ trusted"; the core agentic gap. NB: distinct from the v0.23 skill-AST `CRED_EXFIL_FLOW` taint — that traces dataflow in *skill code*; B28 is about the *agent's own* runtime data provenance, which has no config surface | **No config to read** — but the v0.26 attestation layer lets the agent *self-report* its untrusted→action gating (`ATTESTED` confidence, never overrides a config fact). Runtime taint inference is still out of scope |
| **Inbound reachability** map (entrypoint→actor→agent) | B29 | Largely covered by B2 (open channels) + B30 (sender identity) + B3 (elevated allowFrom) | Mostly covered |
| Known-vulnerable **OpenClaw version** DB (more advisories) | B33+ | B33 ships with one confirmed advisory; the table grows as new advisories are published | Shipped (seed) |
| **Credential blast-radius** — broader inventory (SSH keys, cookies, MCP env) | B41+ | B41 ships `auth.profiles.*` + gateway-token surface vs reachability (PII-safe); SSH/cookies/MCP-env are later | Shipped (core) |
| **Skill/plugin install policy** (auto-update, postinstall scripts, world-writable skill dirs) | B42 | Supply-chain at install time | ✅ Shipped (v0.22.0): postinstall-exec hooks + world-writable skill dirs (auto-update/pinning stays in B25) |
| **Sandbox depth** | B4 (enhanced) + B3 | B4 now flags `docker.sock` bind (host escape) + `workspaceAccess=rw`; `tools.elevated.allowFrom` wildcard is B3. A separate B35 is largely redundant | Mostly covered |
| **Secret redaction in the report** (not just logs) | — | A decoded payload preview could surface a secret value | ✅ Done (H2): decoded previews `redact()`-ed; `--vet`/`--vet-mcp` evidence `_sanitize`-d (v0.21.1) |
| **Suppression governance** (suppressed CRITICAL stays visible; reason/expiry) | — | A suppressed CRITICAL silently uncaps the score | ✅ Done (H3): suppressed HIGH/CRITICAL stay visible in the report |
| **Windows ACL** equivalents of POSIX perm checks | — | Perm checks return UNKNOWN on Windows | **Not buildable under the laws** — no stdlib / no-subprocess way to read NTFS ACLs. UNKNOWN is the honest answer; the message now points to `icacls` (v0.25) |
| Per-finding **confidence** level | — | Methodology asks for it | ✅ Shipped (v0.25): HIGH (config-fact) vs MEDIUM (heuristic) on every finding; in text/JSON/SARIF |

## Rule

> If an attack path has no check and no test, assume the tool can miss it. This file is the
> source of truth for that — update it whenever a check or gap changes.
