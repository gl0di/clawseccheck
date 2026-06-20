# Threat coverage matrix

Honest map of what ClawSecCheck checks today, what it does **not** yet check, and where
the gaps are. `UNKNOWN` is never counted as `PASS`; gaps below are areas with no check at
all (so they can't even surface as a finding). Generated 2026-06-20 for v0.17.1.

Current catalog: `A1, B1–B25, B30, B32, B38, B39, C3–C5`, plus the combinational risk
engine `RISK-01..RISK-09` and the install-time vetters `--vet` (B13 on an uninstalled
skill) / `--vet-mcp`.

## Covered

| Threat | Covered by | Notes |
|---|---|---|
| Plaintext secrets in config / bootstrap | B1 | Reports key paths, not values |
| Gateway exposure & channel auth | B2, B11 | IPv6-aware bind parsing (v0.17.0) |
| Least privilege / dangerous tools | B3, B7, B8 | Approval gate via real `tools.exec.mode` (v0.17.0) |
| Execution sandbox present | B4 | Depth is partial — see gaps (B35) |
| Bootstrap-file injection surface | B6 | Prompt-injection-prone directives in SOUL/AGENTS/TOOLS |
| Trusted-output boundary policy | B21 | Is external content treated as data, not instructions |
| Installed-skill malware (ClawHavoc class) | B13, `--vet` | curl\|sh, base64/PS-encoded, split-stage exfil, paste hosts |
| Egress surface | B14 | Where the agent can reach out |
| MCP server trust | B15, B24, `--vet-mcp` | Unpinned installs, plaintext transport, env/secret passthrough, broad scopes |
| Threat monitoring present | B16, `--monitor` | Detects absence; `--monitor` provides drift detection |
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
| Effective-tools bypass | B31 | `tools.deny`/`toolsBySender`/per-agent deny vs the `deny write` ⇏ `deny apply_patch`/`exec` footgun |
| Sender identity strength | B30 | Mutable display-name allowlists, group history injection |
| Control-plane mutation reachability | B32 | cron/config.apply/update.run exposed over gateway |
| Browser / SSRF exposure | B38 | Metadata-IP, no-sandbox, hostname allowlist |
| Session visibility / cross-user leak | B39 | `session.dmScope`, `tools.sessions.visibility` |
| Backups of identity/memory | C3 | |
| Native binary PATH safety | C5 | |
| **Combinational attack chains** | RISK-01..09 | Lethal trifecta, untrusted→exec, control-plane takeover, malicious-skill→exfil, etc. |

## Gaps (no check today)

| Gap | Intended ID | Why it matters | Status |
|---|---|---|---|
| Dirty-input **content sanitizer** (HTML/bidi/zero-width normalization, hidden-text stripping) | (part of B26) | OpenClaw exposes no sanitizer config field; the context-exposure side ships as B26 (`contextVisibility`), the policy side is B21. Deeper normalization has no config surface to check | Partial / no config surface |
| Dirty-input → **action gate** (block exec/send/write/memory-write influenced by untrusted data w/o approval) | B27 | Stops injection from reaching side-effects | Roadmap |
| **Taint / provenance** labels (summaries inherit source trust) | B28 | "sanitized ≠ trusted"; the core agentic gap | Roadmap |
| **Inbound reachability** map (entrypoint→actor→agent) | B29 | Largely covered by B2 (open channels) + B30 (sender identity) + B3 (elevated allowFrom) | Mostly covered |
| Known-vulnerable **OpenClaw version** DB (more advisories) | B33+ | B33 ships with one confirmed advisory; the table grows as new advisories are published | Shipped (seed) |
| **Credential blast-radius** — broader inventory (SSH keys, cookies, MCP env) | B41+ | B41 ships `auth.profiles.*` + gateway-token surface vs reachability (PII-safe); SSH/cookies/MCP-env are later | Shipped (core) |
| **Skill/plugin install policy** (auto-update, postinstall scripts, world-writable skill dirs) | B42 | Supply-chain at install time; partial via B13/B25 | Backlog |
| **Sandbox depth** | B4 (enhanced) + B3 | B4 now flags `docker.sock` bind (host escape) + `workspaceAccess=rw`; `tools.elevated.allowFrom` wildcard is B3. A separate B35 is largely redundant | Mostly covered |
| **Secret redaction in the report** (not just logs) | — | A decoded payload preview could surface a secret value | See HARDENING_BACKLOG #2 |
| **Suppression governance** (suppressed CRITICAL stays visible; reason/expiry) | — | A suppressed CRITICAL silently uncaps the score | See HARDENING_BACKLOG #3 |
| **Windows ACL** equivalents of POSIX perm checks | — | Perm checks return UNKNOWN on Windows | Backlog |
| Per-finding **confidence** level | — | Methodology asks for it | Backlog |

## Rule

> If an attack path has no check and no test, assume the tool can miss it. This file is the
> source of truth for that — update it whenever a check or gap changes.
