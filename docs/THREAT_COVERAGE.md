# Threat coverage matrix

Honest map of what ClawSecCheck checks today, what it does **not** yet check, and where
the gaps are. `UNKNOWN` is never counted as `PASS`; gaps below are areas with no check at
all (so they can't even surface as a finding). Updated 2026-07-13 for v3.38.1.

Current catalog: A1 plus the B-series, C-series, and T-series (behavioral) — 123 checks
total; see `docs/CHECKS.md` for the full generated list, plus the
combinational risk engine `RISK-01..RISK-19`, the install-time vetters `--vet` (B13 plus
the content-security ring — B59–B105 / B135–B158 on an uninstalled skill; AST-, injection-,
and capability-intent-aware) / `--vet-mcp`, the **attestation
layer** (`--ask` / `--attest`, with a guided interrogation protocol so the agent self-builds
the report; `--attest -` reads stdin) that feeds the agent's self-report into B43/B44, and
the **behavioral trajectory audit** (`--behavioral`, E-032/E-039) — T1/T2/T3, proof-by-log
sequence detectors over OpenClaw's trajectory sidecar, complementing every check above
(which all answer "what the agent *could* do") with "what the agent *actually did*".

## Closure invariant

**"Closed" ≠ zero misses** — that would be a false promise; the honest efficacy verdict is
false-negative-dominant. **"Closed" = zero *silent* gaps**: every threat category below
carries exactly one machine-checked tag, one of four kinds: a **CHECK** tag naming one or
more real `CheckMeta` ids (each with a fixture and a test); a bare **ATTEST** tag (closed
only by the `--attest` self-report interrogation, no static config surface); a **JUDGE** tag
naming an AST taint rule (closed only by the `--judge-packet` advisory band — the rule has
no catalog id of its own); or a bare **CEILING** tag (a declared, honest non-coverage, with
the reason in prose). `UNKNOWN` is a valid, honest per-finding outcome; only an *untagged*
category — one that looks covered but isn't tagged at all — is the thing this invariant
forbids.

`tests/test_threat_coverage_ledger.py` enforces this mechanically: every `CheckMeta` id in
`clawseccheck/catalog.py` must appear inside some CHECK tag below, and every row in the two
canonical sections (**Covered** and **Non-static coverage**) must carry exactly one of the
four tags. The test does *not* judge whether the tag is the *right* one — bucket assignment
is an architect/human call, made here; the test only catches an entry that was never
classified at all.

## Covered

| Threat | Covered by | Notes |
|---|---|---|
| **Lethal Trifecta** (headline correlation) | A1 | Untrusted input × sensitive data × outbound actions active together — the tool's single CRITICAL trifecta check; keep at most 2 of 3 `[CHECK: A1]` |
| Plaintext secrets in config / bootstrap | B1 | Reports key paths, not values `[CHECK: B1]` |
| System-prompt / secret leak in tool output | B9 | `[CHECK: B9]` |
| Audit log & sensitive redaction | B10 | `[CHECK: B10]` |
| Local-first & model hygiene | B12 | `[CHECK: B12]` |
| Gateway exposure & channel auth | B2, B11, B80 | IPv6-aware bind parsing (v0.17.0); B80 flags auth without rate limiting on a non-loopback bind `[CHECK: B2, B11, B80]` |
| Least privilege / dangerous tools | B3, B7, B8 | Approval gate via real `tools.exec.mode` (v0.17.0) `[CHECK: B3, B7, B8]` |
| Execution sandbox present | B4 | Depth is partial — see gaps (B35) `[CHECK: B4]` |
| Bootstrap-file injection surface | B6, B161 | Prompt-injection-prone directives in SOUL/AGENTS/TOOLS (B6); identity-file injection — staleness-framing/safety-disable directive corroborated by a fabricated admin/auth code (B161) `[CHECK: B6, B161]` |
| Trusted-output boundary policy | B21 | Is external content treated as data, not instructions; combined with RISK-01/02/03 this is also the strongest automated leg of the dirty-input→action-gate concern (B27 was never implemented as its own id — no config surface exists for a generic gate — but this row plus the attestation layer below covers the same ground) `[CHECK: B21]` |
| Installed-skill malware (ClawHavoc class) | B13, B86, B87, B88, B89, B90, B91, B92, B93, B94, B96, B97, B98, B99, B100, B102, B103, B104, B105, B135, B151, B152, B153, B154, B156, B157, B158, B165, `--vet` | curl\|sh, base64/PS-encoded, split-stage exfil, paste hosts; **AST obfuscation** (`exec(b64decode)`, xor/zlib-layered and local `_decode()`-wrapper indirection incl. chained multi-stage wrappers, `getattr(os,…)()`, `__import__(…).system`) + injection directives in skill prose — ignore-instructions / hide-from-user plus **anti-refusal & system-prompt/tool-definition leak** directives (fence- and example-context dampened); **AST taint** cred-file→network (`CRED_EXFIL_FLOW`) and env-var / agent-config→network body/URL (`ENV_EXFIL_FLOW`, WARN-first — auth headers excluded, see the JUDGE band below for that exclusion's own recovery); **cross-file import-graph taint** (`CROSS_FILE_EXEC`); **bundled shell (`.sh`)** and **JS/TS** passes (decode-then-exec, remote-fetch-then-exec, dynamic dispatch, unsafe deserialization); **split-payload reassembly** across file boundaries (base64 — B90/B102 — and plaintext — B153/B154); **frontmatter/trigger hygiene** (B88 tag-shaped values, B93 homoglyph/confusable trigger impersonation); **install-time supply chain** (B94 extended lifecycle hooks, B96 config-driven trust widening, B97 per-turn event-hook files, B103 install-directive metadata, B104 offboarding hygiene, B105 cross-skill combined effect, B135 accepted-despite-failed-verification, B151/B152 orphaned plugin cache, B156 overt secret-exfil, B157 non-registry dependency source, B158 declared-but-absent load source, B165 hex-shaped crypto private-key value near wallet context — C-200, gated against tx/block-hash wording to avoid colliding with routine Ethereum tx-hash prose); import-path hijack (B86, `sys.path` from a writable/relative location); dormant-capability code (B89); undeclared capabilities (B98, no `tools.allow` manifest); `.pth`/sitecustomize persistence (B99); ClickFix paste-into-terminal (B100); **cross-session persistence** (B13 sub-signal, C-204/T1098.004 + T1053): `~/.ssh/authorized_keys` public-key append (argument-bound write detection — a read-only audit of the file never fires), plus cron/systemd gap closure (`crontab -` stdin install, the `["crontab","-"]` argv form, `systemctl --user enable`, and per-user `~/.config/systemd/user/*.service`/`.timer` unit files — the pre-existing check already covered `crontab -e`/`@reboot`/bare `systemctl enable`); **insecure-coding, no clear attack intent** (B13 sub-signal, C-199/SkillTrustBench T09): `SHELL_INJECTION_RISK` — a `subprocess.*(shell=True, …)` or bare `os.system()`/`os.popen()` call whose command is not a provable compile-time literal (WARN-grade on the unsafe SHAPE alone, distinct from the stronger crit `TT5_CMD_INJECTION`, which requires PROVEN external taint), and hardcoded/predictable `/tmp` writes (CWE-377 — `tempfile.mkstemp()`/`NamedTemporaryFile()` never flagged); parse failures surface UNKNOWN, not a silent skip `[CHECK: B13, B86, B87, B88, B89, B90, B91, B92, B93, B94, B96, B97, B98, B99, B100, B102, B103, B104, B105, B135, B151, B152, B153, B154, B156, B157, B158, B165]` |
| Egress surface | B14, B155 | Where the agent can reach out; B155 hardens the outbound-proxy leg specifically (credential leak / TLS-verify / SSRF-guard bypass) `[CHECK: B14, B155]` |
| MCP server trust | B15, B24, B47, `--vet-mcp` | Unpinned installs, plaintext transport, env/secret passthrough, broad scopes `[CHECK: B15, B24, B47]` |
| Threat monitoring present | B16, `--monitor` | Detects absence; **Agent Watch** (`--monitor`) gives severity-tagged drift on skills/bootstrap/score **and connections** (new MCP server / channel / gateway-exposed / host-monitor lost) + a local event journal (`--watch-log`) `[CHECK: B16]` |
| Autonomy / heartbeat | B17 | Self-acting agent steerable by untrusted input `[CHECK: B17]` |
| Subagent delegation | B18, B72, B81 | Elevated/exec inheritance w/o approval (real gate, v0.17.0); B72 flags `allowAgents` wildcard; B81 flags spawn limits raised beyond recommended defaults `[CHECK: B18, B72, B81]` |
| Data at-rest perms | B19, B82 | Group/world-readable memory/log dirs; B82 covers `cacheTrace` transcripts persisted without tool-output redaction `[CHECK: B19, B82]` |
| Bootstrap/memory write protection | B20 | Identity-file writability `[CHECK: B20]` |
| Self-modification risk | B22 | Writable identity + tools + no approval `[CHECK: B22]` |
| Approval-bypass directives | B23 | "do X without asking" in bootstrap `[CHECK: B23]` |
| Update / pinning hygiene | B25, C4, C6 | Pinned releases; C6 covers a pre-v2026.6.10 hook-composition tool-policy drop `[CHECK: B25, C4, C6]` |
| Untrusted-context exposure | B26, B140 | `channels.<p>.contextVisibility` — untrusted group/quote/history context injected into the model (config side; B21 is the policy side); B140 flags wildcard group ingress with no `allowFrom` restriction `[CHECK: B26, B140]` |
| Known-vulnerable version gate | B33 | `meta.lastTouchedVersion` vs a maintained advisory table (seeded: GHSA-g8p2-7wf7-98mq, fixed 2026.1.29) `[CHECK: B33]` |
| Credential blast-radius | B41 | `auth.profiles.*` + gateway token vs reachability; PII-safe (provider names only) `[CHECK: B41]` |
| **Capability blast-radius (verb-level least privilege)** | B43 | Attested via `--attest`. Classifies the agent's REAL held verbs: `MAILBOX_CONFIG` (auto-forward/filter/delegation), `DESTRUCTIVE` (delete-forever), `EGRESS` (send/forward), `REVERSIBLE`. Reversible-only ⇒ PASS; high-blast + ungated ⇒ FAIL. `ATTESTED` confidence — has its own id/fixture/test the same as a static check, so it's tagged CHECK; the *residual* case with no config or self-report at all is the ATTEST-band B28 row below `[CHECK: B43]` |
| **Self-report ⇄ config drift** | B44 | Attested. Config grants a high-blast verb the agent omitted ⇒ WARN (drift / blind-spot / injection-mask). Impossible for a static-only scan `[CHECK: B44]` |
| Declared vs. proven capability drift | B84, T3 | B84 (static): declared `tools.allow` vs the agent's own attested-effective set vs what the trajectory log actually proves was used. T3 (`--behavioral`): a high-blast verb PROVEN in the trajectory log that `tools.allow` never declared — the runtime-observed sibling of B84 `[CHECK: B84, T3]` |
| Incident readiness | B85 | Is a tamper-resistant tool-use trail actually present (trajectory sidecar reachable, not rotated away) — the precondition for T1–T3 and B84 to have anything to read `[CHECK: B85]` |
| Effective-tools bypass | B31, B68, B69 | `tools.deny`/`toolsBySender`/per-agent deny vs the `deny write` ⇏ `deny apply_patch`/`exec` footgun; B68 (`apply_patch` workspace-only disabled), B69 (`exec` inline-eval gate missing) `[CHECK: B31, B68, B69]` |
| Sender identity strength | B30 | Mutable display-name allowlists, group history injection `[CHECK: B30]` |
| Control-plane mutation reachability | B32, B71 | cron/config.apply/update.run exposed over gateway; B71 flags `denyCommands` non-exact-entry footguns `[CHECK: B32, B71]` |
| Browser / SSRF exposure | B38, B83 | Metadata-IP, no-sandbox, hostname allowlist; B83 flags excessive redirect-following in the web-fetch tool `[CHECK: B38, B83]` |
| Session visibility / cross-user leak | B39 | `session.dmScope`, `tools.sessions.visibility` `[CHECK: B39]` |
| Backups of identity/memory | C3 | `[CHECK: C3]` |
| Native binary PATH safety | C5 | `[CHECK: C5]` |
| Tool-registry name collision (SkillTrustBench T07) | C5, B104, B24, B30 | Ground-negative (C-196, grounded against the real installed dist, not the recon doc): a skill's SKILL.md frontmatter carries no tool-declaration field at all (the parser recognizes only `name`/`description`/`openclaw.*`/`user-invocable`/`disable-model-invocation` — no `tools:`/`allowed-tools:`); the only tool-REGISTRATION path is plugin/MCP resolution, which seeds its conflict set from the core tool names and drops (never silently overrides) any tool whose normalized name collides with a built-in — MCP tools are additionally namespace-prefixed (`<server>__`), making a bare-name collision with a built-in structurally impossible. The reachable *shadowing* variants remain covered by the checks in this row: PATH-based binary shadowing (C5), skill-install cross-tier shadowing (B104), MCP server impersonation (B24), display-name impersonation (B30). No new check was built — there is no config field to ground one against `[CHECK: C5, B104, B24, B30]` |
| **Host defensive posture** | B50–B54, B101, B150 | Is the agent's *host* watched: network IDS, host audit, file-integrity, EDR/AV, firewall, outbound-egress-filtering posture (B101) — read-only, WARN only for a high-privilege agent, never FAIL. A self-reported `host_monitors` entry (attestation) upgrades a gap to an `ATTESTED` PASS for a monitor the scan can't see; static detection still wins. B150 flags a systemd `Restart=always` OpenClaw-related persistence unit `[CHECK: B50, B51, B52, B53, B54, B101, B150]` |
| Non-loopback gateway hygiene | B56, B70, B73 | B56 (control-UI `allowedOrigins: "*"`), B70 (`trustedProxy.allowLoopback` header-spoof surface on a non-loopback bind), B73 (mDNS full advertisement on a non-loopback bind) `[CHECK: B56, B70, B73]` |
| Plugin / MCP install-time trust | B5, B15, B24, B42, B57, C047 | B57 flags `permissionMode=approve-all`; C047 is a manual-review flag for a non-local MCP endpoint `[CHECK: B5, B15, B24, B42, B57, C047]` |
| Content-security ring — prompt-injection-shaped directives | B58, B59, B60, B61, B62, B63, B64, B65, B66, B67, B74, B91, B95, B159, B160, B163 | Unicode-obfuscated hidden text (B58), markdown-image data-exfil (B59), self-replication (B60), cross-agent config snooping (B61), capability-intent mismatch (B62), silent-instruction (B63), instruction-hierarchy override (B64), sleeper-trigger (B65), persona jailbreak (B66), per-source trust contracts (B67), forged-provenance content (B74), dynamic-dispatch sink obfuscation (B91), dependency confusion (B95), self-privilege-escalation directive (B159), prose-intent bulk-data exfiltration (B160), social-engineering/credential-phishing prose — urgency + authority-claim + credential-solicitation-or-OOB-action triad (B163) `[CHECK: B58, B59, B60, B61, B62, B63, B64, B65, B66, B67, B74, B91, B95, B159, B160, B163]` |
| Multi-agent / subagent privilege separation | B45, B46, B47, B75, B76 | Per-agent trifecta decomposition (B45), multi-agent trifecta exposure (B46), cross-agent trifecta reassembly (B47), MCP tool-inheritance bypass — attested (B75) and high-blast (B76) `[CHECK: B45, B46, B47, B75, B76]` |
| Dangerous break-glass overrides | B48 | `[CHECK: B48]` |
| Filesystem-write tool exposure | B55 | Broad fs-write without scoping `[CHECK: B55]` |
| **Config-write / config-health / session-approval advisories** | B77, B78, B79 | **B77:** reads `~/.openclaw/logs/config-audit.jsonl` for unexpected writers or suspicious-diff flags (advisory, `scored=False`). **B78:** reads `config-health.json` for a non-null `lastObservedSuspiciousSignature` field (advisory). **B79:** samples recent Codex session JSONL files to detect `approval_policy=never` on every sampled turn (advisory) `[CHECK: B77, B78, B79]` |
| **Log corpus threat-hunting (advisory)** | B164 | Content-scans the agent's OWN log/transcript corpus (trajectory sidecars, `logging.file`, `cacheTrace`, session transcripts, config-audit log, memory files, install backups) for signals against the agent (injected instructions surfacing in log content) and against its environment (exfil evidence, dangerous-capability use, compromise IOCs, tamper/anomaly, at-rest secrets). Quiet-by-default (base-rate discipline): WARN only when ≥2 signal classes co-occur in one sink, or a single class with inherent same-line/permission corroboration fires (exfil evidence is secret+exfil-host paired; secrets-at-rest also needs a world-readable sink); isolated single-class hits are suppressed to a quiet report hint, never a WARN. Advisory, `scored=False`, never FAILs `[CHECK: B164]` |
| Codex/device-pairing hygiene | B136, B138 | B136 flags Codex CLI project `trust_level="trusted"`; B138 flags a dangling high-scope pending device pairing `[CHECK: B136, B138]` |
| Cron scheduler persistence surface | C048 | Top-level cron entries `[CHECK: C048]` |
| Injection-like text in HTML image attributes | C074 | `[CHECK: C074]` |
| Egress inventory / secrets-at-rest scan | C014, C015 | C014 enumerates the outbound-capable surface; C015 scans the OpenClaw home for secrets at rest `[CHECK: C014, C015]` |
| Proxy header trust | C032 | Real-IP fallback trust boundary `[CHECK: C032]` |
| **Behavioral trajectory (proof-by-log)** | T1, T2 (`--behavioral`) | Every check above answers "what the agent *could* do" from config/skill-source; the T-series reads OpenClaw's trajectory sidecar and answers "what it *actually did*" — an observed ingress→sensitive→egress verb sequence (T1), a fail→fail→success series on a sensitive verb (T2). T3 is tagged above alongside B84 (its static sibling). Metadata-only: never reads call/return payloads. WARN-only, never scored — a separate mode, not part of the A-F grade `[CHECK: T1, T2]` |

## Non-static coverage (ATTEST / JUDGE / CEILING)

Categories with **no `CheckMeta` id** — closed some other way, or an honest, declared
ceiling. A category with neither a CHECK-tagged row above nor a tagged row here is a
silent gap by definition; `tests/test_threat_coverage_ledger.py` fails the build on one.

- Dirty-input taint/provenance — "sanitized ≠ trusted" for the *agent's own runtime data*
  (distinct from the skill-code `CRED_EXFIL_FLOW`/`ENV_EXFIL_FLOW` AST taint above, which
  traces dataflow in *skill source*, not agent runtime state). No config surface exists to
  read this statically; the `--attest`/`--ask` self-report protocol lets the agent disclose
  its own untrusted→action gating instead, feeding B43/B44 at `ATTESTED` confidence, which
  never overrides a config fact `[ATTEST]`
- File-read → network sink with no independent credential/exfil signal nearby in the skill
  (`TT4_FILE_NET`) — `check_installed_skills` silently drops this "info"-severity AST
  finding when uncorroborated; `--judge-packet` recovers it as `UNKNOWN` for a host-agent
  second look `[JUDGE: TT4_FILE_NET]`
- Externally-controlled value flowing into a network-fetch URL, an SSRF shape
  (`TT_SSRF`) `[JUDGE: TT_SSRF]`
- External input flowing into a subprocess call as a non-program argument, argument (not
  command) injection (`TT5_ARG_INJECTION`) `[JUDGE: TT5_ARG_INJECTION]`
- Direct shell/exec-family sink call with no independent credential/exfil signal nearby
  (`DANGEROUS_SINK`) `[JUDGE: DANGEROUS_SINK]`
- Env-var / agent-config secret placed in an auth-shaped keyword (`headers=`/`auth=`/
  `cert=`) of a network call — deliberately excluded from `ENV_EXFIL_FLOW` above (the normal
  way a skill authenticates to its own API), so it is never even computed by the static
  engine; a dedicated AST walk surfaces it to the judge packet instead
  (`ENV_AUTH_KWARG_EXFIL`, B-190) `[JUDGE: ENV_AUTH_KWARG_EXFIL]`
- **Windows ACL** equivalents of POSIX permission checks — no stdlib / no-subprocess way to
  read NTFS ACLs under this project's laws (§2). `UNKNOWN` is the honest answer; the message
  points to `icacls` `[CEILING]`
- Credential **lifetime / rotation** signal (long-lived static secrets vs short-lived scoped
  ones) — `auth.profiles` ships no documented expiry/TTL/rotation sub-field, and no
  statically-recognizable long-lived-vs-short-lived token shape exists without decoding
  secret material, which this tool never does. Covered today only indirectly via B1
  (at-rest secrets), C015 (home scan), B41 (blast-radius/reachability); re-ground if OpenClaw
  ever exposes a real expiry field `[CEILING]`
- Deep dirty-input content normalization (bidi/zero-width stripping, hidden-text channel
  neutralization beyond what B26/B21/B58 already flag as a *finding*) — OpenClaw exposes no
  sanitizer config field to check; this is a filtering *capability* gap, not a
  detection one `[CEILING]`
- **AST10 — Cross-Platform Reuse** (OWASP Agentic Skills Top 10) — ClawSecCheck audits a
  single install; cross-platform reuse hazards need a multi-deployment view that is out of
  scope for this tool `[CEILING]`

## Framework mapping (OWASP)

ClawSecCheck audits the **agent**, so it maps the OWASP categories onto the agent surface
(not app code). The machine-readable mapping is `catalog.OWASP_MAP` / `owasp_for(id)` and is
surfaced per finding in `--json` (`"owasp": [...]`); this table is its human view. Only clear
fits are tagged — checks with no clean LLM-Top-10 analog are covered by the agent-specific
OWASP Agentic (ASI) classes below, not stretched into a category they don't fit.

### OWASP Top 10 for LLM Applications (2025)

| Code | Category | ClawSecCheck checks |
|---|---|---|
| LLM01 | Prompt Injection | A1, B2, B6, B21, B23, B26, B30, B48, B56, B58, B59, B60, B61, B64, B67, B74, B140, C074 |
| LLM02 | Sensitive Information Disclosure | B1, B9, B11, B12, B14, B19, B39, B41, B59, B61, B67, C014, C015 |
| LLM03 | Supply Chain | B5, B13, B15, B24, B25, B33, B42, B57, B103, B135, B151, B152, C4, C5, C047 |
| LLM04 | Data and Model Poisoning | B7, B20, B22, B55 |
| LLM05 | Improper Output Handling | B21, B47 |
| LLM06 | Excessive Agency | A1, B3, B4, B8, B17, B18, B22, B23, B31, B32, B41, B43, B44, B45, B46, B47, B48, B55, B57, B62, B63, B65, B66, B68, B69, B71, B72, B76, B79, B105, B136, B138, B150, T1, T3 |
| LLM07 | System Prompt Leakage | B9 |
| LLM08 | Vector and Embedding Weaknesses | — (no agent-config surface; RAG/embedding concern) |
| LLM09 | Misinformation | — (model output / overreliance; out of scope) |
| LLM10 | Unbounded Consumption | B17, B150 |

LLM08/LLM09 are honest non-coverage: they live in the model/RAG layer, not the agent config
ClawSecCheck reads. **Excessive Agency (LLM06)** is where the tool is densest — the whole
multi-agent privilege-separation arc (B45/B46/B47) lands here, exactly the agent-specific
surface a web/code reviewer never sees.

### OWASP Agentic Skills Top 10 (2026)

> **Status:** candidate / active development.
> **Source:** <https://owasp.org/www-project-agentic-skills-top-10> (v1.0 2026).

The machine-readable mapping is `catalog.AST_MAP` / `ast_for(id)` and is surfaced per
finding in `--json` (`"ast": [...]`).

| AST code | Category | ClawSecCheck checks |
|---|---|---|
| AST01 | Malicious Skills | B13, B60, B63, B65, C048 |
| AST02 | Supply Chain Compromise | B5, B13, B15, B24, B25, B42, B57, B103, B135, B151, B152, C5, C047 |
| AST03 | Over-Privileged Skills | B3, B8, B17, B18, B22, B23, B31, B32, B41, B43, B44, B45, B46, B47, B48, B55, B57, B68, B69, B71, B72, B75, B76, B79, B138, B150 |
| AST04 | Insecure Metadata | B6, B44, B62, T3 |
| AST05 | Untrusted External Instructions | B6, B7, B20, B21, B23, B26, B30, B58, B59, B60, B61, B63, B64, B65, B66, B67, B74, B105, B140, C074, T1 |
| AST06 | Weak Isolation | B4, B22, B38, B39, B48, B70, B73, B136, C032 |
| AST07 | Update Drift | B25, B33, C4, C6 |
| AST08 | Poor Scanning | B16 |
| AST09 | No Governance | B10, B16, B50, B51, B52, B53, B54, B77, B78 |
| AST10 | Cross-Platform Reuse | — (documented coverage gap: single-install scope) |

**Coverage notes:**

- **AST10** (Cross-Platform Reuse) has no catalog check — ClawSecCheck audits a single
  install; cross-platform reuse hazards require a multi-deployment view that is out of
  scope for this tool.
- **B7** (Memory poisoning) and **B57** (Plugin auto-approve) placements diverge
  intentionally from a naive surface mapping: B7 maps to AST05 (external instructions
  reaching memory), not AST04; B57 maps to AST02/AST03 (supply-chain + privilege),
  reflecting its dual exposure.
- **AST01/B13's Python AST analysis is bounded by the interpreter running the audit.**
  `ast.parse()` (`skillast.py`) uses the running interpreter's own grammar, with no
  `feature_version` pin. A skill wrapping an obfuscated call in syntax newer than the
  running Python (e.g. `match`/`case`, Python 3.10+) fails to parse on an older audit
  interpreter and degrades to UNKNOWN there, though it is correctly caught as FAIL on
  3.10+. This is a deliberate trade-off, not an oversight: pinning to the package's
  minimum (Python 3.9+, per `pyproject.toml`) would make detection uniformly worse —
  every interpreter, including 3.10+, would then reject that syntax too, since
  `feature_version` can only *restrict* a parser to an older grammar, never grant an
  older interpreter the ability to parse newer syntax it structurally lacks. Run the
  audit on the newest available Python for maximum AST-based detection coverage.

### OWASP Agentic Security Initiative (ASI) — by threat name

The original ASI taxonomy (pre-AST-2026 numbering) mapped by threat *name*; retained for
historical continuity. The numbered AST-2026 table above supersedes this for new integrations.

| ASI threat class | ClawSecCheck checks |
|---|---|
| Goal hijacking / prompt injection | A1, B6, B21, B23, B26; B28 is closed via attestation only, see Non-static coverage |
| Tool misuse (unsafe delegation / parameter injection) | B3, B18, B31, B45, B46, B47 |
| Identity & privilege abuse (multi-agent delegation chains) | B30, B45, B46, B47 |
| Runtime supply chain (dynamic tool/plugin composition) | B5, B13, B25, B33, B42 |
| Unexpected RCE (sandboxing failures) | B4, B48, C5 |
| Memory & context poisoning | B7, B20; B28 is closed via attestation only, see Non-static coverage |
| Insecure inter-agent communication | B47, B2, B32 |
| Cascading failures / blast-radius amplification | B41, B43, B45, B46, B47 |
| Human-agent trust / decision-fatigue | B8, B18, B23 |
| Rogue agent misalignment | B17, B22 (partial) |

**Sources (grounded):** OWASP Top 10 for LLM Applications 2025
(<https://genai.owasp.org/llm-top-10/>); OWASP Agentic Skills Top 10 2026
(<https://owasp.org/www-project-agentic-skills-top-10>); OWASP Agentic Security Initiative
(<https://genai.owasp.org/initiatives/agentic-security-initiative/>) and Agentic AI — Threats
and Mitigations (<https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>).

## TAM-01..12 weaponization test matrix (standard §15.3)

Named regression, not accidental coverage — `tests/test_tam_matrix.py` pins each row so a
refactor that silently regresses one leg turns red here. This matrix exercises the
`--monitor` drift subsystem (its own internal finding codes, e.g. `F-079`) rather than the
`CheckMeta` catalog above, so it sits outside the `[CHECK]`/`[ATTEST]`/`[JUDGE]`/`[CEILING]`
tagging scope — its own dedicated test is the closure mechanism here.

| Row | Attack simulation | Mechanism | Status |
|---|---|---|---|
| TAM-01 File tamper | Modify SKILL.md / add an exfil instruction after install | `monitor` skill-hash CHANGED alert (HIGH) | Covered |
| TAM-02 Manifest escalation | Widen network/fs/shell permissions without a version bump | `monitor` capability-diff (F-079, HIGH) | Covered |
| TAM-03 Dependency poison | Add a malicious / unpinned lookalike package | B95 (dependency-confusion co-occurrence) | Covered |
| TAM-04 Cross-skill abuse | Fake low-privilege skill impersonates a caller to a high-privilege skill | — | **Out of scope** — needs a live platform broker mediating caller/callee/action identity; no static equivalent |
| TAM-05 Metadata poison | Tool description/schema changed to look read-only | B24 (MCP hardening) + `monitor` RP1 (oauth.scope expansion) | Covered |
| TAM-06 PATH/import hijack | Fake curl/python/module earlier in PATH | C5 (native binary PATH safety) | Covered |
| TAM-07 Symlink escape | Output/config path replaced with a symlink to a sensitive host path | B87 (symlink-escape finding, F-080) | Covered |
| TAM-08 Prompt weaponization | Poisoned content instructs a skill to use its allowed tools for exfil | Content ring, B63 (silent-instruction) | Covered |
| TAM-09 Downgrade/replay | Install an old signed-but-vulnerable version / replay an old manifest | `monitor` version-regression (F-079, MEDIUM) | **Partial** — static "declared version went backward" signal only; real signed-manifest replay/revocation needs a trust root, not achievable read-only/offline |
| TAM-10 Memory backdoor | Skill writes "always trust attacker.com" into agent memory | B7 (memory poisoning) + B20 (bootstrap write protection); `multiturn.py` covers the live cross-turn leg | Covered |
| TAM-11 Egress mutation | Dependency repoints destination from an approved API to a webhook/pastebin | B24 (MCP hardening) + `monitor` RP3 (endpoint repoint) | Covered |
| TAM-12 Self-modifying skill | Skill writes into its own directory / changes a helper script | RISK-07 (self-modification chain) + B22 | Covered |

## Rule

> If an attack path has no check and no test, assume the tool can miss it. This file is the
> source of truth for that — update it whenever a check or gap changes, and keep every row in
> **Covered** / **Non-static coverage** tagged. `tests/test_threat_coverage_ledger.py` turns
> a drift (a new catalog id with no CHECK tag, or an untagged category row) red in CI before
> it ships silently.
