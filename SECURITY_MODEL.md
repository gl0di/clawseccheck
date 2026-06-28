# Security Model

This document describes what ClawSecCheck is allowed to do, what it is explicitly
forbidden from doing, the trust boundaries it operates within, and what it does not
claim to guarantee.

## Allowed behavior

ClawSecCheck is a **local, read-only** audit tool. Its permitted operations are:

- **Read** the OpenClaw config file (`~/.openclaw/openclaw.json` or the path given
  with `--home`).
- **Read** workspace bootstrap markdown files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`,
  etc.) located under the agent home directory.
- **Read** installed-skill and plugin text files (SKILL.md, scripts, manifests) for
  supply-chain vetting (`--vet`, `--vet-mcp`, B13).
- **Read** selected memory or log file metadata (path, size, permissions) to assess
  data-at-rest exposure (B19).
- **Build findings** from parsed config values and file metadata using deterministic,
  evidence-gated logic.
- **Print** a structured report to stdout (text, JSON, SARIF, HTML, SVG badge).
- **Write to disk** only when the user explicitly requests it via a CLI flag:
  `--save`, `--badge`, `--html`, `--sarif`, `--monitor` (state snapshot),
  `--trend` / `--history` (score history), `--log` (log file).
- **Run one fixed, read-only subprocess** — `openclaw security audit --json` — with
  a timeout, `capture_output=True`, and no `shell=True`, only when `--no-native` is
  not set.

## Forbidden behavior

The following actions are explicitly outside the tool's design and must never be
introduced:

- **Executing scanned content.** ClawSecCheck must not `eval()`, `exec()`,
  `subprocess`-run, or otherwise interpret code found in SKILL.md files, config
  values, bootstrap markdown, or any external file it reads. All external content is
  treated as untrusted data.
- **Network access by default.** No HTTP requests, DNS lookups, socket connections, or
  telemetry. Network access is not a planned feature.
- **Mutating OpenClaw config.** The tool must not write to `~/.openclaw/` or any
  agent-managed path without an explicit, confirmation-gated `--fix` mode (not yet
  implemented). The name promises a *check*.
- **Printing secret values.** Config values that may contain credentials, tokens, or
  other secrets must be redacted via `logsafe.redact()` before appearing in any
  output channel (text, JSON, log, HTML, SARIF, prompts).
- **Trusting external content as instructions.** Finding titles, evidence strings,
  fix text, and skill content surfaced in `--prompts` output are untrusted audit data.
  They must be sanitized and presented as quoted evidence, never as executable
  instructions.

## Trust boundaries

```
[ User's filesystem ]
        |  read-only
        v
[ ClawSecCheck parser / check engine ]
        |  structured findings only
        v
[ Report renderer / stdout ]
        |  sanitized, secrets redacted
        v
[ User / agent ]
```

- Everything ClawSecCheck reads (config, bootstrap, skills) is **untrusted input**.
  The parser treats it as data, not as code or instructions.
- The one subprocess (`openclaw security audit`) is invoked with a fixed, hardcoded
  argument list. Its output is parsed as JSON, not evaluated.
- State files written by `--monitor` and `--trend` contain only hashes, scores, and
  check IDs — no raw config values and no secret material.
- The tool runs with whatever OS permissions the invoking user has. It does not
  attempt privilege escalation.

## Out of scope

- **ClawSecCheck does not prove your agent is safe.** It is a heuristic configuration
  audit, not a formal security proof and not a runtime verifier.
- **It does not replace red-teaming.** Static analysis of configuration files cannot
  detect all attack paths. Adversarial runtime testing against a live agent remains
  necessary.
- **It does not scan your entire filesystem.** The read surface is bounded: the agent
  home directory, installed-skill directories, and the paths you explicitly pass.
- **It cannot detect zero-day vulnerabilities** in OpenClaw itself or in third-party
  MCP servers — it can only flag known risky patterns.
- **UNKNOWN is not PASS.** When the tool cannot determine a configuration state
  (unreadable file, unparseable config, unsupported OpenClaw version), it reports
  `UNKNOWN`. An `UNKNOWN` result is excluded from the score and never treated as a
  safe outcome.

## Release validation protocol

A release must pass local validation before merge/tag:
## Post-release operational backlog (v1.20.6)

- [impact:quality][owner:maintainer][difficulty:1-2h] Confirm B43/B44 confidence wording matches implementation after post-release changes.
  [что проверить] Compare behavior in `tests/test_attest.py` and `clawseccheck/checks.py` for `approval_gates_auto` and `approval bypass` evidence.
  [критерий Done] Behavior remains consistent with runtime docs and user-facing findings.

- [impact:release][owner:release-eng][difficulty:1-2h] Keep operational docs synchronized after each tag.
  [что проверить] README/CHANGELOG/SECURITY/SECURITY_MODEL/SKILL entries mention the same release steps and smoke commands.
  [критерий Done] No stale check IDs or argument contracts between docs and parser behavior.

- [impact:ops][owner:release-eng][difficulty:1 day] Run explicit post-release smoke for installability/repeatability.
  [что проверить] `clawseccheck --self-test --ascii`; `python3 -m pytest tests/test_cli.py tests/test_cli_flags.py tests/test_attest.py`; `python3 -m pytest tests/test_features.py::test_canary_token_and_payload tests/test_features.py::test_canary_evaluate tests/test_features.py::test_canary_deterministic_per_seed`; and `--attest` flow for `B43/B44`.
  [критерий Done] Same commands succeed on a clean environment or the limitation is recorded in release notes.


- `python3 -m ruff check .`
- `python3 -m pytest`
- targeted checks for the changed modules.

Also verify that release documentation is synchronized:
- `README.md`
- `CHANGELOG.md`
- `SECURITY.md`
- `SECURITY_MODEL.md`
- `SKILL.md`

Keep this list current whenever release rules change so the model of operational security stays consistent with the shipped version.
