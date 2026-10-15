<!-- markdownlint-disable MD040 MD032 -->

# Playbook: scope - what ClawSecCheck reads, writes and checks

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it before you answer a scope, privacy, path or secret question.

## What ClawSecCheck does (be transparent)

It runs a local script that is **read-only against your OpenClaw setup** - it does keep its own
local audit-history state on disk by default (see "what it writes" below) - and inspects the
user's own agent. **Full read scope:**

- `~/.openclaw/openclaw.json` - main config
- workspace bootstrap files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md`, etc.)
- text of **installed skills/plugins** (including Python AST-scan, parse-only - never executed)
- the config-write journal (`config-audit` rows in `~/.openclaw/state/openclaw.sqlite`; older installs: `~/.openclaw/logs/config-audit.jsonl`) and the config-health record (`config_health_entries` rows in the same database; older installs: `~/.openclaw/logs/config-health.json`) - config-write provenance & integrity
- `~/.openclaw/agents/.../sessions/*.jsonl` - Codex session logs for approval-policy posture
- the cron job store, the two global OpenClaw dotenv files (`~/.openclaw/.env` and
  `~/.config/openclaw/gateway.env` - these can hold real operational secrets: provider API keys,
  the gateway shared token; every `KEY=VALUE` pair is parsed into memory for the run, and only a
  handful of named toggle/URL keys are ever echoed into a finding, never a credential-shaped
  value - see [SECURITY_MODEL.md](../../SECURITY_MODEL.md)), and OpenClaw-related systemd user-unit
  `Environment=`/`EnvironmentFile=` lines
- **host recon (beyond OpenClaw's own scope, skip with `--no-host`):** existence of IDS, FIM, EDR
  and firewall config files, of their binaries on `PATH`, and of systemd enable-symlinks; the
  *contents* of a few known firewall config files, to read whether the firewall is on and whether
  its default outbound policy is deny (`/etc/ufw/ufw.conf`, `/etc/nftables.conf`, and on macOS
  `com.apple.alf.plist`); the *presence* (never the value) of a handful of proxy-shaped env vars
  (`http_proxy`/`https_proxy`/...); and on Windows only, a handful of read-only registry queries
  under `HKEY_LOCAL_MACHINE` for the same signals (a service key's existence, the firewall's on/off
  state - never a secret value). Reads only, no subprocess, no network
- **the installed npm dependency tree (beyond OpenClaw's own scope, skip with `--no-deptree`):**
  the OpenClaw package root is located from `PATH` (no subprocess), then its `node_modules` is
  walked to read each package's `package.json`, each package root's `binding.gyp`, and the
  in-package files those name as install-time targets - the two ways a dependency can run code at
  install time. Bounded (2000 packages), symlinks never followed, nothing ever executed
- **OpenClaw's own OAuth credential store (`<home>/credentials/`):** every file's *content* is
  read (bounded) and tested with the same secret detector used elsewhere in this tool, to answer
  one boolean per file - does it look like it holds a plaintext secret - plus a truncated digest so
  `--monitor` can notice a credential added, removed, or replaced. Feeds the Lethal Trifecta check,
  which runs on every default audit. The file's content and any detected secret value are never
  stored, echoed into a finding, written to a report, or logged - only the filename, a boolean, and
  a digest survive
- a **separate, narrower** path-existence inventory: whether `.env`, SSH key dirs, keychain/keyring
  directories, and browser cookie stores **exist** near the agent home - this check never opens any
  of them
- the ClawHub CLI's own plaintext token-store config (outside the OpenClaw home) - opened to check
  whether a `token` field is present and the file's permissions; the token *value* itself is never
  read into a report, logged, or placed in evidence (B182)
- permissions of memory/log paths

It makes **no network calls of its own**
and **never modifies `openclaw.json`, your skills, or your bootstrap files** - with exactly one
named, opt-in, confirmation-gated exception, covered below. What it *does* write stays **on your
own machine and is never uploaded**: almost all of it lands in ClawSecCheck's own state, not your
OpenClaw setup - a private local audit history under `~/.clawseccheck/` (owner-only - opt out with
`--no-history`), any report files you explicitly request via a flag (`--save`, `--badge`, `--html`,
`--sarif`, `--pdf`, `--monitor`, `--trend`, `--log`), and a small freshness ledger
(`~/.clawseccheck/coverage.json`) recording when you last ran an opt-in active self-test
(`--canary`/`--redteam`/`--dryrun`/`--self-test`/`--vet-mcp`). Two writes land inside the audited
OpenClaw home, both user-requested and explicit - never on a bare/default run: `--apply-ignore-proposals`
(opt-in, confirmation-gated) appends entries a prior `--propose-ignore` run already proposed to
`<home>/.clawseccheckignore`, never inventing one - see "Judge-panel fan-out" in JUDGE_PANEL.md; and `--pdf`,
when the OpenClaw home's own managed attachment directory (`<home>/media/outbound`) already exists
and is writable, defaults its PDF there instead of `~/.clawseccheck/report.pdf` (`<DIR>/report.pdf` under `--data-dir DIR`), so the file lands
where OpenClaw's own read tool is always allowed to open it back up for a chat attachment - see
"attachable report" in SKILL.md Step 5. Neither write ever touches `openclaw.json`, a skill, or a bootstrap file.
`--purge`
deletes its known store files (history, events, state, coverage, the opt-in run/SBOM-run/incident
stores, and the --watch heartbeat) plus the default-named report files and their lock siblings in
one step; a crash-artifact `.tmp` sibling, if one is ever left behind, is not touched by `--purge` and
needs a manual `rm`. Scoping flags at a glance: `--no-history` (skip
local history), `--no-host` (skip the host-recon bullet above), `--no-native` (skip the one external
command below), `--no-sockets` (skip the B340 effective-bind socket scan - the escape hatch if it
false-FAILs on an unusual host), `--no-deptree` (skip the npm dependency-tree walk - the escape
hatch on a very large tree). Pure Python standard library, no dependencies.

It also runs OpenClaw's **built-in** audit - the one fixed, read-only external command
`openclaw security audit --json` (its read-only mode, never a fixing one; the only subprocess call
this tool makes anywhere - skip it with `--no-native`) - and folds those findings into the same
report. Separately, `--vet`/`--vet-source` guide *your own host agent* to fetch a package into an
isolated quarantine folder before vetting it - ClawSecCheck itself never fetches anything; it prints
the exact fetch/isolate commands for you to review before they run (see the vetting workflow in SKILL.md Step 5).

It checks, among other things:
- the **Lethal Trifecta** (untrusted input x sensitive data x outbound actions - keep at most 2 of 3 active together),
- gateway exposure, channel authentication, plaintext secrets, least privilege, execution sandbox,
  MCP server trust, the agent's egress surface, and whether threat monitoring is active,
- the **host's defensive posture** (read-only - paths, `PATH`, the text of a few known firewall
  config files, and on Windows a handful of read-only registry queries): whether the machine the
  agent runs on has any network IDS, host audit logging, file-integrity monitoring, endpoint/EDR
  sensor, or host firewall - so a powerful agent isn't running blind on an unwatched box,
- the **content of installed skills/plugins** for the ClawHavoc malware class - shell-exec,
  credential/wallet theft, paste-host uploads, and base64-obfuscated payloads (decoded and
  re-scanned, never executed),
- the **content of bootstrap files** (`SOUL.md` etc.) for prompt-injection-prone directives,
- **B77 - config-write audit log:** reads the config-write journal (`config-audit` rows in
  `~/.openclaw/state/openclaw.sqlite`, and `~/.openclaw/logs/config-audit.jsonl` on older
  installs; both when both exist) for unexpected writers or suspicious-diff flags (advisory,
  `scored=False`),
- **B78 - config-health integrity:** reads OpenClaw's config-health record (the
  `config_health_entries` table in `~/.openclaw/state/openclaw.sqlite`, and
  `~/.openclaw/logs/config-health.json` on older installs; both when both exist) for a non-null
  `lastObservedSuspiciousSignature` (advisory, `scored=False`),
- **B79 - session approval-policy posture:** samples recent Codex session JSONL files to detect
  when every sampled turn carries `approval_policy=never` (advisory, `scored=False`),
- **credential surface inventory** (`report.py`): checks whether credential-store paths
  (`.env`, SSH dirs, keychain/keyring, browser cookies) exist near the agent home - path
  existence only, contents are never read,
- **B182 - ClawHub CLI token store:** opens the ClawHub CLI's own plaintext token-store config
  (outside the OpenClaw home) to check whether a `token` field is present and the file's
  permissions - the token value itself is never read into a report, logged, or placed in evidence.

If a finding looks like real malware in an installed skill, tell the user plainly, advise them
to remove that skill and rotate any secrets it could reach, and **never run** the payload.
