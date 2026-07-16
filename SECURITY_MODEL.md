# Security Model

This document describes what ClawSecCheck is allowed to do, what it is explicitly
forbidden from doing, the trust boundaries it operates within, its own capability
surface / least-privilege posture, and what it does not claim to guarantee.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md). For engine-tampering
detection and the honest limits of self-verification, see the README's
["trust no one"](README.md#%EF%B8%8F-important--trust-no-one-including-this-skill)
section and the FAQ's
["What if the host is already compromised?"](docs/FAQ.md#what-if-the-host-is-already-compromised).

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
- **Write to disk** its own state under `~/.clawseccheck/`: a one-line score-history
  entry **by default** (opt out `--no-history`), and — only when you ask —
  `--save`, `--badge`, `--html`, `--sarif`, `--monitor` state, `--sbom`, `--log`.
  `--purge` deletes that store. It never writes your OpenClaw config.
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

```text
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

## Capability surface / least privilege

This section states, explicitly, everything ClawSecCheck's own process is capable of
doing — so a reviewer can check the claim against the code rather than take it on faith.

- **Read-only by default.** The default audit path (`collector.py`) opens files for
  reading only: `~/.openclaw/openclaw.json`, workspace bootstrap markdown, installed
  skill/plugin text (including archive members it decompresses in memory to classify),
  OpenClaw log files, and agent session logs. Nothing under this path is ever opened
  for writing.
- **Stdlib-only, zero runtime dependencies.** There is no third-party package in the
  import graph of the shipped engine — nothing to audit in a dependency tree, nothing
  that can be substituted by a poisoned transitive package.
- **Zero network, forever.** No socket, no HTTP client, no DNS lookup, no telemetry, no
  phone-home, no update check over the wire — not for scoring, not for the staleness
  notice (which reads only the local clock and an optional local hint file), not for
  anything. If a feature could exfiltrate, it does not exist in this codebase.
- **All writes are confined to `~/.clawseccheck/`.** The one place ClawSecCheck writes
  by default (a one-line score-history entry; opt out with `--no-history`) and the
  places it writes only on explicit request (`--save`, `--monitor` state/journal,
  `--badge`, `--html`, `--sarif`, `--log`, `--sbom`) all live under that single owner-only
  directory tree, or an explicit path the user names on the command line. `safeio.py`
  enforces this at the filesystem-primitive level: directories are created mode `0700`
  at creation time (no transient world-readable window from umask) and refused if they
  turn out to be a symlink (`secure_dir`); files are opened with `O_NOFOLLOW` so a
  planted symlink at the target path fails the open (`ELOOP`) instead of being followed,
  and are created mode `0600` at creation time (`secure_write_text` / `secure_append_text`).
  A hostile local process cannot pre-plant a symlink to turn a ClawSecCheck write into an
  arbitrary-file overwrite.
- **The native OpenClaw CLI call is off by default and opt-in only by omission of a flag
  — the flag turns it OFF, not on.** `audit()` accepts `include_native`, and the CLI sets
  it to `not args.no_native`: the built-in `openclaw security audit --json` subprocess
  runs unless `--no-native` is passed. It is the single fixed, read-only, argument-list-
  hardcoded external command ClawSecCheck can ever invoke (no `shell=True`, a timeout,
  captured output) — see `native.py`.
- **The host-level filesystem scan is similarly opt-out, not opt-in by an extra grant:**
  `audit()`'s `include_host` flag drives whether `hostwatch.detect()` runs (B50–B54,
  B101 — path-existence and config-text checks for IDS/FIM/EDR/firewall/egress-policy
  presence); the CLI sets it from `not args.no_host`, so `--no-host` is the way to
  disable it. This layer never runs a subprocess or touches the network — it only
  `stat()`s paths and reads known config file text.

## Deny-by-construction vs. runtime policy

ClawSecCheck does not sit behind a sandbox or policy-engine gate that decides, at
runtime, whether a given read is allowed. It does not need one: being a **read-only
auditor by construction** removes the class of risk such a gate would exist to contain.
There is no code path anywhere in the shipped engine that writes to a file it did not
open under `~/.clawseccheck/` (or a path the user explicitly named), and no code path
that executes content it reads (skill/plugin source is parsed with the stdlib `ast`
module or scanned by regex/lexical passes — never imported, called, or `exec()`'d; see
"A note for scanners auditing ClawSecCheck's own source" below). Removing the capability
at the source is a stronger guarantee than gating it at runtime, and is verifiable by
reading `collector.py`, `safeio.py`, and `native.py` directly.

**This is a doctrine statement about the future, not a description of a shipped
feature:** if a fix/apply capability is ever built (there is no such mode today —
ClawSecCheck reports only, never remediates), it would have to be introduced as a
capability wholly separate from the audit path, and it would have to be:

- **opt-in** — never invoked as a side effect of running an audit;
- **confirmation-gated** — the user affirmatively approves each mutating action, not a
  blanket "yes to everything";
- **clearly separated** from the read-only checks, so the security posture of "run
  ClawSecCheck" does not change silently the day such a mode ships.

Any future change to this doctrine is itself a decision that belongs in this document
before it belongs in code.

## Secrets and data handling

- Every string ClawSecCheck considers surfacing in a report, log, or finding is routed
  through `logsafe.redact()` before it reaches an output channel. `redact()` masks
  generic secret-shaped patterns, provider-specific token formats (GitHub/Slack/Stripe/
  OpenAI-project keys, JWTs, PEM private-key blocks), Luhn-validated credit-card PANs,
  and `key=value` pairs where the key name looks secret-like — and it is idempotent, so
  redacting already-redacted text never un-masks or double-mangles it.
- The structured logger (`logsafe.get_logger`) attaches a `_RedactingFilter` to every
  handler it creates, so redaction is defense-in-depth: even a caller that forgot to
  redact a value before logging it is still covered at the handler level.
- **No PII or secret value ever appears in logs, reports, fixtures, or output** — by
  construction, not by policy. Credential-store checks (`.env`, SSH key directories,
  keychain/keyring, browser cookie stores) inventory **path existence only**; their
  contents are never opened or read.
- **Nothing is ever transmitted anywhere.** There is no code path in this project that
  sends a redacted (or unredacted) value off the machine — see "zero network, forever"
  above.

## Audit trail — tamper-evident local history

The local score history (`~/.clawseccheck/history.jsonl`, written by default; opt out
with `--no-history`) is **tamper-evident via a hash chain**. Each entry carries a
`chain_hash` field: `sha256(prev_chain_hash + canonical_json(entry_without_chain_hash))`
(`history.py`, sharing the same scheme `monitor.py`'s event journal uses). Editing,
reordering, or deleting a historical entry breaks the chain from that point forward.
Verify the chain with:

```bash
clawseccheck --verify-history
```

An absent, empty, or legacy pre-chain file (entries with no `chain_hash` field at all)
verifies as `OK` for backward compatibility; the first entry whose recomputed hash does
not match its stored `chain_hash` reports exactly where the chain broke.

**What the chain does and does not defend.** It is a plain SHA-256 chain, not a keyed
(HMAC) or externally-anchored one, so it detects *accidental corruption* and *naive edits*
(editing/reordering/deleting an entry breaks it) — not a knowledgeable attacker who already
has write access to the file, who can simply recompute the whole chain forward after
tampering. The chain is therefore a drift/tamper-*evidence* aid, **not** a substitute for
filesystem permissions on `~/.clawseccheck/`: anyone who can write that file already runs as
your user and could edit history, patch the engine, or read anything you can. This is the
same honest boundary as `--verify-self` (it does not defend against an adversary who also
patches the verifier).

## A note for other security scanners auditing ClawSecCheck's own source

If you are running a static scanner (including ClawHub's own publish-time audit, or a
generic secret/malware scanner) over this repository, please read this before filing a
false positive.

ClawSecCheck's own source **intentionally contains dangerous-token strings** —
`exec`, `eval`, `subprocess`, `child_process`-shaped patterns, and similar — because
this is a security tool whose entire job is to search *other* skills' code for exactly
those patterns. Those tokens appear as **detection data**: regex literals, AST rule
names, comments, docstrings, and finding-text describing what the check looks for — not
as executed code paths in this tool. `checks.py` and `skillast.py`'s Python analysis is
stdlib `ast` (parse-only, never executed); the shell and JS/TS analyzers are lexical/
regex passes over text. Nothing this project reads from a third-party skill or plugin is
ever imported, called, or run.

This is a known, addressed false-positive class: v3.7.1 reworded the call-shaped prose
and finding-text in `checks.py`, `skillast.py`, and `risk.py` (e.g. `exec (`, `exec()s`,
`.then(eval)`, `eval(atob(...))`) purely so that a naive word-boundary scanner would stop
tripping on the tool's own signature vocabulary — the detection regexes, the
`"child_process" in masked` logic, and every check's label/severity were left completely
unchanged, and the full test suite stayed green throughout. The project's own `--vet`
run against its own source (`clawseccheck --vet .`) reports this honestly rather than
hiding it: a security tool necessarily ships attack signatures as data, and that is
disclosed as a note, not papered over.

## Own capability declaration

This is ClawSecCheck's explicit statement of its own permission/capability surface — a
reviewer can check every clause below directly against the cited module:

- It does **not** write outside `~/.clawseccheck/` or a path the user names on the
  command line (`safeio.py`, `collector.py`).
- `--purge` deletes ClawSecCheck's own store files (a fixed filename list —
  history.jsonl, events.jsonl, state.json, coverage.json + lock sidecars), never
  recursive/glob, never outside `~/.clawseccheck/`.
- It does **not** make a network connection of any kind, for any reason, ever (grep the
  import graph: there is no `socket`, `http.client`, `urllib.request` call site that
  reaches the network at runtime — `urllib.parse` is used only for local string
  parsing in `logsafe.py`).
- It does **not** execute, `eval()`, or import code it reads from a scanned skill,
  plugin, config, or bootstrap file — all such content is parsed as data (`ast.parse`,
  regex, JSON) and never run.
- It does **not** invoke any external command beyond the one fixed, hardcoded,
  read-only `openclaw security audit --json` call, and only when `--no-native` is not
  passed (`native.py`).
- It does **not** log, print, or persist an unredacted secret value anywhere
  (`logsafe.py`).
- It does **not** modify the OpenClaw configuration, bootstrap files, or installed
  skills it reads (see "Forbidden behavior" above).

**On machine-readability of this declaration:** OpenClaw's own skill manifest format
(`SKILL.md`'s `metadata.openclaw` block) currently exposes only three keys — `emoji`,
`os`, and `user-invocable` — and has no dedicated capability/permission declaration
field. There is nothing to add to `SKILL.md`'s frontmatter today that would make this
machine-checkable; this document is the closest artifact available until, and unless,
OpenClaw's skill schema ships such a field, at which point `SKILL.md` should gain it.

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
