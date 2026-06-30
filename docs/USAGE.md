# ClawSecCheck — Usage & Command Reference

A complete, task-oriented tour of every ClawSecCheck mode: **what it does, why it
exists, and how to run it.** ClawSecCheck is a **local, read-only** security
self-audit for your own OpenClaw agent setup — it inspects, scores, and explains;
it never mutates your agent, never makes a network call, and never uploads anything.

- Per-check catalog: [`CHECKS.md`](CHECKS.md)
- Long-tail flags: [`../references/cli-flags.md`](../references/cli-flags.md)
- Output shapes: [`OUTPUT_SCHEMA.md`](OUTPUT_SCHEMA.md)
- Attestation format: [`ATTESTATION.md`](ATTESTATION.md)

---

## How you run it

There are two equivalent ways to drive ClawSecCheck:

**1. Conversationally (the usual way).** Ask your agent, e.g.
*"audit my OpenClaw setup with clawseccheck"* or *"vet this skill before I install
it"*. The skill maps your request to the right mode (see `SKILL.md`).

**2. As a CLI** (`clawseccheck` console script, or `python3 -m clawseccheck.cli`):

```bash
clawseccheck                       # full audit of ~/.openclaw → grade + findings + fixes
clawseccheck --home ~/work/.openclaw   # audit a different OpenClaw home
clawseccheck --json                # machine-readable output for scripts/CI
```

Exactly **one mode** runs per invocation. The mode is resolved by a fixed-order
cascade; if you pass a second mode flag, or a modifier the chosen mode can't use,
ClawSecCheck prints a `note: …` to **stderr** naming what was ignored and continues —
machine-readable stdout (`--json` / `--sarif`) stays clean.

Everything ClawSecCheck writes (history, monitor state, event journal) lives under
`~/.clawseccheck/`. Nothing leaves your machine.

---

## How the A–F grade is computed

The score is a **weighted pass-rate with honesty hard-caps** (`scoring.py`).

### 1. Each check produces a status

| Status | Meaning | Contribution to score |
| --- | --- | --- |
| `PASS` | Control is in place | full weight |
| `WARN` | Partial / likely-insecure default | half weight |
| `FAIL` | Control is missing/broken | 0 |
| `UNKNOWN` | Not determinable from config | **excluded** (not in numerator or denominator) |

`UNKNOWN` is deliberately excluded so an honestly-undeterminable check neither
rewards nor punishes you — it just shrinks the measured surface.

### 2. Each check has a severity weight

```
CRITICAL = 10    HIGH = 6    MEDIUM = 3    LOW = 1
```

### 3. Raw score = weighted pass-rate

```
raw = round( (Σ earned weight) / (Σ total weight of scorable checks) × 100 )
```

where a `PASS` earns its full weight and a `WARN` earns half.

### 4. Honesty hard-caps (the important part)

A weighted average alone lets a big pool of easy `PASS`es dilute one real failure —
so a genuinely dangerous config could still show an "A". To prevent that, **any open
`FAIL` caps the final score** by its severity (most-severe cap wins):

| Open FAIL severity | Score capped at | Max grade |
| --- | --- | --- |
| CRITICAL | **49** | F |
| HIGH | **79** | C |
| MEDIUM | **89** | B |
| LOW | **94** | A− |

So a single open CRITICAL guarantees an **F**, no matter how many other checks pass.

### 5. Final letter grade

```
A: 90+    B: 80–89    C: 70–79    D: 50–69    F: <50
```

### 6. "Not assessable" (N/A)

If nothing is scorable (empty config, or every check came back `UNKNOWN`/advisory),
ClawSecCheck reports a distinct **N/A** — it does *not* mislabel an unknowable setup
as a worst-possible F.

> The shareable card/badge shows **only** the grade, score, and trifecta ratio —
> **never the findings themselves** (sharing your report must not hand an attacker a
> map of your holes).

---

## Modes & flags, grouped by purpose

### Core audit & output formats

| Flag | What & why | How to run |
| --- | --- | --- |
| *(none)* | Full audit of `~/.openclaw`: grade A–F, findings ranked by severity, copy-paste fixes. The default and most common use. | `clawseccheck` |
| `--home PATH` | Point the audit at a different OpenClaw home (default `~/.openclaw`). | `clawseccheck --home ~/alt/.openclaw` |
| `--json` | Machine-readable JSON (frozen schema: `score`, `grade`, `findings[]`, …). For scripts, CI, dashboards. | `clawseccheck --json` |
| `--card` | Print **only** the shareable summary card — grade + score + trifecta ratio, no findings. Safe to paste in a README or chat without leaking your weak spots. | `clawseccheck --card` |
| `--badge PATH` | Write a shareable **SVG** badge (the card as an image) for a README. | `clawseccheck --badge sec.svg` |
| `--html PATH` | Write a standalone, self-contained **HTML** report (nice for sharing with a human reviewer). | `clawseccheck --html report.html` |
| `--sarif PATH` | Write a **SARIF 2.1.0** file for CI / GitHub Code Scanning. Local file only — never uploaded by the tool. | `clawseccheck --sarif results.sarif` |
| `--save PATH` | Also write the human report to a file alongside printing it. | `clawseccheck --save audit.txt` |
| `--ascii` | ASCII-only output (no unicode icons/box) for terminals that can't render unicode. Auto-detected too. | `clawseccheck --ascii` |
| `--full` | One-shot deep pass: audit **+** self-test **+** vet-mcp together (human output). Self-test emits deterministic test material only — it does not attack. | `clawseccheck --full` |

### Vetting — check something **before** you trust it

These answer "is this safe to install / connect?" *before* it touches your agent.

| Flag | What & why | How to run |
| --- | --- | --- |
| `--vet PATH` | Vet a **skill** (a directory or a `SKILL.md`) for malware/abuse patterns before you install it. Exit code 1 on SUSPICIOUS/DANGEROUS. | `clawseccheck --vet ./downloaded-skill` |
| `--vet-mcp [NAME\|FILE]` | Vet configured **MCP servers** (or one named server / a file) for supply-chain risk before trusting them. With no argument, checks the servers already in your config. | `clawseccheck --vet-mcp`<br>`clawseccheck --vet-mcp ./server.json` |
| `--vet-all` / `--recursive` | Vet **every** installed skill under `~/.openclaw/skills/*` — one verdict per skill plus an aggregate. | `clawseccheck --vet-all` |

`--vet` / `--vet-mcp` honor `--json` (emits a vetting object: `mode`, `target`,
`verdict`, `findings[]`) and can write a `--sarif` side-output.

### Self-test — how resilient is the agent to prompt injection?

These generate **deterministic test material** to probe your setup. They do **not**
attack anything live; they hand you payloads/harnesses to run consciously.

| Flag | What & why | How to run |
| --- | --- | --- |
| `--canary` | Active prompt-injection **canary** self-test. | `clawseccheck --canary` |
| `--redteam` | Print a live **red-team payload suite** for adversarial self-testing. | `clawseccheck --redteam` |
| `--dryrun` | Print a behavioral **dry-run harness** (prompt-injection self-test across all sources). | `clawseccheck --dryrun` |
| `--self-test` | All three together: canary + red-team + dry-run. | `clawseccheck --self-test` |
| `--seed VALUE` | Fixed seed for `--redteam` tokens so CI runs are reproducible (default: fresh random each run). | `clawseccheck --redteam --seed 42` |

### Attestation — facts the config can't reveal

Some risks (the real tool inventory, whether approvals are actually gated, host
monitors) aren't visible in static config. Attestation lets the running agent
self-report them, then folds that into the audit.

| Flag | What & why | How to run |
| --- | --- | --- |
| `--ask` | Emit a JSON **attestation template** for the agent to fill from its own ground truth. | `clawseccheck --ask > attest.json` |
| `--attest PATH` | Enrich the audit with that self-report — unlocks checks **B43** (capability blast-radius) and **B44** (self-report ⇄ config drift) at `ATTESTED` confidence. Read-only. `-` reads JSON from stdin. | `clawseccheck --attest attest.json` |

### Monitoring & drift (Agent Watch)

| Flag | What & why | How to run |
| --- | --- | --- |
| `--monitor` | Monitor mode: alert on what **changed** since the last check (config drift over time). Records a score point as part of its job. | `clawseccheck --monitor` |
| `--state PATH` | Snapshot file `--monitor` compares against (default `~/.clawseccheck/state.json`). | `clawseccheck --monitor --state st.json` |
| `--events PATH` | Agent Watch event journal — the local timeline of changes (default `~/.clawseccheck/events.jsonl`). | `clawseccheck --monitor --events ev.jsonl` |
| `--watch-log` | Print the Agent Watch event journal (the change timeline). | `clawseccheck --watch-log` |
| `--no-host` | Skip host-monitor detection (IDS / audit / FIM / EDR / firewall posture) — useful in containers where those don't apply. | `clawseccheck --no-host` |

### Score history, trend & percentile

| Flag | What & why | How to run |
| --- | --- | --- |
| `--trend` | Record this run to history, then print the trend + percentile. Records even under `--no-history` (recording is its job). | `clawseccheck --trend` |
| `--percentile` | Print the offline percentile rank for your current score (how you compare against a bundled reference distribution — computed locally, no network). | `clawseccheck --percentile` |
| `--history PATH` | Path for the trend history file (default `~/.clawseccheck/history.jsonl`). | `clawseccheck --trend --history h.jsonl` |
| `--no-history` | Don't record this run to local score history (default is to record). Honored everywhere **except** `--trend`/`--monitor`. | `clawseccheck --no-history` |

### CI / automation (exit codes)

| Flag | What & why | How to run |
| --- | --- | --- |
| `--fail-under N` | Exit 1 if the score is below N — fail a pipeline on a regression. | `clawseccheck --fail-under 80` |
| `--exit-code` | Exit 1 if any **unsuppressed FAIL** finding exists. | `clawseccheck --exit-code` |

### Remediation help

| Flag | What & why | How to run |
| --- | --- | --- |
| `--fix` | Print paste-ready remediation for the current findings. **Prints only — never applies** (the tool stays read-only). | `clawseccheck --fix` |
| `--prompts` | Print a copy-paste *fix prompt* per finding — hand each to your agent to do the fix. | `clawseccheck --prompts` |
| `--next` | Print recommended next actions based on the audit result (the highest-leverage thing to do next). | `clawseccheck --next` |
| `--risk-paths` | Print only the highest-risk capability chains (the attack-chain / combinational-risk engine: how individually-OK capabilities combine into a dangerous path). | `clawseccheck --risk-paths` |

### Integrity & suppression

| Flag | What & why | How to run |
| --- | --- | --- |
| `--verify-self` | Print the SHA-256 digest of ClawSecCheck's own engine source — detect tampering with the auditor itself. | `clawseccheck --verify-self` |
| `--show-suppressed` | List the finding ids + fingerprints you've silenced via `.clawseccheckignore`, and exit. | `clawseccheck --show-suppressed` |

Suppression: drop accepted findings into `~/.openclaw/.clawseccheckignore` (one id or
fingerprint per line). Suppressed FAILs are excluded from the score (`scoring.py`), so
a baseline you've consciously accepted won't keep capping your grade.

### Quiet / logging modifiers

| Flag | What & why | How to run |
| --- | --- | --- |
| `--no-native` | Don't also run the built-in `openclaw security audit` (offline / hermetic runs). | `clawseccheck --no-native` |
| `--no-update-notice` | Suppress the offline "your build may be stale" reminder (also via `CLAWSECCHECK_NO_UPDATE_NOTICE=1`). Offline only — never a network call. | `clawseccheck --no-update-notice` |
| `--no-freshness-notice` | Suppress the coverage-freshness reminder for opt-in tests (also via `CLAWSECCHECK_NO_FRESHNESS_NOTICE=1`). Offline only. | `clawseccheck --no-freshness-notice` |
| `--verbose` / `--debug` | Emit INFO / DEBUG log breadcrumbs to stderr (with secret redaction). | `clawseccheck --debug` |
| `--log PATH` | Also write log output to PATH (only when given; redacted). | `clawseccheck --log run.log` |
| `--version` / `--help` | Print version / show the help screen. | `clawseccheck --help` |

---

## Common recipes

```bash
# First-time audit, human-readable
clawseccheck

# Vet a skill you just downloaded, before installing
clawseccheck --vet ./some-skill

# CI gate: fail the build below a B, machine output + SARIF for code scanning
clawseccheck --json --sarif results.sarif --fail-under 80

# Deepest single pass (audit + self-test + MCP vetting)
clawseccheck --full

# Attested audit (unlocks blast-radius + drift checks)
clawseccheck --ask > attest.json     # agent fills attest.json from ground truth
clawseccheck --attest attest.json

# Track drift over time
clawseccheck --monitor
clawseccheck --watch-log             # review the change timeline

# Share a grade without leaking findings
clawseccheck --card
clawseccheck --badge security.svg
```
