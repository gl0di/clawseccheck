# ClawSecCheck — Frequently Asked Questions

Answers to the most common questions about ClawSecCheck output, grades, and usage.
For the full check catalog see [`docs/CHECKS.md`](CHECKS.md).
For the threat mapping see [`docs/THREAT_COVERAGE.md`](THREAT_COVERAGE.md).
For all flags run `clawseccheck --help`.

---

## Why do I see UNKNOWN everywhere?

`UNKNOWN` means ClawSecCheck could not determine the state of a check from the
available evidence. It is **not** a PASS — the README's "Honest limits" section
calls this out explicitly: *"`UNKNOWN` ≠ `PASS`"*.

**Common causes:**

- **Config file missing or unreadable.** The audit reads `~/.openclaw/openclaw.json`
  by default. If that file does not exist, every check that depends on it will report
  `UNKNOWN` rather than invent a verdict. Run `clawseccheck --home <path>` if your
  OpenClaw home is somewhere other than `~/.openclaw` (see the
  [How do I run on a different home directory?](#how-do-i-run-on-a-different-home-directory)
  section below).

- **Permission denied on config or bootstrap files.** If the current user cannot read
  `~/.openclaw/openclaw.json`, `SOUL.md`, `AGENTS.md`, or similar bootstrap files,
  ClawSecCheck cannot inspect them and must report `UNKNOWN`. See the
  [I get permission errors](#i-get-permission-errors--what-do-i-do) section below.

- **Feature genuinely not configured.** Many checks are conditional: B4 (execution
  sandbox) returns `UNKNOWN` when there are no exec tools and no sandbox config, because
  the check is simply not applicable to a tool-less setup. B5 (plugin/skill supply-chain)
  reports `UNKNOWN` when no plugins are declared. This is correct and honest — not a
  problem.

- **Attestation-only checks.** Checks B43, B44, B45, B46, B47 require an agent
  self-report that the static config cannot provide. Without `--attest`, they report
  `UNKNOWN`. Use `clawseccheck --ask` to generate the attestation template, fill it with
  your running agent, and then pass `--attest attest.json` to unlock these checks.

**Effect on the score.** `UNKNOWN` findings are **excluded** from the score calculation
entirely — they neither help nor hurt it. If most checks are `UNKNOWN`, the score covers
only the checks that *could* be assessed.

**What to do.** Confirm that `~/.openclaw/openclaw.json` exists and is readable by the
current user, that `--home` points at the right directory, and — if you want the full
picture — that you have run `--attest` with your agent's self-report.

---

## Why is my grade F?

The grading uses a **weighted pass-rate with hard caps** that prevent a single serious
failure from being diluted by many passes:

| Severity of any FAIL | Score capped at | Grade ceiling |
|---|---|---|
| CRITICAL | 49 | F |
| HIGH | 75 | C |
| MEDIUM | 89 | B |
| LOW | 94 | A- |

A single CRITICAL FAIL (for example B1 — plaintext secrets, or B2 — open gateway with
no auth) locks the score at or below 49, which is always an F, regardless of how well
everything else scores.

**What to look at first:**

1. Run `clawseccheck --fix` — it prints paste-ready remediation for every open FAIL and
   WARN finding, most urgent first. No config is changed; you review the output and apply
   it yourself.

2. Run `clawseccheck --prompts` — this turns each finding into a ready-to-paste prompt
   you can hand to your agent to fix it.

3. Run `clawseccheck --risk-paths` — this shows the highest-risk capability chains. A
   chain only fires when every link has positive evidence, so the ones listed are the most
   actionable.

**Common reasons for an F:**

- Secrets or tokens stored in plaintext inside `openclaw.json` or a bootstrap file (**B1**).
- Gateway exposed with no authentication (**B2**).
- Installed third-party skill flagged as suspicious or dangerous by the malware scan (**B13**).
- Control-plane tools (config, cron, gateway) reachable over the HTTP gateway (**B32**).
- A `dangerously*` sandbox escape flag is enabled (**B48**).

After fixing the underlying issue, re-run `clawseccheck` to see the new score.

---

## How do I suppress a false positive?

ClawSecCheck uses a `.clawseccheckignore` file — placed inside the OpenClaw home
directory — to suppress specific findings so they are excluded from the score and the
report.

**Step 1 — identify the finding you want to suppress.**

Run with `--show-suppressed` to list what is currently suppressed, or look at the check
ID (e.g. `B14`) and optionally its fingerprint in the normal report output:

```bash
clawseccheck --show-suppressed
```

**Step 2 — add an entry to `.clawseccheckignore`.**

The file lives at `<openclaw-home>/.clawseccheckignore` (by default
`~/.openclaw/.clawseccheckignore`). Each non-blank, non-comment line is one entry. You
can suppress by:

- **Bare check ID** — suppresses every finding for that check, regardless of detail:

  ```text
  # I accept the current egress surface; reviewed 2026-06-01
  B14
  ```

- **Fingerprint** (`ID:sha1-8`) — suppresses only the one specific finding whose detail
  produced that fingerprint hash. Use this when a check fires multiple findings and you
  only want to accept one of them:

  ```text
  B14:ab12cd34
  ```

Lines beginning with `#` are comments. The fingerprint for any finding is shown in the
`--show-suppressed` output after the check runs.

**Step 3 — verify.**

Re-run `clawseccheck`. Suppressed findings no longer appear in the report or affect the
score. To confirm what is suppressed, use `--show-suppressed` again.

> **Note on false positives.** If you believe a finding is wrong about your config,
> please also open an issue at <https://github.com/gl0di/clawseccheck/issues> with the
> output of `clawseccheck --json` (it redacts secret *values* — only key names and paths
> appear) and your OpenClaw version. That helps improve the grounding for everyone.

---

## I get permission errors — what do I do?

ClawSecCheck is **read-only** — it never changes your config or files. Permission errors
mean the *audit* cannot read a file it needs to inspect.

**Most common causes and fixes:**

- **`openclaw.json` is not readable by the current user.** This is unusual — the config
  is yours. Check ownership and mode:

  ```bash
  ls -la ~/.openclaw/openclaw.json
  ```

  If the file is owned by another user (e.g. you ran OpenClaw under `sudo`), either fix
  ownership (`chown $USER ~/.openclaw/openclaw.json`) or run the audit as the same user
  that owns it.

- **The openclaw home directory itself is not readable.** Similarly check:

  ```bash
  ls -ld ~/.openclaw
  ```

  The directory needs at least execute (`x`) permission for the current user. A mode of
  `700` owned by you is correct and expected.

- **Bootstrap files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`) are locked down.** If these
  files are owned by a different user or have restricted permissions, the checks that
  inspect them (B6, B20) will report `UNKNOWN` with a "could not read" note.

- **`--home` points at a path you do not own.** If you pass a custom home directory,
  ensure the running user can read it.

- **Running inside a container or restricted environment.** If the audit runs in an
  environment without access to the host's `~/.openclaw`, point `--home` at a volume-
  mounted copy of the config directory.

**On Windows.** File-permission checks (POSIX mode bits) are skipped on Windows because
NTFS uses ACLs. You will not see permission-related `UNKNOWN` findings on Windows, but
you may see `UNKNOWN` for any check that depends on a file that does not exist.

---

## What does the config age / staleness nudge mean?

After the main report, you may see a notice like:

```text
This ClawSecCheck build is 63 days old (v0.19.0, released 2026-04-25).
Security tooling should be kept current -- check your ClawHub client for a newer version.
(offline notice: based only on the build date; ClawSecCheck made no network call)
```

This is an **offline** advisory. ClawSecCheck never contacts the internet to check for
updates (that would break its zero-network promise and it would have to flag itself as a
violator of that rule). Instead it compares the baked-in build date (`__released__`) to
your local clock. If the gap is 60 days or more, the nudge appears.

The notice means the *scanner itself* may be out of date, not that your OpenClaw config
has aged. An old scanner can miss new checks or have stale threat-intelligence tables
(for example the known-vulnerable-version advisory list in B33). Keeping the scanner
current is the right response.

**Two ways the notice is triggered:**

1. **Age nudge (offline, clock-based).** The build date is 60+ days behind today. This
   is the most common case and the message always ends with the `(offline notice: based
   only on the build date …)` parenthetical.

2. **Hint file.** Your ClawHub client or auto-updater may write a local file at
   `~/.clawseccheck/latest.json` containing `{"version": "X.Y.Z"}`. If that version is
   strictly newer than the installed one, the notice names the newer version.
   ClawSecCheck only *reads* this file — it never writes it and never fetches it from a
   server.

**Suppress the notice** (after you have already updated, or in CI where the notice is
noise):

```bash
clawseccheck --no-update-notice
# or set the environment variable:
CLAWSECCHECK_NO_UPDATE_NOTICE=1 clawseccheck
```

**Update** via your distribution channel:

```bash
openclaw skills update clawseccheck   # from ClawHub
# or, for the standalone CLI:
pipx upgrade clawseccheck
```

After updating, verify the engine is intact with `clawseccheck --verify-self`.

---

## How do I run on a different home directory?

By default ClawSecCheck reads `~/.openclaw/` as the OpenClaw home. Use `--home` to point
it elsewhere:

```bash
clawseccheck --home /path/to/custom/openclaw/home
```

**Common use cases:**

- **Multiple OpenClaw profiles.** If you maintain separate configs for different agents
  or environments, run the audit against each one in turn:

  ```bash
  clawseccheck --home ~/.openclaw-work
  clawseccheck --home ~/.openclaw-personal
  ```

- **Auditing a backup or exported config.** Copy the config directory somewhere and point
  `--home` at it. The audit is read-only and will not modify anything.

- **Docker / CI.** Mount the config directory into the container and pass `--home`:

  ```bash
  docker run --rm -v "$HOME/.openclaw":/audit-home:ro myimage \
      clawseccheck --home /audit-home --no-native
  ```

  `--no-native` skips the `openclaw security audit` subprocess call (which needs a live
  OpenClaw installation), useful when running in a stripped-down CI environment.

- **Non-standard install paths.** If OpenClaw was installed system-wide or in a
  non-default location, pass the path to the directory that contains `openclaw.json`.

The `.clawseccheckignore` suppress-file and the `--monitor` state snapshot default to
paths inside the home directory you specify, so they stay per-profile automatically.

---

## How do I generate an attestation report?

Static config analysis has a blind spot: `openclaw.json` lists tool *names* as opaque
strings — it cannot tell ClawSecCheck what verbs those tools actually carry (exec, egress,
delete) or which specific agent holds which tools in a multi-agent setup. The attestation
layer closes this gap via an agent self-report.

The workflow is two steps:

**Step 1 — generate the template.**

```bash
clawseccheck --ask
```

This prints a JSON template to stdout. It contains empty fields for the agent to fill:
the tool inventory classified by blast-radius verb, the per-agent roster, the delegation
graph, and optional path hints for bootstrap/identity files. Save it to a file:

```bash
clawseccheck --ask > attest.json
```

**Step 2 — ask your agent to fill it, then feed it back.**

Open `attest.json` in your editor or hand it to your OpenClaw agent with a prompt such as:

> "Fill in this attestation JSON with your actual tool inventory and agent roster. Do not
> invent or omit tools — this is used for a security audit of your own setup."

Once the JSON is filled, pass it back:

```bash
clawseccheck --attest attest.json
```

You can also pipe it directly from the agent's output:

```bash
clawseccheck --attest -       # reads attestation JSON from stdin
```

**What the attestation unlocks:**

| Check | What it assesses with attestation |
|---|---|
| B43 | Classifies each tool verb by blast-radius (EXEC, MAILBOX_CONFIG, DESTRUCTIVE, EGRESS, REVERSIBLE); fails when a high-blast verb fires without an approval gate |
| B44 | Cross-checks the self-report against config `tools.allow`; flags verbs the config grants that the agent omitted (drift / blind spot) |
| B45 | Checks whether any single agent in the roster holds all three Lethal Trifecta legs simultaneously |
| B47 | Walks the delegation graph to detect cross-agent trifecta reassembly (confused-deputy pattern) |

Attestation findings are marked `ATTESTED` confidence — a self-report is weaker evidence
than a config file, so these checks are advisory and never override a config-fact finding.
Without `--attest`, all four checks report `UNKNOWN`.

**Attestation is read-only.** The agent fills the template from its own knowledge; the
audit only reads the resulting file and runs `stat()` on any paths it mentions. Nothing is
written or changed.

---

*For more detail on any individual check, see [`docs/CHECKS.md`](CHECKS.md).*
*To report a false positive or false negative, open an issue at
<https://github.com/gl0di/clawseccheck/issues> with `clawseccheck --json` output (secrets
are redacted).*
