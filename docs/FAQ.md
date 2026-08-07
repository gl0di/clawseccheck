# ClawSecCheck — Frequently Asked Questions

Answers to the most common questions about ClawSecCheck output, grades, and usage —
i.e. questions about *your audited setup*. If ClawSecCheck itself won't run, crashes,
or OpenClaw never picks it up, that's a different problem — see
[`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) instead.

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

- **Attestation-only checks.** Checks B43, B44, B45, B47 require an agent
  self-report that the static config cannot provide. Without `--attest`, they report
  `UNKNOWN`. Use `clawseccheck --ask` to generate the attestation template, fill it with
  your running agent, and then pass `--attest attest.json` to unlock these checks.

**Effect on the score.** An `UNKNOWN` finding never adds or subtracts a scored point — the
severity-weighted pass-rate arithmetic simply excludes it. It is not always fully inert, though: a
check that reports `UNKNOWN` because *its own input* was unreadable/corrupt
(`engine_degraded`) can trip `DEGRADED_CHECK_CAP` and hard-cap the grade at F regardless of
what did pass — see ["Why is my grade F?"](#why-is-my-grade-f). If most checks are
`UNKNOWN`, the score covers only the checks that *could* be assessed.

**What to do.** Confirm that `~/.openclaw/openclaw.json` exists and is readable by the
current user, that `--home` points at the right directory, and — if you want the full
picture — that you have run `--attest` with your agent's self-report.

**Blind states in the Inventory-by-subject view.** `--dashboard` groups findings by
subject rather than by individual check, so a blind subject reads as a short phrase
instead of a bare `UNKNOWN`. From `clawseccheck --dashboard --home fixtures/home_vuln`:

- `📦 Plugins — not scanned — run --full` — the plugin sweep only runs under `--full`; a
  plain audit never looks at plugins at all.
- `📝 Logs & trajectories — not assessed` — no verdict for that subject this run.
- `🧩 Skills — none installed` — **not** a blind state: the subject was checked and
  confirmed empty, shown with the same icon as a clean PASS.

---

## Why is my grade F?

The grading uses a **severity-weighted pass rate with hard caps** that prevent a single serious
failure from being diluted by many passes:

| Severity of any FAIL | Score capped at | Grade ceiling |
|---|---|---|
| CRITICAL | 49 | F |
| HIGH | 79 | C |
| MEDIUM | 89 | B |
| LOW | 94 | A- |

A single CRITICAL FAIL (for example B1 — plaintext secrets, or B2 — open gateway with
no auth) locks the score at or below 49, which is always an F, regardless of how well
everything else scores.

**Five more caps fire with no FAIL finding at all.** If you are hunting the report for a
CRITICAL that explains your F and cannot find one, it is one of these. They are caps only:
they never add or remove a scored point, they just lower the ceiling. (`report.py`'s
`_cap_signal_active` tracks six cap signals in total; the severity-FAIL cap above is the
only one of the six that needs an actual FAIL finding.)

| Signal | Score capped at | Grade ceiling | What the report says |
|---|---|---|---|
| A check **crashed, timed out, or hit an unreadable/corrupted input it needed** | 49 | F | `N check(s) could not reach a reliable verdict this run: cannot rule out a CRITICAL condition`, plus an `N checks could not reach a reliable verdict this run` banner above the score |
| `openclaw.json` is present but **unreadable / unparseable**, or **wholly absent** (no config file found at all) | 49 | F | `openclaw.json unreadable/unparseable this run: cannot rule out a CRITICAL condition` — or, when no config was found at all, `no OpenClaw config found[ at <path>]: cannot rule out a CRITICAL condition` |
| A **corroborated runtime signal** in your own trajectory log | 79 | C | `corroborated runtime signal: …` |
| A **live injection-test harness** (`--canary`/`--dryrun`/`--redteam`/`--multiturn`) reported a **VULNERABLE** verdict, submitted via `--judged-bundle`'s `liveTest` bucket | 49 | F | `a live injection-test scenario reported VULNERABLE (…)` |
| A **behavioral detector** (T1/T2/T3/B191) fired — only when `--full` ran without `--fast` | 89 | B | `a behavioral detector fired (…)` |

The first row covers two shapes: the engine itself gave up on a check (a crash or a
timeout — B-313), or a check ran fine but honestly couldn't tell you its own answer
because something it needed to read was unreadable, corrupt, or malformed (B-399) — as
opposed to a check finding nothing to look at, which never triggers this cap. "There was
nothing to check" and "something broke while we tried to check" are different facts, and
only the second one caps the grade. The second row treats a wholly absent config as
strictly LESS evidence than an unreadable one, so it is capped the same way, never scored
better.

The first three rows share the same reasoning, and it is deliberate: the audit lost
visibility into something, and the honest assumption about an unexamined check is
worst-case, not average-case. Otherwise "make the scanner blind" would be the cheapest way
to improve a grade. Fix the underlying visibility problem — a quieter machine or `--debug`
for a timeout, valid JSON (or any config file at all) for the config — and the cap lifts on
the next run. The last two rows are different: they are *positive* evidence (a self-tested
injection actually succeeded, or a proven-by-log behavioral pattern actually fired), not
lost visibility — the cap lifts only by fixing what the test/detector found.

**What to look at first:**

1. Re-read the FAIL findings in the report, most urgent first — each names exactly what
   is wrong and why (ClawSecCheck is reports-only; how to remediate is your call, with
   the OpenClaw docs).

2. Run `clawseccheck --risk-paths` — this shows the highest-risk capability chains. A
   chain only fires when every link has positive evidence, so the ones listed are the most
   actionable.

**Common reasons for an F:**

- Secrets or tokens stored in plaintext inside `openclaw.json` or a bootstrap file (**B1**).
- Gateway exposed with no authentication (**B2**).
- Installed third-party skill flagged as suspicious or dangerous by the malware scan (**B13**).
- An `ownerAllowFrom`/`autoApproveCidrs` wildcard grants owner command authority or
  device auto-pairing to ANY sender/IP (**B48**, the wildcard-authority case
  specifically — a plain break-glass override on its own is HIGH severity and caps
  the grade at C, not F).
- **No FAIL at all** — a check crashed, timed out, hit an unreadable/corrupted input it
  needed, or `openclaw.json` could not be parsed. See the cap table above; the report
  names which one it was.

After fixing the underlying issue, re-run `clawseccheck` to see the new score.

---

## How do I suppress a false positive?

ClawSecCheck uses a `.clawseccheckignore` file — placed inside the OpenClaw home
directory — to suppress specific findings so they are excluded from the score and the
report.

**Step 1 — identify the finding you want to suppress.**

For a **bare check ID** (e.g. `B14`), just read it off the report — no further work
needed, see below.

For a **fingerprint** (to suppress one specific finding rather than the whole check),
be aware that `--show-suppressed` only prints the fingerprint of a finding that is
**already** suppressed — it cannot show you the fingerprint of one you haven't
suppressed yet:

```bash
clawseccheck --show-suppressed
```

There are two real ways to get a fingerprint for a finding you haven't suppressed:

1. **`--propose-ignore`** (recommended) computes and prints ready-to-use
   `<id>:<fingerprint>` entries for you — but only for findings already offered to a
   host-agent judge panel via `--judge-packet` (unsuppressed `UNKNOWN`s, or the
   documented false-negative-prone `WARN` ids) that the panel verdicted `SAFE`, and
   only when the finding has a single evidence entry. See
   [`docs/OUTPUT_SCHEMA.md`](OUTPUT_SCHEMA.md) §14. This does not cover an ordinary
   `FAIL`/`WARN` finding outside that judged flow.
2. **Compute it yourself.** The fingerprint is `<id>:` followed by the first 8 hex
   characters of the SHA-1 hash of the finding's exact `detail` string — the same
   `detail` `clawseccheck --json` already prints for every finding. This works for
   any finding, verified end to end:

   ```bash
   clawseccheck --json | python3 -c '
   import json, hashlib, sys
   d = json.load(sys.stdin)
   for f in d["findings"]:
       if f["id"] == "B14":          # the check id you want to target
           print(f["id"] + ":" + hashlib.sha1(f["detail"].encode()).hexdigest()[:8],
                 "--", f["detail"])
   '
   ```

   This is the same algorithm `baseline.fingerprint()` uses internally — not a
   documented/frozen API, so if the finding's `detail` text changes in a later
   release the fingerprint changes with it (same caveat `--show-suppressed`'s "dead
   entry" note already gives for any fingerprint entry).

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

`--show-suppressed` reports two things, and the difference matters: the entries that are
currently suppressing a finding, and — separately — any entry that **matches nothing in
this run**. A dead entry means either the finding is gone (you fixed it, and the line can
be deleted) or the finding's detail text changed, so its fingerprint no longer matches and
the suppression has quietly stopped working. Bare check ids (`B14`) never drift this way;
fingerprints (`B14:ab12cd34`) can.

> **Note on false positives.** If you believe a finding is wrong about your config,
> please also open an issue at <https://github.com/gl0di/clawseccheck/issues> with the
> output of `clawseccheck --json` (it redacts secret *values* — only key names and paths
> appear) and your OpenClaw version. That helps improve the grounding for everyone.
>
> **Automating this with a host-agent judge.** If your host agent (the AI assistant
> running ClawSecCheck) can review the borderline findings itself, `--propose-ignore`
> can propose exactly these `.clawseccheckignore` entries for it — see SKILL.md's
> "Judge-panel fan-out" section and `docs/OUTPUT_SCHEMA.md` §14. It still writes
> nothing on its own: applying a proposal is a separate, confirmation-gated step
> (`--apply-ignore-proposals`), and a score-capping finding is never hidden by it.

---

## I get permission errors — what do I do?

ClawSecCheck never changes your OpenClaw config, and by default only writes its own
score history under `~/.clawseccheck/` — a few flags write other local files when you
ask (`--save`, `--badge`, `--html`, `--sarif`, `--pdf`, `--monitor`), and the one
exception that touches the audited home itself is `--apply-ignore-proposals`, opt-in
and confirmation-gated (see above). Permission errors mean the *audit* cannot read a
file it needs to inspect.

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
This ClawSecCheck build is 63 days old (vX.Y.Z, released YYYY-MM-DD).
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
  `--home` at it. The audit will not modify the config directory you point it at (it
  keeps its own score history under `~/.clawseccheck/`).

- **Docker / CI.** Mount the config directory into the container and pass `--home`:

  ```bash
  docker run --rm -v "$HOME/.openclaw":/audit-home:ro myimage \
      clawseccheck --home /audit-home --no-native
  ```

  `--no-native` skips the `openclaw security audit` subprocess call (which needs a live
  OpenClaw installation), useful when running in a stripped-down CI environment.

- **Non-standard install paths.** If OpenClaw was installed system-wide or in a
  non-default location, pass the path to the directory that contains `openclaw.json`.

The `.clawseccheckignore` suppress-file defaults to a path inside the home directory
you specify, so it stays per-profile automatically. The `--monitor` state snapshot does
**not** — its default (`~/.clawseccheck/state.json`) is a single fixed path independent
of `--home`, so auditing two different `--home` profiles with `--monitor` and no other
change writes both to the same shared snapshot. Pass `--state PATH` explicitly per
profile if you run `--monitor` against more than one home.

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
| B43 | Classifies each tool verb by blast-radius (EXEC, MAILBOX_CONFIG, DESTRUCTIVE, EGRESS, REVERSIBLE); warns when a high-blast verb fires without an approval gate (never FAILs — the verdict is the agent's own self-report) |
| B44 | Cross-checks the self-report against config `tools.allow`; flags verbs the config grants that the agent omitted (drift / blind spot) |
| B45 | Checks whether any single agent in the roster holds all three Lethal Trifecta legs simultaneously |
| B47 | Walks the delegation graph to detect cross-agent trifecta reassembly (confused-deputy pattern) |

Attestation findings are marked `ATTESTED` confidence — a self-report is weaker evidence
than a config file, so these checks are advisory and never override a config-fact finding.
Without `--attest`, all four checks report `UNKNOWN`.

**The attestation step writes nothing** — it only reads the file you name and `stat()`s
the paths inside it.

---

## What if the host is already compromised?

Fair question, and worth answering honestly rather than papering over: if malware is
already running on the machine, at your own privilege level, could it just tamper with
ClawSecCheck's own files so the audit doesn't detect it? Yes, in principle it could.

`clawseccheck --verify-self` prints a SHA-256 digest of the engine's own source for
tamper detection, but the tool's own `integrity.py` says plainly that this is
**advisory**: "self-integrity computed from inside the artifact is advisory — a modified
`integrity.py` can print anything." A self-check that runs *on* the host it is checking
can be rewritten by whatever already owns that host. `--verify-self` catches
opportunistic or lazy tampering — a dropped-in backdoor that didn't bother patching the
verifier too — but it is **not** a guarantee against a targeted adversary who patches the
verifier alongside everything else.

**The real answer is a protocol, not a flag: scan from a clean host.**

Since the malware never executes in a separate, trusted machine's process, it cannot
alter what that machine sees or reports. Copy or read-only-mount the suspect
`~/.openclaw` directory onto a different machine you trust, then point ClawSecCheck at
it with the existing `--home` flag:

```bash
# on the clean machine, with the suspect config mounted or copied read-only:
clawseccheck --home /mnt/suspect-openclaw
```

Because the audit process itself is running on hardware the malware never touched, there
is nothing on that host for it to tamper with. This is the primary recommendation
whenever you have real reason to suspect the host, not just a routine run.

**Secondary mitigations**, in rough order of usefulness:

- **Use a fresh install of ClawSecCheck itself for the clean-host scan.** Don't reuse a
  copy of the tool that could have been sitting on the compromised host — install it
  fresh on the clean machine (`pipx install git+https://github.com/gl0di/clawseccheck` or
  a fresh `openclaw skills install @gl0di/clawseccheck`) so the scanner's own binary is one the
  malware never had a chance to touch either.
- **Verify the engine digest out-of-band.** Compare `clawseccheck --verify-self`'s output
  against `SHA256SUMS.txt` published on the corresponding GitHub Release, signed with
  [cosign](https://github.com/sigstore/cosign) in keyless mode — see the
  ["trust no one" section](USAGE.md#important--trust-no-one-including-this-skill)
  in the User guide for the exact `cosign verify-blob` command. This gives `--verify-self` a
  trusted anchor to compare against, instead of just self-reporting.
- **Reproducibility as a tripwire.** ClawSecCheck is deterministic and stdlib-only: given
  the same config, a second clean install run should produce identical findings. If two
  independent clean scans of the same exported data disagree, that divergence is itself a
  red flag worth investigating.
- **Pre-existing host monitoring is the only on-host layer that could have caught the
  tampering as it happened.** File-integrity monitoring and audit/syscall logging (this
  project's own **B51**/**B52** checks detect the *presence* of such tooling, e.g. auditd,
  AIDE, Tripwire) can only help if they were already running *before* the compromise —
  they cannot retroactively witness something they weren't watching for.

**The underlying principle isn't unique to ClawSecCheck.** Any self-check that runs on an
already-compromised host, at the user's own privilege level, is checking itself from
inside the blast radius — treat an already-compromised host as fundamentally untrusted
for self-checking purposes, and verify it from the outside instead.

---

## Why is there no `--llm` mode?

Some peer scanners offer an opt-in flag that sends skill content to an LLM vendor
(OpenAI/Anthropic/Bedrock/Gemini/Ollama) for a deeper read than static rules can give.
ClawSecCheck deliberately doesn't — not because the idea is bad, but because of what this
tool is *for*: it audits `~/.openclaw/` for agents that might leak the user's own data to
a third party, and Golden Rule #1 (`CLAUDE.md` §2) is zero network, zero telemetry. A
scanner that shipped the contents of that same directory to a model vendor to do the
auditing would be the exact thing it exists to catch.

Instead, the engine (stdlib-only, zero network) emits an already-redacted
`--judge-packet`/`--vet-judge-packet` artifact, and **your own host agent** — whatever
model and policy you already trust and already run locally — reads it and judges. No API
key, no per-scan network call, no raw skill content leaves your machine through this
engine, under any flag. The trade-off is real and stated honestly, not hidden: a
standalone static-only comparison currently favors a peer that DOES put an LLM inside the
tool (1.78x more recall at matched precision), and this topology only works with a host
agent attached — it cannot run standalone in a script with nothing else present. See
[`docs/design/judge-topology.md`](design/judge-topology.md) for the full comparison,
including the exact numbers and where they came from.

---

*For more detail on any individual check, see [`docs/CHECKS.md`](CHECKS.md).*
*To report a false positive or false negative, open an issue at
<https://github.com/gl0di/clawseccheck/issues> with `clawseccheck --json` output (secrets
are redacted).*
