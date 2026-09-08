# Check Authoring — the root-cause `detail` convention

> **Status: mostly convention.** This is guidance for *new and edited* checks. The `detail`
> and `fix` conventions deliberately do **not** trigger a build failure and do **not** call
> for a one-pass rewrite of the ~600 existing `_finding()` call-sites — apply them as you
> touch a check. Two later sections are different and say so in place: the evidence-prefix
> separator rule is enforced by a test, and the surface-reach and negative-result rules are
> conventions today with a guard planned. Where a rule is enforced, this document says so
> at the rule; assume the rest is guidance.

Inspired by cloudflare/security-audit-skill's `report-schema.json` `root_cause` field
(a forced one-sentence causal template). ClawSecCheck adopts the *spirit* — a Finding
should say what is wrong **and why it matters** — without the schema rigidity.

## Where a new check lives (before you write the `detail`)

The check engine is organized **by topic**, not one flat file. Put a new check next to
its topic peers, and keep the two registries the single source of truth:

- **Pick the topic.** Config-hardening, content-security ring (skill-malware / prompt
  injection), MCP / plugin, capability / manifest, lifecycle, host, egress / data-at-rest,
  multi-agent — add the check function alongside the checks that read the same part of the
  config or skill.
- **Register it once.** Append the function to the `CHECKS` list (the ordered registry the
  audit iterates). A content-security check goes into the `SKILL_CONTENT_RING` tuple
  instead — that tuple is the single source of truth consumed by **both** the full audit
  **and** `--vet`, so the two paths can never drift.
- **Add its metadata.** One `CheckMeta` entry in `catalog.py` (id, title, severity,
  framework, surface). The audit asserts every check has a catalog entry.
- **Reuse, don't re-implement.** Shared parsing/regex helpers (fence detection,
  frontmatter parsing, channel/tool enumeration, secret patterns) already exist and are
  reused across checks — call the existing helper rather than adding a near-duplicate.
- **Prove it both ways.** Every new/changed check needs a **clean** fixture (no finding)
  and a **bad** fixture (the finding fires), plus a test asserting both, and explicit
  coverage of the `UNKNOWN` path. A new FAIL-capable check also needs an adversarial
  "try to make it fire wrongly" pass against real configs (zero false-positive FAILs).
- **Regenerate the catalog doc.** `docs/CHECKS.md` is generated from `catalog.py` — run
  `python3 scripts/gen_checks_docs.py --write` after adding a check.

Keep the public import surface stable: whatever tests or other modules import from the
check engine must stay importable — the engine re-exports its names from one aggregation
point, so a new module never breaks `from clawseccheck.checks import …`.

## The template (FAIL / WARN details)

A FAIL or WARN `detail` should name the **missing control** and the **consequence**:

> **`<component/field>` `<is/does>` `<observed state>`, allowing `<attacker consequence>`.**

The "allowing …" clause is the load-bearing part: it turns a bare observation
("`exec` is enabled") into a security statement ("`exec` is enabled with no approval
gate, allowing a prompt-injected instruction to run arbitrary shell commands").

Accepted causal connectors (any one is enough): *allowing*, *so that*, *lets an
attacker*, *enabling*, *exposes*, *means*, *→*. Prefer plain, concrete consequences over
abstract risk-words.

### Good (already in the codebase)

- *"Agent can rewrite its own identity/skills WITHOUT approval: `fs_write`/`exec` are
  enabled AND the following targets are writable …"* — names the control gap and the
  self-modification consequence.
- *"Bootstrap contains approval-bypass directive(s) … the directive remains a risk if
  destructive tools are added later."* — states the latent consequence explicitly.

### Weaker (observation without the "allowing" link)

- *"Destructive tools (exec/send/write) present with no clear approval gate."* — states
  the fact; a reader must infer the consequence. Stronger: *"… no approval gate, **so a
  prompt-injected message can invoke them without a human in the loop.**"*
- *"Agent has persistent memory; confirm it is not written from untrusted input."* — an
  instruction, not a consequence. Stronger: *"… persistent memory **that, if written from
  untrusted input, lets an attacker plant instructions that persist across sessions.**"*

## PASS details are exempt

A PASS finding describes a **safe** state; there is no attacker consequence to name, so
the "allowing …" clause does not apply. Keep PASS details short and factual:

- *"Execution is sandboxed."*
- *"Transport is loopback/TLS and config perms are tight."*
- *"No exposed plaintext secrets."*

Do **not** bolt a hypothetical consequence onto a PASS detail — it reads as a finding
when there isn't one.

## UNKNOWN details name *why state is undetermined*

When a check can't decide (Golden Rule #4 — report `UNKNOWN`, never a fake PASS/FAIL),
the `detail` should say what could not be determined and from where, e.g.
*"OpenClaw exposes no audit-log config field … — cannot assess from config."* No
consequence clause; the point is the honest gap.

### `engine_degraded` — say so when the gap is the ENGINE'S fault (B-399)

Not every UNKNOWN is the same kind of gap, and the scoring engine treats two shapes
differently:

- **Genuinely absent** — there is simply nothing to check (no `openclaw.json` at all, a
  feature/file that legitimately does not exist for this subject). This is the common
  case; leave `Finding.engine_degraded` at its default `False`. It must never lower an
  otherwise-clean grade — "nothing was there to examine" is not evidence of a problem.
- **Engine-side** — the check tried to determine state and failed for a reason that has
  nothing to do with the feature being absent: an input it expected to read turned out
  unreadable, corrupt, or malformed (a present-but-unparseable file, a permission error,
  a truncated read), or it hit a scan-budget/timeout escape internal to its own logic.
  Pass `engine_degraded=True` to `_finding()` (or set it directly on the `Finding`) for
  this branch. `scoring.DEGRADED_CHECK_CAP` then hard-caps the grade — the same
  worst-case "cannot rule out a CRITICAL" reasoning already applied to a check the run_all
  wrapper had to crash/timeout out of.

If the check reads `ctx.config` and the gap is `ctx.config_parse_error` (openclaw.json
present but unparseable), don't hand-roll this — call `_config_unreadable(cid, ctx)`
(checks/_shared.py), which already returns a correctly-tagged `engine_degraded=True`
Finding for exactly that case. Reserve a hand-set `engine_degraded=True` for a check's
OWN non-config engine-side failure (e.g. an `except OSError`/`except ValueError` on a
file it positively found but could not read/parse) — never set it on a plain "this
subject doesn't have that feature configured" UNKNOWN.

## `fix` is separate

`detail` explains the problem (and, for FAIL/WARN, the consequence). `fix` is the
short, paste-adjacent remediation hint. Don't fold the remediation into `detail` — the
renderers show them in distinct slots, and `--json` exposes them as separate fields
(see [`OUTPUT_SCHEMA.md`](OUTPUT_SCHEMA.md) §2).

## A new signal has to land somewhere, and the surfaces are not interchangeable

A finding is not the only thing a check produces. Confidence, a coverage note, a
resolved-default disclosure, a destination host, a sub-signal, a layer status — each is an
*information-bearing channel*, and each is wired by hand into whichever renderer its author
happened to be working in. That is how the same defect got filed six separate times: a
channel computed once and rendered by one surface out of ten, invisible until someone read
the other nine side by side.

So before a channel counts as shipped, decide where it lands:

- **The machine-complete surfaces carry everything.** `--json` and `--sarif` exist so a
  consumer never has to re-derive what the engine already knew. A field that reaches neither
  is not available to any automation.
- **The human surfaces carry anything that changes what a reader should DO.** The text
  report, the vet dossier and `--advise`. If a reader would act differently knowing it, it
  belongs there — the fact that it fits in `--json` is not a substitute, because nobody
  reading a dossier is also parsing JSON.
- **The rest are explicitly exempt, and say why.** `--brief` runs no audit at all; `--card`
  is a few lines; `--vet-plan` never scans. Exempt is a decision, not an oversight, and it
  belongs in a comment.

**A surface that cannot carry a channel must say so. It must never assert the opposite.**
This is the presentation half of the rule the UNKNOWN section states for verdicts: report
what you do not know, do not manufacture a clean answer. Two live examples of breaking it —
`--advise` printing *"Nothing dangerous found — this looks safe to install"* for a run whose
dossier says a region was never scanned (B-621); and a report announcing *"33 checks could
not reach a reliable verdict — review the affected finding(s) below"* while marking none of
them (B-624). Both sentences are true about what was assessed and false about what a reader
takes from them.

**A channel nobody reads is finished business, not a loose end.** Render it, delete it, or
write in-source that it is internal and why. Left computed and silently dropped, it reads to
the next author as something that displays somewhere.

One instance of this is already enforced rather than advisory: an evidence line that opens
with a scanned subject's name must use a separator the bundled-skill attribution understands,
or the build fails. The list of separators was extended by hand three times, each time after
a defect; it now answers to the producers instead.

## Before you write "not found"

Every rule above is about not overstating what you found. This one is about the opposite and
is the easier mistake, because a clean result looks like success.

**Show that the check could have found something, and put that demonstration where the
result is read.**

That is the whole requirement, and it is deliberately not written as a list of known traps.
Seven false negatives were produced here in a single day and they came in at least three
different shapes — a probe that never reached the branch, a command whose "nothing" was an
artifact of how it was asked, and a result that was about a different tree than the one being
read. Anyone who memorises those three will be caught by the fourth, exactly as the hand-kept
separator list was caught by each new convention. The demand is on the *negative result*, not
on a catalogue of ways to get one wrong.

In practice that means:

- Every "no finding" assertion carries a non-vacuity assertion beside it, proving the run
  reached its subject at all.
- A guard is shown to fail: mutate a copy so it *should* fire, and confirm it does.
- A corpus result states how many of its targets entered the non-trivial path. A clean sweep
  over a corpus that cannot reach the code proves nothing, and reporting the zero bare
  implies otherwise.
- A run names the object it ran against. If a file could have changed underneath — an edit
  mid-run, a module cached at import — "green" has no subject.

## Citing the OpenClaw dist: name the symbol, not the file

Grounding a check means being able to point at what the runtime actually does. A citation that
nobody can resolve provides the appearance of that without the substance.

**Cite the SYMBOL. Treat `file:line` as a convenience, and stamp the version you read it on.**

The reason is mechanical, not stylistic: OpenClaw's bundle filenames are content-hashed, so a
release renames essentially all of them whether or not anything moved. Measured across the
2026.7.1-2 → 2026.8.2 transition, of 206 distinct bundle names cited in this repo **194 no longer
existed** — 94% — in a window where most of the behaviour they described had not changed at all.
Over the same window, of 55 cited vendor symbols **47 still resolved**.

So a `file:line` citation is written once and decays on the next release regardless of whether it
was ever correct, while a symbol name stays greppable on any version.

The damage is not untidiness. A dead citation collapses two very different situations into one
appearance:

- the bundle was renamed and the claim still holds, and
- the behaviour was removed and the claim is now false.

A reader cannot tell those apart without redoing the grounding, which is the work the citation
existed to save. The eight symbols that genuinely vanished in that transition are exactly the
cases a stale filename would have hidden behind "the file must have moved".

In practice:

- Name the function, constant or type: ``resolveEffectiveToolFsWorkspaceOnly``, not
  `tool-fs-policy-CyOPYI8M.js:14`. Add the filename after it if it helps a reader navigate.
- Stamp the version: *"Grounded on openclaw@2026.8.2 (2026-09-02)"*. That single clause converts
  the citation into a claim that stays true as history instead of one that quietly rots. A dated
  citation is never wrong — it says what was read, and when.
- For a config field, cite the **path** (`gateway.controlUi.embedSandbox`) and check it against
  the schema path list rather than a bundle line. Paths survive releases; line numbers do not.
- When you find a cited symbol gone, that is a finding, not a chore. Re-establish what the runtime
  does now before touching the check — a check written against a vanished predicate is the
  phantom-path class Golden Rule #4 exists to stop.
- Matching a leaf name against a new path list yields a **candidate**, never a proven rename. A
  same-named leaf under a different parent is a different setting.

`scripts/dist_citation_gate.py` enforces the floor: it fails on a NEW unqualified citation of a
bundle the installed dist does not have. It cannot see a citation whose file still exists but
whose line moved, so it is a backstop for the convention, not a substitute for it.
`tests/test_dist_citation_gate.py` runs it inside the suite (local-only — it skips cleanly when
no OpenClaw dist is installed, e.g. in CI).

## Notes

- Output is **English-only** (`i18n.py`/`--lang` were removed) — this convention
  is a single-language guideline; there is no `he` string to keep in parallel.
- Route anything derived from user config through `logsafe.redact()` before it lands in a
  `detail`/`evidence` string (Golden Rule #3 / §8 — no secret values in reports).
