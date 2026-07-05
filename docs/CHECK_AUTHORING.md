# Check Authoring — the root-cause `detail` convention

> **Status: convention, not enforced.** This is guidance for *new and edited* checks. It
> deliberately does **not** trigger a build failure and does **not** call for a one-pass
> rewrite of the ~239 existing `_finding()` call-sites. Apply it as you touch a check.

Inspired by cloudflare/security-audit-skill's `report-schema.json` `root_cause` field
(a forced one-sentence causal template). ClawSecCheck adopts the *spirit* — a Finding
should say what is wrong **and why it matters** — without the schema rigidity.

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

## `fix` is separate

`detail` explains the problem (and, for FAIL/WARN, the consequence). `fix` is the
short, paste-adjacent remediation hint. Don't fold the remediation into `detail` — the
renderers show them in distinct slots, and `--json` exposes them as separate fields
(see [`OUTPUT_SCHEMA.md`](OUTPUT_SCHEMA.md) §2).

## Notes

- Output is **English-only** since v2.0.0 (`i18n.py`/`--lang` removed) — this convention
  is a single-language guideline; there is no `he` string to keep in parallel.
- Route anything derived from user config through `logsafe.redact()` before it lands in a
  `detail`/`evidence` string (Golden Rule #3 / §8 — no secret values in reports).
