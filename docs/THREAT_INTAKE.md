# Threat intake — how a new threat becomes a check

The maintainer-side protocol for the step that happens **before** any of the other docs
apply: something new appeared in the world, and it has to end up somewhere in this repo —
or be recorded as deliberately not covered.

[CHECK_AUTHORING.md](CHECK_AUTHORING.md) tells you how to write a check once you know you
need one. [RELEASING.md](RELEASING.md) tells you how to ship it. This document is the
missing first step: **which signals we watch, how they are classified, and exactly what
each class changes.**

It is process only. Nothing here changes a check, a verdict, or a finding id.

## The constraint that shapes everything

Golden Rule #1 — the engine never opens a socket — is not a limitation to work around
here. It is the thing that determines the entire shape of intake, in two ways.

**Intake is a maintainer-side, release-time activity.** There is no feed, no update
endpoint, no reputation API, not even opt-in. A signal reaches users only when a release
ships. So intake latency *is* release latency, and no amount of process changes that.

**Therefore detection cannot depend on knowing names.** The bundled indicator dataset
(`clawseccheck/iocdb.py`, see [IOC_DATA.md](IOC_DATA.md)) is deliberately small, and its
exclusion policy keeps it that way. It is a **corroborating** layer — it raises confidence
in a verdict some other signal already reached, and it turns a pre-download `--vet-source`
gate into an exact match. It is not, and cannot be, the thing that finds new attacks. An
offline list of names will always be behind a live registry.

What *can* be ahead of a registry is a rule that keys on **form**: a lifecycle hook whose
target is obfuscated, a decode chained into an exec sink, a poll-decode-execute triad, a
capability the manifest never declared. Those fire on a variant nobody has published yet.
`clawseccheck/skillast.py` and `clawseccheck/textnorm.py` exist for exactly this reason.

So the bias in triage is explicit: **prefer a form rule over an indicator, every time.**
An indicator is what you add when the form rule is not yet possible, or as corroboration
for one that is.

## The channel that is not release-bound: the user's own agent

The engine never opens a socket. **The agent running it does** — [SKILL.md](../SKILL.md)
states the boundary in those terms: the tool reaches the network only through your own host
agent. This is not a loophole in Golden Rule #1, it is the topology the project chose
deliberately, and it is already shipped three times over: `--vet` / `--vet-source` guide the
host agent to fetch a package; `--judge-packet` / `--vet-judge-packet` hand the borderline
band to the host agent to adjudicate; `--ask` / `--attest` let the agent report what static
analysis structurally cannot see. [design/judge-topology.md](design/judge-topology.md) is
the decision record.

For intake this matters for one reason: **the host agent's knowledge is newer than our last
release.** It is the only part of the picture that is not release-bound.

| Use of the agent | When | Sound? |
| --- | --- | --- |
| The maintainer's agent runs the watchlist sweep | build time | Yes, unreservedly — this is not the engine at all |
| The host agent enriches a finding the engine already surfaced | run time | Yes, but under its **own** narrower authority — see [design/agent-knowledge-enrichment.md](design/agent-knowledge-enrichment.md) |
| The host agent reports a miss back to us | after a run | Yes — it is a watchlist source in its own right |
| The host agent supplies indicators the engine then trusts | run time | **No** |

**Why the maintainer's agent is the easy win.** Reading advisories is already what a
maintainer does; an agent just does it on a cadence a human does not keep. Nothing about it
touches the shipped tool — it produces triage input, which then goes through the same five
buckets as any other signal. If any part of this document ever becomes automated, this is
the part.

**Why the last row is a hard no**, for two independent reasons, either of which is
sufficient. Provenance: every shipped record is verified against a named, checkable primary
source before it lands, and an agent-supplied indicator has no such chain — the agent may
have read it off a page an attacker controls. Determinism: a score that depends on what a
model happened to know that afternoon is not reproducible, and therefore not auditable.

**The template for any agent-supplied fact already exists.** `clawseccheck/update.py` reads
a local hint file that "the user's ClawHub client / auto-updater / their agent" may drop,
and treats it as **untrusted**: it accepts one narrowly-typed value and reconstructs it from
parsed integers, so a hostile hint can at most misstate a number — never inject text, a URL,
or an action. Any future agent-to-engine channel copies that shape or it does not ship.

The same discipline governs the judge band, scoped by content **provenance** rather than one
global rule: a judge reviewing the user's own config may only *suppress* noise, and a judge
reviewing an untrusted `--vet` target may only *escalate*. A successful injection against
either path can only move the verdict in the direction that costs the attacker nothing.

**The honest limit.** The agent reasons over what the engine surfaced; it does not scan. It
cannot find what the engine never looked at, so this channel sharpens and enriches — it does
not substitute for a form rule. **A blind spot stays blind until bucket 2 or bucket 3
handles it**, no matter how capable the agent is.

## Watchlist — where signals come from

These are the source classes that have actually produced records or grounded prose in
this repo, not an aspirational list. Each row names what that class typically yields, in
the vocabulary of the triage buckets below.

| Source class | Examples that have landed here | Typically yields |
| --- | --- | --- |
| Vendor threat research on agent/skill supply chain | ESET, Palo Alto Unit 42, Koi Security, Proofpoint | indicators **and** attack forms |
| National / sector advisories | NSA, CISA, published CVE records | attack forms, occasionally a version-gated fact |
| Package-ecosystem advisories (npm, PyPI) | ecosystem advisory databases, registry takedowns | attack forms; indicators when a name is confirmed |
| OpenClaw's own releases and advisories | new config surface, changed defaults, fixed bugs | schema drift; sometimes a brand-new check surface |
| The ClawHub registry | trust dispositions, removed listings | indicators |
| Peer scanners and public benchmarks | competitive review, corpus evaluation | blind spots and false negatives |
| Our own runs, and reports from a user's host agent | real-fleet audits, GitHub issues, an agent that judged a finding worse than the engine did | false positives, false negatives, blind spots |
| Threat-model frameworks | OWASP LLM Top 10, OWASP Agentic, MITRE ATLAS | coverage gaps, never a specific indicator |

Two of these deserve a note. **Framework updates never yield an indicator** — they yield a
category, which then needs a real-world form before it can become a check; adding a check
because a framework named a category, with no observed instance, is how a scanner ends up
with impressive coverage claims and no efficacy. And **peer scanners are a source, not a
scoreboard** — the useful output of reading one is "here is a surface we do not look at",
not a metric to chase. A corpus number is not a reason to ship a rule.

## Cadence — what is promised

Promising a polling schedule that nobody keeps is worse than promising nothing, so this
section is deliberately short on promises and specific about triggers.

**Per release.** The indicator dataset's own age is re-checked, and `iocdb.REVISION` is
bumped to the verification date in the same change that adds any record. This is already
part of [RELEASING.md](RELEASING.md)'s documentation-alignment step.

**Per named incident.** When a specific, verifiable event surfaces — a campaign, an
advisory, a registry takedown, an OpenClaw release — it is triaged into the buckets below
and recorded, *even when the outcome is "we are not going to do anything about this."* The
recording is the point. An untriaged incident and a triaged one that produced no code look
identical in the repo unless the second one is written down.

**No fixed sweep schedule is claimed.** If one is ever adopted it belongs here, in this
section, with a date — not as an implication elsewhere. The likeliest way that changes is a
maintainer-side agent sweep over the watchlist above, which is build-time work and touches
nothing in the shipped tool; until such a sweep is actually running, this section keeps
saying no rather than describing an intention.

## Triage — five buckets

Every signal lands in exactly one of these. The bucket determines what changes and which
gate must pass; picking the wrong bucket is the common failure, so the distinguishing
question is stated first for each.

| Bucket | The question | What changes |
| --- | --- | --- |
| 1. New indicator | Do we now know a specific bad *name*? | the indicator dataset |
| 2. New attack form | Can we describe the *shape* without the names? | a new check |
| 3. New blind spot | Is this somewhere we simply do not look? | a coverage note, no verdict |
| 4. Schema drift | Did the thing we read change underneath us? | grounded field paths |
| 5. Known, not scheduled | Real, understood, and not being built yet | a recorded idea |

### 1. New indicator

A named host, package, source slug, or publisher account, confirmed by a checkable primary
source.

- **Changes:** a record in `clawseccheck/iocdb.py`, `iocdb.REVISION` bumped to the
  verification date, and [IOC_DATA.md](IOC_DATA.md) if the policy or table shape moved.
- **Gate:** `tests/test_iocdb.py` — provenance is mechanically enforced; a record missing
  `value`, `type`, `first_seen`, `source_url` or `source_name`, or carrying an unparseable
  or future date, fails the suite.
- **Do not** add an indicator the primary source itself did not confirm, a generic slug, or
  shared hosting infrastructure. The exclusion policy in [IOC_DATA.md](IOC_DATA.md) is
  binding: a small verified dataset beats a padded one.

### 2. New attack form

The shape can be described without any of the names — which is what makes it survive the
next variant.

- **Changes:** the full new-check path. [CHECK_AUTHORING.md](CHECK_AUTHORING.md) owns the
  detail; in outline it is the check function in its topic module, one registry append,
  one `CheckMeta` in `clawseccheck/catalog.py`, a clean fixture, a bad fixture, tests
  including the `UNKNOWN` path, a regenerated `docs/CHECKS.md`, and a ledger tag in
  [THREAT_COVERAGE.md](THREAT_COVERAGE.md).
- **Gate, for anything FAIL-capable:** the adversarial "try to make this fire wrongly" pass
  against real configs, run by someone other than the implementer, plus the real-fleet
  regression gate (`scripts/fleet_fp_gate.py compare`). A new FAIL id or target is a hard
  blocker regardless of how good the corpus number looks.
- **Reuse the obfuscation and taint machinery** rather than writing a second one. If a form
  rule needs "does this look deliberately unreadable", that already exists.

### 3. New blind spot

We are not wrong about this surface — we never looked at it. This bucket exists because the
alternative is silence, and silence reads to a user as a clean result.

- **Changes:** a coverage note on every path that reports about the affected surface, and a
  declared non-coverage tag in [THREAT_COVERAGE.md](THREAT_COVERAGE.md). The `--full`
  coverage page is the user-facing counterpart.
- **Gate:** **no verdict, grade, or finding id may change.** This bucket adds honesty, not
  signal. If a change in this bucket moves a score, it was really bucket 2.
- This is the project's own "`UNKNOWN` is never a silent `PASS`" rule applied one level up,
  to whole surfaces rather than individual findings.

### 4. Schema drift

OpenClaw changed: a field moved, a default flipped, a subtree appeared. Nothing about the
threat landscape changed, but our grounding did.

- **Changes:** the vetted field-path manifest (`tests/grounded_schema_paths.txt`) and any
  affected navigation path in the checks; sometimes a check's verdict logic, when a default
  changed meaning.
- **Gate:** `tests/test_schema_grounding.py`. A field path that is not in the manifest fails
  the build, which is what stops an invented path from ever shipping.
- Diff against the previously installed version, not against a summary of it. A recon
  document describes the schema; only the distribution *is* the schema.

### 5. Known, not scheduled

Real, understood, and deliberately not being built right now — usually because it is a
larger design question than it first appears.

- **Changes:** nothing in the tree. It is recorded as an idea in its own right.
- **Gate:** none, but one rule holds: **it does not get buried inside another item's
  description.** A constraint noted in passing inside a shipped feature's rationale is lost
  the moment that feature ships.

## When is a signal "handled"

[THREAT_COVERAGE.md](THREAT_COVERAGE.md)'s closure invariant already answers this, and
intake inherits it verbatim: **"closed" does not mean "zero misses" — it means zero
*silent* gaps.** A threat category is handled when it carries exactly one machine-checked
tag: a real check id, an attestation-only tag, a judge-band tag, or a declared ceiling.

`tests/test_threat_coverage_ledger.py` enforces that mechanically. What it cannot enforce
is whether the chosen tag is the *right* one — that is a human call, made during triage.
This means the only real failure mode of this whole process is an incident that produced no
tag at all: not a wrong bucket, not a deferred build, but an event nobody wrote down.

## Worked example — the npm dependency tree, 2026-08-04

A supply-chain campaign resurfaced against a package ecosystem: several widely-depended
packages were republished within a single morning, each shipping an install-time lifecycle
hook whose target was an obfuscated file, with the package manifest's file list rewritten so
the payload travelled in the published archive. No affected agent skill or plugin contained
that hook in its own source — it arrived transitively.

Package names are deliberately omitted here. A shipped document is the wrong place for live
indicators: they belong in the dataset where provenance is enforced and freshness is
tracked, and prose naming them ages badly and invites host scanners to flag our own text.

Triage produced three different outcomes, which is the point of the example:

- **Bucket 3 — blind spot.** Installed dependency trees are skipped by every scanner in
  this repo, by design. One path already admitted this in a coverage note; the others said
  nothing, so a reader reasonably concluded the tree had been examined. Fix: emit the note
  everywhere, change no verdict.
- **Bucket 2 — attack form.** "Lifecycle hook **and** the hook's target trips the
  obfuscation detector." Measured before proposing: on the clean machine, install-lifecycle
  hooks were present but every target was a plain readable script — so the naive rule
  ("any lifecycle hook") would have produced false-positive FAILs on a clean box, and the
  conjunction produced none. That measurement is what made this a form rule rather than a
  guess.
- **Bucket 5 — known, not scheduled.** Nothing in this repo parses a package lockfile, so
  the installed tree is never reconciled against what was pinned. That is the artifact that
  would have made the republication visible locally, offline. It was recorded separately
  rather than left as a paragraph inside the other two, because it is a larger design
  question — three lockfile formats, one of them YAML, in a project with no runtime
  dependencies.

The triage also surfaced something about the dataset itself. As of that date,
`clawseccheck/iocdb.py`'s ecosystem vocabulary already carried an `npm` slot with no records
behind it: the dataset's *shape* had anticipated the ecosystem, its *contents* had not. That
is bucket 1 territory, and it is exactly the kind of thing that stays invisible without a
triage step that looks at the dataset rather than only at the incident.

## What this is not

- **Not a feed.** No part of this becomes a runtime fetch, an update endpoint, or a
  reputation lookup. That boundary is permanent, not a phase.
- **Not a promise of speed — for the engine.** The *engine's* intake latency is release
  latency, and its protection against something published today comes from form rules
  already shipped. A *session's* protection is not bounded the same way: the host agent
  brings knowledge newer than our last release, within the authority limits above. Do not
  collapse those two into one claim in either direction.
- **Not a substitute for the user-side signal.** The strongest early warning in the tool
  does not require knowing what is bad at all: monitoring mode reports what appeared since
  the last run. A brand-new skill, MCP server, or channel is worth a look regardless of
  whether any advisory has named it yet.
