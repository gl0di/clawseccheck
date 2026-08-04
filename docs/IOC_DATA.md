# Bundled IOC dataset — provenance policy & refresh cadence

ClawSecCheck ships a small, dated, provenance-tagged dataset of known-compromised
identities and infrastructure — `clawseccheck/iocdb.py`. It is consumed by:

- **`vet_source` / `--vet-source`** — the pre-download reputation gate: an exact
  match FAILs a source slug/package/URL before you ever fetch it.
- **Cross-artifact log correlation** (folded into the log-threat-hunt check) — a
  skill *naming* a dataset host that also shows up in your agent's own log/transcript
  corpus is treated as high-confidence, corroborating evidence.
- **Install-directive and remote-dependency provenance checks** — a skill's
  `metadata.openclaw.install[]` directive, or a `package.json` dependency, that
  points at a dataset host FAILs regardless of transport (plaintext or HTTPS alike).

## What's in it, and what isn't

Three tables, each entry a full record — not a bare string:

- **`SOURCES`** — known-bad identities per source ecosystem (ClawHub slug, npm, PyPI, git).
- **`PUBLISHERS`** — known-bad publisher/author accounts (empty today — see below).
- **`HOSTS`** — C2, drop, and exfiltration hosts/IPs.

Every record carries `value`, `type`, `first_seen`, `source_url`, `source_name`, and
`note`. There is **no CVE table and no version-gate** here on purpose — that is a
different, already-covered surface (see the CVE advisories carried as prose in
`clawseccheck/checks/_lifecycle.py`), and a version-gate is exactly the kind of
mechanism that goes silently stale (see "Freshness" below).

## Provenance policy (Golden Rule #4 — no fabricated IOCs)

Every shipped record is independently verified against its **named, checkable primary
source** before it lands — never copied from a third-party feed without confirmation,
and never invented. An indicator whose provenance cannot be traced to a real advisory
does not ship. `tests/test_iocdb.py` mechanically enforces this: a record missing
`value`, `type`, `first_seen`, `source_url`, or `source_name` — or carrying an
unparseable or future `first_seen` — fails the test suite.

Excluded on purpose: unconfirmed candidates (an indicator the primary source itself
did not confirm), generic slugs, and shared/legitimate hosting infrastructure — all of
these are false-positive-prone and stay out rather than pad the count.

## Never fetched (Golden Rule #1 — no network)

This dataset ships **in-repo as static Python data** and is refreshed only by a
deliberate ClawSecCheck release. There is no update endpoint, no "IOC feed URL"
setting — not even opt-in. `clawseccheck/iocdb.py` has zero I/O of any kind.

## Coverage is a first-class fact too

A date is a proxy for the thing that actually matters. A dataset refreshed yesterday
that carries nothing for the ecosystem you are actually exposed to is exactly as blind
as a stale one — and until C-361 it reported the same silence, because the only input
freshness had was the calendar.

So `iocdb.coverage_notice()` names every ecosystem the dataset carries **no** indicators
for, and says plainly what a clean result there is worth: *nothing is known here*, not
*nothing bad exists*. It matters most at the gate: `vet_source`'s check is an exact match
against `known_bad_sources()`, so an empty pool simply never matches, and without this the
output could not distinguish "checked and found nothing" from "carries nothing to check
against".

Unlike the staleness advisory it reads no clock — it is a pure function of the shipped
data, so it is identical on any two days. And it goes quiet on its own once every
ecosystem is populated, so the line keeps meaning something when it does appear.

## Freshness is a first-class fact, not decoration

The dataset exposes its own snapshot date (`iocdb.REVISION`). Past a staleness
threshold (`iocdb.STALE_AFTER_DAYS`), `iocdb.freshness_notice()` returns an explicit
"IOC dataset is N days old (revision ..., staleness threshold ... days)." advisory —
the same freshness discipline `docs/USAGE.md`'s update/coverage nudges already apply
elsewhere in the tool. Today only the `--vet-source` CLI path calls it, and as a
side-channel stderr print (gated by `--no-freshness-notice`), deliberately kept out of
the `vet_source()` Finding itself — its `evidence`/`detail` never carry a
`date.today()`-derived string, since that would make vet output non-reproducible.
Cross-artifact host correlation and the install-directive/remote-dependency checks
consult the dataset's contents (`is_known_bad_host()`) but do not yet surface this
staleness advisory. A stale dataset never fails loudly and never blocks a scan; it just
stops pretending to be current.

**Both notices now reach a normal audit** (C-361). Before that they were visible only on
the `--vet-source` path, so the overwhelmingly common case — auditing your own setup —
was told nothing about how much a clean identity result was worth. They ride the same
advisory list the report already renders as never touching score, grade or findings, and
the same `--no-freshness-notice` opt-out silences both. Neither ever enters `--json`,
which is a machine contract rather than a place for presentation metadata.

## Refresh cadence

Refreshed as new, independently-verifiable advisories surface — not on a fixed
schedule. Each release that touches the dataset bumps `iocdb.REVISION` to that
release's verification date, in the same change that adds the new record(s).

**Which advisories are watched, and how one becomes a record, is a documented
process:** see [THREAT_INTAKE.md](THREAT_INTAKE.md). Adding an indicator here is
bucket 1 of that triage — and deliberately the *least* preferred outcome. An offline
list of names is always behind a live registry, so intake prefers a rule that keys on
the attack's **form** and treats this dataset as corroboration for it.
