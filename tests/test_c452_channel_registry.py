"""A new information-bearing channel must be given a destination before it ships.

C-452, structural half. The behavioural half — actually lighting each channel and running
every surface — is expensive (the survey it comes from took ~28 minutes across 16 surfaces)
and belongs in a release-time command, not in every commit. This half is static, runs in
milliseconds, and answers the one question that does not need a run:

    has anyone decided where this channel is supposed to appear?

That is the question nobody was asked for six separate defects. `pass_confidence`,
`axis_reasons`, `corroborating_buckets`, `sub_signals`, `destination_hosts` and the coverage
notes were each added to `Finding` and wired into whichever renderer their author was working
in. Two of them reach no audit surface at all. None of that is visible from any single
change, which is why it kept being filed as six unrelated bugs instead of one.

So the guard is simply: **every side-channel on `Finding` is registered with a tier**, and the
registry contains no channel the code does not have. Adding a field without deciding its
destination fails the build; deciding is one line.

The tiers are the ones `docs/CHECK_AUTHORING.md` states. What this file does NOT do is check
that a channel actually reaches its tier — that needs the behavioural half. The `gap` column
is therefore a ledger of known shortfalls, each naming the task that owns it, not a silencer:
it is prose, and the day the behavioural half lands it becomes the list of expected failures
to work through.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import dataclasses

from clawseccheck.catalog import Finding

#: What a surface tier means. `docs/CHECK_AUTHORING.md` is the prose; this is the vocabulary.
_TIERS = {
    "machine": "must reach --json and --sarif",
    "human": "must reach the text report, the vet dossier and --advise",
    "both": "machine + human",
    "judge": "carried as structured data in the adjudication packet",
    "vet": "a vet-path channel; the audit surfaces have nothing to attach it to",
}

#: The finding itself, not a channel riding on it.
_CORE_FIELDS = frozenset({"id", "title", "severity", "status", "detail", "fix"})

#: Every side-channel, its intended destination, and — where the survey found the destination
#: unmet — the task that owns the shortfall. A `gap` is a recorded debt, never permission.
_CHANNELS = {
    "evidence": ("both", "the finding's own evidence lines", None),
    "confidence": ("both", "how sure the engine is; text tags it only on FAIL/WARN", None),
    "pass_confidence": ("machine", "what a PASS actually verified", "B-626 family"),
    "suppressed": ("both", "a finding an ignore rule silenced", None),
    "scored": ("machine", "whether the finding counted toward the score", None),
    "framework": ("machine", "MITRE/OWASP tag", None),
    "not_applicable": ("machine", "a surface positively confirmed missing", None),
    "engine_degraded": (
        "both",
        "the check broke rather than concluded",
        "B-624 — reaches every surface as an aggregate only; no surface marks WHICH finding",
    ),
    "ring_findings": (
        "vet",
        "the content ring's non-primary findings",
        "B-614 fixed the plugin path; --vet-plugin dropped them entirely before that",
    ),
    "axis_reasons": (
        "vet",
        "per-axis rationale behind a dossier verdict",
        "B-626 — read only by dossier.py, so no audit surface can show it",
    ),
    "corroborating_buckets": (
        "machine",
        "which other buckets agreed with a first-match-wins verdict",
        "B-626 — no reader anywhere; render, delete, or document as internal",
    ),
    "sub_signals": ("judge", "which sub-signal of a multi-signal check fired", None),
    "destination_hosts": ("judge", "the external destination a finding names", None),
}


def _side_channels():
    return {f.name for f in dataclasses.fields(Finding)} - _CORE_FIELDS


def test_every_finding_channel_has_a_declared_destination():
    """A field added without a tier is a channel nobody decided the destination of.

    This is the whole point of the guard: the decision is one line, and skipping it is how a
    channel ends up reaching one surface out of ten with no one aware.
    """
    undeclared = sorted(_side_channels() - set(_CHANNELS))
    assert not undeclared, (
        "these Finding fields carry information and have no declared destination — add a "
        f"tier in this file and say where they must appear: {undeclared}"
    )


def test_the_registry_names_no_channel_the_code_lacks():
    """The mirror direction. A registry entry for a removed field is a decision about
    nothing, and it makes the count of 'covered channels' overstate the truth."""
    phantom = sorted(set(_CHANNELS) - _side_channels())
    assert not phantom, f"registered channels that are not fields of Finding: {phantom}"


def test_every_declared_tier_is_one_the_authoring_doc_defines():
    """A tier invented at the call site is not a destination anyone can check against."""
    wrong = sorted(
        f"{name}: {tier!r}" for name, (tier, _why, _gap) in _CHANNELS.items()
        if tier not in _TIERS
    )
    assert not wrong, f"channels declared with an unknown tier: {wrong}"


def test_every_recorded_gap_names_its_owner():
    """A shortfall without a task is a note that will be read as an accepted state."""
    orphan = sorted(
        name for name, (_t, _w, gap) in _CHANNELS.items()
        if gap is not None and not any(c.isdigit() for c in gap)
    )
    assert not orphan, f"recorded gaps with no task reference: {orphan}"


def test_the_registry_is_not_vacuous():
    """The control this project keeps needing. If `_CORE_FIELDS` ever swallowed the whole
    dataclass, every assertion above would pass over an empty set and this guard would go on
    reporting success while checking nothing."""
    channels = _side_channels()
    assert len(channels) >= 10, f"only {len(channels)} side-channels found — predicate broke"
    assert _CORE_FIELDS < {f.name for f in dataclasses.fields(Finding)}, (
        "the core-field list has drifted from the dataclass"
    )


def test_the_guard_bites_on_an_unregistered_channel():
    """Guard the guard, without touching `Finding`: the predicate is exercised against a
    synthetic field set, so this control keeps working after the tree is clean."""
    pretend_fields = _side_channels() | {"provenance_chain"}
    undeclared = sorted(pretend_fields - set(_CHANNELS))
    assert undeclared == ["provenance_chain"], undeclared
