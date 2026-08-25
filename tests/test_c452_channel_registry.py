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

import ast
import dataclasses
from pathlib import Path

from clawseccheck.catalog import Finding

REPO = Path(__file__).resolve().parents[1]

#: What a surface tier means. `docs/CHECK_AUTHORING.md` is the prose; this is the vocabulary.
_TIERS = {
    "machine": "must reach --json and --sarif",
    "human": "must reach the text report, the vet dossier and --advise",
    "both": "machine + human",
    "judge": "carried as structured data in the adjudication packet",
    "vet": "a vet-path channel; the audit surfaces have nothing to attach it to",
    "internal": (
        "deliberately not user-facing: kept for the engine's own use, with the reason "
        "recorded at the field's definition. Requires that record — see "
        "test_an_internal_channel_states_its_reason_at_the_definition"
    ),
}

#: The phrase `catalog.py` uses when a field is kept but not rendered. Prose-keyed on
#: purpose: rewording the justification SHOULD fail this build, because the wording is the
#: decision. A tier of "internal" with nothing behind it is how "internal" becomes the
#: silencer that `gap` was built to avoid.
_INTERNAL_MARKERS = ("not rendered by", "internal bookkeeping", "internal to dossier")

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
    # B-626 measured both of these and found the debt it recorded was not real.
    # Producers: checks/_mcp.py:769,:2282, checks/_content.py:11503, checks/_vet.py:3538 —
    # every one on the VET path. On a real audit run, zero findings carry either field, so
    # "no audit surface shows it" describes a channel that is never lit there rather than
    # one that is dropped. `axis_reasons` reaches the dossier, which IS its declared tier.
    "axis_reasons": ("vet", "per-axis rationale behind a dossier verdict", None),
    # Declared retention-only at its definition: kept for a future corroborating-check FAIL
    # rule, explicitly "not rendered by report.py/sarif.py". That is the third outcome the
    # authoring rule allows — documented as internal — already taken, and recorded where a
    # reader meets the field.
    "corroborating_buckets": (
        "internal",
        "which other buckets agreed with a first-match-wins verdict; retention only",
        None,
    ),
    "sub_signals": ("judge", "which sub-signal of a multi-signal check fired", None),
    "destination_hosts": ("judge", "the external destination a finding names", None),
    # B-636: channels attached AFTER construction, not declared on the dataclass. This
    # guard used to enumerate `dataclasses.fields(Finding)` only, so its name promised more
    # than its reach: four live channels were invisible to it, and `ctx` — which carries an
    # entire engine Context between the skill vet and the plugin dispatcher — had never been
    # tiered by anyone. Found by sweeping PRODUCERS (attribute assignments on a name bound
    # to a Finding factory) rather than by trusting the declaration.
    "unanalysed_code": ("vet", "plugin files no reader opened; drives the dossier axes", None),
    "analysed_loose_code": (
        "vet", "plugin Python the Danger pass read but the other axes cannot see", None,
    ),
    "bundled_contexts": ("vet", "each dispatched bundled skill's engine Context", None),
    "ctx": ("internal", "the vet engine's own Context, handed to the plugin dispatcher", None),
}


#: Callables whose return value IS a Finding. A name bound to one of these is a finding,
#: whatever it is called — keying on the producer rather than on a variable named
#: `finding` is the difference between a guard that answers to the code and one that
#: answers to a naming habit. Measured: the name-based version missed `ctx` entirely.
_FINDING_FACTORIES = frozenset({
    "_finding", "_plugin_finding", "Finding", "coverage_gap_finding",
})


def _dynamic_channels() -> "dict[str, tuple[Path, int]]":
    """Every attribute assigned onto a Finding after construction, with where it happens.

    Bound: this sees assignments of the form `<name>.<attr> = ...` where `<name>` was
    bound to a `_FINDING_FACTORIES` call in the SAME function. A producer that returns a
    finding from a helper and assigns onto it in the caller would not be seen. Stated
    rather than implied, because a coverage claim that is not true is worse than a
    narrow one — measured today: 4 found, and all 4 are real.
    """
    declared = {f.name for f in dataclasses.fields(Finding)}
    found: dict[str, tuple[Path, int]] = {}
    for py in sorted((REPO / "clawseccheck").rglob("*.py")):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - the package always parses
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            bound = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    f = node.value.func
                    if (getattr(f, "id", None) or getattr(f, "attr", None)) in _FINDING_FACTORIES:
                        bound |= {t.id for t in node.targets if isinstance(t, ast.Name)}
            if not bound:
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Assign):
                    continue
                for t in node.targets:
                    if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                            and t.value.id in bound and t.attr not in declared):
                        found.setdefault(t.attr, (py, t.lineno))
    return found


def _side_channels():
    declared = {f.name for f in dataclasses.fields(Finding)} - _CORE_FIELDS
    return declared | set(_dynamic_channels())


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


def test_an_internal_channel_states_its_reason_at_the_definition():
    """`internal` must cost something, or it becomes the silencer `gap` was built to avoid.

    A tier of "internal" is a claim that someone decided this field is not user-facing. The
    claim is only worth anything if the reasoning sits where the next author meets it — at
    the field, not in a task nobody will open. So the definition's own comment block has to
    say it.

    Keyed on `catalog.py`'s own phrasing, and that is deliberate rather than lazy: rewording
    the justification should fail this build, because the wording IS the decision. What must
    NOT be used as the marker is "not part of the frozen public JSON shape" — measured,
    three fields carry that phrase and one of them (`sub_signals`) reaches the judge packet.
    It means "outside the frozen envelope", not "rendered nowhere", and keying on it would
    have mis-tiered a live channel as internal.
    """
    # B-636: a channel has two possible definition sites now — a declared dataclass field
    # in catalog.py, or the assignment that attaches it after construction. The rule is
    # unchanged ("the reason sits where the next reader meets the field"); only the place
    # a reader meets it differs, so the lookup follows the channel instead of assuming one
    # file. Assuming catalog.py is what made this control silently inapplicable to every
    # dynamic channel, including one carrying a whole engine Context.
    dynamic = _dynamic_channels()
    unjustified = []
    for name, (tier, _why, _gap) in _CHANNELS.items():
        if tier != "internal":
            continue
        if name in dynamic:
            path, lineno = dynamic[name]
            lines = path.read_text(encoding="utf-8").splitlines()
            idx = lineno - 1
        else:
            path = REPO / "clawseccheck" / "catalog.py"
            lines = path.read_text(encoding="utf-8").splitlines()
            idx = next((i for i, ln in enumerate(lines)
                        if ln.strip().startswith(f"{name}:")), None)
            assert idx is not None, f"{name} is not defined in catalog.py"
        block, j = [], idx - 1
        while j >= 0 and lines[j].strip().startswith("#"):
            block.append(lines[j])
            j -= 1
        comment = " ".join(reversed(block))
        if not any(marker in comment for marker in _INTERNAL_MARKERS):
            unjustified.append(name)
    assert not unjustified, (
        "channels tiered `internal` with no reason recorded at their definition — write it "
        f"where a reader meets the field, or pick a real tier: {unjustified}"
    )


def test_the_internal_justification_control_is_not_vacuous():
    """Guard the guard: at least one channel must actually be tiered `internal`, or the
    test above passes over an empty loop and stops meaning anything."""
    internal = [n for n, (tier, _w, _g) in _CHANNELS.items() if tier == "internal"]
    assert internal, "no channel is tiered internal — the justification control is inert"


def test_the_frozen_shape_phrase_is_not_used_as_an_internal_marker():
    """Pinned because it was the first predicate tried and it is wrong.

    `not part of the frozen public JSON shape` appears on `axis_reasons`,
    `corroborating_buckets` AND `sub_signals`. The third is carried as structured data in
    the adjudication packet, so the phrase cannot mean "internal".
    """
    assert not any("frozen public JSON shape" in m for m in _INTERNAL_MARKERS)
    assert _CHANNELS["sub_signals"][0] == "judge"
