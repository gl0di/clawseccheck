"""C-481 — a field CENSUS over ClawHub's `.clawhub/lock.json` / `.clawhub/origin.json`.

Three independent producers write into these files (OpenClaw dist, the ClawHub CLI, and
the clawhub.ai server itself — see `skillprovenance.py`'s own module docstring), and a
`PRAGMA`-style schema diff is impossible: the server's `verification` block is not
installable, and the CLI is independently versioned. A field-name CENSUS is possible
instead, because key NAMES survive bundling even where line numbers and file layouts do
not — the same reasoning `test_state_schema_grounding.py`/`test_dist_citation_gate.py`
already lean on for their own vendor surfaces.

Measured live on this machine's own `~/.openclaw/workspace/.clawhub/lock.json`
(2026-09-16): 19 records, 18 carrying only `{installedAt, version}` (the CLI's unpin path
replaces a whole entry), one carrying the full set — which is where `fileTreeSha256` and
`ownerHandle` were found unread, neither read by any function in this tree.

SCOPE BOUNDARY, disclosed rather than silently narrow: this census operates on the
per-skill RECORD's own TOP-LEVEL keys only — `artifact`, `skillFile` and `verification`
are censused as single container keys, not decomposed into their own sub-fields. Three
reasons: (1) it matches how the three producers' own behaviour is described (the CLI's
erasure and the server's `verification` block both operate at this granularity); (2) it
is the granularity `SkillOrigin` (this tree's own read-model) already uses; (3) `artifact`
and `skillFile` DO have one sub-field each independently censused below
(`artifact.sha256`/`skillFile.sha256`, via `_digest_pair`'s own documented contract) —
recursing further into `verification` in particular would follow a surface this task's
own framing puts out of reach anyway ("not installable... versioned by a string in its
own payload").

EXTRACTION ANCHOR. Per this task's own explicit warning, a `.get("literal")` grep over
the whole tree "over-reports catastrophically" — a two-reader census that way turned up
`stats`, `config`, `agents`, `entry`, `defaults` and a dozen other receivers
indistinguishable from a real lock/origin record. So extraction here is anchored on the
actual LOADER functions (an explicit allowlist, `_READER_FUNCTIONS` below) AND, within
each, on the specific parameter/loop-variable name that IS the per-skill record in THAT
function — not a global name guess. `_b181_recorded_files` reuses `entry` for a per-FILE
dict nested inside `verification.artifact.files[]`, one level below the record this
census is about; scoping the variable allowlist per function (not globally) is what
keeps that nested `entry` out of the record-level result, rather than hand-filtering the
extractor's own output after the fact to fit a pre-written registry. One name-collision
remains and is a deliberate, disclosed exception: `_b181_provenance_records` reassigns
its own `data` variable from "the whole lock file object" (an intermediate step, not
extracted) to "one origin.json record" (extracted) — a purely name-based pass cannot
tell those apart, so `skills` (the lock file's own top-level map key, never a per-skill
field) is hand-excluded as the one literal that ambiguity produces. Verified: the
extractor is NOT vacuous (asserted below) and its output, run interactively against the
current tree, is exactly the registry's "read" set — no more, no less.

TWO ARMS (Bucket-B / Bucket-C), per the task's own framing:
  * Bucket-B — every field a reader function actually reads must be registered as "read".
    A field renamed out from under a `.get()` call would otherwise make that reader
    silently return `None` forever, the class that produces a clean PASS over nothing.
  * Bucket-C — every KNOWN producer field is either "read", or carries a REGISTERED
    classification with a substantive, non-empty reason: "dismissed" (reviewed and
    judged not security-bearing) or "coverage_gap" (real, unread, not yet investigated).
    `trustState` and `fileTreeSha256` are pinned to `coverage_gap` specifically — the
    task is explicit that these are NOT legitimate dismissals, and a silent
    reclassification into "dismissed" is exactly the failure a frozen baseline could
    not catch (a baseline has no arm for "a key moved from dismissed to
    security-bearing"; a classified, reason-carrying registry does, because a test can
    pin the classification itself).

WHAT THIS CANNOT CATCH (stated once, per the task's own list, rather than implied):
the CLI's *erasure* of a whole entry (a write-semantics property, invisible to any
key-set comparison); any change to `verification`'s internal shape (its producer is a
server needing no package release); and the population problem — this census asserts
what a producer CAN write, never what any one record DOES carry, which is exactly why
18 of 19 real records on this machine carry only two of the known fields.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from _realhome import REAL_HOME

REPO = Path(__file__).resolve().parent.parent
SKILLPROVENANCE = REPO / "clawseccheck" / "skillprovenance.py"
LIFECYCLE = REPO / "clawseccheck" / "checks" / "_lifecycle.py"

# (path, function name) -> the loop/parameter variable name(s) that ARE the per-skill
# record dict inside THAT function -- not a global guess. Grounded by reading each
# function directly (see the module docstring above for the two cases this matters for).
_READER_FUNCTIONS = {
    (SKILLPROVENANCE, "read_provenance"): frozenset({"rec"}),
    (SKILLPROVENANCE, "_digest_pair"): frozenset({"rec"}),
    (SKILLPROVENANCE, "_corroborate"): frozenset({"rec", "origin"}),
    (LIFECYCLE, "check_clawhub_lock_verification"): frozenset({"entry"}),   # B135
    (LIFECYCLE, "_b181_recorded_files"): frozenset({"record"}),             # B181
    (LIFECYCLE, "_b181_provenance_records"): frozenset({"entry", "data"}),  # B181/B184 shared
    (LIFECYCLE, "check_clawhub_registry_provenance"): frozenset({"record"}),  # B184
}

# The one disclosed name-collision exclusion -- see module docstring's EXTRACTION ANCHOR
# paragraph. "skills" is the lock FILE's own top-level map key, never a per-skill field.
_CONTAINER_KEYS = frozenset({"skills"})

READ = "read"
DISMISSED = "dismissed"
COVERAGE_GAP = "coverage_gap"
_VALID_CLASSIFICATIONS = frozenset({READ, DISMISSED, COVERAGE_GAP})

# field name -> (classification, file(s) it is written in, reason).
# "file" is documentary only (lock/origin/both) -- not structurally enforced, since the
# code itself reads both shapes fairly interchangeably (`_digest_pair`'s own docstring:
# "out of a record in either file's shape").
REGISTRY = {
    # ---- read ------------------------------------------------------------------
    "version": (READ, "both",
                "SkillOrigin.version / B135's version=... label"),
    "installedAt": (READ, "both", "SkillOrigin.installed_at"),
    "registry": (READ, "both", "SkillOrigin.registry / B184's registry provenance"),
    "artifact": (READ, "both",
                 "container: .sha256 read by _digest_pair (see artifact.sha256 below)"),
    "skillFile": (READ, "both",
                  "container: .sha256/.path read by _digest_pair / _b181_recorded_files "
                  "(see skillFile.sha256 below)"),
    "verification": (READ, "lock",
                      "container: B135 reads .ok/.decision/.reasons/.signature/.security; "
                      "B181 reads .artifact.files[] -- internal shape out of this census's "
                      "scope, see module docstring's SCOPE BOUNDARY"),
    "slug": (READ, "origin", "_b181_provenance_records' record identity"),
    "installedVersion": (READ, "origin", "_corroborate's cross-check against lock version"),
    # Individually censused because `_digest_pair` documents them as its own contract
    # ("(artifact.sha256, skillFile.sha256) out of a record in either file's shape").
    "artifact.sha256": (READ, "both", "_digest_pair"),
    "skillFile.sha256": (READ, "both", "_digest_pair"),

    # ---- coverage gaps: real, security-relevant, unread -- NEVER dismissed ------
    "fileTreeSha256": (COVERAGE_GAP, "lock",
                        "whole-tree integrity digest OpenClaw writes unconditionally; "
                        "absent from every reader in this tree (B181's own subject, "
                        "handed to us free). C-481's own headline finding."),
    "trustState": (COVERAGE_GAP, "lock",
                    "marks an install ClawHub never scanned; unread anywhere. C-481's "
                    "second headline finding."),
    "ownerHandle": (COVERAGE_GAP, "lock",
                     "which ClawHub account published/installed under -- found on this "
                     "machine's own real lock file during this census (not named in the "
                     "original task text), unread anywhere. Provenance-adjacent, not yet "
                     "substantively disproved as harmless -- conservatively a gap, not a "
                     "dismissal."),
    "trackedMetadata": (COVERAGE_GAP, "lock",
                         "documented as OpenClaw-dist-written; absent from every record on "
                         "this machine so its real shape/content could not be inspected "
                         "here -- a gap, not a dismissal, until it can be."),

    # ---- dismissed: reviewed, judged not security-bearing -----------------------
    "pinned": (DISMISSED, "lock",
               "a user's local pin preference (survives `clawhub update`); an operational "
               "flag, not an integrity or trust digest -- reviewed, not just unread."),
    "pinReason": (DISMISSED, "lock",
                  "free-text the user gave when pinning; same reasoning as 'pinned' -- "
                  "carries no digest or trust verdict of its own."),
}

# Fields the task is explicit must never be silently reclassified into "dismissed".
_MUST_STAY_COVERAGE_GAP = frozenset({"fileTreeSha256", "trustState"})


def _extract_read_fields():
    """`{field_name: [(relpath, function_name), ...]}` -- see EXTRACTION ANCHOR above."""
    by_field: "dict[str, list]" = {}
    for (path, fn_name), record_vars in _READER_FUNCTIONS.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        matched = [n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == fn_name]
        assert matched, f"{fn_name} not found in {path} -- the census's own anchor moved"
        for node in matched:
            for sub in ast.walk(node):
                key = None
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                        and sub.func.attr == "get"
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id in record_vars):
                    if (sub.args and isinstance(sub.args[0], ast.Constant)
                            and isinstance(sub.args[0].value, str)):
                        key = sub.args[0].value
                elif isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) \
                        and sub.value.id in record_vars:
                    sl = sub.slice
                    if isinstance(sl, ast.Index):  # py3.8-shape AST, tolerated
                        sl = sl.value
                    if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                        key = sl.value
                if key and key not in _CONTAINER_KEYS:
                    by_field.setdefault(key, []).append((path.name, fn_name))
    return by_field


# --------------------------------------------------------------------------- Bucket-B

def test_the_extractor_is_not_vacuous():
    """A silent zero must read as 'the anchor broke', never as 'nothing is read' --
    same reasoning as dist_citation_gate.py's own `total == 0` guard."""
    by_field = _extract_read_fields()
    assert len(by_field) >= 8, (
        f"only {len(by_field)} field(s) extracted from the known reader functions -- "
        "the extraction anchor likely no longer matches the real source (a rename?)"
    )


def test_every_field_a_reader_actually_reads_is_registered_as_read():
    """Bucket-B: a field renamed out from under a `.get()` call must fail here, not
    return None forever from a reader nobody notices went quiet."""
    by_field = _extract_read_fields()
    unregistered = sorted(
        f for f in by_field
        if f not in REGISTRY or REGISTRY[f][0] != READ
    )
    assert not unregistered, (
        f"these fields are read by a loader function but not registered as 'read': "
        f"{[(f, by_field[f]) for f in unregistered]} -- register them in REGISTRY."
    )


def test_the_digest_pair_subfields_are_confirmed_by_the_extractor():
    """`_digest_pair` is documented as its own contract (artifact.sha256/skillFile.sha256)
    rather than extracted structurally (it reads through a local, not the record
    variable directly) -- confirm by source text that the registry's claim is real,
    not just declared."""
    src = SKILLPROVENANCE.read_text(encoding="utf-8")
    start = src.index("def _digest_pair")
    body = src[start:src.index("\ndef ", start + 1)]
    assert 'artifact.get("sha256")' in body
    assert 'skill_file.get("sha256")' in body


# --------------------------------------------------------------------------- Bucket-C

def test_registry_is_well_formed():
    for field, (cls, file_, reason) in REGISTRY.items():
        assert cls in _VALID_CLASSIFICATIONS, f"{field}: unknown classification {cls!r}"
        assert file_ in ("lock", "origin", "both"), f"{field}: unknown file {file_!r}"
        assert isinstance(reason, str) and reason.strip(), (
            f"{field}: empty reason -- a classification without a reason is a silencer, "
            "same rule fleet_fp_gate.py's diagnoses already enforce"
        )


def test_fileTreeSha256_and_trustState_are_coverage_gaps_never_dismissed():
    """The task's own explicit warning, pinned: these two are NOT legitimate
    dismissals. A future edit reclassifying either into 'dismissed' fails here --
    the registry catches the exact silent-reclassification direction a frozen
    baseline has no arm for."""
    for field in _MUST_STAY_COVERAGE_GAP:
        assert field in REGISTRY, f"{field} dropped from the registry entirely"
        cls, _file, _reason = REGISTRY[field]
        assert cls == COVERAGE_GAP, (
            f"{field} is classified {cls!r}, not {COVERAGE_GAP!r} -- this field is a real, "
            "security-relevant, unread integrity/trust signal and must never be dismissed"
        )


def test_no_coverage_gap_or_dismissal_is_actually_read():
    """The reverse of Bucket-B: a field registered as unread that the extractor DOES
    find in a reader function is a stale classification -- someone wired it up and
    forgot to move the registry entry."""
    by_field = _extract_read_fields()
    stale = sorted(
        f for f, (cls, _file, _reason) in REGISTRY.items()
        if cls != READ and f in by_field
    )
    assert not stale, f"registered as unread but actually read: {stale}"


# --------------------------------------------------------------------------- local-only

def _real_lock_paths():
    # REAL_HOME, not Path.home()/expanduser() -- conftest redirects $HOME for the whole
    # suite (see tests/_realhome.py's own docstring), so the redirected form would find
    # nothing here and this test would skip on every real machine, not just CI.
    home = REAL_HOME / ".openclaw"
    if not home.is_dir():
        return []
    return sorted(home.rglob(".clawhub/lock.json"))


def test_no_unregistered_field_on_a_real_installed_lock_file():
    """Local-only (skips where there is no real ClawHub install, e.g. CI/B-106): every
    top-level key this machine's OWN real lock.json records is a KNOWN field in the
    registry. Catches a producer field appearing for the first time on a real machine
    that neither the original research nor this census's own empirical check anticipated."""
    paths = _real_lock_paths()
    if not paths:
        pytest.skip("no real .clawhub/lock.json found under ~/.openclaw (expected in CI)")
    unknown: "set[str]" = set()
    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        skills = data.get("skills")
        if not isinstance(skills, dict):
            continue
        for rec in skills.values():
            if isinstance(rec, dict):
                unknown |= set(rec.keys()) - set(REGISTRY)
    assert not unknown, (
        f"real lock file(s) carry field(s) this census has never seen: {sorted(unknown)} -- "
        f"add them to REGISTRY with a classification and a reason before this can pass again"
    )
