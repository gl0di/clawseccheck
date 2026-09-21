"""Guard 1/2 (B0, staged BEFORE the ``Finding.not_applicable`` migration): every real
config's ``(finding id, fingerprint)`` set stays byte-for-byte stable across a release.

WHY THIS EXISTS. ``baseline.fingerprint()`` (``clawseccheck/baseline.py:37-42``) hashes
``sha1(finding.detail)[:8]`` -- and that exact ``<id>:<8-hex>`` shape is what a real
user's own ``.clawseccheckignore`` names when they suppress a specific finding rather
than a whole check id (``baseline.apply()``). If a later change edits so much as one
character of some check's ``detail`` text -- even in a branch only one obscure fixture
happens to exercise -- every user who suppressed that exact finding by fingerprint is
silently UN-suppressed on their next run: no error, no warning, the finding just
reappears on their dashboard as if newly discovered. That is a false PASS-by-omission
in reverse: a real, previously-triaged finding starts looking like a fresh regression.

Until now this was checked at review time, by eye, for whatever lines a diff happened to
touch. This test makes it a CI-enforced invariant instead: it drives the real
``audit()`` over the ENTIRE fixture corpus, computes the exact
``sorted((f.id, fingerprint) for f in findings)`` a real ``.clawseccheckignore`` could
be keyed against, and diffs it against a manifest committed alongside this file
(``finding_fingerprint_manifest.txt``).

THE INVARIANT THIS PINS FOR THE LATER MIGRATION: ``Finding.detail`` strings stay
byte-for-byte unchanged. A part-B change that needs to reword a ``detail`` string is a
deliberate, separately-announced wording release (see ``baseline.py``'s own module
docstring) -- never a silent side effect of adding/reading ``Finding.not_applicable``.

THE ENVIRONMENT-DERIVED SPANS ARE GONE, AND ``_canonical_detail`` IS NOW A TRIPWIRE FOR
THEIR RETURN. This guard originally shipped with a narrow fold: six ids quoted something
that is not a function of the audited config's *content* -- five quoted the absolute scan
root, and B176 quoted a ``time.time()``-derived age -- so their raw fingerprints differed
between two checkouts of this repo and, for the clock, between two runs of the same
checkout hours apart. They were folded to fixed tokens before hashing so the manifest
could be pinned at all.

That fold papered over a live user-facing defect rather than fixing it: the exact same
variance that made the manifest unpinnable also self-orphaned real users'
``.clawseccheckignore`` fingerprint suppressions -- B176's roughly every 2.4 hours on a
completely unchanged config, and the five path ids' the moment a workspace moved -- with
no wording change involved at all, which is why the guard above could never have caught
it. B-348/B-349 fixed all six at the source (the age moved to ``evidence=``, which is not
hashed; paths are rendered relative to the audited home, whose absolute form the report
header already prints once). ``tests/test_b348_b349_fingerprint_stability.py`` pins the
property directly, per id.

So ``_ENV_DERIVED_IDS`` is now EMPTY and the fold is expected to be pure identity over
the whole corpus -- which means this manifest pins the real, unmodified
``baseline.fingerprint()`` values, i.e. the exact strings a user's ``.clawseccheckignore``
holds. The fold machinery is kept only as a detector:
``test_no_detail_is_environment_derived`` fails, naming the id, if any check starts baking
the checkout path or the wall clock into its detail again, and
``test_no_finding_detail_is_clock_dependent`` /
``test_no_finding_detail_leaks_a_machine_specific_path`` prove nothing else varies with the
environment. Everything is pinned byte-for-byte.

Regenerate ONLY for such a deliberate, announced change, from the repo root:
    PYTHONPATH=. python3 tests/test_finding_fingerprint_manifest.py --write

(``PYTHONPATH=.`` because running this file as a script does not get the rootdir on
``sys.path`` the way pytest does, unless the package happens to be pip-installed.)

That re-derives every line from the real, current ``audit()`` output using the exact
same helpers this file's tests assert against -- generator and guard can never drift
apart because they are the same code.

THE STATUS COLUMN. Each entry now carries ``finding.status`` verbatim as a third
colon-delimited field: ``<id>:<status>:<digest>`` (was ``<id>:<digest>``). This closes a
blind spot the hash-only format had: a check that flips verdict (e.g. PASS -> UNKNOWN)
while its ``detail`` text happens to stay byte-identical produced an UNCHANGED hash, so
the guard above -- which compares only hashes -- was silently vacuous for exactly the
kind of drift it exists to catch. The status is read from ``finding.status`` verbatim,
never a hardcoded literal set, so a future new status is captured automatically. See
``_split_entry`` for why the parse is a two-step ``rpartition`` rather than a plain
``split(":")`` (``Finding.id`` can itself contain a colon).

What this column does NOT cover (read this before assuming it catches something it
doesn't):
  * It records ``finding.status`` only -- not ``Finding.not_applicable`` or
    ``Finding.engine_degraded`` (catalog.py), nor ``suppressed``/``confidence``/
    ``pass_confidence``/``severity``. Two UNKNOWNs for very different reasons (a
    genuinely-absent surface vs. an engine crash/timeout) still collapse to the
    identical token ``UNKNOWN`` here.
  * A severity change (e.g. HIGH -> CRITICAL) with unchanged status and unchanged
    detail is invisible -- severity was never hashed and still isn't.
  * A check producing the SAME status AND the SAME detail for two different
    underlying conditions is still invisible -- status is one more compared
    dimension, not a full state hash.
  * ``baseline.fingerprint()`` (unchanged -- see its own module, and this file's
    ``_Canonicalized`` duck-type) still hashes only ``detail``, so this column changes
    nothing about what a real user's ``.clawseccheckignore`` keys on -- it is a
    CI/dev-side detection upgrade only.
  * A guard failure now names WHICH ids moved and in WHICH DIRECTION (e.g.
    "B387: PASS -> UNKNOWN"), not WHY -- a human still has to read the actual
    check-code diff to judge deliberate vs. accidental.

``--write`` ALSO PINS FIXTURE MODES FIRST (B-842), NOT JUST UNDER PYTEST. Six of the ids
this manifest pins (B1, B11, B19, B20, B85, B188) read a fixture path's real filesystem
permission bits, and every OTHER audit of this corpus (pytest, via ``conftest.py``'s
autouse ``_deterministic_fixture_perms`` fixture) pins those bits to a fixed 0600/0700
before fingerprinting -- but this file's ``__main__`` block runs OUTSIDE pytest, so
without doing the same thing itself it fingerprinted whatever mode the checkout happened
to produce. A fresh ``git worktree`` checks out fixture files at 0644 and directories at
0755 (git records no permission bit but owner-execute), so a ``--write`` run there wrote a
manifest that a subsequent ``pytest`` run then rejected -- 608 of 757 rows, across exactly
those six ids -- even though nothing about the fixtures' CONTENT had changed. ``--write``
therefore calls ``tests/_fixtureperms.pin_fixture_modes()`` -- the same function
``conftest.py``'s fixture calls -- before generating a single line, from ANY starting mode
state (a fresh checkout or an already-pinned tree); see
``test_write_pins_fixture_modes_from_any_starting_state`` below.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

from clawseccheck import audit, baseline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MANIFEST = Path(__file__).resolve().parent / "finding_fingerprint_manifest.txt"
REPO_ROOT = FIXTURES.parent

_HEADER = (
    "# GENERATED by test_finding_fingerprint_manifest.py --write. Do not hand-edit.\n"
    "# One line per fixture home: <relpath>\\t<id1>:<status1>:<fp1>,<id2>:<status2>:<fp2>,...\n"
    "# <fpN> is the 8-hex digest half of baseline.fingerprint() (\"<id>:<hash>\"), UNCHANGED\n"
    "# by this format -- clawseccheck/baseline.py is not touched, so a real user's\n"
    "# .clawseccheckignore fingerprint entries stay valid. <statusN> is finding.status\n"
    "# verbatim (PASS/FAIL/WARN/UNKNOWN/SKILL_ARCHIVE_PATH_TRAVERSAL today), added so a\n"
    "# check that flips verdict while keeping byte-identical detail text is no longer\n"
    "# invisible in a manifest diff.\n"
    "# Regenerate ONLY for a deliberate, announced Finding.detail wording OR manifest-\n"
    "# format release.\n"
)


# Not real fixture homes: `fixtures/conftest.py` (see its own docstring) is imported by
# pytest during collection purely for its `collect_ignore_glob`, which byte-compiles it
# into a `__pycache__/` sibling as a side effect -- present or absent depending on
# collection order and filesystem state, never a committed fixture. Auditing it as a
# "home" would make the corpus (and this guard's membership) collection-order-dependent.
_NOT_A_FIXTURE = {"__pycache__"}


def _corpus_targets() -> list[Path]:
    """Every fixture home in the corpus, plus each fixture's nested ``openclaw_home/``
    variant where present -- mirrors ``tests/test_b315_unscored_never_fails.py``'s own
    corpus discovery so both full-corpus structural guards exercise the identical set,
    minus the non-fixture artifact directories named in ``_NOT_A_FIXTURE`` above.
    """
    homes = sorted(
        d for d in FIXTURES.iterdir()
        if d.is_dir() and not d.name.startswith(".") and d.name not in _NOT_A_FIXTURE
    )
    targets: list[Path] = []
    for h in homes:
        targets.append(h)
        nested = h / "openclaw_home"
        if nested.is_dir():
            targets.append(nested)
    return targets


CORPUS = _corpus_targets()


# ---------------------------------------------------------------------------------------
# The environment-derived-span DETECTOR (see the module docstring). Since B-348/B-349 this
# is expected to be pure identity over the whole corpus; it is retained because it is what
# NAMES the offending id if one of those two channels ever reopens. Deliberately narrow: a
# broad "scrub anything that looks like a path or a number" rewrite would blunt the very
# wording drift this file exists to catch.
# ---------------------------------------------------------------------------------------

_ROOT_TOKEN = "<REPO_ROOT>"

# B176 (clawseccheck/checks/_lifecycle.py) used to embed this. `time.time()` there is still
# the ONLY wall-clock read anywhere in the package outside the scan budget's monotonic
# deadlines, so this one pattern covers every clock-derived span the check engine can emit
# today; the clock test below re-proves that empirically over the whole corpus rather than
# trusting this comment.
_AGE_TOKEN = "lastSeenAgeDays=<AGE>"
_AGE_RE = re.compile(r"lastSeenAgeDays=\d+(?:\.\d+)?d")

# Longest form first so a resolved root cannot be half-substituted by its unresolved
# prefix (they are usually identical; they differ when the checkout is reached via a
# symlink, e.g. some CI runners and every `git worktree` under a symlinked parent).
_ROOT_FORMS = sorted(
    {str(REPO_ROOT), str(Path(__file__).parent.parent)}, key=len, reverse=True
)

# Every check id whose detail contains one of the spans above, on at least one fixture.
# EMPTY since B-348/B-349 fixed the last of them (B158/B176/B183/B184/B186/B192), which is
# what lets this manifest pin real, unmodified baseline.fingerprint() values. Kept as an
# explicit set rather than deleted so a NEW check that bakes the environment into its
# detail cannot be silently absorbed by the fold -- it has to be looked at and named here
# first, and the right answer is almost always to move that span into evidence= (not
# hashed) or render it relative to the audited home, never to add it here.
_ENV_DERIVED_IDS: "set[str]" = set()


def _canonical_detail(detail: str) -> str:
    """*detail* with this checkout's root and B176's former wall-clock age folded to fixed
    tokens. Expected to be identity for EVERY detail string today (asserted below)."""
    out = detail
    for form in _ROOT_FORMS:
        out = out.replace(form, _ROOT_TOKEN)
    return _AGE_RE.sub(_AGE_TOKEN, out)


class _Canonicalized:
    """Duck-type for ``baseline.fingerprint()``: same id, canonicalized detail.

    Reusing the real ``baseline.fingerprint()`` rather than re-deriving sha1 here is
    deliberate -- if the production hash formula ever changes, this guard follows it
    instead of quietly pinning a formula users no longer key on.
    """

    __slots__ = ("id", "detail")

    def __init__(self, finding) -> None:
        self.id = finding.id
        self.detail = _canonical_detail(finding.detail)


def _fingerprint(finding) -> str:
    return baseline.fingerprint(_Canonicalized(finding))


def _fingerprint_pairs(home: Path) -> list[tuple[str, str, str]]:
    """The exact per-fixture value this guard pins: every ``(id, status, fingerprint)``
    triple a real ``.clawseccheckignore`` on this exact config could be keyed on (the
    ``status`` is the new column -- see the module docstring's "THE STATUS COLUMN").
    Sort key matches the task's own formula, ``sorted((f.id, ...) for f in ...)`` --
    note ``baseline.fingerprint()`` already returns the ``<id>:<hash>`` shape
    (``baseline.py``'s own ``fingerprint()`` docstring), so ``f.id`` here is only the
    sort key, never re-embedded a second time in the encoded manifest text (see
    ``_encode_pairs``). ``status`` is ``finding.status`` verbatim, never a hardcoded
    literal set, so a future new status is captured automatically."""
    _, findings, _ = audit(home)
    return sorted((f.id, f.status, _fingerprint(f)) for f in findings)


def _encode_pairs(pairs: list[tuple[str, str, str]]) -> str:
    """``"<id>:<status>:<digest>"`` per entry. Each fingerprint string already IS
    ``"<id>:<hash>"`` -- storing ``f.id`` again would duplicate it for no benefit, so
    only the hash half is kept alongside the new ``status`` field."""
    entries = []
    for fid, status, fp in pairs:
        _, _, digest = fp.rpartition(":")  # fp is "<id>:<hash>"; keep the hash half
        entries.append(f"{fid}:{status}:{digest}")
    return ",".join(entries)


def _manifest_line(home: Path) -> str:
    rel = str(home.relative_to(FIXTURES))
    return f"{rel}\t{_encode_pairs(_fingerprint_pairs(home))}"


def _load_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip("\n")
        if not line or line.startswith("#"):
            continue
        rel, _, pairs = line.partition("\t")
        entries[rel] = pairs
    return entries


def _write_manifest() -> None:
    """Regenerate the manifest from a live ``audit()`` pass over ``CORPUS``.

    B-842: pins fixture modes FIRST, exactly as ``conftest.py``'s autouse
    ``_deterministic_fixture_perms`` fixture does for every pytest run -- by calling that
    same shared function, not by re-deriving the chmod loop here. Six ids (B1, B11, B19,
    B20, B85, B188) fingerprint a fixture path's real permission bits, so without this a
    ``--write`` run outside pytest (this function's only caller) would fingerprint
    whatever mode the checkout happened to produce instead of the pinned mode pytest
    itself audits under -- silently writing a manifest the very next pytest run rejects.
    """
    from _fixtureperms import pin_fixture_modes

    pin_fixture_modes()
    lines = [_manifest_line(h) for h in CORPUS]
    MANIFEST.write_text(_HEADER + "\n".join(lines) + "\n", encoding="utf-8")


# One audit per fixture for the whole module: the parametrized guard below, the two
# guard-the-guard tests, and test_finding_ids_and_statuses_are_safely_parseable all key
# off this cache instead of re-auditing their fixture. (test_no_detail_is_environment_derived
# and test_no_finding_detail_leaks_a_machine_specific_path still audit independently --
# they need the raw, uncanonicalized Finding.detail text, which this cache deliberately
# does not retain; that used to make a hash-only cache useless to them, and still does.)
# Deliberately caches only the small derived strings, never the Finding objects.
_ENCODED_CACHE: dict[Path, str] = {}

# {home: [(id, status), ...]} for every finding on that fixture, in the same order as
# _fingerprint_pairs. Populated by the SAME audit() call _encoded() already makes on a
# cache miss -- never a second pass -- so a test that only needs raw ids/statuses (not
# the encoded digest string) can share this audit instead of re-running it. This closes
# the gap the status column itself opened: test_finding_ids_and_statuses_are_safely_
# parseable (below) used to call audit() a second time over the whole corpus for
# exactly this data.
_ID_STATUS_CACHE: dict[Path, list[tuple[str, str]]] = {}


def _encoded(home: Path) -> str:
    cached = _ENCODED_CACHE.get(home)
    if cached is None:
        pairs = _fingerprint_pairs(home)
        cached = _encode_pairs(pairs)
        _ENCODED_CACHE[home] = cached
        _ID_STATUS_CACHE[home] = [(fid, status) for fid, status, _fp in pairs]
    return cached


def _ids_and_statuses(home: Path) -> list[tuple[str, str]]:
    """``[(id, status), ...]`` for every finding on *home*, via the shared cache --
    populates it (one ``audit()`` call, through ``_encoded``) on a miss, so callers never
    trigger a second full-corpus audit pass just to read ids and statuses."""
    if home not in _ID_STATUS_CACHE:
        _encoded(home)
    return _ID_STATUS_CACHE[home]


# ---------------------------------------------------------------------------------------
# The failure diagnostic. Extracted from the guard so the guard-the-guard tests below can
# drive it directly, and so BOTH sides of the diff are reduced by the SAME function --
# the asymmetry this replaces (raw "<id>:<hash>" on one side, bare "<hash>" on the other)
# made every id in the fixture compare unequal, so a one-id drift was reported as ~160
# ids changed and the real culprit was invisible.
# ---------------------------------------------------------------------------------------

def _split_entry(entry: str) -> tuple[str, str, str]:
    """``("B176", "PASS", "62fa8905")`` from ``"B176:PASS:62fa8905"``. Two ``rpartition``
    calls from the right -- NOT ``split(":")`` -- because ``Finding.id`` can itself
    contain a colon (``checks/__init__.py``'s ``f"ERR:{name}"`` id for a crashed/timed-out
    check). ``status`` and ``digest`` never contain one (pinned by
    ``test_finding_ids_and_statuses_are_safely_parseable`` below), so peeling them off
    the right end first stays exact no matter how many colons ``id`` carries."""
    fid_and_status, _, digest = entry.rpartition(":")
    fid, _, status = fid_and_status.rpartition(":")
    return (fid or fid_and_status), status, digest


def _by_id(encoded: str) -> dict[str, tuple[str, str]]:
    """``{id: (status, digest)}`` from one encoded manifest value. The single
    normalization both sides of the diff go through."""
    return {
        fid: (status, digest)
        for fid, status, digest in (_split_entry(e) for e in encoded.split(",") if e)
    }


def _changed_ids(got: str, want: str) -> list[str]:
    """The check ids whose ``(status, digest)`` pair actually moved between two encoded
    values. Unchanged contract/signature (bare list of ids) -- the two guard-the-guard
    tests below key off THIS, so their setup keeps working unmodified."""
    got_by_id = _by_id(got)
    want_by_id = _by_id(want)
    return sorted(
        fid for fid in set(got_by_id) | set(want_by_id)
        if got_by_id.get(fid) != want_by_id.get(fid)
    )


def _describe_changes(got: str, want: str) -> list[str]:
    """One human-readable line per id that moved, e.g. ``"B387: PASS -> UNKNOWN"`` --
    the actual UX fix the status column exists for: turning "these 149 hashes moved" into
    "B387 flipped PASS -> UNKNOWN on 149 fixtures" without requiring a human to decode
    hex digests by hand. ``want`` is the committed/old value, ``got`` is the live/new one
    (matches this file's own ``want = committed.get(rel)`` / ``got = _encoded(home)``
    naming at the guard's call site)."""
    g, w = _by_id(got), _by_id(want)
    out = []
    for fid in sorted(set(g) | set(w)):
        gv, wv = g.get(fid), w.get(fid)
        if gv == wv:
            continue
        if gv is None:
            out.append(f"{fid}: removed (was {wv[0]})")
        elif wv is None:
            out.append(f"{fid}: added ({gv[0]})")
        elif gv[0] != wv[0]:
            out.append(f"{fid}: {wv[0]} -> {gv[0]}")
        else:
            out.append(f"{fid}: detail changed (status {wv[0]} unchanged)")
    return out


# ---------------------------------------------------------------------------------------
# Sanity: the corpus and the committed manifest cannot silently drift apart in MEMBERSHIP
# (a stale/incomplete manifest would make the per-fixture guard below vacuous for
# whatever fixture went missing from it).
# ---------------------------------------------------------------------------------------

def test_corpus_is_non_empty():
    assert len(CORPUS) >= 400, "expected the full fixtures/ corpus (480+ homes)"


def test_manifest_file_exists():
    assert MANIFEST.is_file(), (
        f"{MANIFEST} is missing -- the committed fingerprint baseline this guard "
        "compares against must exist and be checked in alongside this test"
    )


def test_manifest_covers_the_full_corpus():
    committed = _load_manifest()
    corpus_rels = {str(h.relative_to(FIXTURES)) for h in CORPUS}
    missing = corpus_rels - set(committed)
    stale = set(committed) - corpus_rels
    assert not missing and not stale, (
        f"the committed manifest and the live fixture corpus disagree on membership -- "
        f"missing from manifest: {sorted(missing)[:10]}; "
        f"stale entries no longer in the corpus: {sorted(stale)[:10]}; "
        "regenerate with 'PYTHONPATH=. python3 tests/test_finding_fingerprint_manifest.py --write'"
    )


# ---------------------------------------------------------------------------------------
# THE GUARD. Parametrized per fixture (matches test_b315_unscored_never_fails.py's own
# full-corpus style) so a CI failure names exactly which fixture -- and, via the
# diagnostic above, exactly which check id -- had its fingerprint move.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("home", CORPUS, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fingerprints_match_the_committed_manifest(home):
    """A changed fingerprint here means some check's ``Finding.detail`` text changed on
    this exact fixture -- which orphans any real user's ``.clawseccheckignore``
    fingerprint entry for that finding, silently (see module docstring). This is the
    load-bearing assertion; the membership tests above only guard against a stale or
    incomplete manifest making this one vacuous.
    """
    committed = _load_manifest()
    rel = str(home.relative_to(FIXTURES))
    want = committed.get(rel)
    assert want is not None, f"{rel} is not in the committed manifest"

    got = _encoded(home)
    if got == want:
        return

    pytest.fail(
        f"{rel}: {'; '.join(_describe_changes(got, want))} -- if this is a deliberate, "
        "announced change, regenerate the manifest "
        "('PYTHONPATH=. python3 tests/test_finding_fingerprint_manifest.py --write'); "
        "otherwise a check's verdict or detail text drifted unintentionally and will "
        "silently orphan real users' .clawseccheckignore fingerprint suppressions"
    )


# ---------------------------------------------------------------------------------------
# GUARD THE GUARD. A failure diagnostic only ever runs on failure, so nothing exercises
# it on a green build and it can rot unnoticed -- which is precisely what happened to the
# previous one. These drive it deliberately: perturb EXACTLY one entry of a real fixture's
# manifest value and require the message to name exactly that id and no other.
# ---------------------------------------------------------------------------------------

def _perturb_one(encoded: str, index: int) -> tuple[str, str]:
    """(*encoded* with entry *index*'s digest replaced, the id that was perturbed).
    Status is left untouched -- this drives the "detail changed" branch of
    ``_describe_changes``, distinct from the status-flip branch a real verdict change
    would hit."""
    entries = [e for e in encoded.split(",") if e]
    fid, status, digest = _split_entry(entries[index])
    entries[index] = f"{fid}:{status}:{'0' * 8 if digest != '0' * 8 else '1' * 8}"
    return ",".join(entries), fid


def _drop_one(encoded: str, index: int) -> tuple[str, str]:
    """(*encoded* with entry *index* removed, the id that was removed)."""
    entries = [e for e in encoded.split(",") if e]
    fid, _, _ = _split_entry(entries.pop(index))
    return ",".join(entries), fid


def _run_guard_expecting_failure(home, doctored: str, monkeypatch) -> str:
    rel = str(home.relative_to(FIXTURES))
    monkeypatch.setattr(
        sys.modules[__name__], "_load_manifest", lambda: {rel: doctored}
    )
    try:
        test_fingerprints_match_the_committed_manifest(home)
    except BaseException as exc:  # pytest.fail() raises an OutcomeException
        return str(exc)
    pytest.fail(
        "the guard accepted a manifest value it should have rejected -- it is vacuous"
    )


@pytest.mark.parametrize("index", [0, 7, -1])
def test_diagnostic_names_only_the_perturbed_finding(monkeypatch, index):
    """One moved fingerprint must be reported as ONE changed id.

    Regression pin: the previous diagnostic compared ``baseline.fingerprint()``'s full
    ``"<id>:<hash>"`` string against the manifest's bare ``"<hash>"``, so those two could
    never be equal and every id in the fixture was reported as changed. Reverting
    ``_changed_ids`` to that asymmetry makes this test fail with ~160 ids in the message.
    """
    home = CORPUS[0]
    real = _encoded(home)
    assert len(real.split(",")) > 8, "fixture too small to perturb at index 7"

    doctored, victim = _perturb_one(real, index)
    assert doctored != real

    message = _run_guard_expecting_failure(home, doctored, monkeypatch)
    # Was: f"changed for ['{victim}']" in message, back when the diagnostic named a
    # bare id list. Still proves exactly-one-id-named; no longer pinned to that phrasing.
    assert f"{victim}: " in message, (
        f"expected the diagnostic to name {victim} and no other id; got: {message}"
    )


def test_diagnostic_names_only_the_removed_finding(monkeypatch):
    """Same, for the other half of the diff: an id present on one side only."""
    home = CORPUS[0]
    doctored, victim = _drop_one(_encoded(home), 0)

    message = _run_guard_expecting_failure(home, doctored, monkeypatch)
    assert f"{victim}: " in message, (
        f"expected the diagnostic to name {victim} and no other id; got: {message}"
    )


# ---------------------------------------------------------------------------------------
# No detail may be environment-derived, and the fold must therefore be sufficient AND
# vacuous. Without these three the manifest is either pinned to one machine at one instant
# (unusable in CI, in a worktree, or two hours later) or quietly blunted into pinning
# nothing.
# ---------------------------------------------------------------------------------------

def test_no_detail_is_environment_derived():
    """The fold is pure identity over the whole corpus, so this manifest pins REAL
    ``baseline.fingerprint()`` values -- the exact strings a user's
    ``.clawseccheckignore`` holds.

    Since B-348/B-349 there is no id left whose detail quotes the checkout path or the
    wall clock, so ``_ENV_DERIVED_IDS`` is empty and every detail must survive the fold
    unchanged. A failure here names the id that reopened one of those two channels.
    """
    rewritten: set[str] = set()
    untouched = 0
    for home in CORPUS:
        _, findings, _ = audit(home)
        for f in findings:
            if _canonical_detail(f.detail) != f.detail:
                rewritten.add(f.id)
            else:
                untouched += 1
                assert _fingerprint(f) == baseline.fingerprint(f), (
                    f"{f.id} is untouched by _canonical_detail yet its pinned "
                    "fingerprint differs from the real baseline.fingerprint()"
                )
    assert untouched > 10_000, "expected the corpus audit to produce far more findings"
    assert rewritten == _ENV_DERIVED_IDS, (
        f"the set of checks whose Finding.detail embeds the environment moved: "
        f"newly environment-derived {sorted(rewritten - _ENV_DERIVED_IDS)}, no longer "
        f"environment-derived {sorted(_ENV_DERIVED_IDS - rewritten)}. A NEW id here "
        "means a check started baking the checkout path or the wall clock into its "
        "detail, which self-orphans real users' fingerprint suppressions -- fix the "
        "check (move that span into evidence=, which is not hashed, or render the path "
        "relative to the audited home), do NOT add the id here. A REMOVED id means "
        "someone fixed one: drop it from _ENV_DERIVED_IDS and regenerate the manifest."
    )


# B-729: sampled, not the full corpus. Measured on this box: one full-corpus
# `_fingerprint_pairs` pass over all ~734 homes is ~45s, so the naive "freeze, re-audit
# the whole corpus, compare" shape this test used to have would cost ~90s just for the
# unfrozen + frozen pair (on top of the row-level guard's own full pass elsewhere in this
# file). A clock-dependent `Finding.detail` is a property of the CHECK CODE PATH that
# produced it, not of any one fixture's content -- if a check reads the wall clock, it
# does so on every fixture that check fires on, not selectively -- so a representative
# cross-section catches it exactly as reliably as the full corpus would. Stride over the
# already-sorted (and therefore prefix-diverse: bad_/clean_/home_/traj_/warn_/...)
# CORPUS rather than a random sample, so the set is 100% deterministic across runs and
# machines and needs no seed.
_CLOCK_SAMPLE = CORPUS[::7]


def _clock_dependence_drift(sample: list[Path]) -> dict[str, list[str]]:
    """The one property this guard pins: freezing the wall clock 45 days ahead must not
    move any finding's fingerprint, compared to an UNFROZEN run of the SAME tree taken
    moments apart -- never against the committed manifest.

    B-729: comparing against the committed manifest (the original shape of this guard)
    could not tell "a detail reads the clock" apart from "the manifest is stale for some
    unrelated reason" -- both look identical from that vantage point, and the message
    named the wrong cause for the latter (confirmed live: a fixture rename unrelated to
    time made this fail alongside the correct, and accurately-worded, row-level manifest
    guard). Comparing two live runs of the same tree is now the only source of truth this
    function touches; ``test_clock_guard_is_immune_to_a_stale_manifest_...`` below pins
    that a corrupted manifest cannot make it misfire.
    """
    unfrozen = {
        str(home.relative_to(FIXTURES)): _encode_pairs(_fingerprint_pairs(home))
        for home in sample
    }
    frozen_at = time.time() + 45 * 86_400
    original_time = time.time
    time.time = lambda: frozen_at
    try:
        frozen = {
            str(home.relative_to(FIXTURES)): _encode_pairs(_fingerprint_pairs(home))
            for home in sample
        }
    finally:
        time.time = original_time
    return {
        rel: _changed_ids(frozen[rel], unfrozen[rel])
        for rel in unfrozen
        if frozen[rel] != unfrozen[rel]
    }


def test_no_finding_detail_is_clock_dependent():
    """Patching ``time.time`` is exhaustive for the check engine: it is the only
    wall-clock read in the package outside ``scanbudget``'s ``time.monotonic()``
    deadlines, and no module under ``clawseccheck/checks/`` calls
    ``datetime.now()``/``date.today()``. Before B-348 this failed on B176 for three
    fixtures unless the age was folded away; now it passes with the fold doing nothing,
    because no detail reads the clock at all.
    """
    drifted = _clock_dependence_drift(_CLOCK_SAMPLE)
    assert not drifted, (
        "some Finding.detail text is a function of the wall clock, so its fingerprint "
        "changes on an unchanged config and silently orphans real users' "
        f".clawseccheckignore suppressions: {sorted(drifted.items())[:5]}"
    )


def test_clock_guard_is_immune_to_a_stale_manifest_that_has_nothing_to_do_with_the_clock():
    """B-729's control case, pinned permanently: corrupt the COMMITTED MANIFEST for a
    real fixture with a change that has nothing to do with the wall clock -- exactly the
    B-720 shape that used to make the old, mis-anchored version of this guard misreport
    "clock-dependent" on an ordinary stale-manifest condition. The row-level guard's own
    comparison against that corrupted manifest genuinely would disagree (proving the
    corruption is real and would trip the guard that is SUPPOSED to catch it); the
    clock-dependence guard, which no longer reads the manifest at all, must be completely
    unaffected by it.
    """
    home = _CLOCK_SAMPLE[0]
    rel = str(home.relative_to(FIXTURES))
    real = _encoded(home)
    corrupted_manifest = {rel: real + ",ZZFAKE:deadbeef"}

    # The condition test_fingerprints_match_the_committed_manifest exists to catch: this
    # corrupted entry really does disagree with a live audit, unrelated to any clock.
    assert corrupted_manifest[rel] != real

    # The fix: _clock_dependence_drift never consults the manifest (corrupted or not) --
    # so corrupting it changes nothing about the clock guard's own live-vs-live result.
    assert not _clock_dependence_drift(_CLOCK_SAMPLE)


def test_no_finding_detail_leaks_a_machine_specific_path():
    """Sufficiency of the path fold: after canonicalization no detail may still quote a
    path outside this repo. Such a path could not be pinned at all -- the manifest would
    only ever match the machine that generated it, and CI (or a ``git worktree``, which
    is what surfaced this) would fail on every fixture."""
    # B-519: REAL_HOME, not Path.home(). Under the suite's $HOME redirect the latter is a
    # pytest tmp dir that no finding could ever quote, which would make this assertion
    # vacuous -- it exists to catch a detail that leaks the maintainer's actual home.
    from _realhome import REAL_HOME
    outside_repo = str(REAL_HOME)
    leaked: dict[str, str] = {}
    for home in CORPUS:
        _, findings, _ = audit(home)
        for f in findings:
            canon = _canonical_detail(f.detail)
            if outside_repo in canon:
                leaked.setdefault(f.id, canon[:200])
    assert not leaked, (
        "Finding.detail quotes an absolute path outside the repo, so its fingerprint "
        f"is specific to one machine's filesystem layout: {sorted(leaked.items())[:5]}"
    )


def test_finding_ids_and_statuses_are_safely_parseable():
    """Defensive pin for ``_split_entry``'s two-``rpartition`` parse of the 3-field
    ``<id>:<status>:<digest>`` encoding: every live ``finding.status`` must be
    colon-free (it is always the rightmost-but-one field) and every live
    ``finding.id`` may contain AT MOST ONE colon (today's sole case is the
    ``f"ERR:{name}"`` id ``checks/__init__.py`` gives a crashed/timed-out check,
    always paired with ``status=UNKNOWN``). A status or id that broke either
    assumption would make ``_split_entry`` mis-attribute fields SILENTLY -- this test
    is what fails loudly instead, the moment a future check or status literal violates
    it, rather than corrupting the manifest without any test noticing.

    Reads ids/statuses via ``_ids_and_statuses`` (the shared cache), not a fresh
    ``audit(home)`` call -- this needs no ``Finding.detail`` text, only ``id``/
    ``status``, both of which the cache already carries once the parametrized guard (or
    this test itself, on a cold cache) has audited *home*. Auditing directly here would
    silently turn the module's "one audit per fixture" cache into two.
    """
    bad_status: dict[str, str] = {}
    bad_id: dict[str, str] = {}
    for home in CORPUS:
        for fid, status in _ids_and_statuses(home):
            if ":" in status:
                bad_status.setdefault(fid, status)
            if fid.count(":") > 1:
                bad_id.setdefault(fid, status)
    assert not bad_status, (
        "finding.status contains a colon, which the manifest's 3-field encoding "
        f"reserves as a separator between id/status/digest: {sorted(bad_status.items())[:5]}"
    )
    assert not bad_id, (
        "finding.id contains more than one colon, which _split_entry's two-rpartition "
        f"parse cannot safely attribute: {sorted(bad_id.items())[:5]}"
    )


# ---------------------------------------------------------------------------------------
# B-842: --write must pin fixture modes itself, from ANY starting mode state, so a fresh
# `git worktree` checkout (files 0644, dirs 0755 -- git records no permission bit but
# owner-execute) cannot make a hand-run regeneration disagree with what pytest's own
# autouse `_deterministic_fixture_perms` fixture (`tests/_fixtureperms.pin_fixture_modes`)
# pins for every OTHER run of this same guard.
# ---------------------------------------------------------------------------------------

# Confirmed by direct measurement to carry a live, mode-sensitive B1 and B11 finding --
# i.e. a home where getting the pin wrong actually changes the fingerprint. The test below
# re-proves this itself (rather than trusting the comment) so it cannot go vacuous if the
# corpus changes underneath it.
_MODE_SENSITIVE_HOME = FIXTURES / "b334_nearmiss_documented_helper"


def _set_fresh_checkout_like_modes(home: Path) -> None:
    """Chmod every real path under *home* to what a fresh `git worktree add` actually
    produces: 0644 files, 0755 dirs (git tracks no permission bit but owner-execute)."""
    for p in (home, *home.rglob("*")):
        if p.is_symlink():
            continue
        p.chmod(0o755 if p.is_dir() else 0o644)


def test_write_pins_fixture_modes_from_any_starting_state(monkeypatch):
    """The regression this file exists to prevent (B-842). Reproduces a fresh worktree's
    checkout modes on a fixture confirmed mode-sensitive, then requires `--write`'s own
    code path (`_write_manifest`, via the shared `_fixtureperms.pin_fixture_modes`) to
    land on the exact value the committed, pytest-accepted manifest holds for it --
    whether it started from that unpinned checkout state or from an already-pinned tree.

    Without the fix (`_write_manifest` not calling `pin_fixture_modes`), the first loop
    iteration below fails: fingerprinting the checkout-like (0644/0755) state produces a
    manifest entry that disagrees with `committed`, exactly as it did in the real B-842
    incident (608 of 757 rows, across B1/B11/B19/B20/B85/B188).
    """
    from _fixtureperms import pin_fixture_modes

    home = _MODE_SENSITIVE_HOME
    rel = str(home.relative_to(FIXTURES))
    committed = _load_manifest()[rel]

    real_paths = [p for p in (home, *home.rglob("*")) if not p.is_symlink()]
    saved_modes = {p: p.stat().st_mode & 0o777 for p in real_paths}

    tmp_manifest = MANIFEST.parent / "_b842_scratch_manifest.txt"
    monkeypatch.setattr(sys.modules[__name__], "MANIFEST", tmp_manifest)
    monkeypatch.setattr(sys.modules[__name__], "CORPUS", [home])

    try:
        _set_fresh_checkout_like_modes(home)

        # Guard the guard: this home must actually BE mode-sensitive, or the loop below
        # would pass regardless of whether the fix exists.
        raw_unpinned = _encode_pairs(_fingerprint_pairs(home))
        assert raw_unpinned != committed, (
            f"{rel} no longer differs between checkout-like and pinned modes -- pick a "
            "new fixture with a live B1/B11/B19/B20/B85/B188 finding so this regression "
            "test is not vacuous"
        )

        for label, prime in (
            ("a fresh checkout (0644 files / 0755 dirs)", lambda: None),  # already set
            ("an already-pinned tree (0600 files / 0700 dirs)", pin_fixture_modes),
        ):
            prime()
            _write_manifest()
            written = _load_manifest()[rel]
            assert written == committed, (
                f"--write starting from {label} produced a manifest entry for {rel} "
                f"that pytest would reject: got {written!r}, want {committed!r}"
            )
    finally:
        tmp_manifest.unlink(missing_ok=True)
        for p, mode in saved_modes.items():
            p.chmod(mode)
        pin_fixture_modes()  # restore the corpus-wide invariant for every later test


if __name__ == "__main__":  # pragma: no cover
    if "--write" in sys.argv:
        _write_manifest()
        print(f"wrote {MANIFEST} ({len(CORPUS)} fixture(s))")
    else:
        pytest.main([__file__, "-q"])
