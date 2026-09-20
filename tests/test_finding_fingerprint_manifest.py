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
    "# One line per fixture home: <relpath-under-fixtures>\\t<id1>:<fp1>,<id2>:<fp2>,...\n"
    "# Regenerate ONLY for a deliberate, announced Finding.detail wording release.\n"
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


def _fingerprint_pairs(home: Path) -> list[tuple[str, str]]:
    """The exact per-fixture value this guard pins: every ``(id, fingerprint)`` pair a
    real ``.clawseccheckignore`` on this exact config could be keyed on. Sort key
    matches the task's own formula, ``sorted((f.id, fingerprint) for f in ...)`` --
    note ``baseline.fingerprint()`` already returns the ``<id>:<hash>`` shape
    (``baseline.py``'s own ``fingerprint()`` docstring), so ``f.id`` here is only the
    sort key, never re-embedded in the encoded manifest text (see ``_encode_pairs``)."""
    _, findings, _ = audit(home)
    return sorted((f.id, _fingerprint(f)) for f in findings)


def _encode_pairs(pairs: list[tuple[str, str]]) -> str:
    # Each fingerprint string already IS "<id>:<hash>" -- storing f.id again alongside
    # it would just duplicate the id in every manifest entry for no benefit.
    return ",".join(fp for _fid, fp in pairs)


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


# One audit per fixture for the whole module: the parametrized guard below and the two
# whole-corpus property tests would otherwise re-run the same 496 audits three times.
# Deliberately caches only the small derived strings, never the Finding objects.
_ENCODED_CACHE: dict[Path, str] = {}


def _encoded(home: Path) -> str:
    cached = _ENCODED_CACHE.get(home)
    if cached is None:
        cached = _encode_pairs(_fingerprint_pairs(home))
        _ENCODED_CACHE[home] = cached
    return cached


# ---------------------------------------------------------------------------------------
# The failure diagnostic. Extracted from the guard so the guard-the-guard tests below can
# drive it directly, and so BOTH sides of the diff are reduced by the SAME function --
# the asymmetry this replaces (raw "<id>:<hash>" on one side, bare "<hash>" on the other)
# made every id in the fixture compare unequal, so a one-id drift was reported as ~160
# ids changed and the real culprit was invisible.
# ---------------------------------------------------------------------------------------

def _split_fp(entry: str) -> tuple[str, str]:
    """``("B176", "62fa8905")`` from ``"B176:62fa8905"``. Splits on the LAST colon --
    the 8-hex digest never contains one, so this stays exact even for an id that does."""
    fid, _, digest = entry.rpartition(":")
    return (fid or entry), digest


def _by_id(encoded: str) -> dict[str, str]:
    """``{id: digest}`` from one encoded manifest value. The single normalization both
    sides of the diff go through."""
    return dict(_split_fp(entry) for entry in encoded.split(",") if entry)


def _changed_ids(got: str, want: str) -> list[str]:
    """The check ids whose fingerprint actually moved between two encoded values."""
    got_by_id = _by_id(got)
    want_by_id = _by_id(want)
    return sorted(
        fid for fid in set(got_by_id) | set(want_by_id)
        if got_by_id.get(fid) != want_by_id.get(fid)
    )


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
        f"{rel}: finding fingerprint(s) changed for {_changed_ids(got, want)} -- if "
        "this is a deliberate, announced Finding.detail wording change, regenerate the "
        "manifest ('PYTHONPATH=. python3 tests/test_finding_fingerprint_manifest.py --write'); "
        "otherwise a check's detail text drifted unintentionally and will silently "
        "orphan real users' .clawseccheckignore fingerprint suppressions"
    )


# ---------------------------------------------------------------------------------------
# GUARD THE GUARD. A failure diagnostic only ever runs on failure, so nothing exercises
# it on a green build and it can rot unnoticed -- which is precisely what happened to the
# previous one. These drive it deliberately: perturb EXACTLY one entry of a real fixture's
# manifest value and require the message to name exactly that id and no other.
# ---------------------------------------------------------------------------------------

def _perturb_one(encoded: str, index: int) -> tuple[str, str]:
    """(*encoded* with entry *index*'s digest replaced, the id that was perturbed)."""
    entries = [e for e in encoded.split(",") if e]
    fid, digest = _split_fp(entries[index])
    entries[index] = f"{fid}:{'0' * 8 if digest != '0' * 8 else '1' * 8}"
    return ",".join(entries), fid


def _drop_one(encoded: str, index: int) -> tuple[str, str]:
    """(*encoded* with entry *index* removed, the id that was removed)."""
    entries = [e for e in encoded.split(",") if e]
    fid, _ = _split_fp(entries.pop(index))
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
    assert f"changed for ['{victim}']" in message, (
        f"expected the diagnostic to name exactly ['{victim}'] and no other id; got: "
        f"{message}"
    )


def test_diagnostic_names_only_the_removed_finding(monkeypatch):
    """Same, for the other half of the diff: an id present on one side only."""
    home = CORPUS[0]
    doctored, victim = _drop_one(_encoded(home), 0)

    message = _run_guard_expecting_failure(home, doctored, monkeypatch)
    assert f"changed for ['{victim}']" in message, (
        f"expected the diagnostic to name exactly ['{victim}'] and no other id; got: "
        f"{message}"
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
