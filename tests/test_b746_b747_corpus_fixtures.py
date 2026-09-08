"""The corpus homes for B-746 and B-747, and what each one is for.

Both defects were found and fixed against skills built in ``tmp_path``. That is enough to
prove a fix and not enough to keep it: a ``tmp_path`` skill is visible only to the test
that builds it, while a fixture home is swept by every corpus-wide gate this repo runs —
the fingerprint manifest, the fleet-FP gate, the renderers. Neither shape existed in
``fixtures/`` before, and their absence had a measurable consequence: of the 698 corpus
homes, **0 carried an archive of any kind** -- no ``.zip``, ``.whl``, ``.tar*`` anywhere
under ``fixtures/`` -- so the entire zip-slip path was corpus-dark. The four archives
these homes add are, as of this commit, the only four in the tree.

WHAT EACH PAIR PINS, AND THAT IT WOULD HAVE FAILED BEFORE
--------------------------------------------------------
Both pairs were run against the real pre-fix code, not reasoned about:

``b746`` — a WARN must not hide a confirmed traversal. The two homes hold the SAME skill;
the only difference is whether ``bundle.zip`` escapes. Against ``f6a0357^`` (B-743 in,
B-746 out) both homes returned::

    WARN  Insecure temp-file handling in installed skill(s): archive-demo: ...

i.e. byte-identical verdicts — the escape was not downgraded, it was invisible, because
the WARN arm sat above the traversal arm in a first-match-wins cascade. That is why the
benign half carries the WARN too: without it the pair would prove ordering only by
assertion. ``test_the_warn_is_present_in_both`` keeps that property from rotting away.

``b747`` — an archive member's safety must not depend on what is on disk beside it.
``warn_b747`` is an ordinary editable checkout next to its own built wheel, which is not
an exotic arrangement: for a Python package the source directory and the wheel's
top-level package have the same name *by construction*. Against the pre-fix predicate
(join + ``.resolve()``, which follows the symlink) its most ordinary member is judged an
escape::

    mypkg/__init__.py            -> ESCAPE
    mypkg-1.0.dist-info/METADATA -> safe

A false-positive FAIL on a benign skill is Golden Rule #5. ``bad_b747`` is the same home
with the same symlink plus a member that genuinely escapes — the direction that matters
more, since a fix must not buy its relief by loosening the predicate.

The measured pre-fix answers for that pair are sharper than "one false positive", and are
the reason the assertions below check the *detail* and not only the status::

    bad_b747   -> Archive path traversal detected: ...whl::mypkg/__init__.py
    warn_b747  -> Archive path traversal detected: ...whl::mypkg/__init__.py

Identical strings. On the home that really did ship an escape the tool convicted for the
wrong member and never named ``../../../tmp/escape_via_wheel.txt`` at all — right by
accident, with evidence pointing at the benign file. A status-only assertion would have
called that a pass.

WHY THE BENIGN HALVES ARE ``warn_`` AND NOT ``clean_``
-----------------------------------------------------
The ``clean_`` prefix carries a contract this repo enforces in three places
(``test_vet_content_ring.py::test_clean_skill_stays_silent_via_vet``,
``test_dossier.py::test_clean_skill_profile_has_no_failing_axis``, and the full-corpus
sweep): a ``clean_`` home's SKILL must vet with no FAIL and no WARN from any check. Both
benign homes here breach it, and in both cases the WARN is inherent to what the fixture
reproduces rather than incidental:

  * ``warn_b746`` carries the temp-file WARN on purpose -- it is the arm that used to
    outrank the traversal, so removing it would destroy the ordering test.
  * ``warn_b747`` trips ``B87`` (symlink escape) on the vet path, because the wheel's
    top-level name must collide with a symlink pointing OUT of the skill directory for
    the false positive to exist at all. A symlink that stays inside would resolve within
    the root and reproduce nothing.

So neither can be made silent without ceasing to test anything, and ``warn_`` (14 other
homes use it) is the accurate prefix. Note that ``B87`` firing here is scoped to the VET
path, whose root is the skill directory; a home-scoped ``run_all`` over the same fixture
is silent on B87, which is the measurement B-747's residual note records.

These are corpus tests. The unit-level batteries stay where they were:
``tests/test_b746_cascade_rank_order.py`` and ``tests/test_b747_traversal_is_lexical.py``.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_TRAVERSAL = "SKILL_ARCHIVE_PATH_TRAVERSAL"

#: (home, skill dir, archive, the member that escapes or None)
_HOMES = {
    "bad_b746_traversal_masked_by_warn": ("archive-demo", "bundle.zip", "../../../tmp/escape_via_zip.txt"),
    "warn_b746_tempfile_without_traversal": ("archive-demo", "bundle.zip", None),
    "bad_b747_real_escape_behind_symlink": ("wheel-demo", "mypkg-1.0-py3-none-any.whl", "../../../tmp/escape_via_wheel.txt"),
    "warn_b747_editable_checkout_wheel": ("wheel-demo", "mypkg-1.0-py3-none-any.whl", None),
}


#: The homes that must convict, and the homes that must not. Named explicitly rather than
#: derived from the ``bad_``/``warn_`` prefix: the benign pair carries a WARN by design, so a
#: prefix rule would silently reclassify one if a future rename touched it.
_BAD = {h for h in _HOMES if h.startswith("bad_")}
_BENIGN = set(_HOMES) - _BAD


def _skill_dir(home: str) -> Path:
    return FIXTURES / home / "workspace" / "skills" / _HOMES[home][0]


def _verdict(home: str):
    return check_installed_skills(collect(FIXTURES / home))


@pytest.mark.parametrize("home", sorted(_HOMES))
def test_the_home_is_shaped_like_the_rest_of_the_corpus(home):
    """Guard against a fixture that silently stops being collected.

    A home missing ``openclaw.json`` still parses, still yields a Context, and simply
    contributes nothing — it would pass every verdict assertion below by being empty.
    """
    assert (FIXTURES / home / "openclaw.json").is_file()
    assert (_skill_dir(home) / "SKILL.md").is_file()

    archive = _skill_dir(home) / _HOMES[home][1]
    assert archive.is_file(), f"{home} has no archive — the whole point of the fixture"
    with zipfile.ZipFile(archive) as z:
        members = z.namelist()
    escape = _HOMES[home][2]
    if escape is None:
        assert not any(m.startswith("../") for m in members), members
    else:
        assert escape in members, members


@pytest.mark.parametrize("home", sorted(_BAD))
def test_a_bad_home_convicts(home):
    f = _verdict(home)
    assert f.status == _TRAVERSAL, (f.status, (f.detail or "")[:200])
    assert _HOMES[home][2] in (f.detail or ""), f.detail


@pytest.mark.parametrize("home", sorted(_BENIGN))
def test_a_clean_home_is_not_a_traversal(home):
    f = _verdict(home)
    assert f.status != _TRAVERSAL, (f.status, (f.detail or "")[:200])
    assert "traversal" not in (f.detail or "").lower(), f.detail


def test_the_b746_pair_differs_only_by_the_escape():
    """The ordering pin, stated as a difference rather than as two absolute verdicts.

    Pre-fix these two returned the same string. Asserting only ``bad -> TRAVERSAL`` would
    also hold for a build that convicts everything, so the clean half is asserted to still
    be the WARN it was — the verdict the escape has to outrank.
    """
    bad, clean = _verdict("bad_b746_traversal_masked_by_warn"), _verdict("warn_b746_tempfile_without_traversal")

    assert bad.status == _TRAVERSAL, bad.status
    assert clean.status == "WARN", (clean.status, (clean.detail or "")[:200])
    assert bad.status != clean.status


def test_the_warn_is_present_in_both():
    """Keeps the bad home a real ordering test rather than a plain traversal test.

    If the temp-file WARN ever stops firing on ``archive-demo`` — the check retuned, the
    fixture edited — then ``bad_b746`` would still convict, but it would no longer prove
    that a traversal outranks a WARN, and nothing else would notice. This fails loudly at
    that moment. The WARN is read off the clean twin, whose cascade is not short-circuited
    by the escape.
    """
    clean = _verdict("warn_b746_tempfile_without_traversal")
    assert clean.status == "WARN"
    assert "temp-file" in (clean.detail or ""), clean.detail
    assert "archive-demo" in (clean.detail or ""), clean.detail


def test_the_b747_symlink_is_real_and_stays_inside_the_home():
    """A checked-out symlink is portable only if its target is inside the fixture.

    ``fixtures/`` had no symlink at all before this pair, so this states the two
    properties the rest of the corpus assumes: it IS a symlink (git preserves it, and
    without it the fixture tests nothing), and it does not reach outside its own home on
    a fresh clone.
    """
    for home in ("warn_b747_editable_checkout_wheel", "bad_b747_real_escape_behind_symlink"):
        link = _skill_dir(home) / "mypkg"
        assert link.is_symlink(), f"{home}: not a symlink — the fixture is inert"

        root = (FIXTURES / home).resolve()
        target = link.resolve()
        assert target == root or root in target.parents, (
            f"{home}: the symlink leaves its own fixture home ({target}) — not portable"
        )
        assert (target / "__init__.py").is_file(), f"{home}: dangling symlink"


def test_the_b747_collision_is_the_ordinary_packaging_one():
    """Names the coincidence the false positive rested on, so a rename cannot mute it.

    The wheel's top-level package and the checkout directory must keep the SAME name.
    Rename either and the fixture still passes every assertion above while no longer
    reproducing anything.
    """
    for home in ("warn_b747_editable_checkout_wheel", "bad_b747_real_escape_behind_symlink"):
        with zipfile.ZipFile(_skill_dir(home) / _HOMES[home][1]) as z:
            tops = {m.split("/")[0] for m in z.namelist() if not m.startswith("../")}
        assert "mypkg" in tops, (home, tops)
        assert (_skill_dir(home) / "mypkg").is_symlink()
