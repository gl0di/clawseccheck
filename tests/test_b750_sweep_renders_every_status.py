"""B-750 — the installed-skill sweep must be able to render every status it can receive.

`--full`'s SKILL SWEEP section and `--vet-all` both crashed with ``KeyError`` on any home
whose installed skill shipped an archive with a traversing member::

    $ clawseccheck --vet-all --home <home with a zip-slip skill>
    clawseccheck: unexpected internal error (KeyError); re-run with --debug ...

The traversal was never printed. The tool died on the loudest finding it has.

WHY THE CRASH WAS THE LEAST OF IT
---------------------------------
``check_installed_skills`` can return ``SKILL_ARCHIVE_PATH_TRAVERSAL``. All three rank
tables know it and rank it with FAIL; the sweep compared against the bare literal
``"FAIL"`` in eight places, so it matched none of them. Two crashed. The other six failed
silently, and a patch that only added the dict key would have converted a loud crash into
a quiet lie:

    cli.py:588   has_fail        -> False        # feeds --exit-code under --full
    cli.py:602   counts()        -> counted SAFE # safe = total - fails - warns - truncated
    cli.py:859   worst           -> "PASS"
    cli.py:864   icon            -> KeyError     # the crash
    cli.py:866   verdict         -> KeyError     # the second one, behind the first
    cli.py:898   truncate demote -> TRUNCATED    # loses the traversal
    cli.py:948   partial marker  -> absent
    cli.py:1005  dangerous list  -> omitted

So a home whose only installed skill was a confirmed zip-slip reported ``0 dangerous,
1 safe`` and exit 0. That is the reassuring-but-false number Golden Rule #4 exists for.

WHAT THIS FILE GUARDS
---------------------
The instance is one dict key; the class is "a status reaches the sweep that the sweep
cannot render". ``test_every_mergeable_status_is_renderable`` derives the expectation from
``_VET_MERGE_RANK`` — the cascade's own vocabulary — rather than from a list written here,
so the NEXT status added to the cascade fails this test instead of crashing a user. A
hand-written list would have to be remembered; a derived one cannot be forgotten.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from clawseccheck.checks._vet import _VET_MERGE_RANK
from clawseccheck.cli import (
    _SWEEP_ACTIONABLE_STATUSES,
    _SWEEP_FAIL_STATUSES,
    _SWEEP_ICON_ASCII,
    _SWEEP_ICON_UNI,
    _SWEEP_VERDICT,
    _sweep_quiet_line,
    sweep_installed_skills,
    vet_all,
)
from clawseccheck.dossier import _STATUS_RANK

_TRAVERSAL = "SKILL_ARCHIVE_PATH_TRAVERSAL"


@pytest.mark.parametrize(
    "table, name",
    [(_SWEEP_ICON_ASCII, "_SWEEP_ICON_ASCII"),
     (_SWEEP_ICON_UNI, "_SWEEP_ICON_UNI"),
     (_SWEEP_VERDICT, "_SWEEP_VERDICT")],
)
def test_every_mergeable_status_is_renderable(table, name):
    """The class guard. Derived from the cascade's vocabulary, not from a literal list."""
    missing = sorted(set(_VET_MERGE_RANK) - set(table))
    assert not missing, (
        f"{name} cannot render {missing} — check_installed_skills can return these and the "
        "sweep indexes this table with the raw status, so each one is a KeyError crash in "
        "--full and --vet-all (B-750)"
    )


def test_fail_weight_is_derived_from_the_rank_tables_not_asserted():
    """``_SWEEP_FAIL_STATUSES`` must be exactly the statuses ranked with FAIL.

    Pins the set against the two tables that decide the winner and the dossier verdict, so
    it cannot drift into a hand-maintained list. ``report._VET_STATUS_RANK`` is deliberately
    NOT used: it ranks the traversal at 1, a pre-existing disagreement filed under B-746 and
    left standing rather than quietly reconciled here.
    """
    fail_rank = _VET_MERGE_RANK["FAIL"]
    expected = {s for s, r in _VET_MERGE_RANK.items() if r == fail_rank}

    assert _SWEEP_FAIL_STATUSES == expected, (_SWEEP_FAIL_STATUSES, expected)
    assert {s for s, r in _STATUS_RANK.items() if r == _STATUS_RANK["FAIL"]} == expected
    assert _SWEEP_ACTIONABLE_STATUSES == expected | {"WARN"}


def _home(tmp_path: Path, *, member: str, name: str = "h") -> Path:
    home = tmp_path / name
    d = home / "workspace" / "skills" / "archive-demo"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: archive-demo\ndescription: A skill.\n---\nunpack bundle.zip\n",
        encoding="utf-8",
    )
    with zipfile.ZipFile(d / "bundle.zip", "w") as z:
        z.writestr(member, "x")
    return home


def test_the_sweep_no_longer_crashes(tmp_path):
    """The reported symptom, through the function the two CLI modes share."""
    sweep = sweep_installed_skills(_home(tmp_path, member="../../../tmp/escape.txt"),
                                   narrate=False)
    assert [s for _n, s, _e in sweep.rows] == [_TRAVERSAL]


def test_the_aggregate_treats_it_as_dangerous(tmp_path):
    """The five silent sites, in one assertion each.

    This is the half a dict-key-only patch would have left broken, so each is checked
    against the value it had then, not merely against "is truthy".
    """
    sweep = sweep_installed_skills(_home(tmp_path, member="../../../tmp/escape.txt"),
                                   narrate=False)
    c = sweep.counts()

    assert sweep.worst == "FAIL", sweep.worst          # was "PASS"
    assert sweep.has_fail is True                      # was False -> --exit-code stayed 0
    assert c["fails"] == 1, c                          # was 0
    assert c["safe"] == 0, c                           # was 1 — a zip-slip counted as safe
    assert c["total"] == 1, c


def test_a_benign_archive_is_still_safe(tmp_path):
    """The other direction: the widening must not convict an ordinary bundled archive."""
    sweep = sweep_installed_skills(_home(tmp_path, member="payload/notes.txt"), narrate=False)

    assert sweep.worst == "PASS", (sweep.worst, sweep.rows)
    assert sweep.has_fail is False
    assert sweep.counts()["safe"] == 1, sweep.counts()


def test_the_summary_names_the_dangerous_skill(tmp_path, capsys):
    """End to end through ``--vet-all``: the rendered text, the tally and the exit code."""
    rc = vet_all(_home(tmp_path, member="../../../tmp/escape.txt"), ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 1
    assert "escape.txt" in out, out[-800:]
    assert "1 dangerous" in out, out[-800:]
    assert "0 safe" in out, out[-800:]


def test_the_quiet_full_line_also_names_it(tmp_path):
    """The SECOND renderer, which ``--full``'s quiet branch uses instead of the table.

    Both read the same rows, but only this one builds the ``Dangerous: <names>`` list, off
    its own ``s in _SWEEP_FAIL_STATUSES`` comparison (cli.py:1022). Asserting only the
    ``--vet-all`` table would leave that comparison unproven — the two renderers were
    equally broken before, and a per-renderer test is what tells them apart.
    """
    sweep = sweep_installed_skills(_home(tmp_path, member="../../../tmp/escape.txt"),
                                   narrate=False)
    line = _sweep_quiet_line(sweep)

    assert "1 dangerous" in line, line
    assert "Dangerous: archive-demo" in line, line


def test_both_icon_tables_agree_on_which_statuses_they_cover():
    """A status renderable in unicode but not in ASCII would crash only under ``--ascii``.

    Cheap, and it closes the asymmetric-table failure mode that a single-table test would
    miss entirely.
    """
    assert set(_SWEEP_ICON_ASCII) == set(_SWEEP_ICON_UNI) == set(_SWEEP_VERDICT)
