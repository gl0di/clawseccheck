"""B-746 — cascade POSITION must not override the tree's own severity ranking.

``check_installed_skills`` is a first-match-wins cascade of 25 arms. ``path_traversal`` was
arm 22, below nineteen lower-ranked arms — but it emits ``SKILL_ARCHIVE_PATH_TRAVERSAL``,
which the two tables that decide a VERDICT (``_VET_MERGE_RANK`` and
``dossier._STATUS_RANK``) both rank **3**, the same as FAIL. So any earlier WARN won
instead, and the traversal vanished from the report.

A third table, ``report._VET_STATUS_RANK``, ranks it 1 and is a known pre-existing
disagreement — see ``test_the_verdict_rank_tables_agree_and_the_render_table_is_known_to_differ``.
Saying "both rank tables" here was wrong by omission until this change's own C-135 pass
counted them.

Measured before the fix, two homes differing by one ordinary-looking file, both shipping a
``bundle.zip`` whose only member is ``../../../tmp/escape_via_zip.txt``::

    SKILL.md + bundle.zip
        -> SKILL_ARCHIVE_PATH_TRAVERSAL / DO-NOT-INSTALL, the traversal named
    the same + cache.py containing open("/tmp/demo_cache.txt", "w")
        -> WARN / CAUTION "insecure temp-file handling", and the word "traversal"
           absent from the entire report

**One line of ordinary caching code demoted a confirmed zip-slip.** That is a verdict
inversion an author can trigger deliberately, not a disclosure gap.

This is the same defect B-201 fixed one layer up at the vet merge ("letting any ordinary
content-ring WARN outrank and hide a detected path-traversal archive") and B-160 fixed in
the dossier rank table. It survived inside the cascade those two layers merge from, which
is why the guard below is structural rather than another case: the next FAIL-rank arm
appended to the bottom of this cascade would reintroduce it silently.

WHAT IS DELIBERATELY *NOT* REORDERED
------------------------------------
The coverage arms — ``parse_error_paths`` and the ``skill_limit_hits`` family — stay above
everything, including the rank-3 traversal arm. They answer "the scan could not see all of
this" and carry ``engine_degraded``, which caps the audit score. Promoting a rank-3 arm
above them would trade a capped, honest UNKNOWN for a confident FAIL that hides the gap.
Pinned below, with the measured baseline.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import zipfile
from pathlib import Path

from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import collect

REPO = Path(__file__).resolve().parent.parent

#: The tree's own severity ranking, from ``checks/_vet.py``'s ``_VET_MERGE_RANK`` and
#: ``dossier._STATUS_RANK``. SKILL_ARCHIVE_PATH_TRAVERSAL is rank 3 in both — that equality
#: is the whole point: a status ranked with FAIL must be adjudicated with FAIL.
_RANK = {"FAIL": 3, "SKILL_ARCHIVE_PATH_TRAVERSAL": 3, "WARN": 2, "UNKNOWN": 1, "PASS": 0}

#: Arms whose job is to say "the scan could not see everything", deliberately adjudicated
#: before any positive finding. Named rather than inferred: their rank is LOWER than the
#: traversal arm's, so a rank-only rule would flag them, and flagging them would be wrong.
_COVERAGE_FIRST = frozenset({"parse_error_paths", "skill_limit_hits"})

_TRAVERSAL_MEMBER = "../../../tmp/escape_via_zip.txt"
_BENIGN_TEMPFILE = 'open("/tmp/demo_cache.txt", "w").write("x")\n'


def _cascade_arms() -> list:
    """Every ``if <bucket>: return _b13_verdict(...)`` arm, in source order.

    Read from the source rather than by running the engine: the property under test is
    about ORDER, and only the source knows it. Self-checking — the caller asserts a
    plausible arm count, so a refactor that breaks this extraction fails loudly instead of
    passing vacuously over an empty list.
    """
    fn = next(
        n for n in ast.walk(ast.parse((REPO / "clawseccheck" / "checks" / "_vet.py").read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == "check_installed_skills"
    )
    arms = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        for st in node.body:
            if not (isinstance(st, ast.Return) and isinstance(st.value, ast.Call)):
                continue
            f = st.value.func
            if (getattr(f, "id", None) or getattr(f, "attr", None)) != "_b13_verdict":
                continue
            args = st.value.args
            status = getattr(args[1], "id", None) or getattr(args[1], "value", None)
            winner = args[6].value if len(args) > 6 and isinstance(args[6], ast.Constant) else None
            arms.append((node.lineno, str(status), winner))
    arms.sort()
    return arms


def _inversions(arms) -> list:
    """Arms ranked FAIL-equivalent that sit below a lower-ranked, non-coverage arm."""
    bad, lower_seen = [], []
    for lineno, status, winner in arms:
        rank = _RANK.get(status)
        if rank is None:
            continue
        if rank == 3 and lower_seen:
            bad.append(f"{winner} (line {lineno}, rank 3) sits below {lower_seen}")
        elif rank < 3 and winner not in _COVERAGE_FIRST:
            lower_seen.append(winner)
    return bad


def _home(tmp_path: Path, name: str, *, extra_file: bool) -> Path:
    home = tmp_path / name
    d = home / "workspace" / "skills" / "demo"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: demo\ndescription: A skill.\n---\nsee bundle\n", encoding="utf-8"
    )
    with zipfile.ZipFile(d / "bundle.zip", "w") as z:
        z.writestr(_TRAVERSAL_MEMBER, "x")
    if extra_file:
        (d / "cache.py").write_text(_BENIGN_TEMPFILE, encoding="utf-8")
    return home


def test_a_benign_file_cannot_hide_a_zip_slip(tmp_path):
    """The headline. The only variable is one ordinary-looking file."""
    without = check_installed_skills(collect(_home(tmp_path, "a", extra_file=False)))
    with_extra = check_installed_skills(collect(_home(tmp_path, "b", extra_file=True)))

    assert without.status == "SKILL_ARCHIVE_PATH_TRAVERSAL", without.status
    assert with_extra.status == without.status, (
        "adding a benign file changed the verdict: "
        f"{without.status} -> {with_extra.status} ({with_extra.detail[:120]})"
    )
    for f in (without, with_extra):
        assert "traversal" in (f.detail or "").lower(), f.detail


def test_the_traversal_is_still_named_when_a_warn_also_fired(tmp_path):
    """Not merely the same status — the reader must still be told WHICH danger.

    Before the fix the whole report, detail and evidence, contained no occurrence of the
    word: the finding spoke only about temp-file handling.
    """
    f = check_installed_skills(collect(_home(tmp_path, "c", extra_file=True)))
    blob = (f.detail or "") + " " + " ".join(getattr(f, "evidence", None) or [])
    assert "escape_via_zip.txt" in blob, blob[:300]


def test_the_coverage_arms_still_win_over_the_traversal_arm(tmp_path):
    """The bound on the fix, and the reason the arm was not promoted further.

    `parse_error_paths` / `skill_limit_hits` / the unreadable-file branch carry
    `engine_degraded`, which caps the audit score. Measured baseline on a home holding BOTH
    an unreadable file and a traversal archive: UNKNOWN with engine_degraded=True. Promoting
    a rank-3 arm above them would swap a capped, honest UNKNOWN for a confident FAIL that
    hides the gap — a worse trade than the one being fixed.
    """
    home = _home(tmp_path, "d", extra_file=False)
    locked = home / "workspace" / "skills" / "demo" / "locked.py"
    locked.write_text("secret\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        f = check_installed_skills(collect(home))
    finally:
        locked.chmod(0o600)  # leave tmp_path removable

    assert f.status == "UNKNOWN", f.status
    assert getattr(f, "engine_degraded", False) is True, (
        "the coverage arm must keep engine_degraded, or the audit score loses its cap"
    )


def test_no_fail_ranked_arm_sits_below_a_lower_ranked_one():
    """The CLASS guard, and the reason this file exists rather than one behavioural pin.

    B-201 fixed this shape at the vet merge and B-160 in the dossier rank table; neither
    reached the cascade they merge from, and nothing compared cascade ORDER with the rank
    table it feeds. A new FAIL-rank arm appended to the bottom of this cascade would
    reintroduce the defect with every test still green.
    """
    arms = _cascade_arms()
    assert len(arms) >= 20, (
        f"extracted only {len(arms)} cascade arms — the AST shape changed and this guard "
        "is no longer measuring what it claims; re-ground it"
    )

    bad = _inversions(arms)
    assert not bad, (
        "these arms emit a status ranked 3 (FAIL-equivalent in _VET_MERGE_RANK and "
        "dossier._STATUS_RANK) but are adjudicated after lower-ranked arms, so cascade "
        "position overrides severity and an earlier WARN hides them:\n  "
        + "\n  ".join(bad)
        + "\n\nMove the arm above the WARN block (but below the coverage arms — see "
        "test_the_coverage_arms_still_win_over_the_traversal_arm)."
    )


def test_the_class_guard_bites_on_the_order_that_shipped():
    """Positive control, using the real pre-fix arm order.

    Without it the sweep above passes both on a correct cascade AND on one where the AST
    extraction quietly matched nothing — indistinguishable from one green run.
    """
    pre_b746 = [
        (100, "FAIL", "crit"),
        (200, "UNKNOWN", "parse_error_paths"),
        (300, "UNKNOWN", "skill_limit_hits"),
        (400, "WARN", "warns_install_curl"),
        (500, "WARN", "warns_insecure_tempfile"),
        (600, "SKILL_ARCHIVE_PATH_TRAVERSAL", "path_traversal"),
    ]
    bad = _inversions(pre_b746)
    assert len(bad) == 1 and "path_traversal" in bad[0], bad

    # and the coverage arms alone must NOT trip it — they are ranked lower on purpose
    coverage_only = [
        (100, "UNKNOWN", "parse_error_paths"),
        (200, "UNKNOWN", "skill_limit_hits"),
        (300, "SKILL_ARCHIVE_PATH_TRAVERSAL", "path_traversal"),
    ]
    assert _inversions(coverage_only) == [], (
        "the guard must not demand that a rank-3 arm outrank the coverage arms — that is "
        "the promotion this fix deliberately did not make"
    )


def test_the_verdict_rank_tables_agree_and_the_render_table_is_known_to_differ():
    """The guard's premise, stated with the exception it actually has.

    An earlier version of this test asserted "both rank tables" put
    SKILL_ARCHIVE_PATH_TRAVERSAL with FAIL. There are THREE, and the third disagrees —
    found by this change's own C-135 pass, not by the suite. Asserting two of three and
    calling it agreement is the shape this repo keeps getting caught by, so the third is
    pinned explicitly rather than left out of the sentence.

    The two that decide a VERDICT agree at rank 3. `report._VET_STATUS_RANK` ranks it 1
    (UNKNOWN-level) and `scoring.compute` leaves it out of the scored set accordingly.
    That inconsistency is pre-existing, was measured not to move the audit score on any
    trav/warn combination, and is filed separately. If it is ever reconciled, this test
    should be updated — not deleted, because the reconciliation is exactly the event a
    reader of the cascade needs to know about.
    """
    from clawseccheck.checks._vet import _VET_MERGE_RANK
    from clawseccheck.dossier import _STATUS_RANK
    from clawseccheck import report

    key = "SKILL_ARCHIVE_PATH_TRAVERSAL"
    for table, name in ((_VET_MERGE_RANK, "_VET_MERGE_RANK"), (_STATUS_RANK, "dossier._STATUS_RANK")):
        assert table.get(key) == table.get("FAIL"), (
            f"{name} no longer ranks {key} with FAIL; the cascade ordering guard in this "
            "file is derived from that equality"
        )

    render = getattr(report, "_VET_STATUS_RANK", None)
    assert render is not None, "report._VET_STATUS_RANK vanished — re-ground this test"
    assert render.get(key) != render.get("FAIL"), (
        "report._VET_STATUS_RANK now ranks the traversal status with FAIL, i.e. the "
        "three-way disagreement this test documents has been resolved. Good news — "
        "update this assertion and the comment in checks/_vet.py's path-traversal arm, "
        "which tells the reader the render table differs."
    )
