"""B-751 — a FAIL-weight status must survive every consumer, not just the ones we noticed.

``check_installed_skills`` can return ``SKILL_ARCHIVE_PATH_TRAVERSAL``: a CONFIRMED zip-slip
in an installed skill, which ``_VET_MERGE_RANK`` and ``dossier._STATUS_RANK`` both rank with
FAIL. Roughly thirty sites across eight modules compared against the bare literal ``"FAIL"``,
so the status matched none of them, and **every one degraded toward "fine" rather than toward
"unknown"**. Measured on a home whose only installed skill ships a confirmed escape:

    scoring.compute()            96 / grade A      (79 / C once the conviction counts)
    report._worst_of_statuses()  "PASS"            (the rollup of a zip-slip, alone)
    risk_paths()                 []                (RISK-09, CRITICAL, never fired)
    render_sarif()               7 results, none naming the escape
    render_pdf()                 the escape absent from the document
    report._skill_inventory()    "SUSPICIOUS - Insecure temp-file handling"
    guide.suggest_actions()      3 actions, none about skills; the MILDER temp-file WARN
                                 on the same skill got 4, including the skill action

The last one is the shape of the whole defect: the tool advised on a hardcoded temp-file path
and said nothing about a confirmed archive escape beside it.

WHY THIS FILE IS BEHAVIOURAL AND NOT A GREP
-------------------------------------------
The tempting guard is "no bare ``in (FAIL, WARN)`` anywhere". That is unenforceable — the
literal is correct in the many places where the status genuinely cannot arrive — and a guard
that must be suppressed at half its hits teaches people to suppress it. So the class is closed
from the other end: for EVERY status that ranks with FAIL, drive the real consumers and require
the conviction to survive. A new status added to the cascade is picked up automatically,
because the list is derived from ``_VET_MERGE_RANK`` rather than written here.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import re
import zipfile
import zlib
from pathlib import Path

from clawseccheck.catalog import ACTIONABLE_STATUSES, FAIL_WEIGHT_STATUSES
from clawseccheck.checks import run_all
from clawseccheck.checks._vet import _VET_MERGE_RANK
from clawseccheck.collector import collect
from clawseccheck.dossier import _STATUS_RANK

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TRAVERSAL_HOME = FIXTURES / "bad_b746_traversal_masked_by_warn"
BENIGN_HOME = FIXTURES / "warn_b746_tempfile_without_traversal"


def _findings(home: Path):
    ctx = collect(home)
    return ctx, run_all(ctx)


# ---------------------------------------------------------------- the shared vocabulary


def test_the_set_is_derived_from_the_rank_tables():
    """``FAIL_WEIGHT_STATUSES`` must be exactly what the two live rank tables call FAIL.

    Both are checked, not one: they are maintained separately, and the whole defect began
    with a comment asserting agreement having looked at a subset.
    """
    for table, name in ((_VET_MERGE_RANK, "_VET_MERGE_RANK"), (_STATUS_RANK, "dossier._STATUS_RANK")):
        at_fail = {s for s, r in table.items() if r == table["FAIL"]}
        assert at_fail == FAIL_WEIGHT_STATUSES, (
            f"{name} ranks {sorted(at_fail)} with FAIL but catalog.FAIL_WEIGHT_STATUSES is "
            f"{sorted(FAIL_WEIGHT_STATUSES)} — add the new status to the shared set, then "
            "run this file: every consumer below is checked against it automatically."
        )
    assert ACTIONABLE_STATUSES == FAIL_WEIGHT_STATUSES | {"WARN"}


def test_catalog_stays_a_leaf():
    """The set lives in ``catalog`` so `checks/` and the renderers can share one definition.

    That only works while ``catalog`` imports nothing from the package; if it grows a package
    import the constant has to move, and the layering rule in CLAUDE.md §3 is what breaks.
    """
    src = (Path(__file__).resolve().parent.parent / "clawseccheck" / "catalog.py").read_text()
    offenders = [
        ln for ln in src.splitlines()
        if re.match(r"\s*(from|import)\s", ln) and ("clawseccheck" in ln or re.match(r"\s*from\s+\.", ln))
    ]
    assert not offenders, offenders


# ---------------------------------------------------------------- the consumers, driven


def test_the_score_counts_the_conviction():
    from clawseccheck.scoring import compute

    _, fs = _findings(TRAVERSAL_HOME)
    bad = compute(fs)
    _, benign = _findings(BENIGN_HOME)
    good = compute(benign)

    assert bad.score < good.score, (
        f"a confirmed zip-slip scores {bad.score}/{bad.grade} while the same skill with only "
        f"a temp-file WARN scores {good.score}/{good.grade} — the conviction is not counted"
    )
    assert bad.grade != "A", (bad.score, bad.grade)


def test_the_severity_cap_applies():
    """The gate that actually moves the grade, and it is NOT the ``scored`` filter.

    Including the finding in ``scored`` alone moved the fixture 96 -> 94, because a traversal
    is neither PASS nor WARN and so earns nothing either way. What was missing is the
    severity-cap tally: with ``== FAIL`` there, a confirmed escape counted as no failure at
    all and FAIL_CAPS never applied. Pinned separately because the two are easy to confuse
    and only one of them is load-bearing.
    """
    from clawseccheck.scoring import compute

    _, fs = _findings(TRAVERSAL_HOME)
    assert compute(fs).score <= 79


def test_the_rollup_does_not_return_pass():
    from clawseccheck.report import _worst_of_statuses

    for status in sorted(FAIL_WEIGHT_STATUSES):
        assert _worst_of_statuses([status]) != "PASS", (
            f"_worst_of_statuses([{status!r}]) is PASS — the status is missing from "
            "report._STATUS_ORDER, and that function drops anything it does not recognise"
        )


def test_the_risk_chain_fires():
    from clawseccheck.risk import risk_paths

    ctx, fs = _findings(TRAVERSAL_HOME)
    assert "RISK-09" in [p.id for p in risk_paths(ctx, fs)], (
        "RISK-09 (CRITICAL: malicious skill + egress = active exfiltration) does not fire on "
        "a confirmed zip-slip — a whole CRITICAL chain disabled by a bare status literal"
    )


def test_sarif_emits_the_escape_as_an_error():
    from clawseccheck.sarif import render_sarif

    _, fs = _findings(TRAVERSAL_HOME)
    doc = json.loads(render_sarif(fs))
    results = doc["runs"][0]["results"]
    hits = [r for r in results if "traversal" in json.dumps(r).lower()]

    assert hits, "no SARIF result names the escape — a CI gate consuming SARIF is blind"
    assert all(r.get("level") == "error" for r in hits), [r.get("level") for r in hits]


def test_the_sarif_fail_counter_includes_it():
    """``failCount`` must count the conviction.

    An earlier draft of this test asserted the counters sum to ``len(findings)``. They do
    not, and never did: ``notApplicableCount`` overlaps the others and ``suppressedCount``
    is a separate dimension, so the sum is 209 against 188 findings on this fixture. That
    assertion would have been a false claim pinned by a green test. What the fix actually
    guarantees is narrower and checkable: a FAIL-weight status lands in ``failCount``
    instead of in none of the buckets.
    """
    from clawseccheck.sarif import render_sarif

    _, fs = _findings(TRAVERSAL_HOME)
    counts = json.loads(render_sarif(fs))["runs"][0]["properties"]["analysisCompleteness"]
    expected = sum(1 for f in fs if f.status in FAIL_WEIGHT_STATUSES)

    assert expected, "control broken: this fixture has no FAIL-weight finding"
    assert counts["failCount"] == expected, (counts, expected)


def test_the_pdf_contains_the_escape():
    """Decompress the streams: the page text is FlateDecode'd, so a raw byte search lies.

    A plain ``b"traversal" in pdf`` reports False on a document that does contain it — that
    false negative cost a diagnosis during this fix.
    """
    from clawseccheck.pdf import render_pdf
    from clawseccheck.scoring import compute

    _, fs = _findings(TRAVERSAL_HOME)
    blob = render_pdf(fs, compute(fs))

    text = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", blob, re.S):
        chunk = m.group(1)
        try:
            text += zlib.decompress(chunk)
        except zlib.error:
            text += chunk
    assert b"traversal" in text.lower(), "the escape is absent from the rendered PDF"


def test_the_default_report_row_is_dangerous():
    """The headline: the row a user reads on an ordinary run."""
    from clawseccheck.report import _skill_inventory

    rows = _skill_inventory(collect(TRAVERSAL_HOME))
    assert rows, "no skill rows produced"
    row = rows[0]

    assert row["status"] in FAIL_WEIGHT_STATUSES, row
    assert "DANGEROUS" in row["verdict"], row
    assert any("traversal" in r.lower() for r in row.get("reasons", [])), row


def test_the_per_skill_context_carries_the_violation():
    """The bridge, pinned at the collector rather than only at the row.

    ``report._skill_inventory`` builds a FRESH per-skill Context, so a signal recorded only on
    the main ctx is structurally invisible to it — the B-551 defect, one signal over. The
    violation string is ``<path relative to the skill dir>::<member>``, so two skills each
    shipping a ``bundle.zip`` produce identical strings; attribution has to come from the
    collector, which knows the skill directory, and cannot be recovered downstream.
    """
    ctx = collect(TRAVERSAL_HOME)
    assert ctx.skill_traversal_violations, "the collector did not attribute the violation"

    # keyed by the skill directory's PATH, not its name — see the next test for why
    dirs = getattr(ctx, "installed_skill_dirs", {}) or {}
    assert set(ctx.skill_traversal_violations) == {str(dirs["archive-demo"])}, (
        ctx.skill_traversal_violations, dirs
    )
    assert collect(BENIGN_HOME).skill_traversal_violations == {}


def test_attribution_does_not_leak_between_skills(tmp_path):
    """Two skills, identical archive NAMES, only one of them escaping.

    The naive attribution — "does this skill's directory contain a file with that relpath?" —
    convicts both, because the string carries no skill identity. This is the case that rules
    it out, and it is why the fix lives in the collector.
    """
    home = tmp_path / "home"
    for name, member in (("guilty", "../../../tmp/e.txt"), ("innocent", "data/ok.txt")):
        d = home / "workspace" / "skills" / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: A skill.\n---\nsee bundle\n", encoding="utf-8"
        )
        with zipfile.ZipFile(d / "bundle.zip", "w") as z:   # SAME archive name in both
            z.writestr(member, "x")
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1:8080"}}', encoding="utf-8")

    ctx = collect(home)
    dirs = getattr(ctx, "installed_skill_dirs", {}) or {}
    assert set(ctx.skill_traversal_violations) == {str(dirs["guilty"])}, (
        ctx.skill_traversal_violations, dirs
    )


def test_attribution_survives_a_basename_collision(tmp_path):
    """The case the test above does NOT cover, and the one that broke the first fix.

    ``test_attribution_does_not_leak_between_skills`` names its two skills ``guilty`` and
    ``innocent`` — different basenames — so it passed against an attribution keyed on the
    bare directory NAME. Its own C-135 found the hole: ``installed_skills`` de-duplicates
    colliding basenames into ``skills/<name>`` / ``<name>#2``, so a name-keyed map joins to
    the wrong entry whenever the same skill name exists under two load roots.

    Measured on that first fix, and it is inverted rather than merely lost: the copy
    shipping nothing but a SKILL.md was convicted DANGEROUS, and the copy that really
    shipped the zip-slip rendered ``SUSPICIOUS - Insecure temp-file handling`` — the exact
    B-746 symptom this whole change exists to remove. Convicting an innocent subject is
    worse than the defect being fixed, so this pins the join by PATH.
    """
    from clawseccheck.report import _skill_inventory

    home = tmp_path / "home"
    # same basename under two different load roots
    evil = home / "workspace" / "skills" / "archive-demo"
    evil.mkdir(parents=True)
    (evil / "SKILL.md").write_text(
        "---\nname: archive-demo\ndescription: A skill.\n---\nsee bundle\n", encoding="utf-8"
    )
    with zipfile.ZipFile(evil / "bundle.zip", "w") as z:
        z.writestr("../../../tmp/escape.txt", "x")

    good = home / "skills" / "archive-demo"
    good.mkdir(parents=True)
    (good / "SKILL.md").write_text(
        "---\nname: archive-demo\ndescription: A skill.\n---\njust prose\n", encoding="utf-8"
    )
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1:8080"}}', encoding="utf-8")

    ctx = collect(home)
    dirs = getattr(ctx, "installed_skill_dirs", {}) or {}
    assert len(dirs) == 2, f"control broken: expected two colliding skills, got {dirs}"

    for row in _skill_inventory(ctx):
        ships_the_escape = "workspace" in str(dirs.get(row["name"], ""))
        convicted = row["status"] in FAIL_WEIGHT_STATUSES
        assert convicted == ships_the_escape, (
            f"{row['name']!r} (dir {dirs.get(row['name'])}) is "
            f"{'convicted' if convicted else 'cleared'} but "
            f"{'ships' if ships_the_escape else 'does not ship'} the escape"
        )


def test_the_text_report_does_not_call_it_clean():
    """The renderer a human actually reads, pinned separately from the JSON inventory.

    ``_skill_inventory`` returning a correct DANGEROUS row is not the same as the report
    printing it, and for one revision of this fix it was not: ``_skills_inventory_lines``
    kept a bare ``in (FAIL, WARN, UNKNOWN)``, so the row fell out of ``flagged``, landed in
    the ``clean`` roster and its detail line was never emitted. The block printed, in
    consecutive lines::

        Skills (1 installed) — 1 issue(s)
        1 clean: archive-demo

    for a home whose only installed skill was a confirmed zip-slip. Asserting the JSON row
    alone would have called that a pass — which is why this asserts the rendered text.
    """
    from clawseccheck.report import render_report
    from clawseccheck.scoring import compute

    ctx, fs = _findings(TRAVERSAL_HOME)
    text = render_report(fs, compute(fs), ctx=ctx)

    assert "clean: archive-demo" not in text, (
        "the skills block lists a confirmed zip-slip in its clean roster"
    )
    assert "archive-demo" in text and "traversal" in text.lower()


def test_the_guide_advises_on_it_at_least_as_loudly_as_the_milder_warn():
    """The positive control is the point.

    "3 actions, no skill action" alone proves nothing — the fixture might simply produce no
    skill actions. The comparison does: the MILDER temp-file WARN on the same skill got the
    skill action while the confirmed escape did not.
    """
    from clawseccheck.guide import suggest_actions
    from clawseccheck.scoring import compute

    def skill_actions(home):
        _, fs = _findings(home)
        return [a for a in suggest_actions(fs, compute(fs))
                if "skill" in (getattr(a, "id", "") or "").lower()]

    assert skill_actions(BENIGN_HOME), "control broken: the temp-file WARN stopped advising"
    assert skill_actions(TRAVERSAL_HOME), (
        "the next-actions guide advises on a hardcoded temp-file path but says nothing about "
        "a confirmed zip-slip on the same skill"
    )


def test_dedup_does_not_sort_it_below_pass():
    from clawseccheck.dedup import _STATUS_ORDER

    for status in sorted(FAIL_WEIGHT_STATUSES):
        assert _STATUS_ORDER.get(status.upper(), 9) <= _STATUS_ORDER["PASS"], (
            f"{status} scores {_STATUS_ORDER.get(status.upper(), 9)} against PASS="
            f"{_STATUS_ORDER['PASS']} — a confirmed conviction sorts below every clean check"
        )


def test_the_benign_control_is_untouched_everywhere():
    """Nothing above bought its result by convicting more broadly.

    Same skill, same archive, benign member: every consumer must be exactly where it was.
    """
    from clawseccheck.report import _skill_inventory
    from clawseccheck.risk import risk_paths
    from clawseccheck.scoring import compute

    ctx, fs = _findings(BENIGN_HOME)
    assert compute(fs).grade == "A"
    assert "RISK-09" not in [p.id for p in risk_paths(ctx, fs)]
    row = _skill_inventory(ctx)[0]
    assert row["status"] == "WARN" and row["verdict"] == "SUSPICIOUS", row
