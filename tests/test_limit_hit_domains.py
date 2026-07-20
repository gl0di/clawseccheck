"""W-DB2 round-3 — ``ctx.limit_hits`` is DOMAIN-SCOPED, and B13 reads only its own domain.

THE DEFECT. ``limit_hits`` was one undifferentiated bucket written by ~50 unrelated
collectors, while ``check_installed_skills`` (B13 — installed-skill safety, HIGH, scored)
treated ANY non-empty bucket as proof that the SKILL scan was incomplete. So a cap hit in a
completely unrelated collector silenced an unrelated skill scan. Reproduced end-to-end on a
benign home (one clean skill, one benign daily cron job, modes 0700/0600) with nothing
varying but cron history depth::

    rows=499  limit_hits=[]  -> B13 PASS
                                "Scanned 1 installed skill(s); no ... patterns found."
    rows=500  limit_hits=[cron run-log 500-row cap]
              -> B13 UNKNOWN (HIGH)
                 "Skill scanning was truncated / hit limits — coverage is incomplete: ..."

A FALSE STATEMENT INSIDE A HIGH FINDING (the skill scan completed in full, both times) that
also destroyed a genuine PASS signal. Routine, not exotic: a daily job crosses 500 rows in
about 17 months.

THE TWO DIRECTIONS. The cheap "fix" is to stop reading ``limit_hits`` at all, which trades
the false positive for a false negative — a padded skill would then read as fully covered.
Every test below therefore comes in a matched pair: the unrelated domain must NOT fire, and
the skill domain MUST still fire. ``test_control_isolates_the_single_variable`` runs all
four arms against one identical home so the only independent variable is which scan was
truncated.
"""
from __future__ import annotations

import ast
import os
import sqlite3
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import (
    LIMIT_DOMAIN_CRON,
    LIMIT_DOMAIN_SKILL,
    LIMIT_DOMAINS,
    Context,
    LimitHit,
    _MAX_BYTES_PER_SKILL,
    limit_hits_for,
    note_limit,
)

_PKG = Path(__file__).resolve().parent.parent / "clawseccheck"

_CRON_JOBS_DDL = (
    "CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, "
    "delete_after_run INTEGER, trigger_script TEXT, payload_kind TEXT, payload_message TEXT)"
)
_CRON_RUN_LOGS_DDL = (
    "CREATE TABLE cron_run_logs (store_key TEXT NOT NULL, job_id TEXT NOT NULL, "
    "seq INTEGER NOT NULL, ts INTEGER NOT NULL, status TEXT, error TEXT, summary TEXT, "
    "diagnostics_summary TEXT, delivery_status TEXT, delivery_error TEXT, delivered INTEGER, "
    "session_id TEXT, session_key TEXT, run_id TEXT, run_at_ms INTEGER, duration_ms INTEGER, "
    "next_run_at_ms INTEGER, model TEXT, provider TEXT, total_tokens INTEGER, "
    "entry_json TEXT NOT NULL, created_at INTEGER NOT NULL, "
    "PRIMARY KEY (store_key, job_id, seq))"
)


def _benign_home(tmp_path, *, n_runs: int, oversize_skill: bool) -> Path:
    """One benign home: a single clean installed skill + a single benign daily cron job.

    The ONLY two knobs are which scan gets truncated — cron history depth, and whether the
    skill carries a file past the per-skill text budget. Everything else is byte-identical
    across arms, which is what makes the four-arm control a control.
    """
    home = tmp_path / "openclaw"
    home.mkdir(parents=True)
    skill = home / "workspace" / "skills" / "notes"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: notes\ndescription: Take notes.\n---\n\n"
        "# Notes\n\nWrite a note to a local file. Nothing else.\n",
        encoding="utf-8",
    )
    os.chmod(skill / "SKILL.md", 0o600)
    if oversize_skill:
        pad = skill / "reference.md"
        pad.write_text("benign reference prose. " * (_MAX_BYTES_PER_SKILL // 20),
                       encoding="utf-8")
        os.chmod(pad, 0o600)

    state = home / "state"
    state.mkdir()
    db = state / "openclaw.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute(_CRON_JOBS_DDL)
        conn.execute(_CRON_RUN_LOGS_DDL)
        conn.execute(
            "INSERT INTO cron_jobs VALUES (?,?,?,?,?,?,?)",
            ("j1", "daily-digest", 1, 0, None, "message", "Send me the daily digest."),
        )
        for i in range(n_runs):
            conn.execute(
                "INSERT INTO cron_run_logs (store_key, job_id, seq, ts, status, "
                "session_id, session_key, run_id, entry_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("default", "j1", i, 1_700_000_000 + i, "ok", "s1", "k1",
                 f"run-{i}", "{}", 1_700_000_000 + i),
            )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db, 0o600)
    os.chmod(state, 0o700)
    return home


def _b13(home: Path):
    ctx, findings, _score = audit(home=home)
    return ctx, next(f for f in findings if f.id == "B13")


# ---------------------------------------------------------------------------------------
# The primitives.
# ---------------------------------------------------------------------------------------

def test_limit_hit_is_a_plain_string_to_every_existing_consumer():
    """The tag must be purely additive. Consumers treat the bucket as ``list[str]`` —
    substring tests, joins, JSON/SARIF dumps, monitor's regex parse — and all of that has
    to keep working byte-for-byte, or this refactor breaks unrelated checks."""
    hit = LimitHit("text scan of skill 'x' hit the 1000KB cap", LIMIT_DOMAIN_SKILL)
    assert isinstance(hit, str)
    assert hit == "text scan of skill 'x' hit the 1000KB cap"
    assert "hit the" in hit
    assert "; ".join([hit]) == str(hit)
    assert hit.domain == LIMIT_DOMAIN_SKILL


def test_note_limit_tags_and_limit_hits_for_filters():
    ctx = Context(home=Path("/nonexistent"))
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_SKILL, "skill scan truncated")
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CRON, "cron run-log cap")
    assert len(ctx.limit_hits) == 2
    assert limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) == ["skill scan truncated"]
    assert limit_hits_for(ctx, LIMIT_DOMAIN_CRON) == ["cron run-log cap"]
    assert len(limit_hits_for(ctx, LIMIT_DOMAIN_SKILL, LIMIT_DOMAIN_CRON)) == 2


def test_untagged_entries_are_included_not_dropped():
    """Golden Rule #4, in the conservative direction. A bare ``str`` carries no evidence
    about which scan it truncated; dropping it would convert "cannot tell" into a clean
    PASS. Also keeps hand-built test contexts that assign a plain list behaving as before.
    """
    ctx = Context(home=Path("/nonexistent"))
    ctx.limit_hits = ["some legacy untagged hit"]
    assert limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) == ["some legacy untagged hit"]
    assert limit_hits_for(ctx, LIMIT_DOMAIN_CRON) == ["some legacy untagged hit"]


def test_every_limit_hits_writer_in_the_package_is_tagged():
    """MECHANICAL GUARD — the reason default-exclude is safe.

    A bare ``limit_hits.append(...)`` anywhere in the package would produce an untagged
    entry and re-open the cross-contamination channel for whatever consumer scopes itself.
    This walks the real AST of every shipped module (a grep would miss a call whose
    arguments wrap across lines) and requires every writer to go through ``note_limit``.

    ``skilldiscovery`` is the one module that legitimately calls ``.append`` on the sink
    it was handed — it is a leaf and cannot import the collector — so the collector passes
    it a pre-scoped ``_ScopedLimitSink``. That is asserted separately below.
    """
    offenders = []
    for path in sorted(_PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == "append"):
                continue
            tgt = fn.value
            is_limit_sink = (
                (isinstance(tgt, ast.Attribute) and tgt.attr == "limit_hits")
                or (isinstance(tgt, ast.Name) and tgt.id == "limit_hits")
            )
            if is_limit_sink and path.name != "skilldiscovery.py":
                offenders.append(f"{path.relative_to(_PKG)}:{node.lineno}")
    assert not offenders, (
        "untagged limit_hits writer(s) — use note_limit(sink, LIMIT_DOMAIN_*, msg): "
        + ", ".join(offenders)
    )


def test_skilldiscovery_cap_hit_arrives_tagged_as_skill(tmp_path):
    """The leaf's own append must still land tagged, via the collector's scoped sink."""
    from clawseccheck.collector import _ScopedLimitSink

    ctx = Context(home=tmp_path)
    sink = _ScopedLimitSink(ctx.limit_hits, LIMIT_DOMAIN_SKILL)
    sink.append("skill discovery under '/x' exceeded the cap")
    assert len(sink) == 1
    assert "skill discovery under '/x' exceeded the cap" in sink
    assert ctx.limit_hits[0].domain == LIMIT_DOMAIN_SKILL


def test_domain_constants_are_registered():
    """A new domain must be added to LIMIT_DOMAINS so the roster stays discoverable."""
    assert LIMIT_DOMAIN_SKILL in LIMIT_DOMAINS
    assert LIMIT_DOMAIN_CRON in LIMIT_DOMAINS
    assert len(set(LIMIT_DOMAINS)) == len(LIMIT_DOMAINS)


# ---------------------------------------------------------------------------------------
# DIRECTION 1 — the false positive is gone.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("n_runs", [499, 500, 501])
def test_cron_history_depth_never_touches_the_skill_verdict(tmp_path, n_runs):
    """The exact reproduction. 499 passed before the fix and 500 did not; 501 genuinely
    truncates the cron read and still must not touch B13, because the SKILL scan is
    complete at every depth."""
    ctx, b13 = _b13(_benign_home(tmp_path / str(n_runs), n_runs=n_runs, oversize_skill=False))
    assert b13.status == PASS, f"cron depth {n_runs} contaminated the skill verdict"
    assert "installed skill(s)" in b13.detail
    assert "coverage is incomplete" not in b13.detail
    # ...and any cron cap that did fire is tagged, so it stays out of the skill domain.
    assert all(h.domain == LIMIT_DOMAIN_CRON for h in ctx.limit_hits)
    assert limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) == []


def test_the_run_log_cap_fires_only_past_the_cap(tmp_path):
    """Boundary, tied to the off-by-one fix: exactly 500 rows is a COMPLETE read."""
    ctx_at, _ = _b13(_benign_home(tmp_path / "at", n_runs=500, oversize_skill=False))
    ctx_over, _ = _b13(_benign_home(tmp_path / "over", n_runs=501, oversize_skill=False))
    assert not [h for h in ctx_at.limit_hits if "run-log" in h]
    assert [h for h in ctx_over.limit_hits if "run-log" in h]


# ---------------------------------------------------------------------------------------
# DIRECTION 2 — the true positive still fires. Without these, "delete the branch" passes.
# ---------------------------------------------------------------------------------------

def test_a_real_skill_truncation_still_forces_unknown(tmp_path):
    """The FN guard. A skill carrying content past the per-skill budget was NOT fully
    scanned, so B13 must still refuse to report a clean PASS (B-074)."""
    ctx, b13 = _b13(_benign_home(tmp_path, n_runs=10, oversize_skill=True))
    assert b13.status == UNKNOWN
    assert "coverage is incomplete" in b13.detail
    assert limit_hits_for(ctx, LIMIT_DOMAIN_SKILL)


def test_skill_truncation_wins_even_when_cron_also_capped(tmp_path):
    """Both domains truncated at once: the skill UNKNOWN still fires, and the evidence
    quotes the SKILL hit rather than the irrelevant cron one."""
    ctx, b13 = _b13(_benign_home(tmp_path, n_runs=501, oversize_skill=True))
    assert b13.status == UNKNOWN
    assert "coverage is incomplete" in b13.detail
    assert "reference.md" in b13.detail
    assert "run-log" not in b13.detail, "a cron cap leaked into the skill finding's text"
    assert {h.domain for h in ctx.limit_hits} == {LIMIT_DOMAIN_SKILL, LIMIT_DOMAIN_CRON}


def test_an_untagged_hit_still_forces_unknown():
    """The conservative default, end-to-end through the real check: a bucket the collector
    did not tag must still degrade B13, never silently pass."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": "# a skill\n"}
    ctx.limit_hits = ["scan of skill 'x' hit some cap"]
    assert check_installed_skills(ctx).status == UNKNOWN


def test_control_isolates_the_single_variable(tmp_path):
    """THE CONTROL. Four arms over one identical benign home; the only thing that varies
    is WHICH scan was truncated. A fix that merely stopped detecting shows PASS in arms
    (c)/(d); the pre-fix code shows UNKNOWN in arm (b)."""
    arms = {
        "a_neither": dict(n_runs=10, oversize_skill=False),
        "b_cron_only": dict(n_runs=501, oversize_skill=False),
        "c_skill_only": dict(n_runs=10, oversize_skill=True),
        "d_both": dict(n_runs=501, oversize_skill=True),
    }
    got = {}
    for name, kw in arms.items():
        _ctx, b13 = _b13(_benign_home(tmp_path / name, **kw))
        got[name] = b13.status
    assert got == {
        "a_neither": PASS,
        "b_cron_only": PASS,      # the fixed false positive
        "c_skill_only": UNKNOWN,  # the true positive, preserved
        "d_both": UNKNOWN,        # the true positive, not masked by the fix
    }, got
