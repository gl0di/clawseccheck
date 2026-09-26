"""F-148: --vet-all has a whole-sweep wall-clock ceiling.

Cost tracks input SIZE super-linearly (1 MB of benign content measures ~41s of
CPU, more than the hostile test fixture), so an unbounded sweep over a large
fleet (up to collector._MAX_SKILLS = 300) had no bound and no way to interrupt
it short of Ctrl-C. ``vet_all(..., sweep_budget_s=...)`` now
stops scanning further targets once the sweep deadline passes.

Per Golden Rule #4 (report UNKNOWN with the reason, never a silent skip or a
guessed PASS), the unscanned targets must:
  - be named in the printed output,
  - appear in the aggregate table with an explicit "not scanned" state,
  - NOT be counted in the "safe" tally bucket,
  - and force a non-zero return code, since a truncated sweep cannot honestly
    claim "checked everything, found nothing".

Tests are offline, write nothing outside tmp_path, and never sleep — budget
exhaustion is driven by monkeypatching ``clawseccheck.cli.budget_exceeded``
(the same predicate ``vet_all`` calls), not by a real clock delay.
"""
import json
from pathlib import Path

import clawseccheck.cli as cli

# ---------------------------------------------------------------------------
# helpers (mirrors tests/test_cli_recursive.py's _make_skill)
# ---------------------------------------------------------------------------

_CLEAN_MD = """\
---
name: word-counter
description: Count the words in a file the user names.
---
# Word Counter
Count the words in a file the user names. Ask before reading other files.
"""


def _make_skill(base: Path, name: str, content: str = _CLEAN_MD) -> Path:
    """Create a skill directory with a SKILL.md under base/skills/."""
    skill_dir = base / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


# ---------------------------------------------------------------------------
# clean case: default budget scans everything, shape unchanged from today
# ---------------------------------------------------------------------------

def test_vet_all_default_budget_scans_everything(tmp_path, capsys):
    """With the (generous) default budget, both skills are scanned and the
    output/tally shape matches pre-F-148 behaviour exactly — no truncation
    banner, no 'not scanned' segment, no SKIPPED rows."""
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "=== alpha ===" in out
    assert "=== beta ===" in out
    assert "Aggregate summary" in out
    assert "2 skill(s) checked | 2 safe | 0 suspicious | 0 dangerous" in out
    assert "not scanned" not in out.lower()
    assert "SKIPPED" not in out
    assert rc == 0


def test_vet_all_accepts_sweep_budget_kwarg_without_changing_behavior(tmp_path, capsys):
    """Existing callers (main()) don't pass sweep_budget_s — the new kwarg must be
    optional and, when given a generous value, behave identically."""
    _make_skill(tmp_path, "solo")

    rc = cli.vet_all(tmp_path, ascii_only=True, sweep_budget_s=600.0)
    out = capsys.readouterr().out

    assert "=== solo ===" in out
    assert "1 skill(s) checked | 1 safe | 0 suspicious | 0 dangerous" in out
    assert rc == 0


# ---------------------------------------------------------------------------
# budget-exhausted case: nothing gets scanned, nothing is silently dropped
# ---------------------------------------------------------------------------

def test_vet_all_budget_exhausted_names_unscanned_skills(tmp_path, capsys, monkeypatch):
    """Deadline already passed before the first target: both skills are named
    as not-scanned, appear in the summary table with an explicit state, are
    excluded from the 'safe' count, and the sweep returns non-zero."""
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")

    # Deterministic exhaustion — no sleeping, no real clock race.
    monkeypatch.setattr(cli, "budget_exceeded", lambda deadline: True)

    rc = cli.vet_all(tmp_path, ascii_only=True, sweep_budget_s=0.001)
    out = capsys.readouterr().out

    # Neither skill was actually vetted (no per-skill '=== name ===' section).
    assert "=== alpha ===" not in out
    assert "=== beta ===" not in out

    # But both are still named, not silently dropped.
    assert "alpha" in out
    assert "beta" in out
    assert "NOT scanned" in out  # the narrative truncation banner

    # The aggregate table carries an explicit not-scanned state.
    assert "not scanned (budget exceeded)" in out

    # The tally must not fold the unscanned skills into "safe".
    assert "0 skill(s) checked | 0 safe | 0 suspicious | 0 dangerous" in out
    assert "2 not scanned (budget exceeded)" in out

    # A truncated sweep is not a clean-0 sweep (see cli.vet_all's F-148 comment
    # on the return statement): it never inspected alpha/beta, so it cannot
    # claim "checked everything, found nothing".
    assert rc == 1


def test_vet_all_budget_exhausted_mid_sweep_keeps_already_scanned_result(tmp_path, capsys, monkeypatch):
    """The deadline is checked BEFORE each target, never mid-target: a skill
    already underway finishes normally, and only the ones after it are
    marked not-scanned."""
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")
    _make_skill(tmp_path, "gamma")

    calls = {"n": 0}

    def fake_exceeded(_deadline):
        calls["n"] += 1
        return calls["n"] > 1  # alpha's pre-check passes; beta's/gamma's don't

    monkeypatch.setattr(cli, "budget_exceeded", fake_exceeded)

    rc = cli.vet_all(tmp_path, ascii_only=True, sweep_budget_s=5.0)
    out = capsys.readouterr().out

    assert "=== alpha ===" in out       # scanned in full
    assert "=== beta ===" not in out    # never started
    assert "=== gamma ===" not in out   # never started
    assert "beta" in out and "gamma" in out  # still named as not-scanned
    assert "1 skill(s) checked | 1 safe | 0 suspicious | 0 dangerous" in out
    assert "2 not scanned (budget exceeded)" in out
    assert rc == 1


def test_vet_all_budget_exhausted_lists_many_skipped_names_with_overflow_count(tmp_path, capsys, monkeypatch):
    """More than the 12-name narrative cap: every skill still gets a row in the
    aggregate table (no silent cap there), and the narrative print shows an
    explicit '+N more' rather than truncating without saying so."""
    names = [f"skill_{i:02d}" for i in range(15)]
    for name in names:
        _make_skill(tmp_path, name)

    monkeypatch.setattr(cli, "budget_exceeded", lambda deadline: True)

    rc = cli.vet_all(tmp_path, ascii_only=True, sweep_budget_s=0.001)
    out = capsys.readouterr().out

    assert "15 skill(s) NOT scanned" in out
    assert "(+3 more)" in out
    # Every one of the 15 must appear somewhere (narrative list or overflow-implied
    # table row) — check the aggregate table specifically has all 15 rows.
    for name in names:
        assert name in out
    assert "0 skill(s) checked | 0 safe | 0 suspicious | 0 dangerous" in out
    assert "15 not scanned (budget exceeded)" in out
    assert rc == 1


# ---------------------------------------------------------------------------
# per-target truncation: a skill that was only PARTIALLY scanned is not "safe"
# ---------------------------------------------------------------------------


def _coverage_gap_finding():
    """What vet_skill returns when a target's own per-target budget cut it short."""
    from clawseccheck.catalog import Finding

    return Finding(
        "VET-COVERAGE", "Content-ring coverage", "HIGH", "UNKNOWN",
        "content-ring coverage is incomplete: the per-target CPU scan budget was exhausted",
        "Review the skill's largest files by hand.", "Skill Trust", False,
    )


def test_partially_scanned_skill_is_not_counted_safe_and_exits_nonzero(
    tmp_path, capsys, monkeypatch
):
    """A per-target budget cut is NOT the sweep-level cut, and was missed by it.

    The sweep finished and reached every target, so nothing is "not scanned" — but one
    target was only partially inspected. Folding that into "safe" and returning 0 tells
    the user the fleet is clean when part of it was never looked at.
    """
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")
    monkeypatch.setattr(cli, "vet_skill", lambda p: _coverage_gap_finding())

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc != 0, "a sweep that only partially scanned its targets returned success"
    assert "0 safe" in out, f"a partially-scanned skill was counted safe:\n{out}"
    assert "partially scanned" in out


def test_scan_budget_exceeded_from_vet_skill_is_not_swallowed_as_safe(
    tmp_path, capsys, monkeypatch
):
    """ScanBudgetExceeded is a plain Exception subclass.

    vet_all's bare `except Exception` would catch it, print a generic error row and let
    the skill land in the clean bucket -- the exact false "nothing found" the budget work
    exists to prevent.
    """
    from clawseccheck.scanbudget import ScanBudgetExceeded

    _make_skill(tmp_path, "alpha")

    def _boom(_p):
        raise ScanBudgetExceeded

    monkeypatch.setattr(cli, "vet_skill", _boom)

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc != 0, "a deadline was swallowed into a successful sweep"
    assert "0 safe" in out, f"a timed-out skill was counted safe:\n{out}"


# ---------------------------------------------------------------------------
# CLAWSECCHECK-B-888 item 2: an uncaught (non-budget) exception out of vet_skill()
# ---------------------------------------------------------------------------


def test_uncaught_exception_from_vet_skill_is_not_counted_safe(
    tmp_path, capsys, monkeypatch
):
    """A plain, uncaught exception out of ``vet_skill()`` — most commonly an AST-walking
    helper crashing mid-analysis (CLAWSECCHECK-B-888), not a scan-budget deadline — is
    already caught by the bare ``except Exception`` below and reported as an
    "(error vetting ...)" row with status UNKNOWN. But ``SkillSweep.counts()`` computed
    ``safe`` as ``total - fails - warns - truncated``, which does not subtract UNKNOWN
    rows either — the exact gap the comment directly above the ``ScanBudgetExceeded``
    handler already conceded in prose ("which -- same as a plain PASS/UNKNOWN --
    currently reads as 'safe' in the tally below") had no test pinning it before this.

    Unlike the ScanBudgetExceeded/coverage-gap cases above, this path does not set
    ``sweep.truncated`` and does not touch ``sweep.worst`` (the row is never reached by
    the code that would), so ``vet_all``'s return code is unaffected by this fix and can
    stay 0 here — the printed tally and ``sweep.counts()`` are what must stop lying, and
    that gap is what CLAWSECCHECK-B-888 asked for. (The exit-code side of the same
    crash-handler branch is a separate, lower-severity gap — filed for 4.3.1 rather than
    folded into this fix, since it does not itself misreport a target as safe.)
    """
    _make_skill(tmp_path, "alpha")

    def _boom(_p):
        raise RecursionError("simulated post-parse AST-walk crash (B-888 test)")

    monkeypatch.setattr(cli, "vet_skill", _boom)

    cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "error vetting" in out, out
    assert "1 skill(s) checked | 0 safe | 0 suspicious | 0 dangerous | " \
        "1 could not be analyzed (engine error)" in out, (
        f"a crashed skill was counted safe (CLAWSECCHECK-B-888):\n{out}"
    )


def test_uncaught_exception_next_to_a_clean_skill_only_the_crashed_one_is_excluded(
    tmp_path, capsys, monkeypatch
):
    """The isolation half of the same fix: ``--full``/``--vet-all`` already scan each
    skill independently (unlike the default audit's B13 cascade, CLAWSECCHECK-B-888 item
    1), so a sibling skill's clean result must survive untouched next to the crash — only
    the crashed skill itself should ever be excluded from "safe"."""
    from clawseccheck.catalog import Finding

    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")

    def _flaky(p):
        if Path(p).name == "alpha":
            raise RecursionError("simulated post-parse AST-walk crash (B-888 test)")
        return Finding(
            "B13", "Installed skill sweep", "INFO", "PASS",
            "nothing found", "n/a", "Skill Trust",
        )

    monkeypatch.setattr(cli, "vet_skill", _flaky)

    cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "2 skill(s) checked | 1 safe | 0 suspicious | 0 dangerous | " \
        "1 could not be analyzed (engine error)" in out, out


# ---------------------------------------------------------------------------
# B-937: a plain-Exception crash (not ScanBudgetExceeded) must also flip the
# sweep's return code, the same way the sibling ScanBudgetExceeded arm above
# already does.
# ---------------------------------------------------------------------------


def test_plain_exception_from_vet_skill_flips_exit_code_nonzero(
    tmp_path, capsys, monkeypatch
):
    """A skill whose vet_skill() call raises a plain (non-budget) exception is
    correctly tagged UNKNOWN and reported by name -- that part already worked. But
    until now it never set `sweep.truncated`, so `vet_all`'s return-code check
    (`if sweep.truncated: return 1`) fell through to `sweep.worst`, which every
    OTHER, cleanly-scanned skill left at "PASS" -- so a sweep that never actually
    assessed this target still returned 0. Mirrors the confirmed repro: one
    crashing skill, everything else clean, exit code must not be 0.
    """
    _make_skill(tmp_path, "crashy")

    def _boom(_p):
        raise RuntimeError("engine error")

    monkeypatch.setattr(cli, "vet_skill", _boom)

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 1, f"a crashed skill was swallowed into a successful sweep (rc={rc})"
    assert "error vetting crashy" in out


def test_plain_exception_does_not_abort_the_rest_of_the_sweep(
    tmp_path, capsys, monkeypatch
):
    """One skill's engine crash must not stop the sweep from reaching its siblings
    -- the bare `except Exception` around the per-skill vet_skill() call exists
    precisely so one bad target can't unwind the whole loop."""
    _make_skill(tmp_path, "crashy")
    _make_skill(tmp_path, "clean")

    real_vet_skill = cli.vet_skill

    def _boom(p):
        if "crashy" in str(p):
            raise RuntimeError("engine error")
        return real_vet_skill(p)

    monkeypatch.setattr(cli, "vet_skill", _boom)

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 1
    assert "=== clean ===" in out, "the crash aborted the rest of the sweep"
    assert "error vetting crashy" in out


def test_plain_exception_leaves_the_tally_and_json_shape_unchanged(
    tmp_path, capsys, monkeypatch
):
    """Regression guard: the B-937 fix only touches `sweep.truncated` in the bare
    `except Exception` branch. It must not change the printed tally numbers or the
    JSON `skills`/`notScanned` shape -- those are owned by SkillSweep.counts() /
    not_scanned(). (CLAWSECCHECK-B-888, merged after this fix was written, gave
    `not_scanned()` its own "unknown" bucket for exactly this crash shape, so
    `notScanned` now correctly names the crashed skill instead of staying empty --
    this test pins TODAY's actual tally text/JSON shape, B-888 and B-937 both
    landed, so it doesn't silently drift.)
    """
    _make_skill(tmp_path, "crashy")

    def _boom(_p):
        raise RuntimeError("engine error")

    monkeypatch.setattr(cli, "vet_skill", _boom)

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out
    assert rc == 1
    assert "1 skill(s) checked" in out
    assert "0 suspicious | 0 dangerous" in out

    monkeypatch.setattr(cli, "vet_skill", _boom)
    rc_json = cli.vet_all(tmp_path, ascii_only=True, json_output=True)
    doc = json.loads(capsys.readouterr().out)
    assert rc_json == 1
    assert doc["complete"] is False, "a crashed target must not read as a complete sweep"
    assert doc["skills"] == []
    assert doc["notScanned"] == ["crashy"], "B-888: a crashed skill must be named, not silently dropped"


def test_all_clean_sweep_with_no_crashes_still_returns_zero(tmp_path, capsys):
    """Control: nothing about the B-937 fix should affect an ordinary, fully-clean
    sweep -- it must still return 0."""
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")

    rc = cli.vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 0
    assert "2 skill(s) checked | 2 safe | 0 suspicious | 0 dangerous" in out
