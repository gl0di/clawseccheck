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
