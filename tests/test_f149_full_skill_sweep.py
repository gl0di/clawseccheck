"""F-149 — ``--full`` sweeps every installed skill with the vet engine.

``--full`` used to run audit + self-test + vet-mcp. The audit already inspects skill
*content*, but it attributes what it finds to the HOME: "something in this fleet is
wrong". The vet engine answers a different question with a different unit — "which
skill, and how bad is THAT one" — which is the unit an owner acts on, because you
uninstall a skill, not a finding. So the sweep is an added angle, not a repeat pass.

Contract pinned here:

* the section is APPENDED, after VET-MCP — everything above it keeps its exact shape
  and order, and the report body stays a byte-for-byte prefix of the quiet output;
* ``--full --quiet`` collapses it to one honest line, the way self-test and vet-mcp
  already do, and that line still says when the sweep was incomplete;
* a DANGEROUS skill feeds ``--exit-code`` **FAIL-only** (a SUSPICIOUS one does not),
  mirroring the vet-mcp rule, and truncation never flips the exit code;
* skill verdicts are visibility only — they never move the audit score or grade;
* nothing is silently capped: an unscanned skill is named and kept out of "safe".

Offline, read-only, writes nothing outside ``tmp_path``. Budget exhaustion is driven
by monkeypatching ``clawseccheck.cli.budget_exceeded``, never by sleeping.
"""
from __future__ import annotations

import json
from pathlib import Path

import clawseccheck.cli as cli
from clawseccheck.cli import (
    _SWEEP_ICON_ASCII, _SWEEP_ICON_UNI, _SWEEP_VERDICT,
    _VET_ICON_ASCII, _VET_ICON_UNI, _VET_VERDICT,
    SkillSweep, _sweep_quiet_line, _sweep_summary_lines, main,
    sweep_installed_skills,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

NO_SKILLS = str(FIXTURES / "home_safe")                       # no skills root at all
CLEAN = str(FIXTURES / "clean_b104_wired")                    # 2 clean installed skills
DANGEROUS = str(FIXTURES / "bad_b13_runtime_fetch")           # 1 DANGEROUS skill
SUSPICIOUS = str(FIXTURES / "bad_b307_two_uncorroborated_mentions_warn")  # 1 WARN skill

BASE = ["--no-native", "--no-host", "--no-history", "--ascii", "--seed", "f149"]

SECTION = "CLAWSECCHECK SKILL SWEEP"

_CLEAN_MD = """\
---
name: word-counter
description: Count the words in a file the user names.
---
# Word Counter
Count the words in a file the user names. Ask before reading other files.
"""


def _run(capsys, home: str, extra: list[str]) -> tuple[int, str]:
    rc = main(["--home", home] + BASE + extra)
    return rc, capsys.readouterr().out


def _home_with_skill(tmp_path: Path, name: str) -> Path:
    """A minimal auditable home carrying one clean installed skill."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    d = tmp_path / "skills" / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(_CLEAN_MD, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# The section exists, and it is APPENDED (ordering / prefix constraints)
# ---------------------------------------------------------------------------

def test_full_emits_skill_sweep_section(capsys):
    rc, out = _run(capsys, CLEAN, ["--full"])
    assert rc == 0
    assert SECTION in out


def test_skill_sweep_comes_after_self_test_and_vet_mcp(capsys):
    """Appending last is what keeps the two pinned orderings and the quiet-prefix
    property intact — the sweep must never move above VET-MCP."""
    _, out = _run(capsys, CLEAN, ["--full"])
    selftest = out.find("CLAWSECCHECK SELF-TEST")
    vetmcp = out.find("CLAWSECCHECK VET-MCP")
    sweep = out.find(SECTION)
    assert 0 <= selftest < vetmcp < sweep


def test_report_body_still_prefix_of_quiet_with_skills_present(capsys):
    """The quiet-output-is-a-prefix property, re-checked on a home that actually HAS
    skills (the shipped guard runs on a home with none, so it could not have caught a
    sweep line printed before SELF-TEST)."""
    _, full = _run(capsys, CLEAN, ["--full"])
    _, quiet = _run(capsys, CLEAN, ["--full", "--quiet"])
    quiet_head = quiet.split("\nSELF-TEST:")[0]
    assert full.startswith(quiet_head)


def test_default_run_has_no_skill_sweep(capsys):
    """No --full, no sweep: a default audit must not gain the section (or its cost)."""
    rc, out = _run(capsys, CLEAN, [])
    assert rc == 0
    assert SECTION not in out
    assert "SKILL SWEEP:" not in out


def test_full_json_has_no_skill_sweep_text(capsys):
    """--full --json stays machine-readable: the human section is not appended."""
    rc = main(["--home", CLEAN, "--no-native", "--no-host", "--no-history",
               "--full", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert SECTION not in out
    doc = json.loads(out)
    assert "grade" in doc


# ---------------------------------------------------------------------------
# F-149 JSON gap: --full --json carries the sweep as structured data
# ---------------------------------------------------------------------------

def test_full_json_carries_skill_sweep(capsys):
    rc = main(["--home", CLEAN, "--no-native", "--no-host", "--no-history",
               "--full", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    sweep = doc["skill_sweep"]
    assert sweep["worst"] == "PASS"
    assert sweep["truncated"] is False
    assert sweep["counts"] == {
        "total": 2, "fails": 0, "warns": 0, "truncated": 0, "skipped": 0, "safe": 2,
    }
    names = {t["name"] for t in sweep["targets"]}
    assert names == {"alpha", "beta"}
    assert all(t["status"] == "PASS" for t in sweep["targets"])


def test_plain_json_has_no_skill_sweep_key(capsys):
    """Without --full, --json must not gain the key (or its cost) at all."""
    rc = main(["--home", CLEAN, "--no-native", "--no-host", "--no-history", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "skill_sweep" not in json.loads(out)


def test_full_json_dangerous_skill_is_named_with_evidence(capsys):
    rc = main(["--home", DANGEROUS, "--no-native", "--no-host", "--no-history",
               "--full", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    sweep = doc["skill_sweep"]
    assert sweep["worst"] == "FAIL"
    fails = [t for t in sweep["targets"] if t["status"] == "FAIL"]
    assert len(fails) == 1
    assert fails[0]["evidence_count"] > 0


def test_full_json_no_skills_directory_reports_it_structurally(capsys):
    rc = main(["--home", NO_SKILLS, "--no-native", "--no-host", "--no-history",
               "--full", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    sweep = doc["skill_sweep"]
    assert sweep["no_roots"] is True
    assert sweep["targets"] == []


def test_full_json_exit_code_reacts_to_dangerous_skill(capsys):
    """The JSON gap used to hide this from --exit-code too: the whole sweep never
    ran under --json, so sweep_has_fail stayed False no matter what the fleet held."""
    rc = main(["--home", DANGEROUS, "--no-native", "--no-host", "--no-history",
               "--full", "--json", "--exit-code"])
    capsys.readouterr()
    assert rc == 1


def test_full_json_sweep_is_silent(capsys):
    """JSON output must never carry the narrative prose the human --full section
    prints — the sweep runs with narrate=False under --json."""
    rc = main(["--home", DANGEROUS, "--no-native", "--no-host", "--no-history",
               "--full", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    # The whole payload is exactly one JSON document — any stray narrated print
    # before/after it would break json.loads on the full captured stdout.
    json.loads(out)


# ---------------------------------------------------------------------------
# clean / bad / empty rendering
# ---------------------------------------------------------------------------

def test_clean_home_reports_every_skill_safe(capsys):
    _, out = _run(capsys, CLEAN, ["--full"])
    section = out.split(SECTION, 1)[1]
    assert "alpha" in section and "beta" in section
    assert "2 skill(s) checked | 2 safe | 0 suspicious | 0 dangerous" in section
    assert "DANGEROUS" not in section


def test_dangerous_skill_is_named_with_evidence(capsys):
    _, out = _run(capsys, DANGEROUS, ["--full"])
    section = out.split(SECTION, 1)[1]
    assert "evil-fetch-skill" in section
    assert "DANGEROUS" in section
    assert "Evidence:" in section
    assert "1 skill(s) checked | 0 safe | 0 suspicious | 1 dangerous" in section


def test_no_skills_directory_says_so_plainly(capsys):
    """An honest one-liner, not a wall of UNKNOWN noise."""
    rc, out = _run(capsys, NO_SKILLS, ["--full"])
    section = out.split(SECTION, 1)[1]
    assert rc == 0
    assert "No skills directory found under" in section
    assert "Aggregate summary" not in section
    assert "UNKNOWN" not in section


def test_empty_skills_directory_says_so_plainly(tmp_path, capsys):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    (tmp_path / "skills").mkdir()
    rc, out = _run(capsys, str(tmp_path), ["--full"])
    section = out.split(SECTION, 1)[1]
    assert rc == 0
    assert "No skills found under" in section
    assert "Aggregate summary" not in section


def test_section_header_prints_even_with_nothing_to_report(capsys):
    """Silence would be indistinguishable from 'nothing to report'."""
    _, out = _run(capsys, NO_SKILLS, ["--full"])
    assert SECTION in out


# ---------------------------------------------------------------------------
# --quiet collapse
# ---------------------------------------------------------------------------

def test_quiet_collapses_to_one_line(capsys):
    _, quiet = _run(capsys, CLEAN, ["--full", "--quiet"])
    assert SECTION not in quiet
    assert "SKILL SWEEP: 2 installed skill(s) vetted" in quiet
    assert "0 dangerous" in quiet
    assert "Full detail: --vet-all." in quiet
    # One line, not a block: no per-skill verdict headers leaked through.
    assert "=== alpha ===" not in quiet
    assert "Aggregate summary" not in quiet


def test_quiet_names_the_dangerous_skill(capsys):
    _, quiet = _run(capsys, DANGEROUS, ["--full", "--quiet"])
    assert "1 dangerous" in quiet
    assert "Dangerous: evil-fetch-skill." in quiet


def test_quiet_line_avoids_the_pinned_verbose_markers(capsys):
    """C3: the quiet summary must not reintroduce a banner --quiet promised to drop."""
    _, quiet = _run(capsys, DANGEROUS, ["--full", "--quiet"])
    assert "CLAWSECCHECK SELF-TEST" not in quiet
    assert "CLAWSECCHECK VET-MCP" not in quiet
    assert SECTION not in quiet
    assert "VULNERABLE" not in quiet


def test_quiet_no_skills_directory(capsys):
    _, quiet = _run(capsys, NO_SKILLS, ["--full", "--quiet"])
    assert "SKILL SWEEP: no skills directory found under" in quiet


def test_quiet_is_substantially_shorter_with_skills_present(capsys):
    _, full = _run(capsys, DANGEROUS, ["--full"])
    _, quiet = _run(capsys, DANGEROUS, ["--full", "--quiet"])
    assert len(quiet.splitlines()) < len(full.splitlines()) // 2


# ---------------------------------------------------------------------------
# --exit-code: FAIL-only, identical on both branches, deaf to truncation
# ---------------------------------------------------------------------------

def _stub_sweep(monkeypatch, rows: list[tuple[str, str, int]], truncated: bool = False):
    """Replace the sweep with a synthetic result, so the exit-code wiring is tested
    in isolation from whatever the audit itself finds on the fixture."""
    def fake(home_dir, ascii_only=False, sweep_budget_s=0.0, narrate=True):
        if narrate:
            print("(stub sweep)")
        return SkillSweep(home_dir=Path(home_dir), checked_dirs=[Path(home_dir)],
                          rows=list(rows), truncated=truncated)
    monkeypatch.setattr(cli, "sweep_installed_skills", fake)


def test_dangerous_skill_trips_exit_code(tmp_path, monkeypatch, capsys):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _stub_sweep(monkeypatch, [("evil", "FAIL", 1)])
    rc, _ = _run(capsys, str(tmp_path), ["--full", "--exit-code"])
    assert rc == 1


def test_suspicious_skill_does_not_trip_exit_code(tmp_path, monkeypatch, capsys):
    """FAIL-only, exactly as a WARN MCP server is treated."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _stub_sweep(monkeypatch, [("iffy", "WARN", 1)])
    rc, _ = _run(capsys, str(tmp_path), ["--full", "--exit-code"])
    assert rc == 0


def test_truncated_sweep_does_not_trip_exit_code(tmp_path, monkeypatch, capsys):
    """An incomplete sweep is reported by the printed section, never by reddening a
    CI gate that would otherwise be green."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _stub_sweep(monkeypatch, [("a", "SKIPPED", 0), ("b", "TRUNCATED", 0)],
                truncated=True)
    rc, _ = _run(capsys, str(tmp_path), ["--full", "--exit-code"])
    assert rc == 0


def test_exit_code_parity_quiet_vs_verbose_with_dangerous_skill(tmp_path, monkeypatch, capsys):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _stub_sweep(monkeypatch, [("evil", "FAIL", 1)])
    rc_verbose, _ = _run(capsys, str(tmp_path), ["--full", "--exit-code"])
    rc_quiet, _ = _run(capsys, str(tmp_path), ["--full", "--quiet", "--exit-code"])
    assert rc_verbose == rc_quiet == 1


def test_full_without_exit_code_stays_zero_on_dangerous_skill(capsys):
    rc, _ = _run(capsys, DANGEROUS, ["--full"])
    assert rc == 0


def test_suspicious_fixture_exits_zero_end_to_end(capsys):
    """The real WARN fixture through the real engine — no stub — still exits 0."""
    rc, out = _run(capsys, SUSPICIOUS, ["--full", "--exit-code"])
    section = out.split(SECTION, 1)[1]
    assert "SUSPICIOUS" in section
    assert rc == 0


# ---------------------------------------------------------------------------
# Visibility only: the sweep never moves the audit score or grade
# ---------------------------------------------------------------------------

def test_sweep_does_not_change_score_or_grade(capsys):
    """--full must produce the same audit verdict as a plain run on the same home."""
    rc_plain = main(["--home", DANGEROUS, "--no-native", "--no-host", "--no-history",
                     "--json"])
    plain = json.loads(capsys.readouterr().out)
    rc_full = main(["--home", DANGEROUS, "--no-native", "--no-host", "--no-history",
                    "--full", "--json"])
    full = json.loads(capsys.readouterr().out)
    assert rc_plain == rc_full
    assert (plain["score"], plain["grade"]) == (full["score"], full["grade"])


# ---------------------------------------------------------------------------
# Truncation: named, not "safe", honest on both branches
# ---------------------------------------------------------------------------

def test_budget_exhausted_names_unscanned_skills_in_full(capsys, monkeypatch):
    monkeypatch.setattr(cli, "budget_exceeded", lambda deadline: True)
    _, out = _run(capsys, CLEAN, ["--full"])
    section = out.split(SECTION, 1)[1]
    assert "NOT scanned" in section
    assert "alpha" in section and "beta" in section
    assert "not scanned (budget exceeded)" in section
    # Never folded into "safe".
    assert "0 skill(s) checked | 0 safe | 0 suspicious | 0 dangerous" in section


def test_budget_exhausted_quiet_line_admits_it(capsys, monkeypatch):
    monkeypatch.setattr(cli, "budget_exceeded", lambda deadline: True)
    _, quiet = _run(capsys, CLEAN, ["--full", "--quiet"])
    assert "not scanned (budget exceeded)" in quiet


def test_truncated_run_keeps_exit_code_zero_end_to_end(capsys, monkeypatch):
    """Truncation moves the printed section, not the rc — a truncated sweep must not
    silently redden a gate, and must not silently pass as clean either (the section
    above is what says so)."""
    monkeypatch.setattr(cli, "budget_exceeded", lambda deadline: True)
    rc, _ = _run(capsys, CLEAN, ["--full", "--exit-code"])
    assert rc == 0


# ---------------------------------------------------------------------------
# Ledger (C1): the sweep records through _record_run, so --no-history suppresses it
# ---------------------------------------------------------------------------

def test_full_records_vet_capability(tmp_path, monkeypatch, capsys):
    from clawseccheck.ledger import load_ledger
    monkeypatch.setenv("HOME", str(tmp_path))
    main(["--home", CLEAN, "--no-native", "--no-host", "--ascii", "--seed", "x",
          "--full"])
    capsys.readouterr()
    assert "vet" in load_ledger(str(tmp_path))


def test_no_history_suppresses_the_sweep_ledger_write(tmp_path, monkeypatch, capsys):
    from clawseccheck.ledger import load_ledger
    monkeypatch.setenv("HOME", str(tmp_path))
    _run(capsys, CLEAN, ["--full"])          # BASE carries --no-history
    assert load_ledger(str(tmp_path)) == {}


def test_full_still_suppresses_the_coverage_gap_notice(tmp_path, monkeypatch, capsys):
    """Recording a 'vet' run must not conjure a new freshness advisory line."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _, out = _run(capsys, CLEAN, ["--full"])
    assert "Coverage gap" not in out


# ---------------------------------------------------------------------------
# C6: the sweep vocabulary is its own, and the vet-mcp one was not widened
# ---------------------------------------------------------------------------

def test_sweep_vocabulary_has_the_two_incomplete_states():
    expected = {"FAIL", "WARN", "PASS", "UNKNOWN", "SKIPPED", "TRUNCATED"}
    assert set(_SWEEP_ICON_ASCII) == expected
    assert set(_SWEEP_ICON_UNI) == expected
    assert set(_SWEEP_VERDICT) == expected
    assert _SWEEP_VERDICT["SKIPPED"] == "not scanned (budget exceeded)"


def test_vet_mcp_vocabulary_was_not_widened():
    """The sweep's extra states must never leak into the vet-mcp dicts."""
    four = {"FAIL", "WARN", "PASS", "UNKNOWN"}
    assert set(_VET_ICON_ASCII) == set(_VET_ICON_UNI) == set(_VET_VERDICT) == four


# ---------------------------------------------------------------------------
# C8: an attacker-controlled skill NAME cannot inject terminal control sequences
# ---------------------------------------------------------------------------

def test_skill_name_escape_sequence_is_sanitized(tmp_path, capsys):
    home = _home_with_skill(tmp_path, "ev\x1b[31mil")
    _, out = _run(capsys, str(home), ["--full"])
    assert "\x1b[31m" not in out
    assert "evil" in out.split(SECTION, 1)[1]


# ---------------------------------------------------------------------------
# Engine unit tests — SkillSweep is the single source both branches read
# ---------------------------------------------------------------------------

def test_has_fail_is_fail_only():
    home = Path("/nonexistent")
    assert SkillSweep(home_dir=home, rows=[("a", "FAIL", 0)]).has_fail
    assert not SkillSweep(home_dir=home, rows=[("a", "WARN", 0)]).has_fail
    assert not SkillSweep(home_dir=home, rows=[("a", "UNKNOWN", 0)]).has_fail
    assert not SkillSweep(home_dir=home, rows=[("a", "SKIPPED", 0)]).has_fail
    assert not SkillSweep(home_dir=home, rows=[("a", "TRUNCATED", 0)]).has_fail


def test_counts_keep_unscanned_targets_out_of_safe():
    sweep = SkillSweep(home_dir=Path("/nonexistent"), rows=[
        ("a", "PASS", 0), ("b", "FAIL", 2), ("c", "WARN", 1),
        ("d", "TRUNCATED", 0), ("e", "SKIPPED", 0),
    ], truncated=True)
    c = sweep.counts()
    assert c == {"total": 4, "fails": 1, "warns": 1, "truncated": 1,
                 "skipped": 1, "safe": 1}
    assert sweep.not_scanned() == ["d", "e"]
    assert sweep.complete is False


def test_sweep_is_silent_when_not_narrating(tmp_path, capsys):
    home = _home_with_skill(tmp_path, "quiet-one")
    sweep = sweep_installed_skills(home, narrate=False)
    assert capsys.readouterr().out == ""
    assert [r[0] for r in sweep.rows] == ["quiet-one"]
    assert sweep.complete is True
    assert sweep.findings and sweep.findings[0][0] == "quiet-one"


def test_narrated_and_silent_sweeps_agree(tmp_path, capsys):
    """The verbose and quiet --full branches must never disagree about the verdict."""
    home = _home_with_skill(tmp_path, "twin")
    loud = sweep_installed_skills(home, narrate=True)
    capsys.readouterr()
    silent = sweep_installed_skills(home, narrate=False)
    assert loud.rows == silent.rows
    assert loud.has_fail == silent.has_fail
    assert loud.worst == silent.worst


def test_summary_lines_empty_when_no_targets(tmp_path, capsys):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    sweep = sweep_installed_skills(tmp_path, narrate=False)
    assert sweep.no_roots is True
    assert sweep.no_targets is True
    assert _sweep_summary_lines(sweep) == []


def test_quiet_line_reports_partial_and_skipped_counts():
    sweep = SkillSweep(home_dir=Path("/nonexistent"), checked_dirs=[Path("/x")], rows=[
        ("a", "PASS", 0), ("b", "TRUNCATED", 0), ("c", "SKIPPED", 0),
    ], truncated=True)
    line = _sweep_quiet_line(sweep)
    assert "1 partially scanned" in line
    assert "1 not scanned (budget exceeded)" in line


def test_aggregate_table_marks_truncation_on_a_fail_row_too():
    """C-307: a skill that was both partially scanned AND tripped a real FAIL/WARN
    used to render in the aggregate table with the finding's row state ONLY — the
    "this verdict is based on an incomplete scan" fact was visible in the per-skill
    narration above the table but invisible in the row itself. `row_status` in
    ``sweep_installed_skills`` deliberately keeps FAIL/WARN as the row status (a real
    danger signal must never be demoted to TRUNCATED), so the table row must carry
    BOTH facts some other way.
    """
    from clawseccheck.catalog import Finding
    from clawseccheck.checks import coverage_gap_finding

    danger = Finding(
        "B99", "danger check", "CRITICAL", "FAIL",
        "dangerous content found", "remove it", "Skill Trust", True,
    )
    # Mirrors vet_skill(): the coverage gap rides on ring_findings when a worse
    # FAIL/WARN outranked it as the primary result (checks/_vet.py's merge rank).
    danger.ring_findings = [coverage_gap_finding("content-ring coverage is incomplete: "
                                                  "the per-target scan budget was exhausted")]

    clean = Finding(
        "B00", "clean check", "LOW", "PASS", "nothing found", "n/a", "Skill Trust", True,
    )

    sweep = SkillSweep(
        home_dir=Path("/nonexistent"),
        rows=[("danger-skill", "FAIL", 1), ("clean-skill", "PASS", 0)],
        findings=[("danger-skill", danger), ("clean-skill", clean)],
        truncated=True, worst="FAIL",
    )
    lines = _sweep_summary_lines(sweep)
    danger_line = next(ln for ln in lines if "danger-skill" in ln)
    clean_line = next(ln for ln in lines if "clean-skill" in ln)

    # Both facts, same row: still DANGEROUS (the row status/icon/tally are untouched)
    # AND flagged as a partial scan.
    assert _SWEEP_VERDICT["FAIL"] in danger_line
    assert "partial" in danger_line.lower()
    # The clean, non-truncated row must NOT pick up the marker.
    assert "partial" not in clean_line.lower()
    # Tally logic itself is untouched by this presentation-only fix.
    c = sweep.counts()
    assert c["fails"] == 1
    assert c["safe"] == 1
