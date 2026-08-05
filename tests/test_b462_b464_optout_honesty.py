"""B-462 / B-463 / B-464 — three places that reported a clean-looking result for something
that was never assessed.

- B-462 `--behavioral`: a green "✓ No behavioral anomalies found." was printed after a run
  in which every detector returned UNKNOWN and zero bytes of trajectory were read, and a
  typo'd explicit PATH was never echoed — the message blamed the host instead, exit 0.
  The rule was already written ten lines above the offending line.
- B-463 `--sbom`: a BOM for a `--home` that does not exist serialised BYTE-IDENTICALLY to
  one for a real setup with no components, so a typo'd path read as "everything was
  uninstalled".
- B-464 `--no-host`: UNKNOWNs are excluded from scoring, so opting a subsystem out removes
  its WARNs from the denominator and the score goes UP (measured 97 -> 98) with nothing in
  the output revealing it.

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.behavioral import explicit_path_problem, render_behavioral_analysis
from clawseccheck.cli import main
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


def _run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


# ---- B-462 ----

def test_typo_path_is_named_not_blamed_on_the_host(tmp_path):
    ghost = tmp_path / "typo.jsonl"
    problem = explicit_path_problem(str(ghost))
    assert problem and "no such file" in problem
    assert str(ghost) in problem


def test_a_directory_is_reported_as_such(tmp_path):
    problem = explicit_path_problem(str(tmp_path))
    assert problem and "is a directory" in problem


def test_a_good_path_reports_no_problem(tmp_path):
    good = tmp_path / "t.jsonl"
    good.write_text("", encoding="utf-8")
    assert explicit_path_problem(str(good)) is None
    assert explicit_path_problem(None) is None


def test_typo_path_exits_nonzero(tmp_path, capsys):
    code, out = _run(capsys, "--home", SAFE, "--behavioral", str(tmp_path / "typo.jsonl"))
    assert code == 1, "a path the user named that does not resolve is an operational failure"
    assert "typo.jsonl" in out


def test_all_unknown_run_never_prints_a_green_all_clear(tmp_path, capsys):
    ctx = Context(home=Path(SAFE))
    out = render_behavioral_analysis(ctx, ascii_only=True)
    assert "No behavioral anomalies found." not in out
    assert "No behavioural verdict" in out
    assert "not a clean result" in out


# ---- B-463 ----

def _sbom(capsys, home: str) -> dict:
    _, out = _run(capsys, "--home", home, "--sbom")
    return json.loads(out)


def test_ghost_home_bom_is_distinguishable_from_a_real_empty_one(tmp_path, capsys):
    ghost = _sbom(capsys, str(tmp_path / "does_not_exist"))
    real = _sbom(capsys, SAFE)

    assert ghost["config_found"] is False
    assert ghost["complete"] is False
    assert real["config_found"] is True
    assert ghost != real, "a BOM for a home we never found must not equal a real one"


def test_bom_records_which_home_it_scanned(tmp_path, capsys):
    target = tmp_path / "nowhere"
    bom = _sbom(capsys, str(target))
    assert str(target) in str(bom["scanned_home"])


# ---- B-464 ----

def _score_block(capsys, *extra) -> str:
    _, out = _run(capsys, "--home", SAFE, "--no-history", "--no-color", *extra)
    return out


def test_no_host_run_discloses_that_the_score_is_not_comparable(capsys):
    out = _score_block(capsys, "--no-host")
    assert "--no-host" in out
    assert "NOT comparable" in out


def test_a_full_run_carries_no_such_note(capsys):
    """Guard against the note becoming unconditional noise."""
    out = _score_block(capsys)
    assert "NOT comparable" not in out


def test_library_audit_gets_no_optout_note(capsys):
    """The note must key on flags the OPERATOR passed, not on ctx.include_host.

    That field defaults to False, so keying on it made a plain library `audit(home)` call
    print a note naming a flag the caller never passed. Pinned in both directions.
    """
    from clawseccheck import audit, render_report

    ctx, findings, score = audit(SAFE)
    assert "NOT comparable" not in render_report(findings, score, ctx=ctx)


def test_every_optout_flag_is_named(capsys):
    _, out = _run(capsys, "--home", SAFE, "--no-history", "--no-color",
                  "--no-host", "--no-native")
    note = [ln for ln in out.splitlines() if ln.startswith("Note:")]
    assert note, "expected the denominator-narrowing note"
    assert "--no-host" in note[0] and "--no-native" in note[0]


def test_host_check_detail_text_is_left_alone(capsys):
    """B-464 deliberately did NOT reword B50-B54.

    Naming --no-host in those details was tried and reverted: Context.include_host cannot
    tell an explicit opt-out from an ordinary library audit() at that layer, and rewriting
    the detail rewrites the fingerprint a user's .clawseccheckignore suppression is keyed
    on. This pins the revert so it is not silently re-attempted.
    """
    _, out = _run(capsys, "--home", SAFE, "--no-history", "--no-host", "--json")
    data = json.loads(out)
    host_checks = [f for f in data["findings"] if f["id"] in ("B50", "B51", "B52", "B53")]
    assert host_checks, "expected the host-monitor checks in the finding set"
    for f in host_checks:
        assert "--no-host" not in f["detail"]
