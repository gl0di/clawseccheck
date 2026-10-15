"""C-719: ``--save-sbom-run`` / ``--format`` without ``--sbom`` say so on stderr.

Both flags only mean something alongside ``--sbom`` (``_MODE_HONORS["sbom"]``). On the
plain-audit path (no primary mode at all) ``_flag_coherence_notes`` returned early and
named neither, so ``--save-sbom-run`` alone ran an ordinary audit, exited 0 and printed
nothing - the user believed a run had been stored. Every other global modifier that does
nothing on that path (``--quiet``, ``--fast``, ``--yes`` ...) already gets a one-line
``note:``. stdout and the exit code are unchanged: this is a note, not a refusal.

Offline, nothing is written outside tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.cli import main

ROOT = Path(__file__).resolve().parent.parent
HOME = str(ROOT / "fixtures" / "home_safe")
BASE = ["--no-native", "--no-history", "--no-deptree", "--no-host", "--no-sockets"]


def _run(capsys, tmp_path, extra):
    code = main(["--home", HOME, "--data-dir", str(tmp_path / "d")] + BASE + extra)
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_save_sbom_run_without_sbom_is_named(capsys, tmp_path):
    code, out, err = _run(capsys, tmp_path, ["--save-sbom-run"])
    assert "note: --save-sbom-run has no effect without --sbom" in err
    assert out.strip(), "the ordinary audit still runs and prints its report"
    assert code == 0
    assert not (tmp_path / "d" / "sbom_runs.jsonl").exists()


def test_format_without_sbom_is_named(capsys, tmp_path):
    for fmt in ("cyclonedx", "spdx"):
        code, out, err = _run(capsys, tmp_path, ["--format", fmt])
        assert "note: --format has no effect without --sbom" in err, fmt
        assert out.strip() and code == 0


def test_both_flags_get_their_own_note(capsys, tmp_path):
    _, _, err = _run(capsys, tmp_path, ["--format", "spdx", "--save-sbom-run"])
    assert "--format has no effect without --sbom" in err
    assert "--save-sbom-run has no effect without --sbom" in err


def test_sbom_mode_still_honors_both_and_stays_quiet(capsys, tmp_path):
    code, _, err = _run(capsys, tmp_path, ["--sbom", "--format", "spdx", "--save-sbom-run"])
    assert code == 0
    assert "has no effect" not in err


def test_default_format_and_plain_audit_stay_quiet(capsys, tmp_path):
    _, _, err = _run(capsys, tmp_path, [])
    assert "has no effect" not in err
    _, _, err = _run(capsys, tmp_path, ["--format", "native"])
    assert "has no effect" not in err


def test_other_primary_mode_already_notes_them(capsys, tmp_path):
    # The winning-mode branch (not the plain-audit one) was already correct; pin it so the
    # two paths cannot drift apart again.
    _, _, err = _run(capsys, tmp_path, ["--next", "--save-sbom-run"])
    assert "--save-sbom-run has no effect with --next" in err
