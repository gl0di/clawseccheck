"""Plain-output polish: no literal markdown, card margin, lone-file vet name, did-you-mean."""
import subprocess
from pathlib import Path

from clawseccheck import report

PY = "python3.12"
ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "fixtures" / "home_safe"


def _run(*args):
    return subprocess.run([PY, "-m", "clawseccheck", *args],
                          capture_output=True, text=True, cwd=ROOT)


def test_no_literal_asterisks_in_default_report():
    r = _run("--home", str(HOME), "--ascii")
    assert "*can*" not in r.stdout and "*behaves*" not in r.stdout
    assert "bounds what your agent CAN do" in r.stdout


def test_card_has_right_margin():
    r = _run("--home", str(HOME), "--card", "--ascii")
    rows = [ln for ln in r.stdout.splitlines() if ln.startswith("|")]
    assert rows
    assert all(ln.endswith(" |") or ln.rstrip("|").endswith(" ") for ln in rows[:-1])
    assert len({len(ln) for ln in rows}) == 1
    assert report  # module import sanity


def test_lone_file_vet_names_the_file(tmp_path):
    d = tmp_path / "scratchpad"
    d.mkdir()
    f = d / "thing.py"
    f.write_text("print('hi')\n")
    r = _run("--vet", str(f))
    assert "scratchpad:" not in r.stdout


def test_misspelled_flag_gets_suggestion():
    r = _run("--brefe")
    assert r.returncode == 2
    assert "did you mean --brief" in r.stderr
