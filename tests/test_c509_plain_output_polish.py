"""Plain-output polish: no literal markdown, card margin, lone-file vet name, did-you-mean."""
import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck import report

PY = sys.executable  # C-573: was a hard-coded "python3.12" — see the guard test below.
ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "fixtures" / "home_safe"


def _run(*args):
    return subprocess.run([PY, "-m", "clawseccheck", "--no-deptree", *args],
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


# --- C-573 guard: a hard-coded "python3.<minor>" interpreter must never come back ---

_HARDCODED_INTERPRETER = re.compile(r"^python3\.\d+$")


@pytest.mark.mechanical  # dependency-free source scan; the rest of this file spawns subprocesses
def test_no_test_hardcodes_a_python3_minor_interpreter():
    """This file hard-coded PY = "python3.12" until C-573: on the CI 3.9 leg (and on
    any box without a python3.12 binary) it silently ran the wrong interpreter, or not
    at all, instead of failing loudly. A string literal that is nothing but
    "python3.<N>" never occurs legitimately elsewhere in the suite — a real
    interpreter path, a shebang fixture, or a regeneration-command docstring always
    embeds the version inside a longer string, never as the whole literal (verified:
    only this file's old PY assignment ever matched this pattern). Use sys.executable
    instead, as every other test file does."""
    offenders = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and _HARDCODED_INTERPRETER.match(node.value)):
                offenders.append(f"{path.name}: {node.value!r}")
    assert not offenders, (
        "hard-coded python3.<minor> interpreter literal(s) found — use sys.executable "
        f"instead: {offenders}"
    )
