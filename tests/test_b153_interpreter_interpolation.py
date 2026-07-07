"""B153 (CLAWSECCHECK-B-137): untrusted variable interpolation into an interpreter
one-liner sink (python -c / node -e / bun -e).

A shell script that builds a double-quoted -c/-e argument with $VAR/${VAR} lets bash
expand it BEFORE the interpreter sees it — a quote-breakout injection risk independent
of whether the body also names a dangerous import (the gap B13's existing
`python -c ... import socket/os.system` match doesn't cover). WARN-only, part of
SKILL_CONTENT_RING (runs in both the full audit and --vet).

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_interpreter_interpolation_injection, vet_skill

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class _FakeCtx:
    def __init__(self, skills):
        self.installed_skills = skills


# ---------------------------------------------------------------------------
# check_interpreter_interpolation_injection unit tests
# ---------------------------------------------------------------------------


def test_no_installed_skills_is_unknown():
    f = check_interpreter_interpolation_injection(_FakeCtx({}))
    assert f.status == UNKNOWN


def test_python_c_double_quoted_var_interp_fires():
    skills = {"s": '# file: run.sh\npython3 -c "print(\'${triggeredCount}\')"\n'}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == WARN
    assert "python3 -c" in f.detail


def test_node_e_double_quoted_var_interp_fires():
    skills = {"s": '# file: run.sh\nnode -e "require(\'child_process\').exec(\'$CMD\')"\n'}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == WARN


def test_bun_e_double_quoted_var_interp_fires():
    skills = {"s": '# file: bun-fetch.sh\nbun -e "fetch(\'${URL}\')"\n'}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == WARN


def test_backtick_command_substitution_fires():
    skills = {"s": '# file: run.sh\npython3 -c "print(`whoami`)"\n'}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == WARN


def test_single_quoted_body_is_clean():
    """Single quotes suppress shell expansion — $VAR reaches the interpreter literally."""
    skills = {"s": "# file: run.sh\npython3 -c 'print(\"$VAR\")'\n"}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == PASS


def test_no_interpolation_is_clean():
    skills = {"s": '# file: run.sh\npython3 -c "print(\'static text\')"\n'}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == PASS


def test_unrelated_python_invocation_is_clean():
    """A python3 call with no -c one-liner at all must not fire."""
    skills = {"s": "# file: run.py\nimport subprocess\nsubprocess.run(['python3', 'script.py'])\n"}
    f = check_interpreter_interpolation_injection(_FakeCtx(skills))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# vet_skill integration: fixture directories (cross-file case — .sh, not SKILL.md)
# ---------------------------------------------------------------------------


def test_vet_pyc_interp_fixture_is_warn():
    skill_dir = FIXTURES / "bad_b153_pyc_interp" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.id == "B153"
    assert f.status == WARN


def test_vet_bun_interp_fixture_is_warn():
    skill_dir = FIXTURES / "bad_b153_bun_interp" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.id == "B153"
    assert f.status == WARN


def test_vet_singlequote_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b153_singlequote" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_no_interp_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b153_no_interp" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_check_registered_in_content_ring():
    from clawseccheck.checks._vet import SKILL_CONTENT_RING

    assert check_interpreter_interpolation_injection in SKILL_CONTENT_RING


def test_check_registered_in_catalog():
    from clawseccheck.catalog import BY_ID

    assert "B153" in BY_ID
    assert BY_ID["B153"].scored is False
