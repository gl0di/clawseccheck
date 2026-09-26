"""I-038: ``--exit-code-scheme {binary,graduated}``.

By default (``binary``) ``--fail-on``/``--exit-code`` return 1 for BOTH a real
severity-tripping FAIL and a run that could not produce a trustworthy verdict at all
(a crash, ``ScanBudgetExceeded``, an unusable ``--judged`` path, or an
unreadable/absent config) — the two are indistinguishable by exit code alone, and that
is unchanged by this task; it is a documented public contract (docs/USAGE.md's CI
recipe) real CI configs may already depend on.

C-563: ``--vet`` deliberately does NOT appear above. ``--vet``/``--vet-skill``/
``--vet-plugin``/``--vet-mcp``/``--advise`` never reach ``_findings_exit_gate`` — "vet"
carries no "exit_code"/"fail_on" entry in ``_MODE_HONORS``, so neither
``--exit-code``/``--fail-on`` nor ``--exit-code-scheme`` has any effect on a vet
invocation. An unassessable vet target is exit 2 (``_report_unassessable``), on a code
path this file's gate is never asked to arbitrate; see ``tests/test_b680_vet_absent_target.py``
and ``tests/test_b685_advise_unassessable_target.py`` for that separate contract.

``--exit-code-scheme graduated`` is a purely additive, opt-in alternative that reuses
``--monitor``'s own 0/1/3 convention (C-419) instead of inventing a second one:

  0  clean — the gate did not trip
  1  could not produce a trustworthy verdict
  3  a real, severity-tripping FAIL
  2  never returned by this logic — argparse itself owns it for a usage error

This file pins:

* every binary-mode assertion below holds identically whether ``--exit-code-scheme`` is
  omitted or given explicitly as ``binary`` — the default must be indistinguishable from
  before this flag existed;
* graduated mode's four-way split (0/1/3, and that 3 is never confused with 1);
* the "could not complete" bucket's four members reachable through the real CLI: a tool
  crash, ``ScanBudgetExceeded``, an unusable input path (``UnusableInputPath``), and an
  unreadable/absent config;
* ``_findings_exit_gate``'s own narrower reading of "an incomplete required layer": a
  layer that genuinely erred (``layers.STATUS_ERROR``) trips the graduated "1" bucket,
  but the routine ``not_reached``/``unavailable``/``skipped`` layers a bare (non-``--full``)
  run always carries do NOT — see that function's own I-038 docstring paragraph for why
  the literal "any non-empty missing_layers" reading was rejected (it would return 1 on
  nearly every invocation that omits ``--full``, contradicting the documented "needs no
  score, works on a default (ungraded) run too" contract for ``--fail-on``/``--exit-code``).

Findings are driven either through the real fixtures (``home_vuln`` genuinely carries FAIL
findings at CRITICAL — see tests/test_b584_ci_gate.py) or a from-scratch neutral config
(``_vendor_neutral.neutral_config``, matching tests/test_c424_fail_on.py's own idiom) rather
than home_safe: home_safe carries a real, pre-existing CRITICAL FAIL (B1) once ``--no-native``
is passed, unrelated to this task, and asserting against it would make these tests hostage to
that fixture's drift.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from _vendor_neutral import neutral_config

from clawseccheck import cli
from clawseccheck.catalog import CRITICAL, FAIL, PASS, Finding
from clawseccheck.cli import _findings_exit_gate, main
from clawseccheck.layers import STATUS_ERROR, STATUS_NOT_REACHED

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")  # 8 FAIL, 3 CRITICAL (test_b584_ci_gate.py)
BASE = ["--no-native", "--no-history", "--ascii"]
_REPO = Path(__file__).resolve().parent.parent
_USAGE_MD = _REPO / "docs" / "USAGE.md"
_CLI_FLAGS_MD = _REPO / "references" / "cli-flags.md"


def _clean_home(tmp_path: Path, name: str = "clean_home") -> str:
    """A from-scratch home with zero unsuppressed FAILs — see module docstring for why
    this is used instead of fixtures/home_safe."""
    home = tmp_path / name
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps(neutral_config()), encoding="utf-8")
    return str(home)


def _empty_home(tmp_path: Path, name: str = "empty_home") -> str:
    """A home with no openclaw.json at all — ``config_found`` is False (B-363)."""
    home = tmp_path / name
    home.mkdir(exist_ok=True)
    return str(home)


# ---------------------------------------------------------------------------
# binary mode (default, and given explicitly) is unchanged
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scheme_args", [[], ["--exit-code-scheme", "binary"]])
def test_binary_real_fail_on_returns_one(scheme_args):
    rc = main(["--home", VULN] + BASE + ["--fail-on", "critical"] + scheme_args)
    assert rc == 1


@pytest.mark.parametrize("scheme_args", [[], ["--exit-code-scheme", "binary"]])
def test_binary_real_exit_code_returns_one(scheme_args):
    rc = main(["--home", VULN] + BASE + ["--exit-code"] + scheme_args)
    assert rc == 1


@pytest.mark.parametrize("scheme_args", [[], ["--exit-code-scheme", "binary"]])
def test_binary_unreadable_config_returns_one(tmp_path, scheme_args):
    rc = main(["--home", _empty_home(tmp_path)] + BASE + ["--exit-code"] + scheme_args)
    assert rc == 1


@pytest.mark.parametrize("scheme_args", [[], ["--exit-code-scheme", "binary"]])
def test_binary_crash_returns_one(monkeypatch, tmp_path, scheme_args):
    def _boom(*a, **k):
        raise ValueError("forced crash for I-038 test")

    monkeypatch.setattr(cli, "audit", _boom)
    rc = cli.main(["--home", _clean_home(tmp_path)] + BASE + ["--exit-code"] + scheme_args)
    assert rc == 1


@pytest.mark.parametrize("scheme_args", [[], ["--exit-code-scheme", "binary"]])
def test_binary_clean_returns_zero(tmp_path, scheme_args):
    rc = main(["--home", _clean_home(tmp_path)] + BASE + ["--exit-code"] + scheme_args)
    assert rc == 0


def test_binary_no_gate_flag_stays_zero_even_on_a_failing_config(tmp_path):
    """--exit-code-scheme alone (neither --fail-on nor --exit-code given) must not gate —
    matching --fail-on/--exit-code's own existing "no effect when omitted" contract."""
    rc = main(["--home", VULN] + BASE + ["--exit-code-scheme", "graduated"])
    assert rc == 0


# ---------------------------------------------------------------------------
# graduated mode: 0 clean / 1 could-not-complete / 3 real threshold FAIL
# ---------------------------------------------------------------------------

def test_graduated_fail_on_real_fail_returns_three():
    rc = main(["--home", VULN] + BASE
              + ["--fail-on", "critical", "--exit-code-scheme", "graduated"])
    assert rc == 3


def test_graduated_exit_code_real_fail_returns_three():
    rc = main(["--home", VULN] + BASE + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc == 3


def test_graduated_clean_returns_zero(tmp_path):
    rc = main(["--home", _clean_home(tmp_path)] + BASE
              + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc == 0


def test_graduated_unreadable_config_returns_one_not_three(tmp_path):
    rc = main(["--home", _empty_home(tmp_path)] + BASE
              + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc == 1


def test_graduated_unreadable_config_fail_on_returns_one(tmp_path):
    """The B-166/B-363 config-blind trip on the --fail-on side of the gate, same bucket."""
    rc = main(["--home", _empty_home(tmp_path)] + BASE
              + ["--fail-on", "critical", "--exit-code-scheme", "graduated"])
    assert rc == 1


def test_graduated_crash_returns_one_not_three(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise ValueError("forced crash for I-038 test")

    monkeypatch.setattr(cli, "audit", _boom)
    rc = cli.main(["--home", _clean_home(tmp_path)] + BASE
                  + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc == 1


def test_graduated_scan_budget_exceeded_returns_one(monkeypatch, tmp_path):
    def _budget_boom(*a, **k):
        from clawseccheck.scanbudget import ScanBudgetExceeded  # noqa: PLC0415
        raise ScanBudgetExceeded("forced budget exceeded for I-038 test")

    monkeypatch.setattr(cli, "audit", _budget_boom)
    rc = cli.main(["--home", _clean_home(tmp_path)] + BASE
                  + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc == 1


def test_graduated_unusable_input_path_returns_one(tmp_path):
    """UnusableInputPath (B-684) — here via `--judged` on a file that is not valid UTF-8 —
    reaches main()'s generic guard exactly like a crash does, several frames above
    `_findings_exit_gate`. Reachable with no --exit-code/--fail-on at all (the mode itself
    never reaches the gate), which is the point: `main()`'s except arms return 1 for this
    unconditionally, under either scheme (see that function's own I-038 docstring note)."""
    judged = tmp_path / "judged.bin"
    judged.write_bytes(b"\xff\xfe\x00\x01")
    rc = main(["--home", _clean_home(tmp_path), "--judged", str(judged),
               "--exit-code-scheme", "graduated"])
    assert rc == 1


# ---------------------------------------------------------------------------
# 2 is reserved for argparse's own usage error, never returned by this logic
# ---------------------------------------------------------------------------

def test_invalid_scheme_value_is_an_argparse_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--home", _clean_home(tmp_path), "--exit-code-scheme", "bogus"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("case", ["clean", "blind", "fail"])
def test_graduated_never_returns_two(tmp_path, case):
    if case == "clean":
        home = _clean_home(tmp_path)
    elif case == "blind":
        home = _empty_home(tmp_path)
    else:
        home = VULN
    rc = main(["--home", home] + BASE + ["--exit-code", "--exit-code-scheme", "graduated"])
    assert rc != 2


# ---------------------------------------------------------------------------
# _findings_exit_gate's own contract, direct — matching test_b584_ci_gate.py's idiom
# ---------------------------------------------------------------------------

def _f(fid: str, status: str, severity: str) -> Finding:
    return Finding(id=fid, title=fid, severity=severity, status=status,
                   detail="d", fix="f", framework="x")


class _Args:
    def __init__(self, exit_code=False, fail_on=None, exit_code_scheme="binary"):
        self.exit_code = exit_code
        self.fail_on = fail_on
        self.exit_code_scheme = exit_code_scheme


class _Ctx:
    config_parse_error = False
    config_found = True


class _BlindCtx:
    config_parse_error = True
    config_found = True


class _Score:
    def __init__(self, missing_layers=()):
        self.missing_layers = missing_layers


def test_gate_duck_typed_args_without_the_new_attribute_defaults_to_binary():
    """A caller/test built before I-038 (no `exit_code_scheme` attribute at all) must see
    byte-identical behaviour — `getattr(args, "exit_code_scheme", "binary")` is what makes
    tests/test_b584_ci_gate.py's own pre-existing `_Args` (with no such attribute) still
    pass unmodified."""
    class _OldArgs:
        def __init__(self, exit_code=False, fail_on=None):
            self.exit_code = exit_code
            self.fail_on = fail_on

    fail = [_f("B1", FAIL, CRITICAL)]
    assert _findings_exit_gate(_OldArgs(exit_code=True), fail, _Ctx()) == 1


def test_gate_graduated_real_fail_is_three():
    fail = [_f("B1", FAIL, CRITICAL)]
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    assert _findings_exit_gate(args, fail, _Ctx()) == 3


def test_gate_graduated_fail_on_real_fail_is_three():
    fail = [_f("B1", FAIL, CRITICAL)]
    args = _Args(fail_on="critical", exit_code_scheme="graduated")
    assert _findings_exit_gate(args, fail, _Ctx()) == 3


def test_gate_graduated_blind_config_is_one_even_with_a_fail_present():
    """A blind/errored run outranks a real FAIL — see _findings_exit_gate's own I-038
    docstring paragraph: it is a fact about whether the run can be trusted at all."""
    fail = [_f("B1", FAIL, CRITICAL)]
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    assert _findings_exit_gate(args, fail, _BlindCtx()) == 1


def test_gate_graduated_clean_is_zero():
    clean = [_f("B1", PASS, CRITICAL)]
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    assert _findings_exit_gate(args, clean, _Ctx()) == 0


def test_gate_binary_unaffected_by_scheme_attribute_present_but_binary():
    fail = [_f("B1", FAIL, CRITICAL)]
    args = _Args(exit_code=True, exit_code_scheme="binary")
    assert _findings_exit_gate(args, fail, _Ctx()) == 1


# -- the narrowed "incomplete required layer" reading: STATUS_ERROR only ---------------

def test_gate_graduated_errored_layer_alone_trips_one():
    """A layer that genuinely erred (STATUS_ERROR) is a "could not complete" signal even
    with zero findings at all — the bucket the crash/budget/unusable-path cases share."""
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    score = _Score(missing_layers=(("live_behaviour", STATUS_ERROR),))
    assert _findings_exit_gate(args, [], _Ctx(), score=score) == 1


def test_gate_graduated_routine_missing_layers_do_not_trip_one():
    """The rejected literal reading, pinned as a regression test: a bare run's routine
    not_reached/unavailable/skipped layers (never STATUS_ERROR) must NOT trip the "could
    not complete" bucket, or --exit-code-scheme graduated would return 1 on nearly every
    invocation that omits --full — see _findings_exit_gate's own I-038 docstring
    paragraph and the module docstring above."""
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    score = _Score(missing_layers=(
        ("installed_sweep", STATUS_NOT_REACHED),
        ("self_report", STATUS_NOT_REACHED),
        ("live_behaviour", STATUS_NOT_REACHED),
    ))
    assert _findings_exit_gate(args, [], _Ctx(), score=score) == 0


def test_gate_graduated_errored_layer_with_no_score_kwarg_is_inert():
    """Omitting `score` entirely (every pre-I-038 call site not updated to pass it) must
    not crash and must not spuriously trip the errored-layer branch."""
    args = _Args(exit_code=True, exit_code_scheme="graduated")
    assert _findings_exit_gate(args, [], _Ctx()) == 0


def test_gate_binary_ignores_errored_layer():
    """`score`/STATUS_ERROR is read ONLY under the graduated scheme — binary must stay
    exactly what it always was regardless of what `missing_layers` carries."""
    args = _Args(exit_code=True, exit_code_scheme="binary")
    score = _Score(missing_layers=(("live_behaviour", STATUS_ERROR),))
    assert _findings_exit_gate(args, [], _Ctx(), score=score) == 0


# ---------------------------------------------------------------------------
# C-563: --exit-code-scheme (and --exit-code/--fail-on themselves) have NO
# effect on --vet, which keeps its own, separate 1/2 contract entirely outside
# _findings_exit_gate (see _report_unassessable). The prior --help/docs wording
# wrongly listed "an unusable --vet path" as part of the binary/graduated "1"
# bucket above; measured, an unassessable --vet target is exit 2 regardless of
# --exit-code-scheme, because "vet" mode never reaches this gate at all ("vet"
# carries no "exit_code"/"fail_on" entry in _MODE_HONORS).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gate_args", [[], ["--exit-code"]])
@pytest.mark.parametrize("scheme_args", [
    [],
    ["--exit-code-scheme", "binary"],
    ["--exit-code-scheme", "graduated"],
])
def test_vet_unassessable_target_is_always_two_regardless_of_scheme(
    tmp_path, scheme_args, gate_args
):
    missing = str(tmp_path / "definitely-does-not-exist-c563")
    rc = main(["--vet", missing] + BASE + gate_args + scheme_args)
    assert rc == 2, (
        "an unassessable --vet target must stay exit 2 (its own usage-error "
        "contract) no matter what --exit-code-scheme says about the "
        "--fail-on/--exit-code gate, which --vet never reaches"
    )


def test_help_exit_code_scheme_does_not_misattribute_vet_to_its_gate_bucket():
    """--help for --exit-code-scheme must not claim an "unusable --vet path" is part of
    the binary/graduated "1" bucket -- that bucket is _findings_exit_gate's, and --vet
    never reaches it. Grounded against the real argparse text, not just the source
    comment beside it."""
    out = subprocess.run(
        [sys.executable, str(_REPO / "audit.py"), "--help"],
        cwd=_REPO, capture_output=True, text=True, timeout=30,
    ).stdout
    # The flag also appears in the usage synopsis at the top of --help; anchor on the
    # option-list entry (its own indented "  --exit-code-scheme ..." line) so the window
    # captures the actual help paragraph, not the one-line synopsis.
    idx = out.find("\n  --exit-code-scheme ")
    assert idx != -1
    window = out[idx:idx + 1200]
    assert "unusable" not in window.lower() or "vet" not in window.lower(), (
        "the --exit-code-scheme help text still attributes an unusable --vet path to "
        "this gate's own 1/3 bucket; measured, --vet exits 2 on a code path this flag "
        "never reaches"
    )
    assert "no effect" in window.lower() and "vet" in window.lower(), (
        "the --exit-code-scheme help text should say plainly that it has no effect on "
        "--vet, which keeps its own separate contract"
    )


def test_docs_usage_md_does_not_bucket_unusable_vet_path_under_exit_code_scheme():
    text = _USAGE_MD.read_text(encoding="utf-8")
    idx = text.find("Telling a real FAIL apart from a run that could not complete")
    assert idx != -1
    section = text[idx:idx + 1600]
    assert "unusable `--vet`" not in section, (
        "docs/USAGE.md's --exit-code-scheme section still claims an unusable --vet "
        "path is part of the binary/graduated bucket; measured, --vet exits 2 on a "
        "code path this flag never reaches"
    )


def test_docs_cli_flags_md_does_not_bucket_unusable_vet_path_under_exit_code_scheme():
    text = _CLI_FLAGS_MD.read_text(encoding="utf-8")
    idx = text.find("--exit-code-scheme {binary,graduated}")
    assert idx != -1
    section = text[idx:idx + 900]
    assert "unusable `--vet`" not in section, (
        "references/cli-flags.md's --exit-code-scheme entry still claims an unusable "
        "--vet path is part of the binary/graduated bucket; measured, --vet exits 2 "
        "on a code path this flag never reaches"
    )
