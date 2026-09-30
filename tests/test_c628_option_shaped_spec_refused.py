"""C-628: --vet-plan must not render an npm/pypi spec that a package manager reads as an option.

`npm:--registry=http://203.0.113.9` used to render
`npm pack --registry=http://203.0.113.9 --pack-destination "$QUARANTINE"`, and `--vet-source`
on the same spec returned UNKNOWN / rc 0. `shlex.quote` cannot help: the shell strips the
quotes before npm / pip read argv, so argv[N] still starts with `-`. That is argument
injection, a different class from B-487 (shell metacharacters) and B-577 (line separators).

The token printed for npm is `name@version` and for pypi `name==version`, so it starts with
`-` exactly when `name` does; the version leg is belt-and-braces. Only npm/pypi are guarded:
a url / git `name` is a path segment and may legitimately start with `-`.

Helpers are imported INSIDE the tests that need them (see the B-577 file's note): a
module-level import of a name absent from the pre-fix tree would turn every behavioural test
into a collection error and prove nothing about the defect.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import shlex

import pytest

_BAD_SPECS = [
    "npm:--registry=http://203.0.113.9",
    "pypi:--index-url=http://203.0.113.9",
    "npm:-rhttp://203.0.113.9",
    "pypi:-r http://203.0.113.9",
    "npm: --x",
    "NPM:--x",
    "PyPI:--x",
    "npm:-",
    "npm:left-pad@--registry=http://x",
    "pypi:requests==--index-url=http://x",
    "npm:@@--x",
    "npm:@scope/name@--x",
]

_CLEAN_SPECS = [
    "npm:left-pad@1.0.0",
    "npm:@openclaw/brave-plugin@2026.6.11",
    "npm:left-pad",
    "npm:left-pad@1.0.0-beta.1",
    "npm:@scope/name@1.0.0",
    "pypi:requests==2.0",
    "pypi:some-mcp-server==1.0",
    "pypi:requests",
    "pypi:requests>=2.0",
    "git:github.com/o/-r@main",
    "https://x.test/-r",
]

_FETCH_VERBS = ("npm pack", "pip download", "curl", "git clone", "rm -rf")

_OPTION_REASON = "starts with '-'"
_CONTROL_CHAR_REASON = "control character"


def _cli(argv: list[str]) -> tuple[int, str]:
    from clawseccheck.cli import main

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def _command_lines(rendered: str) -> list[str]:
    out = []
    for raw in rendered.splitlines():
        line = raw.strip()
        if any(line.startswith(v) for v in _FETCH_VERBS):
            out.append(line.split("   #")[0].rstrip())
    return out


def _outside_target_line(rendered: str) -> str:
    return "\n".join(
        ln for ln in rendered.splitlines() if not ln.lstrip().startswith("target (escaped):"))


# ------------------------------------------------------------------ bad: refuse / warn
@pytest.mark.parametrize("spec", _BAD_SPECS)
def test_vet_plan_refuses_an_option_shaped_spec(spec):
    from clawseccheck.report import render_vet_plan

    plan = render_vet_plan(spec)
    assert "I will not build a fetch plan" in plan
    assert _command_lines(plan) == [], "a fetch command was rendered for an option-shaped spec"
    assert "--vet-source" not in plan and "QUARANTINE" not in plan
    assert _OPTION_REASON in plan
    assert _CONTROL_CHAR_REASON not in plan, "refusal must not print the control-character reason"
    # the option text may only appear inside the repr'd target line
    assert f"target (escaped): {spec!r}" in plan
    assert spec not in _outside_target_line(plan)


@pytest.mark.parametrize("spec", _BAD_SPECS)
def test_parse_marks_option_shaped(spec):
    from clawseccheck.checks import _parse_source_target

    assert _parse_source_target(spec)["option_shaped"] is True


@pytest.mark.parametrize("spec", _BAD_SPECS)
def test_vet_source_warns_on_an_option_shaped_spec(spec):
    from clawseccheck.catalog import MEDIUM, WARN
    from clawseccheck.checks import vet_source

    f = vet_source(spec)
    assert f.status == WARN
    assert f.severity == MEDIUM
    assert f.detail.startswith("suspicious source identity")
    assert _OPTION_REASON in f.detail
    assert _OPTION_REASON in f.evidence[0], "the option reason must be the headline evidence"


@pytest.mark.parametrize("spec", _BAD_SPECS)
def test_cli_vet_plan_refuses_and_vet_source_cautions(spec):
    rc, out = _cli(["--vet-plan", spec])
    assert rc == 0  # --vet-plan always returns 0 (same as the control-character refusal)
    assert "I will not build a fetch plan" in out
    assert _command_lines(out) == []

    rc, out = _cli(["--vet-source", spec])
    assert rc == 1
    assert "CAUTION" in out


def test_option_reason_leads_over_a_typosquat_reason():
    """`insert(0)`: when another reason also fires, the option reason is still the headline."""
    from clawseccheck.checks import vet_source

    f = vet_source("npm:-openclawy@--x")
    assert _OPTION_REASON in f.detail


# ---------------------------------------------------------- clean: must not change
@pytest.mark.parametrize("spec", _CLEAN_SPECS)
def test_clean_specs_still_render_a_plan(spec):
    from clawseccheck.checks import _parse_source_target
    from clawseccheck.report import render_vet_plan

    assert _parse_source_target(spec)["option_shaped"] is False
    plan = render_vet_plan(spec)
    assert "I will not build a fetch plan" not in plan
    assert _command_lines(plan), f"no fetch command rendered for {spec!r}"
    for line in _command_lines(plan):
        assert "--" not in shlex.split(line)[1:], (
            f"standalone -- token in {line!r}; it would make --pack-destination positional")


def test_clean_command_lines_are_byte_identical():
    from clawseccheck.report import render_vet_plan

    assert ('npm pack left-pad@1.0.0 --pack-destination "$QUARANTINE"'
            in _command_lines(render_vet_plan("npm:left-pad@1.0.0")))
    assert ('npm pack @openclaw/brave-plugin@2026.6.11 --pack-destination "$QUARANTINE"'
            in _command_lines(render_vet_plan("npm:@openclaw/brave-plugin@2026.6.11")))
    assert ('pip download --no-deps -d "$QUARANTINE" requests==2.0'
            in _command_lines(render_vet_plan("pypi:requests==2.0")))
    # the operator is part of the name here, so it is shell-quoted as one token (B-487)
    assert ('pip download --no-deps -d "$QUARANTINE" \'requests>=2.0\''
            in _command_lines(render_vet_plan("pypi:requests>=2.0")))


def test_url_and_git_dash_leading_segment_still_render():
    from clawseccheck.report import render_vet_plan

    assert any(ln.startswith("git clone") for ln in _command_lines(
        render_vet_plan("git:github.com/o/-r@main")))
    assert any(ln.startswith("curl") for ln in _command_lines(
        render_vet_plan("https://x.test/-r")))


@pytest.mark.parametrize("spec", [
    "npm:left-pad@1.0.0", "npm:left-pad", "pypi:requests==2.0", "pypi:requests",
    "git:github.com/o/-r@main", "https://x.test/-r"])
def test_clean_specs_keep_their_vet_source_verdict(spec):
    from clawseccheck.catalog import WARN
    from clawseccheck.checks import vet_source

    f = vet_source(spec)
    # never the option-shaped headline
    assert _OPTION_REASON not in f.detail
    if spec.startswith(("npm:", "pypi:")):
        assert f.status != WARN


# --------------------------------------------------- the control-character refusal is intact
def test_control_character_refusal_keeps_its_own_reason():
    from clawseccheck.report import render_vet_plan

    plan = render_vet_plan("bare-name\nrm -rf /")
    assert "I will not build a fetch plan" in plan
    assert _CONTROL_CHAR_REASON in plan
    assert _OPTION_REASON not in plan
