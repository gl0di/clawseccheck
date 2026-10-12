"""C-691 (behaviour, part 2) - B323 read `${NAME:-default}` as a literal PATH override.

The `:-` default operator exists only from OpenClaw 2026.9.7 (see checks/_shared.py, C-646).
So the reading is BUILD-CONDITIONAL, on the audited installed build via `_env_default_operator`:
  * 2026.9.7 and later ("yes")  : `${HOME:-/x}/bin` is an env reference the vendor never applies
                                  literally -> B323 PASS (the false WARN this task removes);
  * earlier ("no") or an undetermined build : the body `HOME:-/x` fails the name test, so the
                                  value IS a literal PATH override -> B323 WARN (unchanged).
Every consumer of the port is covered: B323, B326 (`elevatedDefault`, the `tools.exec.*` fields)
and the exec-policy monitor dimension. Imports only names that exist on the unfixed tree.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_elevated_default_full, check_env_vars_path_override
from clawseccheck.collector import collect
from clawseccheck.monitordims._execpolicy import _exec_policy_sig

_NEW = ["2026.9.7", "2026.9.9", "2026.10.2"]
_OLD_OR_UNKNOWN = ["2026.9.6", "2026.8.1", "2026.7.1", None, "0.0.0", "not-a-version", "2026.9"]


def _ctx(cfg: dict, build):
    home = Path(tempfile.mkdtemp(prefix="c691-"))
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    ctx = collect(home)
    ctx.installed_dist_version = build
    return ctx


def _b323(value, build):
    return check_env_vars_path_override(_ctx({"env": {"vars": {"PATH": value}}}, build)).status


# value -> (status on a >= 2026.9.7 build, status on an older or undetermined build)
_PATH_CASES = {
    "${HOME:-/x}/bin": (PASS, WARN),
    "${HOME:-}": (PASS, WARN),
    "/opt/evil:${FOO:-/usr/bin}": (PASS, WARN),
    "${HOME:-x}${y}/evil": (PASS, WARN),
    # the vendor drops ANY value that contains an env reference (isConfigRuntimeEnvVarAllowed),
    # whatever else it holds: an intended PASS-direction move on a build that has the operator
    "${FOO:-/tmp/evil}": (PASS, WARN),
    "${FOO:-a}:/tmp/evil": (PASS, WARN),
    "${HOME}:/tmp/evil": (PASS, PASS),  # the same rule, already so before this change
    "${HOME}/bin": (PASS, PASS),
    "/opt/evil/bin:/usr/bin": (WARN, WARN),
    "${HOME:-$x}/bin": (WARN, WARN),
    "${FOO:-{x}}:/opt/evil/bin": (WARN, WARN),
    "${home:-/x}/bin": (WARN, WARN),
    "$${HOME:-/x}/bin": (WARN, WARN),
}


@pytest.mark.parametrize("value", list(_PATH_CASES))
@pytest.mark.parametrize("build", _NEW)
def test_b323_on_a_build_that_understands_the_default_operator(value, build):
    assert _b323(value, build) == _PATH_CASES[value][0], (value, build)


@pytest.mark.parametrize("value", list(_PATH_CASES))
@pytest.mark.parametrize("build", _OLD_OR_UNKNOWN, ids=[str(b) for b in _OLD_OR_UNKNOWN])
def test_b323_on_an_older_or_undetermined_build_keeps_the_literal_reading(value, build):
    assert _b323(value, build) == _PATH_CASES[value][1], (value, build)


def test_b323_arbitrary_env_key_catchall_follows_the_same_build_rule():
    for build, expected in (("2026.10.2", PASS), ("2026.9.6", WARN), (None, WARN)):
        ctx = _ctx({"env": {"PATH": "${HOME:-/x}/bin"}}, build)
        assert check_env_vars_path_override(ctx).status == expected, build


@pytest.mark.parametrize("build", _NEW)
def test_b326_reads_a_default_operator_value_as_a_reference_on_a_new_build(build):
    cfg = {"agents": {"defaults": {"elevatedDefault": "${LVL:-full}"}}}
    assert check_elevated_default_full(_ctx(cfg, build)).status == UNKNOWN


@pytest.mark.parametrize("build", ["2026.9.6", "2026.8.1", None])
def test_b326_keeps_the_literal_reading_on_an_older_or_undetermined_build(build):
    cfg = {"agents": {"defaults": {"elevatedDefault": "${LVL:-full}"}}}
    assert check_elevated_default_full(_ctx(cfg, build)).status == PASS


def test_b326_plain_references_are_build_independent():
    cfg = {"agents": {"defaults": {"elevatedDefault": "${LVL}"}}}
    for build in ("2026.9.6", "2026.10.2", None):
        assert check_elevated_default_full(_ctx(cfg, build)).status == UNKNOWN, build


@pytest.mark.parametrize("build", _NEW)
def test_exec_policy_monitor_dimension_marks_a_default_operator_value_undetermined(build):
    sig = _exec_policy_sig(_ctx({"tools": {"exec": {"security": "${S:-full}"}}}, build))
    assert sig["scopes"]["global"] == {"undetermined": "an unresolved ${...} reference"}


@pytest.mark.parametrize("build", ["2026.9.6", None])
def test_exec_policy_monitor_dimension_keeps_the_literal_reading_on_an_older_build(build):
    sig = _exec_policy_sig(_ctx({"tools": {"exec": {"security": "${S:-full}"}}}, build))
    assert "undetermined" not in sig["scopes"]["global"]
    assert sig["scopes"]["global"]["security"] == "${S:-full}"
