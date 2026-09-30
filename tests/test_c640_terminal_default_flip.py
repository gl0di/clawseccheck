"""B350 (C-640) - the default of gateway.terminal.enabled flipped from OFF to ON, in code,
with the config path unchanged.

    2026.7.1 .. 2026.7.35   launch-*.js:109,120  enabled !== true ; :154 === true   (unset = off)
    2026.8.1 .. 2026.9.7    enabled-*.js:3        enabled !== false                  (unset = ON)

Before this fix B350 PASSed an unset key ("absent or not true") on every build, including
2026.8.1+ where the operator terminal is on unless the key is explicitly false. The tests
below pin the three-valued build answer (``off`` / ``on`` / ``unknown``), the verdict
matrix it drives, and the things that must NOT move: the explicit-``true`` WARN text
(``baseline.fingerprint()`` hashes ``detail``, so changing it orphans users'
``.clawseccheckignore`` entries) and "never FAIL".

Offline and read-only: no dist is read, the build is injected through
``Context.installed_dist_version`` or ``meta.lastTouchedVersion``.
"""
from __future__ import annotations

import json

import pytest

import clawseccheck
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _TERMINAL_DEFAULT_ON_MIN,
    _TERMINAL_OFF_MEASURED_MAX,
    _TERMINAL_OFF_MEASURED_MIN,
    _terminal_default,
    check_gateway_operator_terminal,
)
from clawseccheck.collector import Context

_UNSET = object()

# Literal copy of the explicit-true detail as it was BEFORE C-640 (loopback + login shell).
# Any edit to this string re-keys users' .clawseccheckignore entries.
_TRUE_DETAIL_LOOPBACK = (
    "gateway.terminal.enabled is true: OpenClaw serves a PTY-backed shell running with "
    "the gateway process environment to Control UI and mobile clients, and it launches "
    "the host login shell ($SHELL), since gateway.terminal.shell is unset. Right now the "
    "gateway is bound to loopback, so the shell is reachable only from this host."
)


def _ctx(cfg, tmp_path, version=None):
    return Context(home=tmp_path, config=cfg, config_found=True,
                   installed_dist_version=version)


def _stamped(cfg, stamp):
    cfg = dict(cfg)
    cfg["meta"] = {"lastTouchedVersion": stamp}
    return cfg


def _cfg(enabled=_UNSET, shape="terminal", bind="127.0.0.1:8080"):
    """A gateway config. ``shape``: 'terminal' = a terminal block (with ``enabled`` when
    given), 'no_terminal' = a gateway with no terminal key, 'no_gateway' = no gateway."""
    if shape == "no_gateway":
        return {"tools": {"profile": "minimal"}}
    gw = {"bind": bind}
    if shape == "terminal":
        term = {"shell": "/bin/bash"} if enabled is _UNSET else {"enabled": enabled}
        gw["terminal"] = term
    return {"gateway": gw}


def _run(cfg, tmp_path, version=None):
    return check_gateway_operator_terminal(_ctx(cfg, tmp_path, version))


# ------------------------------------------------------------------ _terminal_default table
@pytest.mark.parametrize("version,expected", [
    (None, "unknown"),
    ("2026.6.34", "unknown"),       # the feature does not exist yet
    ("2026.6.9", "unknown"),
    ("2026.7.1", "off"),            # oldest measured
    ("2026.7.33", "off"),
    ("2026.7.35", "off"),           # newest measured
    ("2026.7.36", "unknown"),       # unmeasured window
    ("2026.8.0", "unknown"),        # unmeasured window
    ("2026.8.1", "on"),
    ("2026.9.6", "on"),
    ("2026.9.7", "on"),
    ("2027.1.1", "on"),
    ("0.0.0", "unknown"),
    ("2026.7", "unknown"),          # not shaped like a calendar release
    ("2026.9.8-beta.1", "unknown"),  # pre-release orders as None
    # The cached 2026.7.2 pre-releases carry the default-ON gate (`!== false`), unlike the
    # stable 7.1 / 7.33-7.35 line: a pre-release string must never be read as "off".
    ("2026.7.2-beta.5", "unknown"),
    ("2026.7.2-beta.7", "unknown"),
    ("2026.7.1-2", "off"),          # the re-publish of 7.1, itself read as `=== true`
    ("garbage", "unknown"),
])
def test_installed_version_truth_table(version, expected, tmp_path):
    assert _terminal_default(_ctx(_cfg(), tmp_path, version)) == expected


def test_constants_are_the_measured_ones():
    assert _TERMINAL_DEFAULT_ON_MIN == (2026, 8, 1)
    assert _TERMINAL_OFF_MEASURED_MIN == (2026, 7, 1)
    assert _TERMINAL_OFF_MEASURED_MAX == (2026, 7, 35)


def test_a_stamp_only_ever_proves_on(tmp_path):
    """meta.lastTouchedVersion at 8.1+ proves an 8.1+ build once saved the config; a stamp
    below the threshold proves nothing about what is installed now, so it is UNKNOWN,
    never off."""
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.9.6"), tmp_path)) == "on"
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.8.1"), tmp_path)) == "on"
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.7.1"), tmp_path)) == "unknown"
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.7.35"), tmp_path)) == "unknown"
    assert _terminal_default(_ctx(_stamped(_cfg(), "not-a-version"), tmp_path)) == "unknown"


def test_installed_beats_the_stamp(tmp_path):
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.9.6"), tmp_path, "2026.7.35")) == "off"
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.7.1"), tmp_path, "2026.9.7")) == "on"
    # an installed build in the unmeasured window is UNKNOWN even with a newer stamp
    assert _terminal_default(_ctx(_stamped(_cfg(), "2026.9.6"), tmp_path, "2026.7.36")) == "unknown"


# ------------------------------------------------------------------ clean
@pytest.mark.parametrize("version", [None, "2026.7.35", "2026.9.7"])
def test_explicit_false_passes_on_every_build(version, tmp_path):
    f = _run(_cfg(False), tmp_path, version)
    assert f.status == PASS, f.detail
    assert "explicitly disabled" in f.detail


@pytest.mark.parametrize("version", ["2026.7.1", "2026.7.35"])
@pytest.mark.parametrize("shape", ["terminal", "no_terminal", "no_gateway"])
def test_unset_on_a_measured_default_off_build_passes(version, shape, tmp_path):
    f = _run(_cfg(_UNSET, shape), tmp_path, version)
    assert f.status == PASS, f.detail
    assert "defaults it to off" in f.detail
    # the disclosure that the default flipped lives in fix, never detail
    assert "2026.8.1" in f.fix and "2026.8.1" not in f.detail


# ------------------------------------------------------------------ bad
@pytest.mark.parametrize("version", ["2026.8.1", "2026.9.6", "2026.9.7"])
@pytest.mark.parametrize("shape", ["terminal", "no_terminal", "no_gateway"])
def test_unset_on_installed_default_on_build_is_warn_not_pass(version, shape, tmp_path):
    """The regression this task exists for: before C-640 every one of these was PASS."""
    f = _run(_cfg(_UNSET, shape), tmp_path, version)
    assert f.status == WARN, f"{shape}@{version}: {f.status}: {f.detail}"
    assert "unset" in f.detail and "defaults it to true" in f.detail
    assert "admin-scope" in f.detail


def test_unset_on_installed_9_7_is_warn_not_pass(tmp_path):
    """Named guard: with the fix reverted the old code returns PASS here."""
    f = _run({"gateway": {}}, tmp_path, "2026.9.7")
    assert f.status == WARN


def test_unset_with_a_recent_stamp_and_no_installed_version_warns(tmp_path):
    f = _run(_stamped(_cfg(_UNSET, "no_terminal"), "2026.9.6"), tmp_path, None)
    assert f.status == WARN, f.detail


@pytest.mark.parametrize("version", [None, "2026.7.35", "2026.9.7"])
def test_explicit_true_warns_with_the_unchanged_detail(version, tmp_path):
    cfg = {"gateway": {"bind": "127.0.0.1:8080", "terminal": {"enabled": True}}}
    f = _run(cfg, tmp_path, version)
    assert f.status == WARN
    assert f.detail == _TRUE_DETAIL_LOOPBACK, "explicit-true detail is fingerprinted"


def test_the_default_on_warn_names_reach_and_mitigation(tmp_path):
    loop = _run(_cfg(_UNSET, bind="127.0.0.1:8080"), tmp_path, "2026.9.7")
    lan = _run(_cfg(_UNSET, bind="0.0.0.0:8080"), tmp_path, "2026.9.7")
    none = _run(_cfg(_UNSET, "no_gateway"), tmp_path, "2026.9.7")
    assert "only from this host" in loop.detail
    assert "reachable beyond loopback" in lan.detail
    assert "cannot be resolved from config alone" in none.detail
    assert "default bind is loopback" not in none.detail
    for f in (loop, lan, none):
        assert "admin-scope" in f.fix
        assert "2026.8.1" in f.fix
        assert "sandbox.mode 'all'" in f.fix
        assert "gateway.mode" in f.fix and "remote" in f.fix   # the named limit


def test_an_unset_bind_is_unresolved_on_the_default_on_branch_only(tmp_path):
    """The explicit-true detail keeps its old reading of an unset bind as loopback (it is
    fingerprinted); the default-ON branch does not claim a loopback nobody configured."""
    dflt = _run({"gateway": {}}, tmp_path, "2026.9.7")
    assert "cannot be resolved from config alone" in dflt.detail
    assert "only from this host" not in dflt.detail
    explicit = _run({"gateway": {"terminal": {"enabled": True}}}, tmp_path, "2026.9.7")
    assert explicit.detail == _TRUE_DETAIL_LOOPBACK


def test_default_on_warn_shares_its_sentences_with_explicit_true(tmp_path):
    """The two WARN branches are built from one helper, so they cannot drift."""
    on = _run(_cfg(True, bind="0.0.0.0:8080"), tmp_path, "2026.9.7")
    dflt = _run(_cfg(_UNSET, "no_terminal", bind="0.0.0.0:8080"), tmp_path, "2026.9.7")
    reach = "the gateway is reachable beyond loopback"
    assert reach in on.detail and reach in dflt.detail
    # the "which interpreter ... Right now <reach>." tail is the shared helper's output
    assert on.detail.split(", and ", 1)[1] == dflt.detail.split(", and ", 1)[1]
    assert on.fix == dflt.fix


# ------------------------------------------------------------------ unknown
@pytest.mark.parametrize("version", [None, "2026.6.34", "2026.7.36", "2026.8.0",
                                     "0.0.0", "2026.9.8-beta.1", "2026.7"])
@pytest.mark.parametrize("shape", ["terminal", "no_terminal", "no_gateway"])
def test_unset_with_an_undeterminable_build_is_unknown(version, shape, tmp_path):
    f = _run(_cfg(_UNSET, shape), tmp_path, version)
    assert f.status == UNKNOWN, f"{shape}@{version}: {f.status}: {f.detail}"
    assert f.not_applicable is False
    assert f.config_field_paths == {"gateway.terminal.enabled"}
    assert "2026.7.35" in f.detail and "2026.8.1" in f.detail


def test_an_old_stamp_with_no_installed_version_is_unknown(tmp_path):
    f = _run(_stamped(_cfg(_UNSET, "no_terminal"), "2026.7.1"), tmp_path, None)
    assert f.status == UNKNOWN, f.detail


# ------------------------------------------------------------- non-bool values are UNSET
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, "no"])
def test_a_non_bool_enabled_is_read_as_unset(value, tmp_path):
    """Matches the executed vendor gate: on 8.1+ the string "false" and null are ON, and
    on <= 7.35 the string "true" is off. Only a real boolean counts."""
    cfg = {"gateway": {"terminal": {"enabled": value}}}
    assert _run(cfg, tmp_path, "2026.9.7").status == WARN
    assert _run(cfg, tmp_path, "2026.7.35").status == PASS
    assert _run(cfg, tmp_path, None).status == UNKNOWN


@pytest.mark.parametrize("terminal", [False, True, None, "off", 3, []])
def test_a_non_dict_terminal_is_read_as_unset(terminal, tmp_path):
    cfg = {"gateway": {"terminal": terminal}}
    assert _run(cfg, tmp_path, "2026.9.7").status == WARN
    assert _run(cfg, tmp_path, "2026.7.35").status == PASS
    assert _run(cfg, tmp_path, None).status == UNKNOWN


# ------------------------------------------------------------ malformed / unread unchanged
@pytest.mark.parametrize("version", [None, "2026.7.35", "2026.9.7"])
def test_a_malformed_gateway_stays_unknown_on_every_build(version, tmp_path):
    for malformed in (None, [], 7, "on"):
        f = _run({"gateway": malformed}, tmp_path, version)
        assert f.status == UNKNOWN, f"{malformed!r}@{version}: {f.detail}"
        assert "not an object" in f.detail


def test_a_read_empty_config_stays_not_applicable_unknown(tmp_path):
    f = _run({}, tmp_path, "2026.9.7")
    assert f.status == UNKNOWN and f.not_applicable is True


# ------------------------------------------------------------------ never FAIL / CRITICAL
def test_the_check_never_fails_across_the_matrix(tmp_path):
    versions = [None, "2026.6.34", "2026.7.1", "2026.7.35", "2026.7.36", "2026.8.0",
                "2026.8.1", "2026.9.7", "0.0.0", "2026.9.8-beta.1"]
    enabled_values = [_UNSET, True, False, "false", None, 0]
    seen = set()
    for v in versions:
        for e in enabled_values:
            for shape in ("terminal", "no_terminal", "no_gateway"):
                f = _run(_cfg(e, shape), tmp_path, v)
                seen.add(f.status)
                assert f.status in (PASS, WARN, UNKNOWN), (v, e, shape, f.status)
                assert f.severity != "CRITICAL"
    assert seen == {PASS, WARN, UNKNOWN}, "the matrix must exercise all three verdicts"


# ------------------------------------------------------------------ $include
def test_an_included_explicit_false_is_seen_as_off(tmp_path):
    """False-WARN surface (a): `enabled: false` arriving through a `$include` fragment
    must PASS on a default-on build exactly as the inline form does."""
    from clawseccheck.collector import collect

    inc = tmp_path / "inc"
    inc.mkdir()
    (inc / "gw.json").write_text(
        json.dumps({"terminal": {"enabled": False}}), encoding="utf-8")
    (inc / "openclaw.json").write_text(
        json.dumps({"tools": {"profile": "minimal"},
                    "gateway": {"$include": "./gw.json"}}), encoding="utf-8")
    ctx = collect(inc)
    ctx.installed_dist_version = "2026.9.7"
    f = check_gateway_operator_terminal(ctx)
    assert f.status == PASS, f.detail
    assert "explicitly disabled" in f.detail


# ------------------------------------------------------------------ wiring
def test_include_dist_wiring_reaches_the_report_path(tmp_path, monkeypatch):
    """The real seam: audit(include_dist=True) fills ctx.installed_dist_version from
    clawseccheck._installed_dist_version, and B350 must WARN on it. Asserting on the
    check function alone would stay green with the wiring cut."""
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"gateway": {"bind": "127.0.0.1:8080"},
                    "tools": {"profile": "minimal"}}), encoding="utf-8")
    monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, **k: "2026.9.7")
    _ctx_obj, findings, _score = clawseccheck.audit(tmp_path, include_dist=True)
    b350 = [f for f in findings if f.id == "B350"]
    assert len(b350) == 1
    assert b350[0].status == WARN, b350[0].detail


def test_hermetic_audit_reports_unknown_not_pass(tmp_path):
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"gateway": {"bind": "127.0.0.1:8080"},
                    "tools": {"profile": "minimal"}}), encoding="utf-8")
    _ctx_obj, findings, _score = clawseccheck.audit(tmp_path)
    b350 = [f for f in findings if f.id == "B350"]
    assert len(b350) == 1
    assert b350[0].status == UNKNOWN, b350[0].detail


def test_a_stamped_fixture_warns_in_the_hermetic_path():
    """A fixture-driven WARN for the unset case (meta.lastTouchedVersion 2026.9.6)."""
    from pathlib import Path

    from clawseccheck.collector import collect

    fx = Path(__file__).resolve().parent.parent / "fixtures" / "bad_b350_terminal_default_on_stamped"
    f = check_gateway_operator_terminal(collect(fx))
    assert f.status == WARN, f.detail
    assert "defaults it to true" in f.detail
