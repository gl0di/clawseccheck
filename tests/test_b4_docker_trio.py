"""B4 / NC-7 tests: documented dangerous docker break-glass flags (the trio).

Grounded fields (docs.openclaw.ai/gateway/security — the "dangerously*" schema
accordion; see the docker/sandbox section of the internal openclaw-schema-recon.md):
  agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets
  agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources
  agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin

Each defaults false; only an explicit boolean true is dangerous. B4 previously caught
docker.sock binds + network=host but PASSed a config that set ONLY the trio (the gap
NC-7 closes). FP-guard: a truthy non-bool ("false" string) or an absent key must NOT fire.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context
from clawseccheck.i18n import tp

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_TRIO = (
    "dangerouslyAllowReservedContainerTargets",
    "dangerouslyAllowExternalBindSources",
    "dangerouslyAllowContainerNamespaceJoin",
)


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _sandbox(**docker_flags) -> dict:
    """A safe-everything-else sandbox config; only the passed docker flags vary."""
    docker = {"network": "bridge"}
    docker.update(docker_flags)
    return {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "workspaceAccess": "ro",
                    "docker": docker,
                }
            }
        }
    }


# ---------------------------------------------------------------------------
# Each trio flag, set true, must FAIL and surface its own evidence line
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", _TRIO)
def test_single_trio_flag_true_fails(flag):
    f = check_sandbox(_ctx(_sandbox(**{flag: True})))
    assert f.status == FAIL
    assert any(flag in line and "=true" in line for line in f.evidence), (
        f"{flag}=true must add its own evidence line; got {f.evidence}"
    )


def test_all_three_trio_flags_true_fails_with_three_lines():
    cfg = _sandbox(**{flag: True for flag in _TRIO})
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    for flag in _TRIO:
        assert any(flag in line for line in f.evidence), f"missing evidence for {flag}"


def test_trio_is_sole_fail_cause_in_bad_fixture_shape():
    """The bad fixture sets a safe sandbox otherwise — the ONLY FAIL evidence is the trio.

    Proves NC-7 detection is not piggy-backing on docker.sock / network=host / rw.
    """
    cfg = _sandbox(**{flag: True for flag in _TRIO})
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    for line in f.evidence:
        assert "dangerouslyAllow" in line, (
            f"unexpected non-trio evidence leaked into the isolation fixture: {line!r}"
        )


# ---------------------------------------------------------------------------
# FP-guard: false / absent / truthy-non-bool must NOT fire
# ---------------------------------------------------------------------------

def test_trio_all_false_passes():
    cfg = _sandbox(**{flag: False for flag in _TRIO})
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


def test_trio_absent_passes():
    f = check_sandbox(_ctx(_sandbox()))
    assert f.status == PASS


@pytest.mark.parametrize("flag", _TRIO)
def test_trio_truthy_string_does_not_fire(flag):
    """A string value (even the truthy "false") must not trip the `is True` guard."""
    f = check_sandbox(_ctx(_sandbox(**{flag: "false"})))
    assert f.status == PASS, f"{flag}='false' (string) must not FAIL (is-True guard)"
    assert not any("dangerouslyAllow" in line for line in f.evidence)


# ---------------------------------------------------------------------------
# Fires regardless of mode when no exec tools mask it via WARN
# ---------------------------------------------------------------------------

def test_trio_fires_with_mode_set_and_exec_tools():
    cfg = _sandbox(**{flag: True for flag in _TRIO})
    cfg["tools"] = {"allow": ["exec"]}
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


# ---------------------------------------------------------------------------
# Remediation guidance mentions disabling the dangerous flags
# ---------------------------------------------------------------------------

def test_fix_mentions_disabling_dangerous_flags():
    f = check_sandbox(_ctx(_sandbox(**{_TRIO[0]: True})))
    assert "dangerouslyAllow" in f.fix


# ---------------------------------------------------------------------------
# Hebrew localization: a trio-only FAIL must not leak English
# ---------------------------------------------------------------------------

def test_trio_detail_localized_he():
    f = check_sandbox(_ctx(_sandbox(**{flag: True for flag in _TRIO})))
    he = tp(f.detail, "he")
    import re
    assert re.search(r"[֐-׿]", he), f"trio detail not localized to Hebrew: {he!r}"


def test_trio_fix_localized_he():
    f = check_sandbox(_ctx(_sandbox(**{_TRIO[0]: True})))
    he = tp(f.fix, "he")
    import re
    assert re.search(r"[֐-׿]", he), f"trio remediation not localized to Hebrew: {he!r}"


# ---------------------------------------------------------------------------
# Fixtures on disk fire the expected verdicts
# ---------------------------------------------------------------------------

def test_bad_fixture_fails():
    from clawseccheck.collector import collect
    ctx = collect(FIXTURES / "bad_b4_docker_trio")
    f = check_sandbox(ctx)
    assert f.status == FAIL
    assert any("dangerouslyAllow" in line for line in f.evidence)


def test_clean_fixture_passes():
    from clawseccheck.collector import collect
    ctx = collect(FIXTURES / "clean_b4_docker_trio")
    f = check_sandbox(ctx)
    assert f.status == PASS
