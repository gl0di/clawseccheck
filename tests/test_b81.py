"""B81 — subagent spawn limits raised beyond recommended defaults.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_subagent_spawn_limits
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_b81_unset_is_pass():
    assert check_subagent_spawn_limits(_ctx({})).status == PASS


def test_b81_within_recommended_is_pass():
    cfg = {"agents": {"defaults": {"subagents": {"maxSpawnDepth": 2, "maxConcurrent": 8}}}}
    assert check_subagent_spawn_limits(_ctx(cfg)).status == PASS


def test_b81_raised_but_no_untrusted_channel_is_pass():
    cfg = {"agents": {"defaults": {"subagents": {"maxSpawnDepth": 5}}}}
    assert check_subagent_spawn_limits(_ctx(cfg)).status == PASS


def test_b81_raised_with_untrusted_channel_is_warn():
    cfg = {
        "agents": {"defaults": {"subagents": {"maxSpawnDepth": 5}}},
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    assert check_subagent_spawn_limits(_ctx(cfg)).status == WARN


def test_b81_clean_fixture_pass():
    assert check_subagent_spawn_limits(collect(FIXTURES / "clean_b81_subagent_limits")).status == PASS


def test_b81_bad_fixture_warn():
    assert check_subagent_spawn_limits(collect(FIXTURES / "bad_b81_subagent_limits")).status == WARN


def test_b81_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b81_subagent_limits", include_native=False)
    assert "B81" in {f.id for f in findings}
