"""B392 (CLAWSECCHECK-F-200) — tools.swarm collector-mode subagent fan-out limits.

Re-grounded directly against the installed 2026.9.5 dist. The filed task's premise does
NOT survive re-grounding — see checks/_agents.py::check_swarm_fanout_limits for the full
citation trail (dist/schema-CwAIqZVE.mjs:820-826 vendor descriptions,
dist/swarm-config-BYkyPTuH.mjs:4-34 the actual runtime resolver `resolveSwarmConfig`,
confirmed live via sessions-spawn-tool-CE1WiS6Q.mjs / openclaw-tools-DIxownJF.mjs) and
tests/dist_verified_paths.txt (`tools.swarm`, regenerated against the installed 2026.9.5
dist) for the machine-checked layer:

  1. `tools.swarm.enabled` actually defaults to `true` (the filed task's "default is
     off" was read off the vendor's UI-facing description text, not the resolver).
  2. No config can make a swarm limit literally unbounded — `readBoundedPositiveInteger`
     clamps every field via `Math.min(value, cap)`, cap = 1000 / 10,000 / 100,000 /
     86,400 for maxConcurrent / maxChildrenPerGroup / maxTotalPerGroup /
     waitTimeoutSecondsMax respectively.

Verdicts:
  PASS    : swarm disabled at every scope that matters, OR every scope's fields
            resolve to the vendor's sane defaults (the common case, including an
            entirely absent `tools.swarm`).
  WARN    : enabled (default or explicit) with a limit raised above its vendor default
            but below its hard ceiling, AND an untrusted channel can reach the agent.
  FAIL    : enabled (default or explicit) with a limit pushed to/past its vendor hard
            ceiling, at any scope — NOT gated on an untrusted channel.
  UNKNOWN : (a) config unreadable/unparseable (engine-side), or (b) no config was found
            at all (config_found=False) — not_applicable is False in both cases, since
            neither rules out a real risk. A config that WAS found and merely parses to
            `{}` is a real (if minimal) read, not "nothing looked at" — same B-661
            distinction B81 draws in this same module — so it resolves normally (PASS,
            since an absent tools.swarm means the vendor-safe defaults apply).
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_BASELINE = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "agents": {"defaults": {"sandbox": {"mode": "all"}}},
}


def _ctx(cfg: dict, *, config_found: bool = True, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = config_found
    return c


def _finding_direct(cfg: dict):
    return C.check_swarm_fanout_limits(_ctx(cfg))


def _finding_via_home(cfg: dict):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = Path(tempfile.mkdtemp(prefix="b392-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B392")


# ---- catalog sanity ----


def test_b392_is_catalogued_hardening_scored_medium():
    meta = BY_ID["B392"]
    assert meta.block == "hardening"
    assert meta.scored is True
    assert meta.severity == MEDIUM
    assert meta.surface == "agents"


# ---- PASS: absent / disabled / at vendor defaults ----


def test_swarm_entirely_absent_passes():
    # The re-grounding headline: absent tools.swarm still resolves enabled=true, but
    # with sane defaults, so this is PASS, not a hidden WARN/FAIL.
    f = _finding_direct({**_BASELINE})
    assert f.status == PASS


def test_swarm_explicitly_disabled_by_bool_shorthand_passes():
    cfg = {**_BASELINE, "tools": {"swarm": False}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_swarm_enabled_false_passes():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": False, "maxConcurrent": 999999}}}
    f = _finding_direct(cfg)
    assert f.status == PASS, "a disabled scope's limits are moot, however large"


def test_swarm_explicitly_enabled_with_defaults_passes():
    cfg = {
        **_BASELINE,
        "tools": {
            "swarm": {
                "enabled": True,
                "maxConcurrent": 8,
                "maxChildrenPerGroup": 50,
                "maxTotalPerGroup": 200,
                "waitTimeoutSecondsMax": 600,
            }
        },
    }
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_non_positive_or_non_integer_limits_fall_back_to_default_and_pass():
    # Mirrors readBoundedPositiveInteger: 0, a negative number, and a non-integer are
    # all NOT "positive integer" and fall back to the vendor default, not to 0/unbounded.
    for bogus in (0, -5, 3.5, "8", None, True):
        cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": bogus}}}
        assert _finding_direct(cfg).status == PASS, f"maxConcurrent={bogus!r} must fall back to default"


# ---- WARN: raised above default, below the hard ceiling, untrusted channel reachable ----


def test_raised_maxconcurrent_with_untrusted_channel_warns():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True, "maxConcurrent": 64}},
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "maxConcurrent" in f.detail or any("maxConcurrent" in e for e in f.evidence)


def test_raised_but_no_untrusted_channel_passes():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxChildrenPerGroup": 300}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_raised_maxtotalpergroup_or_wait_timeout_also_warns():
    for field, value in (("maxTotalPerGroup", 5000), ("waitTimeoutSecondsMax", 3600)):
        cfg = {
            **_BASELINE,
            "tools": {"swarm": {"enabled": True, field: value}},
            "channels": {"telegram": {"dmPolicy": "open"}},
        }
        assert _finding_direct(cfg).status == WARN, field


# ---- FAIL: pushed to/past the vendor's own hard ceiling, regardless of channel ----


def test_maxconcurrent_at_hard_ceiling_fails_even_without_untrusted_channel():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": 1000}}}
    f = _finding_direct(cfg)
    assert f.status == FAIL


def test_maxconcurrent_far_past_hard_ceiling_still_fails():
    # A value far beyond the cap clamps to the SAME resolved ceiling as exactly-1000 —
    # this is precisely the "trying to configure unbounded" shape the filed task named.
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": 10_000_000}}}
    f = _finding_direct(cfg)
    assert f.status == FAIL


def test_maxchildrenpergroup_at_hard_ceiling_fails():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxChildrenPerGroup": 10_000}}}
    assert _finding_direct(cfg).status == FAIL


def test_disabled_scope_at_ceiling_never_fails():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": False, "maxConcurrent": 1_000_000}}}
    assert _finding_direct(cfg).status == PASS


# ---- per-agent override: merges over global, mirrors resolveSwarmConfig ----


def test_agent_override_raises_a_field_the_global_scope_left_at_default():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {"researcher": {"tools": {"swarm": {"maxConcurrent": 500}}}},
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert any("researcher" in e for e in f.evidence)


def test_agent_override_pushes_a_field_to_the_ceiling_fails():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {"researcher": {"tools": {"swarm": {"maxChildrenPerGroup": 999999}}}},
        },
    }
    f = _finding_direct(cfg)
    assert f.status == FAIL
    assert any("researcher" in e for e in f.evidence)


def test_agent_override_disabling_swarm_does_not_inherit_a_raised_global_value():
    # merged = {**global_raw, **agent_raw}; agent_raw={"enabled": False} must fully
    # short-circuit that agent's scope regardless of the raised global maxConcurrent.
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True, "maxConcurrent": 1000}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {"researcher": {"tools": {"swarm": False}}},
        },
    }
    f = _finding_direct(cfg)
    # The GLOBAL scope alone still maxes out, so this must still FAIL — but via the
    # global evidence, not the disabled agent.
    assert f.status == FAIL
    assert not any("researcher" in e for e in f.evidence)
    assert any("global" in e for e in f.evidence)


def test_agent_with_no_swarm_override_is_not_evaluated_separately():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {"researcher": {"model": "gpt"}},
        },
    }
    assert _finding_direct(cfg).status == PASS


# ---- a config that was actually FOUND and parses to {} is a real (if minimal) read,
# not "nothing was looked at" — same B-661 distinction B81 draws in this same module:
# only a config that was never found at all degrades to UNKNOWN (see below). ----


def test_found_but_completely_empty_config_passes():
    f = _finding_direct({})
    assert f.status == PASS


# ---- UNKNOWN: config truly unreadable — distinct engine-degraded case ----


def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_swarm_fanout_limits(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert f.not_applicable is False


def test_unread_config_is_unknown_not_a_false_pass():
    f = C.check_swarm_fanout_limits(_ctx({}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---- fixtures, round-tripped through the real audit pipeline ----


def test_the_fixtures_fire_the_expected_verdicts():
    for name, expected in (
        ("clean_b392_swarm_bounded", PASS),
        ("bad_b392_swarm_raised_untrusted", WARN),
        ("bad_b392_swarm_maxed_fanout", FAIL),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B392")
        assert f.status == expected, name


def test_b392_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b392_swarm_maxed_fanout", include_native=False)
    assert "B392" in {fi.id for fi in findings}


def test_full_pipeline_round_trip_matches_direct_call():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": 1000}}}
    assert _finding_via_home(cfg).status == _finding_direct(cfg).status == FAIL
