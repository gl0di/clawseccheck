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


# ---- fix (a): float-integral values (JSON `1e3`/`1000.0`) mirror Number.isInteger ----


def test_float_integral_at_hard_ceiling_fails_same_as_int_form():
    # `1e3` parses in Python's json module as a float, not an int -- the runtime
    # (`Number.isInteger`) treats it identically to the literal integer 1000.
    for value in (1e3, 1000.0):
        cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": value}}}
        assert _finding_direct(cfg).status == FAIL, f"maxConcurrent={value!r} must FAIL like int 1000"


def test_float_integral_far_past_ceiling_still_fails():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": 999999.0}}}
    assert _finding_direct(cfg).status == FAIL


def test_float_integral_raised_warns_same_as_int_form():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True, "maxConcurrent": 64.0}},
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert any("maxConcurrent" in e for e in f.evidence)


def test_non_integral_or_non_finite_float_still_falls_back_to_default():
    # 1000.5 is not Number.isInteger; inf/nan are not finite. All three must still fall
    # back to the vendor default, exactly as before this fix -- never a hidden FAIL/WARN.
    for bogus in (1000.5, float("inf"), float("nan")):
        cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": bogus}}}
        assert _finding_direct(cfg).status == PASS, f"maxConcurrent={bogus!r} must fall back to default"


def test_bool_still_falls_back_despite_being_an_int_subclass():
    # bool is a subclass of int in Python but is never a float, so it is untouched by
    # the new float-integral coercion and must keep falling back, as before.
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": True}}}
    assert _finding_direct(cfg).status == PASS


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


# ---- fix (b): waitTimeoutSecondsMax is not an admission-control field, so its own
# hard ceiling stays WARN-eligible (gated on reachability), never the ungated FAIL tier.


def test_wait_timeout_at_hard_ceiling_with_no_channels_does_not_fail():
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "waitTimeoutSecondsMax": 86400}}}
    f = _finding_direct(cfg)
    assert f.status != FAIL
    assert f.status == PASS


def test_wait_timeout_at_hard_ceiling_with_untrusted_channel_still_warns():
    cfg = {
        **_BASELINE,
        "tools": {"swarm": {"enabled": True, "waitTimeoutSecondsMax": 86400}},
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert any("waitTimeoutSecondsMax" in e for e in f.evidence)


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


# ---- fix (d): a raised/maxed limit is moot when the gating tool (sessions_spawn /
# agents_wait) is not even reachable under tools.profile/tools.alsoAllow ----


def test_minimal_profile_with_maxed_maxconcurrent_does_not_fail():
    # "minimal" grants neither sessions_spawn nor agents_wait -- maxConcurrent gates on
    # sessions_spawn, so a maxed value here is unreachable and must not FAIL.
    cfg = {
        **_BASELINE,
        "tools": {"profile": "minimal", "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert any("maxConcurrent" in e for e in f.evidence)


def test_minimal_profile_plus_alsoallow_sessions_spawn_fails_again():
    # tools.alsoAllow is the schema's escape hatch: it grants sessions_spawn back on
    # top of "minimal", so the same maxed value is reachable again and must FAIL.
    cfg = {
        **_BASELINE,
        "tools": {
            "profile": "minimal",
            "alsoAllow": ["sessions_spawn"],
            "swarm": {"enabled": True, "maxConcurrent": 1000},
        },
    }
    f = _finding_direct(cfg)
    assert f.status == FAIL


def test_minimal_profile_does_not_grant_agents_wait_either():
    cfg = {
        **_BASELINE,
        "tools": {
            "profile": "minimal",
            "swarm": {"enabled": True, "waitTimeoutSecondsMax": 86400},
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    assert _finding_direct(cfg).status == PASS


def test_messaging_profile_grants_sessions_spawn_but_not_agents_wait():
    # sessions_spawn's profiles are ["coding","messaging"]; agents_wait's are
    # ["coding"] only -- messaging must FAIL on a maxed maxConcurrent but not on a
    # maxed waitTimeoutSecondsMax (dropped as unreachable there).
    spawn_cfg = {
        **_BASELINE,
        "tools": {"profile": "messaging", "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    assert _finding_direct(spawn_cfg).status == FAIL
    wait_cfg = {
        **_BASELINE,
        "tools": {"profile": "messaging", "swarm": {"enabled": True, "waitTimeoutSecondsMax": 86400}},
    }
    assert _finding_direct(wait_cfg).status == PASS


def test_full_profile_grants_both_tools():
    cfg = {
        **_BASELINE,
        "tools": {"profile": "full", "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    assert _finding_direct(cfg).status == FAIL


def test_absent_profile_is_permissive_not_minimal():
    # An absent tools.profile pushes NO policy at all (resolveCoreToolProfilePolicy:
    # `if (!profile) return;`) -- the permissive end, same as every other
    # profile+alsoAllow read in this codebase. It must NOT be treated as "minimal".
    cfg = {**_BASELINE, "tools": {"swarm": {"enabled": True, "maxConcurrent": 1000}}}
    assert _finding_direct(cfg).status == FAIL


def test_unrecognised_profile_is_unknown_not_a_silent_pass():
    cfg = {
        **_BASELINE,
        "tools": {"profile": "not-a-real-profile", "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    f = _finding_direct(cfg)
    assert f.status == UNKNOWN
    assert any("maxConcurrent" in e for e in f.evidence)


def test_non_string_profile_is_unknown_not_a_silent_pass():
    cfg = {
        **_BASELINE,
        "tools": {"profile": 12345, "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    assert _finding_direct(cfg).status == UNKNOWN


def test_agent_scope_profile_overrides_global_for_reachability():
    # Global grants sessions_spawn ("coding"); the researcher agent's own "minimal"
    # profile REPLACES it for that agent's scope (per-key ?? resolution), so the
    # agent's own maxed maxConcurrent is unreachable and must not contribute a FAIL.
    cfg = {
        **_BASELINE,
        "tools": {"profile": "coding", "swarm": {"enabled": True}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {
                "researcher": {
                    "tools": {"profile": "minimal", "swarm": {"maxConcurrent": 1000}},
                }
            },
        },
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert any("researcher" in e for e in f.evidence)


def test_agent_scope_inherits_global_alsoallow_for_reachability():
    # The agent overrides tools.profile to "minimal" but does not set its own
    # alsoAllow, so it inherits the GLOBAL alsoAllow independently of the profile
    # override (agentTools?.alsoAllow ?? globalTools?.alsoAllow).
    cfg = {
        **_BASELINE,
        "tools": {"profile": "coding", "alsoAllow": ["sessions_spawn"], "swarm": {"enabled": True}},
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {
                "researcher": {
                    "tools": {"profile": "minimal", "swarm": {"maxConcurrent": 1000}},
                }
            },
        },
    }
    f = _finding_direct(cfg)
    assert f.status == FAIL
    assert any("researcher" in e for e in f.evidence)


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


# ---- tools.allow: the other, mutually-exclusive grant shape ----
# OpenClaw rejects allow+alsoAllow in one scope (zod-schema.agent-runtime-DQfiImgc.mjs:
# 367-369), so a config using `tools.allow` never carries the alsoAllow escape hatch this
# check reads. An allow-list omitting sessions_spawn plausibly makes the fan-out surface
# unreachable -- but `tools.allow` is its own policy layer beside the profile's and this
# check has not traced how the two combine, so it reports UNKNOWN rather than guessing
# either way. These pin that it is neither a FAIL (the false positive) nor a silent PASS.


def test_explicit_allow_omitting_the_spawn_tool_is_unknown_not_fail():
    cfg = {
        **_BASELINE,
        "tools": {
            "allow": ["read", "write"],
            "swarm": {"enabled": True, "maxConcurrent": 1000},
        },
    }
    f = _finding_direct(cfg)
    assert f.status == UNKNOWN, f.detail
    assert f.status != FAIL


def test_explicit_allow_granting_the_spawn_tool_still_fails():
    cfg = {
        **_BASELINE,
        "tools": {
            "allow": ["read", "sessions_spawn"],
            "swarm": {"enabled": True, "maxConcurrent": 1000},
        },
    }
    assert _finding_direct(cfg).status == FAIL


def test_empty_allow_list_does_not_suppress_the_finding():
    """An empty list grants nothing explicitly; it must not read as "omits the tool" and
    silently downgrade a maxed config -- that would be absence treated as safety."""
    cfg = {
        **_BASELINE,
        "tools": {"allow": [], "swarm": {"enabled": True, "maxConcurrent": 1000}},
    }
    assert _finding_direct(cfg).status == FAIL


def test_allow_is_resolved_per_agent_over_the_global_one():
    cfg = {
        **_BASELINE,
        "tools": {"allow": ["sessions_spawn"], "swarm": {"enabled": True}},
        "agents": {
            "entries": {
                "main": {
                    "tools": {
                        "allow": ["read"],
                        "swarm": {"enabled": True, "maxConcurrent": 1000},
                    }
                }
            }
        },
    }
    f = _finding_direct(cfg)
    assert f.status == UNKNOWN, f.detail


def test_per_agent_allow_control_same_config_grants_the_tool_and_fails():
    """The paired control for the test above: identical config except the agent's own
    allow-list grants sessions_spawn. Without this pair, an UNKNOWN there could just as
    well come from the global scope and the per-agent resolution would be untested."""
    cfg = {
        **_BASELINE,
        "tools": {"allow": ["sessions_spawn"], "swarm": {"enabled": True}},
        "agents": {
            "entries": {
                "main": {
                    "tools": {
                        "allow": ["sessions_spawn"],
                        "swarm": {"enabled": True, "maxConcurrent": 1000},
                    }
                }
            }
        },
    }
    assert _finding_direct(cfg).status == FAIL
