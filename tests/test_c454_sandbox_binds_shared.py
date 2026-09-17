"""CLAWSECCHECK-C-454 — one shared `sandbox.docker.binds` extraction primitive.

As of B-497 there were three independent hand-written readers of this field (B4's
defaults-level check, B4's per-agent `_peragent_sandbox_evidence`, and RISK-12's
containment reader) plus a fourth, RISK-16's `_host_reaching_bind` — the exact
divergence class B-673 already fixed once for `_bind_mode_is_ro`/
`_resolve_sandbox_scope`, recurring one field over: B4 FAILing "a per-agent override
can re-expose the host" while RISK-12 stayed silent on the identical config.

`_sandbox_docker_binds`/`_bind_mentions_docker_sock` (checks/_shared.py) now do the
NORMALIZATION (dict->get->str/list-coercion, fail-closed on a malformed shape) every
caller used to duplicate. They deliberately do NOT decide "does this bind defeat
containment" — B4 (any declared bind is evidence) and RISK-12 (only a non-":ro" bind
defeats containment) answer that differently for good, C-135-tested reasons
(tests/test_b673_peragent_bind_scope.py::test_the_ro_helper_is_not_wired_into_this_check)
and this change does not touch that judgment, only the parsing feeding it.

RISK-16's `_host_reaching_bind` (risk.py) is deliberately NOT converted: it is the
sole remaining direct `dig(cfg, "agents.defaults.sandbox.docker.binds")` LEAF call in
the tree, and `agents.defaults.sandbox.docker.binds` is a grounded LEAF path in
tests/grounded_schema_paths.txt — converting it to plain-dict traversal (required to
reach the shared helper, which takes the non-leaf `sandbox` node) would leave nothing
in the tree satisfying test_schema_grounding.py's dig()-path/manifest equality guard
for that path. Verified: that guard still passes after this change.

`_resolve_sandbox_backend` (risk.py) is deliberately NOT moved to `checks/_shared.py`
either: B4 never reads `sandbox.backend` at all (grep confirms), so there is currently
only ONE consumer — moving a single-consumer helper into the shared leaf "for later"
would itself be the premature-abstraction mistake this project's own §3.1 table warns
against (a helper used by exactly one topic stays in that topic module).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL
from clawseccheck.checks import (
    _bind_mentions_docker_sock,
    _sandbox_docker_binds,
    check_sandbox,
    run_all,
)
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths

SOCK = "/var/run/docker.sock:/var/run/docker.sock"
WRITABLE = "/srv:/srv:rw"

_INGRESS_WRITE_BASE = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {"allow": ["fs_write"]},
}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _b4_status(cfg: dict) -> str:
    return check_sandbox(_ctx(cfg)).status


def _risk12_fires(cfg: dict) -> bool:
    cfg = {**_INGRESS_WRITE_BASE, **{k: v for k, v in cfg.items() if k != "tools"}}
    ctx = _ctx(cfg)
    findings = run_all(ctx)
    return "RISK-12" in {p.id for p in risk_paths(ctx, findings)}


# ---------------------------------------------------------------------------
# 1. Structural guard — precedent: test_b673_peragent_bind_scope.py's
#    test_the_helpers_live_in_one_place_only, extended for the new primitives.
# ---------------------------------------------------------------------------

def test_the_new_helpers_live_in_one_place_only():
    root = Path(__file__).resolve().parent.parent / "clawseccheck"
    shared = (root / "checks" / "_shared.py").read_text(encoding="utf-8")
    for name in ("_sandbox_docker_binds", "_bind_mentions_docker_sock"):
        assert f"def {name}(" in shared, f"{name} should be defined in the leaf"
    for other in (root / "risk.py", root / "checks" / "_config.py"):
        text = other.read_text(encoding="utf-8")
        for name in ("_sandbox_docker_binds", "_bind_mentions_docker_sock"):
            assert f"def {name}(" not in text, (
                f"{other.name} redefines {name} — a fourth independently-drifting copy "
                f"is exactly what C-454 exists to remove")


def test_config_no_longer_hand_normalizes_binds():
    """The pattern this task removes: `.get(\"binds\")` followed by an inline
    isinstance(list)/str join, duplicated at both B4 call sites before this fix."""
    text = (Path(__file__).resolve().parent.parent / "clawseccheck"
            / "checks" / "_config.py").read_text(encoding="utf-8")
    assert '.get("binds")' not in text


# ---------------------------------------------------------------------------
# 2. The primitive itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sandbox,expected", [
    ({}, []),
    ({"docker": {}}, []),
    ({"docker": {"binds": []}}, []),
    ({"docker": {"binds": WRITABLE}}, [WRITABLE]),
    ({"docker": {"binds": [WRITABLE, SOCK]}}, [WRITABLE, SOCK]),
    ({"docker": "not-a-dict"}, None),
    ({"docker": {"binds": 42}}, None),
])
def test_sandbox_docker_binds_normalizes(sandbox, expected):
    assert _sandbox_docker_binds(sandbox) == expected


def test_bind_mentions_docker_sock():
    assert _bind_mentions_docker_sock([SOCK]) is True
    assert _bind_mentions_docker_sock([WRITABLE]) is False
    assert _bind_mentions_docker_sock([]) is False
    assert _bind_mentions_docker_sock(None) is False


# ---------------------------------------------------------------------------
# 3. B4 / RISK-12 agreement across the bind-declaration shapes named in the task's
#    own gate: at defaults, at per-agent, at both, empty list, malformed types.
#    Not identical verdicts (B4 and RISK-12 apply different, deliberately-different
#    judgment) — agreement means neither is BLIND to a bind the other reacts to,
#    the exact B-497 defect this task exists to stop recurring.
# ---------------------------------------------------------------------------

def test_writable_bind_at_defaults_fails_b4_and_fires_risk12():
    cfg = {"agents": {"defaults": {"sandbox": {"docker": {"binds": [WRITABLE]}}}}}
    assert _b4_status(cfg) == FAIL
    assert _risk12_fires(cfg) is True


def test_writable_bind_at_per_agent_fails_b4_and_fires_risk12():
    cfg = {"agents": {"entries": {"worker": {"sandbox": {"docker": {"binds": [WRITABLE]}}}}}}
    assert _b4_status(cfg) == FAIL
    assert _risk12_fires(cfg) is True


def test_writable_bind_at_both_levels_fails_b4_and_fires_risk12():
    cfg = {"agents": {
        "defaults": {"sandbox": {"docker": {"binds": [WRITABLE]}}},
        "entries": {"worker": {"sandbox": {"docker": {"binds": ["/other:/other:rw"]}}}},
    }}
    assert _b4_status(cfg) == FAIL
    assert _risk12_fires(cfg) is True


def test_empty_bind_list_is_not_reported_by_either():
    cfg = {"agents": {"defaults": {"sandbox": {"docker": {"binds": []}}}}}
    assert _b4_status(cfg) != FAIL
    assert _risk12_fires(cfg) is True  # RISK-12 fires on no-containment-declared, unrelated to binds


def test_malformed_docker_shape_fails_closed_for_risk12():
    """RISK-12 must fail closed on an unparseable shape (cannot verify containment);
    this is unchanged by the extraction — see _sandbox_has_writable_bind's own
    docstring, which the extraction preserves exactly."""
    cfg = {"agents": {"defaults": {"sandbox": {
        "mode": "all", "workspaceAccess": "ro", "docker": "not-a-dict",
    }}}}
    assert _risk12_fires(cfg) is True


# ---------------------------------------------------------------------------
# 4. Independent C-135 regression (2026-09-17): B4's two call sites treated
#    `_sandbox_docker_binds`'s `None` (malformed `binds`, e.g. a dict instead of a
#    string/list) the same as `[]` (genuinely absent), silently. Reproduced directly
#    against bf31513^ (this task's own parent commit): the pre-extraction code read
#    the raw value and gated on bare truthiness, so a malformed-but-truthy shape
#    fired the evidence exactly like a well-formed one — this extraction narrowed
#    that to string/list only, turning a real FAIL into a silent UNKNOWN. The
#    implementer's own self-review (no independent Agent-dispatch tool was available)
#    asserted the opposite — that this branch "never fail-closed on that shape" even
#    before the extraction — which a real before/after run disproved.
# ---------------------------------------------------------------------------

def test_malformed_binds_shape_at_defaults_still_fails_b4():
    cfg = {"agents": {"defaults": {"sandbox": {"docker": {"binds": {"src": "/etc", "dst": "/etc"}}}}}}
    assert _b4_status(cfg) == FAIL


def test_malformed_binds_shape_at_per_agent_still_fails_b4():
    cfg = {"agents": {"entries": {"worker": {"sandbox": {"docker": {"binds": 42}}}}}}
    assert _b4_status(cfg) == FAIL
