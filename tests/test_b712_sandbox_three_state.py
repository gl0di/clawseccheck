"""B-712: `_sandbox_confines` answers True / False / None, and None is a real answer.

The predicate used to return a confident boolean for a property `openclaw.json` does not
determine. The vendor's own function is four lines and says exactly where the line falls
(`runtime-status-*.js`, installed 2026.9.1)::

    function shouldSandboxSession(cfg, sessionKey, mainSessionKey, sandboxRequired) {
        if (sandboxRequired) return true;
        if (cfg.mode === "off")  return false;
        if (cfg.mode === "all")  return true;
        return sessionKey.trim() !== mainSessionKey.trim();
    }

`all` and `off` are decidable from config. `non-main` falls through to a comparison against
the RUNNING session's key, which no config carries — so there is no static answer, and
inventing one in either direction is a fabrication. Returning `False` instead of `True` would
have swapped fabricated isolation for fabricated exposure; both are equally untrue.

WHY THE BATTERY IS NOT A THREE-WAY EQUALITY
-------------------------------------------
The vendor always answers true/false, because it always has a session. We answer `None`
sometimes, on purpose. So the contract cannot be "our answer equals the vendor's". It is:

    where we answer,  we agree with the vendor for BOTH session positions;
    where we say None, the vendor's two positions DISAGREE WITH EACH OTHER.

That disagreement is the proof that no single static answer existed — a stronger check than
agreeing with either position would have been, because it makes the vendor establish the
undecidability rather than us asserting it.

WHY THE CASES ARE GENERATED
---------------------------
`fixtures/` contains no config with `sandbox.mode: "non-main"` AND a non-default agent — the
exact shape this task exists for. A corpus run therefore proves nothing here, and a quiet
corpus was part of how the defect survived. `tests/data/sandbox_battery.json` was produced by
EXECUTING `resolveSandboxRuntimeStatus` from the installed dist over a generated matrix
(mode x placement x roster shape x agent), asking each case for both session positions, with
the session store redirected to a tmp path so no real state was read. It ships so the suite
needs neither node nor an installed OpenClaw.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.collector import collect
from clawseccheck.checks import run_all
from clawseccheck.toolpolicy import (
    _sandbox_confines,
    _UNDECIDED_SUFFIX,
    any_confinement_undecided,
    confined_scopes,
    confinement_undecided_only,
    scopes_reaching_outside_workspace,
    undecided_inheriting_scopes,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

BATTERY = Path(__file__).resolve().parent / "data" / "sandbox_battery.json"


def _cases():
    return json.loads(BATTERY.read_text(encoding="utf-8"))


def _build(mode, placement, roster):
    """Rebuild the config a battery row was generated from."""
    agents: dict = {}
    sb: dict = {} if mode is None else {"sandbox": {"mode": mode}}
    if placement == "defaults":
        agents["defaults"] = dict(sb)
    if roster == "entries":
        entries = {"main": {"default": True}, "helper": {}}
        if placement == "entry":
            entries["helper"] = dict(sb)
        agents["entries"] = entries
    elif roster == "list":
        lst = [{"id": "main", "default": True}, {"id": "helper"}]
        if placement == "entry":
            lst[1] = {"id": "helper", **sb}
        agents["list"] = lst
    return {"agents": agents} if agents else {}


def _entry_of(cfg, agent):
    agents = cfg.get("agents") or {}
    if "entries" in agents:
        return (agents["entries"] or {}).get(agent)
    return {e.get("id"): e for e in (agents.get("list") or [])}.get(agent)


def test_the_battery_is_present_and_covers_all_three_answers():
    """A battery that lost its `unknown` rows would let every other test here pass while
    proving nothing about the state this task added."""
    cases = _cases()
    assert len(cases) >= 40, len(cases)
    answers = {c["static_answer"] for c in cases}
    assert answers == {True, False, "unknown"}, answers


@pytest.mark.parametrize("case", _cases(), ids=lambda c: f"{c['mode']}-{c['placement']}-{c['roster']}-{c['agent']}")
def test_our_answer_matches_the_vendor_or_declines(case):
    cfg = _build(case["mode"], case["placement"], case["roster"])
    ours = _sandbox_confines(cfg, case["agent"], _entry_of(cfg, case["agent"]))
    want = case["static_answer"]
    if want == "unknown":
        assert ours is None, (
            f"the vendor answered {case['vendor_sandboxed_own_main_session']} for this agent's "
            f"own main session and {case['vendor_sandboxed_other_session']} for another of its "
            "sessions — the two positions disagree, so no static answer exists and we must "
            f"decline; got {ours!r}"
        )
    else:
        assert ours is want, (
            f"the vendor answered {want} for BOTH session positions, so this IS decidable "
            f"from config; got {ours!r}"
        )


def test_non_main_is_undecidable_for_every_agent_not_only_the_non_default_ones():
    """The correction this task's own title did not contain.

    The retired implementation was `mode == "non-main" and agent_id != _default_agent_id(cfg)`
    — i.e. "non-main" read as "not the main AGENT". `resolveMainSessionKeyForSandbox` resolves
    per agent, so EVERY agent has its own main session that runs unsandboxed and other
    sessions that do not. The default agent is undecidable too.
    """
    cfg = _build("non-main", "defaults", "entries")
    for agent in ("main", "helper"):
        assert _sandbox_confines(cfg, agent, _entry_of(cfg, agent)) is None, agent


def test_an_absent_mode_is_a_real_false_not_an_unknown():
    """`off` is the vendor's effective mode for an absent key, so `False` there is an answer,
    not a guess. Without this, "decline whenever unsure" would swallow the whole predicate."""
    cfg = {"agents": {"entries": {"main": {"default": True}}}}
    assert _sandbox_confines(cfg, "main", _entry_of(cfg, "main")) is False


def test_an_unrecognised_mode_declines_rather_than_guessing():
    """Golden Rule #4's default. Not reachable from a loadable config — the schema restricts
    `mode` to the three literals, probed: `"bogus"` is rejected as `invalid_union` at both the
    defaults and the per-entry placement — so this pins the fallback, not a live branch."""
    cfg = {"agents": {"defaults": {"sandbox": {"mode": "bogus"}}}}
    assert _sandbox_confines(cfg, "main", None) is None


def test_an_undecided_scope_is_not_subtracted_and_says_so():
    """Both halves of the caller-visible contract.

    Subtracting an undecided scope would fabricate containment; dropping the qualifier would
    assert a reach we have not established. The label carries the uncertainty so the finding
    can word itself honestly instead of the sentence being written by whoever got there first.
    """
    cfg = {
        "tools": {"allow": ["read"]},
        "agents": {"defaults": {"sandbox": {"mode": "non-main"}}},
    }
    reach = scopes_reaching_outside_workspace(cfg)
    assert reach, "an undecided scope must not be silently subtracted"
    assert any(_UNDECIDED_SUFFIX in label for label in reach), reach
    assert any_confinement_undecided(reach) is True


def test_a_proven_confined_scope_is_still_subtracted():
    """The control in the opposite direction. `mode: "all"` is decidable, so the scope is
    removed exactly as before — the third state must not leak into cases that have an answer.
    """
    cfg = {
        "tools": {"allow": ["read"]},
        "agents": {"defaults": {"sandbox": {"mode": "all"}}},
    }
    assert scopes_reaching_outside_workspace(cfg) == []
    assert any_confinement_undecided(scopes_reaching_outside_workspace(cfg)) is False


def test_workspace_only_still_beats_an_undecided_sandbox():
    """`tools.fs.workspaceOnly: true` is proof on its own. An undecided sandbox beside it must
    not downgrade a scope that is confined by a different mechanism."""
    cfg = {
        "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
        "agents": {"defaults": {"sandbox": {"mode": "non-main"}}},
    }
    assert scopes_reaching_outside_workspace(cfg) == []


def test_the_undecided_marker_guard_bites():
    """Positive control for `any_confinement_undecided`. Without it, the assertions above
    could pass against a predicate that returns False for everything."""
    assert any_confinement_undecided([f"agent 'x'{_UNDECIDED_SUFFIX}"]) is True
    assert any_confinement_undecided(["agent 'x'"]) is False
    assert any_confinement_undecided([]) is False
    assert any_confinement_undecided(None) is False


# --- the shape `fixtures/` did not contain, found by an independent C-135 pass ------------
#
# Every `non-main` fixture in the corpus leaves the MAIN scope unconfined anyway, so the old
# predicate and the new one agreed on all of them and the corpus measurement reported "no
# verdict moved". That was true of the corpus and false in general: the flip needs the main
# scope confined by another route PLUS a non-default agent relying on `non-main`, and nothing
# shipped had it. These three fixtures are that shape, so the guard can see its own blind spot
# instead of a reviewer having to construct it by hand again.


def _statuses(name):
    return {f.id: f.status for f in run_all(collect(str(FIXTURES / name)))}


def test_an_undecided_non_default_scope_escalates_and_the_escalation_is_true():
    """A1 PASS -> FAIL and B55 WARN -> FAIL on this shape, and both are correct: the vendor
    reports `helper`'s own main session as UNSANDBOXED, so a granted read/write really does
    reach outside there. The old `True` was a false negative, not a conservative default."""
    s = _statuses("bad_b712_undecided_scope_escape")
    assert s["A1"] == "FAIL", s
    assert s["B55"] == "FAIL", s
    assert confined_scopes(
        json.loads((FIXTURES / "bad_b712_undecided_scope_escape" / "openclaw.json").read_text())
    ) == [True, None]


def test_the_same_state_is_reachable_through_a_workspaceonly_override():
    """Second route, same undecided state — a global `tools.fs.workspaceOnly: true` that a
    per-agent entry turns off while running `non-main`. Pinned separately because a fix that
    only looked at `sandbox.mode` would pass the first fixture and miss this one."""
    s = _statuses("bad_b712_undecided_workspaceonly_override")
    assert s["A1"] == "FAIL", s
    assert s["B55"] == "FAIL", s


def test_closing_the_escape_removes_it_entirely():
    """The control. Identical layout with `helper` also on `mode: "all"` — every scope proven
    confined, nothing undecided, A1 back to PASS. Without this the two tests above would pass
    against a predicate that flags this shape unconditionally."""
    name = "warn_b712_every_scope_sandboxed"
    cfg = json.loads((FIXTURES / name / "openclaw.json").read_text())
    assert confined_scopes(cfg) == [True, True]
    assert undecided_inheriting_scopes(cfg) == []
    assert confinement_undecided_only(cfg) is False
    s = _statuses(name)
    assert s["A1"] == "PASS", s
    # B55 still WARNs, and legitimately: write IS reachable by untrusted senders, merely
    # confined to the workspace. Hence the `warn_` prefix rather than `clean_`.
    assert s["B55"] == "WARN", s


def test_a_fail_driven_by_an_undecided_scope_says_so():
    """The other half of the C-135 finding, and the one that was actually wrong.

    Escalating was correct; asserting it was not. B55's FAIL text claims "no write-specific
    scoping" and "arbitrary file writes", and A1's source line claims a sensitive-data grant —
    both about a scope whose confinement the config does not settle. The verdicts stand; the
    evidence now distinguishes "not proven confined" from "proven unconfined".
    """
    findings = {f.id: f for f in run_all(collect(str(FIXTURES / "bad_b712_undecided_scope_escape")))}
    b55_ev = " ".join(findings["B55"].evidence or [])
    assert "UNDECIDED rather than proven unconfined" in b55_ev, b55_ev[:400]
    a1 = findings["A1"]
    a1_text = (a1.detail or "") + " " + " ".join(a1.evidence or [])
    assert "confinement undecided" in a1_text, a1_text[:400]


def test_a_proven_unconfined_scope_gets_no_hedge():
    """The control for the hedge. Real evidence must not be softened — a scope with the
    sandbox demonstrably off is not undecided, and saying "undecided" there would understate
    a finding as badly as the reverse overstates one."""
    cfg = {
        "agents": {"list": [{"id": "main", "default": True, "sandbox": {"mode": "off"}}]},
        "tools": {"allow": ["read", "write"]},
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    assert confinement_undecided_only(cfg) is False
    assert undecided_inheriting_scopes(cfg) == []
