"""B-670 — `fs_confined` read both its disjuncts globally, so a per-agent escape read as safe.

`check_fs_write_exposure` (B55) uses `fs_confined` to DOWNGRADE a hard FAIL to WARN. It was:

    fs_confined = (dig(cfg, "tools.fs.workspaceOnly") is True
                   or dig(cfg, "agents.defaults.sandbox.mode") == "all")

Both fields are per-agent overridable — `resolveSandboxConfigForAgent` resolves
`sandbox.mode` per FIELD with `??`, and `resolveToolFsConfig` does the same for
`tools.fs.workspaceOnly`. So a global `sandbox.mode: "all"` beside a per-agent
`sandbox.mode: "off"` fabricated confinement for an agent that has none, and the
fabrication SUPPRESSED a real finding. A false PASS-shaped downgrade, which is the
opposite direction from B-673's false FAIL and needs the opposite adversarial brief.

TWO FIXES WERE RETRACTED BEFORE THIS ONE. Both retractions are load-bearing and each has
its own section below, because the shape of the surviving fix is a direct consequence:

1. Gating on `confined_scopes` alone — the READ-confinement question — made a hard FAIL
   out of an unconfined agent that cannot write at all. Section 4.
2. Answering "can this scope write" inside `toolpolicy` by parametrising
   `_scope_reaches_outside` was UNSOUND, and downgraded a designed-bad fixture. Section 5.

What survives asks only what can be answered soundly at this layer: B55's own vetted
resolver already established that a write tool is granted GLOBALLY, so the open question is
which scopes inherit that grant unchanged AND are unconfined.
`toolpolicy.unconfined_scopes_inheriting_global_tools` answers exactly that.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.catalog import FAIL, WARN
from clawseccheck.collector import collect
from clawseccheck.toolpolicy import (
    confined_scopes,
    unconfined_scopes_inheriting_global_tools,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_OPEN = {"channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}}
_WRITE = {"tools": {"allow": ["write"]}}
_SANDBOXED = {"sandbox": {"mode": "all"}}

# 2026.8.2's OpenClawSchema REJECTS a multi-agent `agents.entries` record with no owner
# marker ("multi-agent rosters require agents.ownership=\"explicit\" or one legacy
# default=true marker"), so every roster below carries one. Measured with the installed
# dist's own `safeParse`, not assumed. A fixture OpenClaw would refuse to load cannot
# ground a claim about what OpenClaw does — the same rule that invalidated two probes
# earlier in this task.
_MAIN = {"default": True}


def _b55_for(cfg):
    home = Path(tempfile.mkdtemp(prefix="b670-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = "2026.8.2"
    return next(f for f in C.run_all(ctx) if f.id == "B55")


def _b55(agents):
    return _b55_for({**_OPEN, **_WRITE, "agents": agents})


# ======================================================================================
# 1. The suppression this removes
# ======================================================================================

@pytest.mark.parametrize("agents,why", [
    ({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {"sandbox": {"mode": "off"}}}},
     "a global sandbox.mode='all' with a per-agent 'off' — the agent really is unsandboxed"),
    ({"defaults": _SANDBOXED, "list": [{"id": "main"}, {"id": "w", "sandbox": {"mode": "off"}}]},
     "the same, on the legacy roster shape, which a real user can still be running. "
     "Measured on 2026.8.2 rather than assumed, because a partial reading of it argues "
     "for deleting this case: `validateConfigObject` ACCEPTS `agents.list` and migrates "
     "it to `agents.entries`, re-exposing `list` as a NON-ENUMERABLE, read-only computed "
     "view (JSON.stringify omits it); `validateConfigObjectRaw` -- the write-back "
     "validator -- rejects it as an unrecognised key. That asymmetry is deliberate "
     "design, read-legacy / never-write-it-back, not a contradiction. So a legacy config "
     "on disk loads, and B-699's dual-shape reader is right to cover it."),
], ids=["entries", "list"])
def test_a_per_agent_escape_is_no_longer_read_as_confinement(agents, why):
    assert _b55(agents).status == FAIL, why


def test_genuine_confinement_still_downgrades_to_warn():
    """The control that matters most. Without it, "never downgrade" satisfies the test above
    and the whole confined/unconfined distinction quietly disappears — which would be a false
    FAIL on every properly sandboxed fleet."""
    f = _b55({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {}}})
    assert f.status == WARN
    assert any("confined to the workspace" in e for e in (f.evidence or []))


def test_nothing_confining_is_still_a_fail():
    """The other control: the FAIL must not be coming from the new code path."""
    assert _b55({"entries": {"main": _MAIN, "w": {}}}).status == FAIL


# ======================================================================================
# 2. The confinement primitive — one unconfined scope is enough
# ======================================================================================

@pytest.mark.parametrize("agents,expected", [
    ({"defaults": _SANDBOXED}, [True]),
    ({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {}}}, [True, True]),
    ({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {"sandbox": {"mode": "off"}}}},
     [True, False]),
    ({"entries": {"main": _MAIN, "w": {}}}, [False, False]),
], ids=["defaults-only", "all-inherit", "one-escapes", "none-confined"])
def test_every_declared_scope_is_enumerated(agents, expected):
    """`confined_scopes` reports the default agent's surface plus each roster entry, so the
    caller can require ALL of them. A predicate that returned one aggregate answer could not
    express "one of five agents escapes", which is the whole bug."""
    assert confined_scopes({"agents": agents}) == expected


def test_the_workspace_only_field_is_per_agent_too():
    """The OTHER disjunct. It is easy to fix only the sandbox half and leave this one global,
    which would close half the hole and read as done.

    Asserted through `confined_scopes` rather than the escape predicate, because an agent
    that opts out of `workspaceOnly` does so by writing a `tools` key — which the escape
    predicate deliberately declines to interpret (section 5). The confinement half is still
    per-agent, and that is what this pins.
    """
    escaped = {"tools": {"fs": {"workspaceOnly": True}},
               "agents": {"entries": {"main": _MAIN,
                                      "w": {"tools": {"fs": {"workspaceOnly": False}}}}}}
    assert confined_scopes(escaped) == [True, False]
    inherited = {"tools": {"fs": {"workspaceOnly": True}},
                 "agents": {"entries": {"main": _MAIN, "w": {}}}}
    assert confined_scopes(inherited) == [True, True]


def test_an_empty_scope_list_is_not_confinement():
    """`all([])` is True, so a predicate written as a bare `all(...)` would report confinement
    for a config it could not read a single scope from — fabricating the very thing this task
    removes, in a new place."""
    assert unconfined_scopes_inheriting_global_tools({}) is None
    assert confined_scopes({}) is None


def test_the_non_main_mode_does_not_confine_the_default_agent():
    """`sandbox.mode: "non-main"` leaves the DEFAULT agent unsandboxed by design, so it can
    never be blanket confinement — a distinction the old two-line read could not express at
    all, since it compared only against the literal "all".

    Asserted on the default agent's scope ONLY, deliberately. The adversarial pass showed the
    vendor's `shouldSandboxSession` compares against `resolveAgentMainSessionKey`, which is
    per-AGENT (`agent:<id>:main`), so under `non-main` EVERY agent's own main session runs
    unsandboxed and `_sandbox_confines` is wrong about the non-default ones too. That is a
    real defect with a wider blast radius — it also moves the read side (C-462) — so it is
    filed as B-712, and this test declines to pin either value for the non-default scope
    rather than pinning the one the vendor contradicts.
    """
    cfg = {"agents": {"defaults": {"sandbox": {"mode": "non-main"}},
                      "entries": {"main": _MAIN, "w": {}}}}
    assert "main" in (unconfined_scopes_inheriting_global_tools(cfg) or []), (
        "the default agent is unsandboxed under non-main")


# ======================================================================================
# 3. The evidence line has to describe what the check now does
# ======================================================================================

def test_the_evidence_no_longer_claims_a_defaults_only_read():
    """The sentence said "agents.defaults.sandbox.mode='all'" while the predicate had become a
    per-scope conjunction. A reader shown that line would look at their defaults, find `all`,
    and conclude the tool agreed with them — which is how a correct verdict still misinforms."""
    f = _b55({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {}}})
    line = next(e for e in (f.evidence or []) if "confined" in e)
    assert "agents.defaults.sandbox.mode" not in line
    assert "resolved per agent" in line
    # And it must claim CONFINEMENT and nothing weaker. An earlier attempt widened this
    # sentence to cover "scopes that inherit the grant", which let a config where NOTHING was
    # confined print a confinement claim. Section 4 is why that distinction is load-bearing.
    assert "EVERY declared scope" in line


def test_the_check_does_not_keep_its_own_copy_of_the_predicate():
    """B-673's root cause was four independently-drifting readings of this family. Structural,
    because a fifth copy would pass every behavioural test above on the day it was written and
    drift afterwards."""
    src = (Path(__file__).resolve().parent.parent
           / "clawseccheck" / "checks" / "_capability.py").read_text(encoding="utf-8")
    assert 'dig(cfg, "agents.defaults.sandbox.mode") == "all"' not in src, (
        "the global-only sandbox read is back")


# ======================================================================================
# 4. RETRACTION ONE — an unconfined scope that cannot write is not a finding
# ======================================================================================

@pytest.mark.parametrize("ops,why", [
    ({"sandbox": {"mode": "off"}, "tools": {"deny": ["write", "edit", "apply_patch"]}},
     "write tools denied for that agent"),
    ({"sandbox": {"mode": "off"}, "tools": {"profile": "messaging"}},
     "a messaging-profile notifier bot — an ordinary fleet layout"),
    ({"sandbox": {"mode": "off"}, "tools": {"allow": ["session_status"]}},
     "a narrow allowlist with no write tool in it"),
], ids=["denied", "messaging-profile", "narrow-allowlist"])
def test_an_unconfined_scope_that_narrows_its_tools_is_not_a_finding(ops, why):  # noqa: D401
    """The first blocker. A sandboxed coding agent beside an unsandboxed notifier is a normal
    layout, and the operator narrowed the second agent precisely so it could run on the host.
    Gating on confinement alone convicted all three.

    Note what this test does NOT claim. It does not assert that these agents cannot write —
    establishing that soundly needs a write-grant model this layer does not have (F-186). It
    asserts the weaker, sound thing: a scope that sets its own `tools` has not been shown to
    inherit the global write grant, so it cannot carry the FAIL on its own.
    """
    f = _b55({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "ops": ops}})
    assert f.status == WARN, why


def test_an_unconfined_scope_that_inherits_the_grant_is_still_a_finding():
    """The control the three cases above need. Without it, "never FAIL on an escaping agent"
    satisfies all of them and B-670 is undone."""
    f = _b55({"defaults": _SANDBOXED, "entries": {"main": _MAIN, "ops": {"sandbox": {"mode": "off"}}}})
    assert f.status == FAIL


@pytest.mark.parametrize("ops,expected", [
    ({}, []),
    ({"sandbox": {"mode": "off"}}, ["ops"]),
    ({"sandbox": {"mode": "off"}, "tools": {"deny": ["write"]}}, []),
    ({"sandbox": {"mode": "off"}, "tools": {"profile": "messaging"}}, []),
], ids=["confined", "escapes-inheriting", "escapes-with-override", "messaging"])
def test_the_predicate_names_the_scope_that_escaped(ops, expected):
    """Names rather than booleans, so a caller can say WHICH agent escaped — `confined_scopes`
    returns positional booleans that cannot carry that."""
    cfg = {**_WRITE, "agents": {"defaults": _SANDBOXED, "entries": {"main": _MAIN, "ops": ops}}}
    assert unconfined_scopes_inheriting_global_tools(cfg) == expected


# ======================================================================================
# 5. RETRACTION TWO — the write question must not be answered by the read stack
# ======================================================================================

def test_the_designed_bad_fixture_still_fails():
    """The regression that killed the second attempt, pinned by name.

    `fixtures/bad_b55_fs_write_broad` grants `tools.allow: ["fs_write"]` — a LEGACY ALIAS.
    B55's own resolver knows it (`_FS_WRITE_TOOL_HINTS` exists for exactly this fixture);
    `toolpolicy`'s read stack does not. So asking `toolpolicy` "can this scope write" answered
    NO for a config built to demonstrate YES, and a designed-bad fixture was downgraded to
    WARN. A false FAIL traded for a real suppression is the worse deal, and this is the test
    that would have caught it in the scoped run instead of 26 minutes later in the full suite.
    """
    assert _b55_for(json.loads(
        (FIXTURES / "bad_b55_fs_write_broad" / "openclaw.json").read_text(encoding="utf-8")
    )).status == FAIL


def test_the_read_predicate_is_not_parametrised_by_tool():
    """Structural, because the behavioural test above only covers the one alias that happens to
    be in a fixture. Two of `_scope_reaches_outside`'s three layers are read-specific —
    `_PROFILES_GRANTING_READ` answers only "does this profile grant read", and the alias table
    carries the aliases that matter for read — so a `tool=` parameter returns the READ verdict
    under a write-shaped name. `confined_scopes` documents the same trap one tool over
    (`fs_read`). The write family needs its own vetted model: F-186.
    """
    src = (Path(__file__).resolve().parent.parent
           / "clawseccheck" / "toolpolicy.py").read_text(encoding="utf-8")
    signature = src.split("def _scope_reaches_outside(", 1)[1].split(")", 1)[0]
    params = [a.split(":")[0].split("=")[0].strip() for a in signature.split(",")]
    assert "tool" not in params, (
        f"_scope_reaches_outside takes a tool parameter again: ({signature}). Its profile and "
        "alias tables are read-specific; parametrising it answers the read question under a "
        "write-shaped name."
    )


def test_a_narrowed_escape_is_warned_without_claiming_confinement():
    """The distinction the third attempt got wrong, pinned so it cannot come back.

    When the only unconfined scope narrows its own tools the verdict drops to WARN — but the
    finding must NOT print the confinement sentence, because nothing here is confined. An
    earlier version expressed this downgrade by making `fs_confined` true, which made a config
    with no sandbox and no workspaceOnly claim that "filesystem writes are confined to the
    workspace in EVERY declared scope". That is a fabricated confinement, the exact class of
    defect B-670 exists to remove, reintroduced by its own fix.
    """
    f = _b55({"defaults": _SANDBOXED,
              "entries": {"main": _MAIN,
                          "ops": {"sandbox": {"mode": "off"},
                                  "tools": {"profile": "messaging"}}}})
    assert f.status == WARN
    assert not any("confined to the workspace" in e for e in (f.evidence or [])), (
        "the WARN must not claim confinement — the escaping scope is not confined")
    assert any("narrows its own tool policy" in e for e in (f.evidence or [])), (
        "the reason for the downgrade must be on screen")


def test_nothing_confined_and_nothing_narrowed_still_fails():
    """The control for the branch above: with no sandbox, no workspaceOnly and no per-agent
    tool narrowing anywhere, the FAIL must survive."""
    f = _b55({"entries": {"main": _MAIN, "ops": {}}})
    assert f.status == FAIL


def test_a_scope_whose_own_tools_GRANT_the_write_family_still_fails():
    """The over-correction control, and the reason "sets its own tools" is not the whole rule.

    `tools: {"profile": "coding"}` on an unconfined agent has not narrowed anything — that
    profile is what grants the write family in the first place. Treating any `tools` key as
    possible narrowing downgraded this to WARN; the check's existing widening detection is
    direct evidence of the opposite and now gates the branch. Caught by
    tests/test_b55.py::test_b409_widening_still_applies_when_global_allow_is_a_wildcard.
    """
    f = _b55_for({"tools": {"allow": ["*"]},
                  "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},
                  "channels": {"telegram": {"dmPolicy": "open"}}})
    assert f.status == FAIL


# ======================================================================================
# 6. RETRACTION THREE — "the entry has a tools key" is not "the entry narrowed writes"
# ======================================================================================

def _escape(w_tools, global_allow=("write",)):
    """main sandboxed, `w` outside the sandbox — so only `w`'s own tools decide the verdict."""
    w = {"sandbox": {"mode": "off"}}
    if w_tools is not None:
        w["tools"] = w_tools
    return {**_OPEN, "tools": {"allow": list(global_allow)},
            "agents": {"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": w}}}


@pytest.mark.parametrize("w_tools,why", [
    ({}, "an empty tools block narrows nothing"),
    ({"fs": {"workspaceOnly": False}},
     "THE WORST ONE: a per-agent workspaceOnly opt-out is one of the two escapes B-670 "
     "exists to catch, and it can only be written inside a `tools` key"),
    ({"alsoAllow": ["exec"]}, "alsoAllow only ADDS — it is unioned into the allow side"),
    ({"deny": ["exec"]}, "a deny that names nothing in the write family"),
    ({"allow": ["write"]}, "an allow that names the write tool outright"),
    ({"allow": ["fs_write"]}, "the same via the legacy alias a real fixture uses"),
    (None, "control: no tools key at all — must FAIL, or the cases above prove nothing"),
], ids=["empty", "fs-optout", "alsoAllow", "deny-unrelated", "allow-write",
        "allow-fs_write", "control-no-tools"])
def test_a_tools_block_that_does_not_touch_writes_is_still_an_escape(w_tools, why):
    """The third retraction. The rule was "the entry carries a `tools` key, so it MIGHT have
    narrowed the write family away" — and an adversarial pass broke it seven ways by EXECUTING
    the vendor's `resolveConfiguredToolPolicies` + `isToolAllowedByPolicies`, which answered
    `writeAllowed=true` for every case here while B55 downgraded to WARN.

    The fs-optout case is the one that mattered most: it made B-670's fix cover the sandbox
    half of the escape and silently leave the `tools.fs.workspaceOnly` half open, which reads
    as a complete fix and is not one.
    """
    assert _b55_for(_escape(w_tools)).status == FAIL, why


@pytest.mark.parametrize("w_tools,why", [
    ({"deny": ["write", "edit", "apply_patch"]}, "a deny naming the family"),
    ({"profile": "messaging"}, "a profile replaces the tool set wholesale"),
    ({"allow": ["session_status"]}, "an allow naming no write tool"),
    ({"byProvider": {"openai": {"deny": ["write"]}}},
     "a layer this module does not resolve — treated as possible narrowing, the quiet "
     "direction: it can cost a finding, never invent one"),
], ids=["deny-family", "profile", "narrow-allow", "opaque-byProvider"])
def test_a_tools_block_that_could_remove_writes_still_downgrades(w_tools, why):
    """The other half of the partition. Without these the narrowing test could be deleted
    entirely and every case above would still pass."""
    assert _b55_for(_escape(w_tools)).status == WARN, why


def test_the_downgrade_evidence_does_not_assert_an_unchecked_widening_claim():
    """The sentence used to end "...and none of them widens toward the write family", asserted
    from `_agent_profile_widenings` — which is PROFILE-only and cannot see an allow/alsoAllow
    widening. So for `tools: {"allow": ["write"]}` the finding printed a claim the code had
    never checked, about an override naming the write tool outright. Correct verdicts can still
    misinform; this pins the sentence to what is actually tested.
    """
    f = _b55_for(_escape({"profile": "messaging"}))
    line = next(e for e in (f.evidence or []) if "narrows" in e)
    assert "widens" not in line
    assert "tools.profile" in line and "tools.deny" in line


@pytest.mark.parametrize("w_tools,expected,why", [
    ({"allow": ["*"]}, FAIL, "a wildcard allow grants the write family along with everything"),
    ({"allow": ["group:fs"]}, FAIL, "the fs group's members are read/write/edit/apply_patch"),
    ({"deny": ["*"]}, WARN, "a wildcard deny removes it along with everything"),
    ({"deny": ["group:fs"]}, WARN, "the group form removes the whole family at once"),
], ids=["allow-star", "allow-group", "deny-star", "deny-group"])
def test_the_family_moves_as_a_whole_under_a_wildcard_or_group(w_tools, expected, why):
    """Added because a mutation SURVIVED the rest of this file: dropping `*` from the
    write-family token set passed all 142 tests, so nothing pinned that `tools.allow: ["*"]`
    on an escaping agent grants writes. Both spellings that move the family wholesale need a
    case on each side, or half the token set is decorative.
    """
    assert _b55_for(_escape(w_tools)).status == expected, why
