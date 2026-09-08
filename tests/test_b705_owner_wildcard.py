"""B-705 — `commands.ownerAllowFrom: ["*"]` means opposite things on the two builds.

B-231 grounded this leg and was RIGHT for its time. On 2026.7.1-2, `command-auth-*.js`::

    const ownerAllowAll = hasWildcardAllowFrom(configOwnerAllowFromList);
    const senderIsOwner = senderIsOwnerByIdentity || senderIsOwnerByScope
                       || ownerState.ownerAllowAll;
    const isOwnerForCommands = !requireOwner ? true
                             : ownerState.ownerAllowAll ? true : ...;

A bare `"*"` really did make every sender an owner. OpenClaw 2026.8.1 removed the whole
mechanism — `ownerAllowAll` appears in ZERO files of that dist against one in 2026.7.1-2 —
and the surviving code strips the entry before anything reads it::

    const explicitOwners = Array.from(new Set(stripWildcardAllowFrom(configOwnerAllowFromList)));
    const ownerAllowlistConfigured = ownerState.explicitOwners.length > 0;
    const senderIsOwner = senderIsOwnerByIdentity || senderIsOwnerByScope;

So on 2026.8.1 the entry leaves `explicitOwners = []`, which is EXACTLY the state of the
key being absent — a state these checks call PASS. Two opposite verdicts, at CRITICAL, for
one configuration.

Note what the schema description could NOT settle: *"'\\*' is ignored"* reads identically in
both builds. It was true of the candidate list in 7.x and became true of the authorization
decision in 8.1 without the sentence changing. Only the code moved, which is why the fix
had to be grounded in the code of BOTH versions rather than in the doc string of either.

The `commands.allowFrom` wildcard is deliberately NOT gated: it is still honoured on
2026.8.1 (`allowAll = ... || hasWildcardAllowFrom(allowFromList)`), and gating both halves
together would have traded one false FAIL for a false negative on a genuinely open gate.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.catalog import FAIL, PASS
from clawseccheck.collector import collect

MODERN = "2026.8.1"
LEGACY = "2026.7.1-2"

_OPEN_CHANNEL = {"channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}}


def _finding(cfg, installed, cid):
    home = Path(tempfile.mkdtemp(prefix="b705-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg))
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return next(f for f in C.run_all(ctx) if f.id == cid)


def _with_owner(base, value):
    cfg = json.loads(json.dumps(base))
    if value is not None:
        cfg.setdefault("commands", {})["ownerAllowFrom"] = value
    return cfg


# The shapes that reach each verdict branch. A twin property asserted on one config would
# prove almost nothing — the branches are what differ.
_SHAPES = [
    ("closed-privileged", {"commands": {"enabled": True, "bash": True}}),
    ("open-privileged", {**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}}),
    ("open-unprivileged", {**_OPEN_CHANNEL, "commands": {"enabled": True}}),
    ("plain", {"commands": {"enabled": True}}),
]


# ------------------------------------------------- the property, stated as equality

@pytest.mark.parametrize("cid", ["B48", "B171"])
@pytest.mark.parametrize("label,base", _SHAPES, ids=[n for n, _b in _SHAPES])
def test_the_wildcard_and_the_absent_key_are_the_same_config_on_a_modern_build(
        label, base, cid):
    """Asserted as EQUALITY rather than as two expectations, so the two cannot drift apart
    again: whatever the verdict is, it has to be the same one, because OpenClaw resolves
    both to `explicitOwners = []`."""
    absent = _finding(_with_owner(base, None), MODERN, cid).status
    wildcard = _finding(_with_owner(base, ["*"]), MODERN, cid).status
    assert absent == wildcard, f"{cid} on {label}: absent={absent} wildcard={wildcard}"


# ------------------------------------------------- the 2026.7.x grant is real

@pytest.mark.parametrize("cid", ["B48", "B171"])
def test_the_grant_is_still_reported_on_a_legacy_build(cid):
    """B-231 was not wrong; the code changed under it. Deleting the leg outright would
    have gone blind on every 2026.7.x fleet."""
    cfg = _with_owner({**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}}, ["*"])
    assert _finding(cfg, LEGACY, cid).status == FAIL


def test_an_undeterminable_build_keeps_the_legacy_verdict():
    """Silence here would be a claim about a build we cannot see, and the legacy state is
    the dangerous one."""
    cfg = _with_owner({"commands": {"enabled": True}}, ["*"])
    assert _finding(cfg, None, "B48").status == FAIL


# ------------------------------------------------- the false negative this fix created

def test_a_wildcard_only_owner_list_is_still_no_gate_at_all():
    """The sharpest case, and one this fix BROKE before it fixed: removing the wildcard
    FAIL took away the finding that used to catch this shape on its way past, and B171's
    `gate_configured` then read the raw list's truthiness — counting `["*"]` as a
    configured gate when the runtime sees none.

    Measured before the second fix: open channel + `commands.bash` + `ownerAllowFrom:
    ["*"]` gave FAIL/CRITICAL on 2026.7.x and PASS on 2026.8.1.
    """
    cfg = _with_owner({**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}}, ["*"])
    finding = _finding(cfg, MODERN, "B171")
    assert finding.status == FAIL
    no_gate = _finding({**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}},
                       MODERN, "B171")
    assert finding.status == no_gate.status, "still the same config as having no gate"


def test_a_wildcard_beside_a_real_owner_is_the_scoped_config_it_actually_is():
    """`["*", "telegram:1"]` strips to `["telegram:1"]` — a properly scoped owner list, and
    on 2026.8.1 that is all it ever was."""
    cfg = _with_owner({**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}},
                      ["*", "telegram:1"])
    scoped = _with_owner({**_OPEN_CHANNEL, "commands": {"enabled": True, "bash": True}},
                         ["telegram:1"])
    assert _finding(cfg, MODERN, "B171").status == _finding(scoped, MODERN, "B171").status


# ------------------------------------------------- the half that must NOT be gated

@pytest.mark.parametrize("installed", [MODERN, LEGACY], ids=["modern", "legacy"])
def test_a_wildcard_in_commands_allow_from_is_still_a_finding(installed):
    """The false-negative control, and the reason the two halves are gated separately.
    `commands.allowFrom`'s wildcard is honoured on BOTH builds:
    `allowAll = ... || hasWildcardAllowFrom(allowFromList)`. A blanket gate over the shared
    detector would have silenced a genuinely open command gate."""
    cfg = {"commands": {"enabled": True, "bash": True, "allowFrom": {"*": ["*"]}}}
    finding = _finding(cfg, installed, "B171")
    assert finding.status == FAIL
    assert any("allowFrom['*']" in e for e in (finding.evidence or []))


def test_the_two_halves_are_reported_independently_on_a_modern_build():
    """Both wildcards set: the owner half is silent, the allowFrom half still speaks."""
    cfg = {"commands": {"enabled": True, "bash": True,
                        "ownerAllowFrom": ["*"], "allowFrom": {"*": ["*"]}}}
    evidence = " ".join(_finding(cfg, MODERN, "B171").evidence or [])
    assert "allowFrom['*'] contains '*'" in evidence
    assert "ownerAllowFrom contains '*'" not in evidence


# ------------------------------------------------- the control

@pytest.mark.parametrize("installed", [MODERN, LEGACY], ids=["modern", "legacy"])
def test_a_scoped_owner_list_is_clean_on_both_builds(installed):
    """Without this, "always PASS on modern" would satisfy every assertion above."""
    cfg = _with_owner({"commands": {"enabled": True, "bash": True}}, ["telegram:1"])
    assert _finding(cfg, installed, "B48").status == PASS


def test_the_predicate_stayed_a_fact_about_the_config():
    """`_is_owner_wildcard_allow_from` must not learn about versions: two call sites gate
    it differently, and a predicate that decided for them could not serve both."""
    from clawseccheck.checks import _is_owner_wildcard_allow_from
    assert _is_owner_wildcard_allow_from(["*"]) is True
    assert _is_owner_wildcard_allow_from(["telegram:1"]) is False
    assert _is_owner_wildcard_allow_from("*") is True
    assert _is_owner_wildcard_allow_from(None) is False
