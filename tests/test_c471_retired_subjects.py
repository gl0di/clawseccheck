"""C-471 — checks whose SUBJECT OpenClaw 2026.8.1 retired.

Six of the fourteen drifted paths were removed outright rather than moved. A removed
setting is not the same problem as a moved one: there is no new key to read, and the
question is whether the check still has anything to say. Each answer differs, so they are
not batched into one rewrite.

Two of the removals are fail-SAFE, which is unusual enough to be the reason these are
PASS rather than "silently dropped legs":

* `gateway.controlUi.allowInsecureAuth` — gone from config AND runtime.
  `evaluateMissingDeviceIdentity` now reads `if (params.isControlUi) return { kind:
  "reject-control-ui-insecure-auth" };` with no config consulted. Grep confirms the
  asymmetry: on 2026.8.1 the string survives only in `legacy-*.js` (the retired-path
  list), while on 2026.7.1-2 it is read by `audit-*.js`,
  `dangerous-config-flags-current-*.js` and `gateway-chat-*.js`.
* `commands.useAccessGroups` — ZERO of the 5,254 paths of the 2026.8.1 schema mention it
  (one in 2026.7.1-2), and the runtime reads `command.useAccessGroups ?? true`. Nothing
  can turn enforcement off any more.

Neither is remapped. `dangerouslyDisableDeviceAuth` and the root `accessGroups` both
COEXISTED with the retired keys in 2026.7.1-2, which disqualifies each as a rename target
by construction — the same rule the upgrade triage used to kill its own first guesses.

Every legacy assertion below is the other half of the contract: a 2026.7.x fleet still has
these settings live, so no leg may be deleted, only version-scoped.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
import clawseccheck.risk as R
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.collector import collect

MODERN = "2026.8.1"
LEGACY = "2026.7.1-2"


def _ctx(cfg, installed):
    home = Path(tempfile.mkdtemp(prefix="c471-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg))
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return ctx


def _finding(cfg, installed, cid):
    return next(f for f in C.run_all(_ctx(cfg, installed)) if f.id == cid)


# ---------------------------------------- 1. gateway.controlUi.allowInsecureAuth (B2)

_INSECURE = {"gateway": {"controlUi": {"allowInsecureAuth": True}}}
_INSECURE_AND_EXPOSED = {"gateway": {"bind": "0.0.0.0:8080",
                                     "controlUi": {"allowInsecureAuth": True}}}


def test_a_stale_insecure_auth_key_alone_is_not_a_finding_on_a_modern_build():
    """B2's WARN is SCORED at CRITICAL. A note that lands on its own therefore costs the
    user grade for a line that grants nothing — which is why this rides along with a real
    finding instead of creating one. The first version of this fix did create one, and
    measuring `scored` is what caught it."""
    assert _finding(_INSECURE, MODERN, "B2").status == PASS


def test_the_same_key_is_still_a_real_finding_on_a_legacy_build():
    assert _finding(_INSECURE, LEGACY, "B2").status == WARN


def test_an_undeterminable_build_keeps_the_legacy_verdict():
    """Silence would be a claim about a build we cannot see."""
    assert _finding(_INSECURE, None, "B2").status == WARN


def test_the_stale_key_is_explained_where_a_real_finding_already_exists():
    """The information is not thrown away — it is attached to a finding that stands on its
    own, so the reader learns the line is dead without it manufacturing a verdict."""
    finding = _finding(_INSECURE_AND_EXPOSED, MODERN, "B2")
    assert finding.status == FAIL
    assert "grants nothing" in (finding.detail or "")


def test_a_real_exposure_is_unaffected_by_the_stale_key():
    """The control: the FAIL above must come from the bind, not from the note."""
    assert _finding({"gateway": {"bind": "0.0.0.0:8080"}}, MODERN, "B2").status == FAIL


# ---------------------------------------- 2. marketplaces.feeds (B325) + RISK-25

_BAD_FEED = {"marketplaces": {"feeds": {"clawhub-public":
                                        {"url": "https://evil.example/feed.json"}}}}


def test_a_retired_marketplaces_block_is_not_a_supply_chain_source():
    """`marketplaces` is entry #2 in the vendor's own RETIRED_TUNING_PATHS and
    `doctor --fix` deletes a stale block rather than erroring on it. The hole B325 was
    written for — a named config profile whose host joins the trusted-fetch allowlist with
    no vetting — cannot exist when config can no longer name a profile."""
    finding = _finding(_BAD_FEED, MODERN, "B325")
    assert finding.status == PASS
    detail = finding.detail or ""
    # The MEANING, not one word: the text must say which build makes this inert and that
    # the profiles are not a source on it. An earlier version of this assertion pinned the
    # literal word "ignored" and broke when the wording was made more precise, which is a
    # test measuring the sentence rather than the claim.
    assert "2026.8.1" in detail
    assert "not a supply-chain source" in detail
    assert finding.evidence, "the profiles are still named, so the user can delete them"


def test_the_same_block_is_still_a_warning_on_a_legacy_build():
    assert _finding(_BAD_FEED, LEGACY, "B325").status == WARN


def test_the_risk_leg_retires_itself_with_no_change_in_risk_py():
    """RISK-25 is gated on `B325 == WARN`, so reporting the truth in the check is what
    stops the chain being asserted — asserted here rather than described, because a rule
    that keeps firing on a retired leg is the failure this task exists to prevent."""
    for installed, expect_fires in ((MODERN, False), (LEGACY, True)):
        ctx = _ctx(_BAD_FEED, installed)
        findings = C.run_all(ctx)
        fires = "RISK-25" in {p.id for p in R.risk_paths(ctx, findings)}
        assert fires is expect_fires, installed


def test_the_dormant_wording_is_english_not_a_leaked_none():
    """RETRACTION, pinned so it is not "fixed" into a regression. The upgrade triage
    recorded a "separate small defect: B325's WARN text ends with a stray `None`". It does
    not. The sentence is *"None of these use the \\"clawhub-public\\" profile name..."* —
    the English word starting a sentence, after the previous one ends in `'. `. There was
    never a `None` to remove.
    """
    detail = _finding(
        {"marketplaces": {"feeds": {"mine": {"url": "https://evil.example/f.json"}}}},
        LEGACY, "B325").detail or ""
    assert "None of these use" in detail
    assert not detail.rstrip().endswith("None")


# ---------------------------------------- 4. commands.useAccessGroups (B171)

_ACCESS_GROUPS_OFF = {"commands": {"enabled": True, "bash": True,
                                   "useAccessGroups": False,
                                   "ownerAllowFrom": ["telegram:1"]}}


def test_a_stale_use_access_groups_key_is_not_counted_as_a_gap():
    """Enforcement cannot be switched off on 2026.8.1, so counting a leftover `false` as a
    disabled layer would warn about a state the runtime cannot be in."""
    finding = _finding(_ACCESS_GROUPS_OFF, MODERN, "B171")
    assert finding.status == PASS
    assert "useAccessGroups" not in (finding.detail or "")


def test_the_same_key_is_still_a_gap_on_a_legacy_build():
    finding = _finding(_ACCESS_GROUPS_OFF, LEGACY, "B171")
    assert finding.status == WARN
    assert "useAccessGroups" in (finding.detail or "")


# ---------------------------------------- already closed elsewhere, pinned here

def test_the_redaction_subject_was_settled_in_b700():
    """Item 3 of this task asked whether redaction became unconditional. It did, grounded
    in the runtime rather than in the field's description: `DEFAULT_REDACT_MODE` is a
    constant config never feeds, and custom patterns are unioned with the built-ins. B9
    already PASSes on absence for a modern build; this pins that it stayed fixed."""
    assert _finding({}, MODERN, "B9").status == PASS
    assert _finding({}, LEGACY, "B9").status == WARN


def test_the_workshop_subject_was_settled_in_b700_and_b702():
    """Item 6 asked for the enum and its VALUE, not just the path. Both landed; pinned here
    so a later edit to this family cannot quietly undo the version split."""
    assert _finding({}, MODERN, "B175").status == FAIL
    assert _finding({}, LEGACY, "B175").status == PASS


# ---------------------------------------- the shared contract

@pytest.mark.parametrize("cfg,cid", [
    (_INSECURE, "B2"),
    (_BAD_FEED, "B325"),
    (_ACCESS_GROUPS_OFF, "B171"),
], ids=["insecure-auth", "marketplaces", "access-groups"])
def test_no_leg_was_deleted_for_the_fleet_that_still_has_it(cfg, cid):
    """The DoD, as one assertion: every retired subject still produces its original verdict
    on a build where the setting is live. A check that stopped reporting on 2026.7.x would
    have traded one blind spot for another."""
    assert _finding(cfg, LEGACY, cid).status in (WARN, FAIL)
