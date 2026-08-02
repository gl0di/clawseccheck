"""CLAWSECCHECK-B-371 — A1 and B41 agree on untrusted-ingress classification.

STEP 1 FINDING (this ticket's original premise, re-verified against current code):
the literal claimed defect — `_external_input_channels()` returning `["telegram"]` for
`{"channels": {"telegram": {}}}` "purely because the channel is present, regardless of
policy" — is STALE. On current code that call returns `[]` (see
`test_b371_literal_ticket_shape_...` below): `_external_input_channels` already requires
an actual dmPolicy/groupPolicy match, or the B-297 open-wildcard-group shape, neither of
which a bare `{}` channel node carries.

A GENUINE, different disagreement was found instead, via the real config this ticket
references (`clawrange/corpus/coding_telegram_insecure`, read-only, not depended on
here — the shape is reproduced inline so this test stays offline/self-contained): a
`channels.<name>.groups {"*": ...}` entry with NO dmPolicy/groupPolicy field at all and
no allowFrom (the B-297 shape). Before B-371, `_external_input_channels` (which B41
calls) saw it as ingress but `_trifecta_legs` (which A1 calls, via
`_untrusted_input_channels`) did not — a divergence
`tests/test_b297_wildcard_group_ingress_leg.py` had explicitly pinned as a deliberate,
deferred scope decision pending "its own C-135 pass". B-371 is that pass:
`_trifecta_legs` now ALSO reads a new, narrower helper,
`_unpolicied_open_wildcard_group_channels` (checks/_shared.py) — deliberately NOT the
full `_external_input_channels` B41 uses, because an initial attempt to wire A1 straight
to it broke two pre-existing FP-guard tests (an explicit-but-unmodeled groupPolicy value
like "ask"/"owner-only" alongside a wildcard group — see
`test_checks.py::test_a1_approval_gated_group_bot_not_untrusted_input` /
`::test_a1_owner_only_group_bot_not_untrusted_input`). So A1 and B41 now agree on the
shape this ticket's real scenario carries (no policy field at all) but keep a DELIBERATE,
pinned residual asymmetry on the unmodeled-policy shape — see
`test_b371_residual_asymmetry_on_unmodeled_group_policy_is_deliberate` below.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _external_input_channels,
    _trifecta_legs,
    check_credential_blast_radius,
    check_trifecta,
)
from clawseccheck.collector import Context

# The exact minimal shape the ticket description gave: a Telegram channel present with
# no dmPolicy/groupPolicy set at all.
_LITERAL_TICKET_CFG = {"channels": {"telegram": {}}}

# The real-world shape this ticket actually traces to (coding_telegram_insecure,
# channels/tools/auth subset only — reproduced inline, not read from the sibling
# clawrange repo, so this test has no external/network dependency).
_WILDCARD_GROUP_CFG = {
    "tools": {"profile": "coding"},
    "auth": {"profiles": {"openai:tester@example.com": {"provider": "openai"}}},
    "gateway": {"auth": {"mode": "token", "token": "fake-gateway-token-not-a-real-secret"}},
    "channels": {
        "telegram": {
            "enabled": True,
            "groups": {"*": {"requireMention": True}},
        }
    },
}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _untrusted_ingress_per_a1(cfg: dict) -> bool:
    """A1's own notion of 'has untrusted ingress', read off its shared leg helper."""
    return _trifecta_legs(_ctx(cfg))["untrusted input"]


def _untrusted_ingress_per_b41(cfg: dict) -> bool:
    """B41's own notion, read the same way B41 itself computes it (checks/_config.py:
    `has_untrusted_ingress = bool(_external_input_channels(cfg)) or _hint(tools, ...)`),
    isolated from B41's separate has_credentials/has_outbound gates."""
    return bool(_external_input_channels(cfg))


# ---------------------------------------------------------------------------
# Step 1 — the literal ticket shape: premise was stale, nothing to reconcile
# ---------------------------------------------------------------------------


def test_b371_literal_ticket_shape_has_no_ingress_by_either_notion():
    assert _untrusted_ingress_per_a1(_LITERAL_TICKET_CFG) is False
    assert _untrusted_ingress_per_b41(_LITERAL_TICKET_CFG) is False


def test_b371_literal_ticket_shape_b41_is_unknown_not_warn():
    """No credentials in this minimal config at all, so B41 can't even reach the
    ingress question — it reports UNKNOWN, not the WARN the ticket described."""
    assert check_credential_blast_radius(_ctx(_LITERAL_TICKET_CFG)).status == UNKNOWN


def test_b371_literal_ticket_shape_a1_is_not_fail():
    """A1 never FAILs here (only 1/3 legs can be active — no untrusted input, no
    sensitive data); it reads WARN rather than PASS because the enabled Telegram
    channel makes 'outbound actions' active while 'untrusted input' stays an unresolved
    unknown absent an attestation (B-033 thin-surface guard) — not because the two
    checks disagree about ingress."""
    assert check_trifecta(_ctx(_LITERAL_TICKET_CFG)).status in (WARN, PASS)


# ---------------------------------------------------------------------------
# Step 1 (continued) — the REAL scenario: a genuine disagreement existed, now closed
# ---------------------------------------------------------------------------


def test_b371_wildcard_group_shape_agrees_both_see_ingress():
    """The regression this ticket exists to prevent: A1 and B41 must not silently
    diverge again on a reachable, unrestricted `groups["*"]` channel."""
    assert _untrusted_ingress_per_a1(_WILDCARD_GROUP_CFG) is True
    assert _untrusted_ingress_per_b41(_WILDCARD_GROUP_CFG) is True


def test_b371_wildcard_group_shape_full_findings_agree():
    """End-to-end (not just the internal leg helpers): on the real config shape, A1
    FAILs the completed 3/3 trifecta and B41 WARNs that the credentials are broadly
    reachable — both because of the same open-group ingress, not two different stories."""
    a1 = check_trifecta(_ctx(_WILDCARD_GROUP_CFG))
    b41 = check_credential_blast_radius(_ctx(_WILDCARD_GROUP_CFG))
    assert a1.status == FAIL
    assert b41.status == WARN
    # Both must independently and correctly count this exact config as an untrusted-ingress
    # config — the whole point of the regression pin, verified via each finding's own
    # detail/evidence text rather than trusting the internal helper agreement alone.
    assert "untrusted input" in a1.detail or "untrusted-ingress" in a1.detail
    assert "untrusted ingress" in b41.detail


# ---------------------------------------------------------------------------
# The deliberate residual: NOT a re-divergence, pinned so it stays deliberate
# ---------------------------------------------------------------------------


def test_b371_disabled_account_wildcard_group_is_not_untrusted_ingress():
    """B-438 (C-135 adversarial review, found while widening B55's FAIL gate to reuse
    this same helper): `_unpolicied_open_wildcard_group_channels` used to check the
    CHANNEL-level `enabled` flag but not the per-resolved-NODE one — so a retired
    Telegram account left with its old, wide-open `groups["*"]` policy on record (no
    dmPolicy/groupPolicy field, same shape `_WILDCARD_GROUP_CFG` above carries) still
    counted as untrusted ingress for A1 even though it is administratively disabled and
    ingests nothing. `_open_wildcard_group_channels` (B41's broader helper) already
    carried this guard — this pins the two helpers back in parity for this shape."""
    cfg = {
        "channels": {
            "telegram": {
                "enabled": True,
                "accounts": {
                    "retired_support_bot": {
                        "enabled": False,
                        "groups": {"*": {"requireMention": True}},
                    }
                },
            }
        }
    }
    assert _untrusted_ingress_per_a1(cfg) is False
    assert _untrusted_ingress_per_b41(cfg) is False


def test_b371_residual_asymmetry_on_unmodeled_group_policy_is_deliberate():
    """A1 and B41 do NOT agree on every possible config — an explicit-but-unmodeled
    groupPolicy value (e.g. "ask"/"owner-only" — not a real OpenClaw schema literal,
    see `_wildcard_group_gap`'s docstring) alongside an otherwise-open `groups["*"]`
    still trips B41's broader `_external_input_channels` reading but NOT A1's leg. This
    is intentional (A1 is CRITICAL/hard-FAIL-capable, B41 is WARN-only — same
    conservative-FAIL/broader-WARN split already established elsewhere, e.g. B55's FAIL
    gate vs B46's WARN gate), pinned here so a future change cannot silently narrow B41
    or widen A1 to force full alignment without a fresh C-135 pass of its own."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "groupPolicy": "ask"}}}
    assert _untrusted_ingress_per_a1(cfg) is False
    assert _untrusted_ingress_per_b41(cfg) is True
