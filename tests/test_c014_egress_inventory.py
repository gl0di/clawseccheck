"""C014 — egress inventory of outbound-capable surfaces."""
import copy
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_egress_inventory
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    ctx = Context(home=Path("/tmp/egress-inventory"))
    ctx.config = cfg
    return ctx


def test_c014_unknown_without_outbound_surfaces():
    f = check_egress_inventory(_ctx({"gateway": {"bind": "127.0.0.1:8080"}}))
    assert f.status == UNKNOWN


def test_c014_warns_when_surfaces_have_no_restriction_signals():
    ctx = _ctx({
        "tools": {"allow": ["exec", "webhook"], "exec": {"mode": "full"}},
        "channels": {"discord": {"dmPolicy": "open", "groupPolicy": "open"}},
        "mcp": {"servers": {"remote": {"url": "https://mcp.example.com/sse"}}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == WARN
    assert any("tool exec" in item for item in f.evidence)
    assert any("MCP remote" in item for item in f.evidence)


def test_c014_passes_when_restriction_signals_exist():
    """Multiple restricted surfaces + one unrestricted surface still PASS, and every
    surface is inventoried.

    This config carries FOUR restriction signals at once, so it cannot pin any individual
    one — `test_c014_single_restriction_limb_alone_yields_pass` below is what does that.
    What it *can* pin is inventory completeness: PASS must not stop C014 listing the
    unrestricted `http_post` surface, because the PASS wording tells the reader to go read
    the per-surface lines and treat any unrestricted surface as open. Asserting the exact
    evidence list is what makes that promise real.
    """
    ctx = _ctx({
        "tools": {
            "allow": ["exec", "http_post"],
            "exec": {"mode": "ask"},
        },
        "channels": {"slack": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
        "mcp": {"servers": {"local": {"command": "npx", "args": ["-y", "srv"]}}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == PASS
    assert f.evidence == [
        "channel slack: outbound-capable path (dmPolicy=allowlist, groupPolicy=allowlist)",
        "tool exec: outbound-capable (approval gate present)",
        "tool http_post: outbound-capable (no explicit restriction signal)",
        "MCP local: local stdio subprocess",
    ]


# --- Each restriction limb must be able to carry PASS ON ITS OWN ---
#
# Every restriction signal C014 can report is PER-SURFACE: OpenClaw has no global
# egress-control field (see the B-263 regression tests below). `restricted` is therefore an
# OR across surfaces, and that makes a multi-signal config useless for pinning any single
# limb — the other limbs keep producing PASS while one rots.
#
# Measured, not assumed: disabling each `restricted = True` in check_egress_inventory() one
# at a time left this whole file green for the dmPolicy limb, the groupPolicy limb, the exec
# approval gate, the tools.elevated.allowFrom limb, and the MCP local-stdio limb. Only the
# two MCP allowedHosts/local-URL limbs were caught, by their own dedicated tests below.
#
# So each limb gets a config where it is the ONLY restriction signal on the ONLY surface.
# PASS then depends on that one limb alone, and pinning the exact evidence list keeps the
# assertion about restriction SEMANTICS rather than about a string the check appends
# unconditionally.

_SINGLE_RESTRICTION_LIMBS = [
    (
        "channel dmPolicy allowlist",
        {"channels": {"slack": {"dmPolicy": "allowlist"}}},
        "channel slack: outbound-capable path (dmPolicy=allowlist)",
    ),
    (
        "channel groupPolicy allowlist",
        {"channels": {"slack": {"groupPolicy": "allowlist"}}},
        "channel slack: outbound-capable path (groupPolicy=allowlist)",
    ),
    (
        "exec approval gate",
        {"tools": {"allow": ["exec"], "exec": {"mode": "ask"}}},
        "tool exec: outbound-capable (approval gate present)",
    ),
    (
        "tools.elevated.allowFrom",
        {"tools": {"allow": ["elevated"], "elevated": {"allowFrom": ["owner"]}}},
        "tool elevated: outbound-capable (sender allowlist configured)",
    ),
    (
        "MCP local stdio transport",
        {"mcp": {"servers": {"local": {"command": "npx", "args": ["-y", "srv"]}}}},
        "MCP local: local stdio subprocess",
    ),
]


@pytest.mark.parametrize("label,cfg,expected_evidence", _SINGLE_RESTRICTION_LIMBS,
                         ids=[label for label, _, _ in _SINGLE_RESTRICTION_LIMBS])
def test_c014_single_restriction_limb_alone_yields_pass(label, cfg, expected_evidence):
    f = check_egress_inventory(_ctx(copy.deepcopy(cfg)))
    assert f.status == PASS, (
        f"{label} is the only restriction signal on the only surface, so C014 must PASS "
        f"on it alone — got {f.status}. If this limb was intentionally removed, remove its "
        "entry here too; do not let it rot silently."
    )
    # One surface, one line: the PASS cannot be coming from somewhere else.
    assert f.evidence == [expected_evidence]


# --- B-263: schema-rejected keys must never certify egress as restricted ---
#
# C014 used to treat four would-be global allowlists as proof of a restricted egress
# posture. None of them exists: the OpenClaw root object rejects `network` and `egress`,
# the `gateway` object rejects `egress`, and the strict `ToolsSchema` rejects `http` —
# each with a zod `unrecognized_keys` issue, i.e. OpenClaw REFUSES to load such a config.
# clawseccheck reads raw JSON and never validates against zod, so these were not dead
# branches: any one of them flipped a wide-open config from WARN to PASS. A config the
# agent cannot even load must not be able to launder an unrestricted posture into a
# clean verdict.

_UNRESTRICTED_BASE = {
    "tools": {"allow": ["webhook"]},
    "channels": {"discord": {"dmPolicy": "open"}},
}

_SCHEMA_REJECTED_EGRESS_KEYS = [
    ("gateway.egress", {"gateway": {"egress": {"allow": ["exfil.example.com"]}}}),
    ("network.egress", {"network": {"egress": ["exfil.example.com"]}}),
    ("top-level egress", {"egress": ["exfil.example.com"]}),
    ("tools.http.allow", {"tools": {"allow": ["webhook"], "http": {"allow": ["x.example.com"]}}}),
]


def test_c014_baseline_without_restriction_is_warn():
    """Control for the regression below: the base config must genuinely be WARN."""
    f = check_egress_inventory(_ctx(copy.deepcopy(_UNRESTRICTED_BASE)))
    assert f.status == WARN


@pytest.mark.parametrize("label,patch", _SCHEMA_REJECTED_EGRESS_KEYS,
                         ids=[label for label, _ in _SCHEMA_REJECTED_EGRESS_KEYS])
def test_c014_schema_rejected_key_does_not_certify_restriction(label, patch):
    cfg = copy.deepcopy(_UNRESTRICTED_BASE)
    cfg.update(copy.deepcopy(patch))
    f = check_egress_inventory(_ctx(cfg))
    assert f.status == WARN, (
        f"{label} does not exist in the OpenClaw schema (config would be rejected at "
        f"load) yet it flipped C014 to {f.status}"
    )
    assert not any("global egress restriction" in item for item in f.evidence)


# --- QUALITY: MCP allowedHosts wildcard / user-content host is a weak mitigation ---

def test_c014_mcp_wildcard_allowed_hosts_not_counted_as_restricted():
    # allowedHosts is the ONLY restriction signal for this MCP entry and it's a
    # wildcard — must not flip restricted=True for that surface, so the overall
    # verdict stays WARN (no other restriction signal anywhere else in the config).
    ctx = _ctx({
        "mcp": {"servers": {"remote": {
            "url": "https://mcp.example.com/sse",
            "allowedHosts": ["*.mcp.example.com"],
        }}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == WARN
    assert any("weak mitigation" in item for item in f.evidence)
    assert any("*.mcp.example.com" in item for item in f.evidence)


def test_c014_mcp_known_user_content_host_not_counted_as_restricted():
    ctx = _ctx({
        "mcp": {"servers": {"remote": {
            "url": "https://mcp.example.com/sse",
            "allowedHosts": ["webhook.site"],
        }}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == WARN
    assert any("weak mitigation" in item for item in f.evidence)
    assert any("webhook.site" in item for item in f.evidence)


def test_c014_mcp_clean_tight_allowed_hosts_passes():
    # No false positives: a clean, specific allowedHosts list must still count as
    # a restriction signal and PASS.
    ctx = _ctx({
        "mcp": {"servers": {"remote": {
            "url": "https://mcp.example.com/sse",
            "allowedHosts": ["mcp.example.com"],
        }}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == PASS
    assert any("allowedHosts restricted" in item for item in f.evidence)



def test_fixture_bad_c014_warns():
    assert check_egress_inventory(collect(FIXTURES / "bad_c014_egress_inventory")).status == WARN


def test_fixture_bad_c014_unrestricted_tool_warns():
    """An outbound-capable tool and nothing else: the WARN is attributable to the tool.

    Deliberately narrower than bad_c014_egress_inventory (channels + MCP + tools), so a
    regression in the tool leg alone cannot hide behind another surface's evidence.
    """
    f = check_egress_inventory(collect(FIXTURES / "bad_c014_egress_tool_unrestricted"))
    assert f.status == WARN
    assert f.evidence == ["tool webhook: outbound-capable (no explicit restriction signal)"]


def test_fixture_clean_c014_passes():
    assert check_egress_inventory(collect(FIXTURES / "clean_c014_egress_inventory")).status == PASS


def test_c014_present_in_audit_results_for_bad_fixture():
    _, findings, _ = audit(FIXTURES / "bad_c014_egress_inventory", include_native=False)
    by_id = {f.id: f for f in findings}
    assert by_id["C014"].status == WARN
