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
    # Every restriction signal C014 can report is PER-SURFACE — OpenClaw has no global
    # egress-control field (see B-263 regression tests below).
    assert any("dmPolicy=allowlist" in item for item in f.evidence)
    assert any("local stdio subprocess" in item for item in f.evidence)


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
