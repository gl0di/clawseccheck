"""C014 — egress inventory of outbound-capable surfaces."""
from pathlib import Path

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
            "http": {"allow": ["api.example.com"]},
            "exec": {"mode": "ask"},
        },
        "channels": {"slack": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
        "mcp": {"servers": {"local": {"command": "npx", "args": ["-y", "srv"]}}},
    })
    f = check_egress_inventory(ctx)
    assert f.status == PASS
    assert any("global egress restriction configured" in item for item in f.evidence)



def test_fixture_bad_c014_warns():
    assert check_egress_inventory(collect(FIXTURES / "bad_c014_egress_inventory")).status == WARN


def test_fixture_clean_c014_passes():
    assert check_egress_inventory(collect(FIXTURES / "clean_c014_egress_inventory")).status == PASS


def test_c014_present_in_audit_results_for_bad_fixture():
    _, findings, _ = audit(FIXTURES / "bad_c014_egress_inventory", include_native=False)
    by_id = {f.id: f for f in findings}
    assert by_id["C014"].status == WARN
