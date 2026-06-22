"""B48 — dangerous break-glass overrides. Grounded against the real openclaw schema.

All flag paths are documented "DANGEROUS / keep disabled" in `openclaw config schema`.
Default/absent = nothing flagged (PASS) -> zero false positives on a stock config.
"""
from pathlib import Path

from clawseccheck.checks import check_dangerous_overrides
from clawseccheck.collector import Context


def _ctx(config):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    return c


# ---- clean config -> PASS (no override active) ----
def test_b48_clean_config_passes():
    r = check_dangerous_overrides(_ctx({"gateway": {"port": 19001}}))
    assert r.id == "B48"
    assert r.status == "PASS"
    assert r.scored is True


def test_b48_empty_config_passes():
    assert check_dangerous_overrides(_ctx({})).status == "PASS"


# ---- FAIL: sandbox escape (defaults) ----
def test_b48_sandbox_namespace_join_fails():
    cfg = {"agents": {"defaults": {"sandbox": {"docker": {
        "dangerouslyAllowContainerNamespaceJoin": True}}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "FAIL"
    assert any("ContainerNamespaceJoin" in e for e in r.evidence)


# ---- FAIL: control-plane device auth disabled ----
def test_b48_disable_device_auth_fails():
    cfg = {"gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True}}}
    assert check_dangerous_overrides(_ctx(cfg)).status == "FAIL"


# ---- FAIL: per-agent sandbox escape ----
def test_b48_per_agent_sandbox_escape_fails():
    cfg = {"agents": {"list": [
        {"name": "a"},
        {"name": "b", "sandbox": {"docker": {"dangerouslyAllowExternalBindSources": True}}},
    ]}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "FAIL"
    assert any("agents.list[1]" in e for e in r.evidence)


# ---- WARN: lower-severity overrides ----
def test_b48_real_ip_fallback_warns():
    assert check_dangerous_overrides(_ctx({"gateway": {"allowRealIpFallback": True}})).status == "WARN"


def test_b48_channel_signature_validation_disabled_warns():
    cfg = {"channels": {"sms": {"dangerouslyDisableSignatureValidation": True}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "WARN"
    assert any("sms" in e and "SignatureValidation" in e for e in r.evidence)


def test_b48_unsafe_external_content_warns():
    cfg = {"hooks": {"gmail": {"allowUnsafeExternalContent": True}}}
    assert check_dangerous_overrides(_ctx(cfg)).status == "WARN"


def test_b48_channel_private_network_warns():
    cfg = {"channels": {"slack": {"network": {"dangerouslyAllowPrivateNetwork": True}}}}
    assert check_dangerous_overrides(_ctx(cfg)).status == "WARN"


def test_b48_plugin_private_network_warns():
    cfg = {"plugins": {"entries": {"comfy": {"config": {"allowPrivateNetwork": True}}}}}
    assert check_dangerous_overrides(_ctx(cfg)).status == "WARN"


# ---- gateway.nodes.allowCommands: non-empty array WARNs, empty does not ----
def test_b48_node_allow_commands_nonempty_warns():
    assert check_dangerous_overrides(
        _ctx({"gateway": {"nodes": {"allowCommands": ["rm"]}}})).status == "WARN"


def test_b48_node_allow_commands_empty_passes():
    assert check_dangerous_overrides(
        _ctx({"gateway": {"nodes": {"allowCommands": []}}})).status == "PASS"


# ---- FAIL takes priority and evidence carries both tiers ----
def test_b48_fail_priority_over_warn():
    cfg = {
        "gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True},
                    "allowRealIpFallback": True},
    }
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "FAIL"
    joined = " ".join(r.evidence)
    assert "dangerouslyDisableDeviceAuth" in joined and "allowRealIpFallback" in joined


# ---- never UNKNOWN: config is always readable ----
def test_b48_never_unknown():
    for cfg in ({}, {"gateway": {"allowRealIpFallback": True}},
                {"gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True}}}):
        assert check_dangerous_overrides(_ctx(cfg)).status != "UNKNOWN"
