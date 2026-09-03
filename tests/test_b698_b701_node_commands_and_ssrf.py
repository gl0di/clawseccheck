"""B-698 + B-701 — the node command lists in both config shapes, and two SSRF flags
that exist only in the 2026.8.1+ schema.

B-698: OpenClaw 2026.8.1 moved ``gateway.nodes.allowCommands`` / ``denyCommands`` under a
new strict object ``gateway.nodes.commands.{allow,deny}``. We read only the old spelling,
so B48 returned "No dangerous break-glass override flags enabled." about a grant it never
read — Golden Rule #4. B71 degraded to UNKNOWN instead, honest but blind.

B-701: ``cron.webhookSsrfPolicy.dangerouslyAllowPrivateNetwork`` and
``tools.web.fetch.ssrfPolicy.dangerouslyAllowPrivateNetwork`` are new in 2026.8.1 and were
in neither ``_DANGER_FIXED`` nor B48's explicit ``dig()`` calls.

Every shape-parity assertion below is PARAMETRISED over the two spellings on purpose: a
per-shape test can go green while one shape silently stops being read, which is the exact
failure this pair of bugs was.
"""
from pathlib import Path

import pytest

from clawseccheck.checks import (
    _DANGER_FIXED_2026_8_1,
    _node_commands,
    check_browser_ssrf,
    check_dangerous_overrides,
    check_node_denycommands_ineffective,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(config):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    return c


def _allow(value):
    """The grant in the OLD spelling and the NEW one, as (label, config) pairs."""
    return [
        ("legacy", {"gateway": {"nodes": {"allowCommands": value}}}),
        ("2026.8.1", {"gateway": {"nodes": {"commands": {"allow": value}}}}),
    ]


def _deny(value):
    return [
        ("legacy", {"gateway": {"nodes": {"denyCommands": value}}}),
        ("2026.8.1", {"gateway": {"nodes": {"commands": {"deny": value}}}}),
    ]


# ---------------------------------------------------------------- the accessor

@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_accessor_reads_the_legacy_spelling(kind):
    key = f"{kind}Commands"
    value, path = _node_commands({"gateway": {"nodes": {key: ["system.run"]}}}, kind)
    assert value == ["system.run"]
    assert path == f"gateway.nodes.{key}"


@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_accessor_reads_the_new_spelling(kind):
    cfg = {"gateway": {"nodes": {"commands": {kind: ["system.run"]}}}}
    value, path = _node_commands(cfg, kind)
    assert value == ["system.run"]
    assert path == f"gateway.nodes.commands.{kind}"


@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_accessor_labels_the_shape_actually_found(kind):
    """A 2026.8.1 user pointed at `gateway.nodes.allowCommands` is pointed at a key their
    own file does not contain — the label is not cosmetic."""
    _, legacy_path = _node_commands(
        {"gateway": {"nodes": {f"{kind}Commands": ["x"]}}}, kind)
    _, new_path = _node_commands(
        {"gateway": {"nodes": {"commands": {kind: ["x"]}}}}, kind)
    assert legacy_path != new_path


@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_new_key_wins_when_both_are_present(kind):
    """Mirrors the vendor's own migration (legacy-*.js)::

        if (commands.allow === void 0) commands.allow = nodes.allowCommands;

    The legacy value is used ONLY when the new key is absent. A config carrying both is
    reachable mid-migration, and disagreeing with OpenClaw about which one wins would put
    our verdict on a list the runtime does not use.
    """
    cfg = {"gateway": {"nodes": {
        f"{kind}Commands": ["legacy.cmd"],
        "commands": {kind: ["new.cmd"]},
    }}}
    value, path = _node_commands(cfg, kind)
    assert value == ["new.cmd"]
    assert path == f"gateway.nodes.commands.{kind}"


@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_an_explicit_null_new_key_still_wins(kind):
    """`=== void 0` is false for `null`, so a present-but-null new key beats the legacy
    one for OpenClaw too. Reading it as "new key if truthy" would make us report on a list
    the runtime has already discarded."""
    cfg = {"gateway": {"nodes": {
        f"{kind}Commands": ["legacy.cmd"],
        "commands": {kind: None},
    }}}
    value, _ = _node_commands(cfg, kind)
    assert value is None


@pytest.mark.parametrize("kind", ["allow", "deny"])
def test_accessor_is_quiet_on_a_config_with_neither(kind):
    for cfg in ({}, {"gateway": {}}, {"gateway": {"nodes": {}}},
                {"gateway": {"nodes": {"commands": {}}}}, {"gateway": "not-a-dict"}):
        value, path = _node_commands(cfg, kind)
        assert value is None, cfg
        assert path == f"gateway.nodes.commands.{kind}"


# ------------------------------------------------------------------- B48 (allow)

@pytest.mark.parametrize("shape,cfg", _allow(["system.run"]))
def test_b48_warns_on_a_node_command_grant_in_either_shape(shape, cfg):
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "WARN", shape
    assert any("node.invoke commands enabled" in e for e in r.evidence), shape


@pytest.mark.parametrize("shape,cfg", _allow(["system.run"]))
def test_b48_evidence_names_the_shape_actually_present(shape, cfg):
    r = check_dangerous_overrides(_ctx(cfg))
    expected = ("gateway.nodes.allowCommands" if shape == "legacy"
                else "gateway.nodes.commands.allow")
    assert any(e.startswith(expected) for e in r.evidence), r.evidence


def test_b48_still_passes_with_no_node_command_grant():
    """The control. Without it, an "always WARN" bug passes every assertion above."""
    for cfg in ({}, {"gateway": {"nodes": {}}},
                {"gateway": {"nodes": {"commands": {"allow": []}}}},
                {"gateway": {"nodes": {"allowCommands": []}}}):
        assert check_dangerous_overrides(_ctx(cfg)).status == "PASS", cfg


# -------------------------------------------------------------------- B71 (deny)

@pytest.mark.parametrize("shape,cfg", _deny(["system.run --foo"]))
def test_b71_warns_on_an_ineffective_entry_in_either_shape(shape, cfg):
    r = check_node_denycommands_ineffective(_ctx(cfg))
    assert r.status == "WARN", shape
    assert r.evidence, shape


@pytest.mark.parametrize("shape,cfg", _deny(["system.run"]))
def test_b71_passes_on_exact_names_in_either_shape(shape, cfg):
    assert check_node_denycommands_ineffective(_ctx(cfg)).status == "PASS", shape


@pytest.mark.parametrize("shape,cfg", _deny(["system.run --foo"]))
def test_b71_user_facing_text_names_the_shape_actually_present(shape, cfg):
    r = check_node_denycommands_ineffective(_ctx(cfg))
    expected = ("gateway.nodes.denyCommands" if shape == "legacy"
                else "gateway.nodes.commands.deny")
    wrong = ("gateway.nodes.commands.deny" if shape == "legacy"
             else "gateway.nodes.denyCommands")
    blob = " ".join([r.detail or "", r.fix or "", *(r.evidence or [])])
    assert expected in blob
    assert wrong not in blob


def test_b71_unknown_text_names_both_spellings():
    """With no deny list at all there is no found shape to name, and the fleet is mixed —
    so the advice must not silently pick one version's key."""
    r = check_node_denycommands_ineffective(_ctx({}))
    assert r.status == "UNKNOWN"
    blob = " ".join([r.detail or "", r.fix or ""])
    assert "gateway.nodes.commands.deny" in blob
    assert "gateway.nodes.denyCommands" in blob


# --------------------------------------------------------- B-701: the two SSRF flags

@pytest.mark.parametrize("path,_label", _DANGER_FIXED_2026_8_1)
def test_b48_warns_on_each_new_schema_ssrf_flag(path, _label):
    cfg = {}
    node = cfg
    parts = path.split(".")
    for key in parts[:-1]:
        node = node.setdefault(key, {})
    node[parts[-1]] = True
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == "WARN", path
    assert any(e.startswith(path) for e in r.evidence), r.evidence


@pytest.mark.parametrize("path,_label", _DANGER_FIXED_2026_8_1)
def test_b48_is_quiet_when_the_flag_is_explicitly_false(path, _label):
    cfg = {}
    node = cfg
    parts = path.split(".")
    for key in parts[:-1]:
        node = node.setdefault(key, {})
    node[parts[-1]] = False
    assert check_dangerous_overrides(_ctx(cfg)).status == "PASS", path


def test_the_new_schema_table_is_not_empty():
    """A table that silently emptied would make every parametrised test above vacuous."""
    assert len(_DANGER_FIXED_2026_8_1) >= 2


def test_browser_ssrf_stays_out_of_b48():
    """`browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` is B38's subject and B38 FAILs
    on it. Adding it to B48 as well would double-count, which checks/_egress.py's own
    no-double-count rule with B38 forbids. This is the sole justification for the
    omission, so it is pinned by actually calling B38 (not just by asserting absence
    from B48's table) -- if B38's browser branch ever regressed, this must go red.
    """
    paths = [p for p, _ in _DANGER_FIXED_2026_8_1]
    assert "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork" not in paths

    cfg = {"browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}}
    assert check_browser_ssrf(_ctx(cfg)).status == "FAIL"


# ------------------------------------------------------------------- fixtures

@pytest.mark.parametrize("name,check,status", [
    ("bad_b48_node_allowcommands_new_shape", check_dangerous_overrides, "WARN"),
    ("bad_b48_cron_webhook_ssrf", check_dangerous_overrides, "WARN"),
    ("bad_b48_web_fetch_ssrf", check_dangerous_overrides, "WARN"),
    ("bad_b71_denycommands_ineffective_new_shape",
     check_node_denycommands_ineffective, "WARN"),
    ("clean_b71_denycommands_effective_new_shape",
     check_node_denycommands_ineffective, "PASS"),
])
def test_fixture_produces_the_expected_status(name, check, status):
    from clawseccheck.collector import collect
    assert check(collect(FIXTURES / name)).status == status
