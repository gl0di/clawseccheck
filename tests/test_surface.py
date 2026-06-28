"""Surface taxonomy tests (C-101 / ZAХОД 1 foundation).

Verifies that every CheckMeta has a non-empty surface slug drawn from the
canonical SURFACES set, that the FAMILY_OF roll-up is consistent, and that
a selection of unambiguous checks map to the expected surface.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID, CATALOG, FAMILY_OF, SURFACES


# ── Canonical surface set ─────────────────────────────────────────────────────

_VALID_SURFACES: frozenset[str] = frozenset(SURFACES)
_BUCKET_SURFACES: frozenset[str] = _VALID_SURFACES - {"trifecta"}

_SEVEN_FAMILIES: frozenset[str] = frozenset({
    "exposure", "privilege", "supply_chain",
    "content_integrity", "secrets", "detection", "automation",
})


def test_surfaces_contains_thirteen_buckets_plus_trifecta():
    """SURFACES must have exactly the 13 named buckets plus 'trifecta'."""
    assert len(SURFACES) == 14
    assert "trifecta" in SURFACES
    assert len(_BUCKET_SURFACES) == 13


def test_surfaces_contains_all_required_slugs():
    """Every required surface slug must be present."""
    required = {
        "gateway", "tools", "agents", "mcp", "skills",
        "bootstrap", "channels", "sessions", "secrets",
        "monitoring", "hooks", "host", "update",
        "trifecta",
    }
    assert required == _VALID_SURFACES


# ── FAMILY_OF consistency ─────────────────────────────────────────────────────

def test_family_of_keys_equal_the_13_bucket_surfaces():
    """FAMILY_OF must have exactly the 13 bucket surfaces as keys (no trifecta)."""
    assert frozenset(FAMILY_OF.keys()) == _BUCKET_SURFACES


def test_family_of_values_are_one_of_the_seven_families():
    """Every value in FAMILY_OF must be one of the 7 dashboard families."""
    for surface, family in FAMILY_OF.items():
        assert family in _SEVEN_FAMILIES, (
            f"surface {surface!r} maps to unknown family {family!r}"
        )


def test_family_of_has_exactly_seven_distinct_families():
    """All 7 family slugs appear in FAMILY_OF values."""
    assert frozenset(FAMILY_OF.values()) == _SEVEN_FAMILIES


# ── Every CheckMeta has a valid surface ───────────────────────────────────────

def test_every_checkmeta_has_non_empty_surface():
    """No CheckMeta in CATALOG may have an empty surface."""
    empty = [c.id for c in CATALOG if not c.surface]
    assert not empty, f"CheckMeta entries with empty surface: {empty}"


def test_every_surface_is_in_valid_set():
    """Every CheckMeta.surface must be in SURFACES (the 13 slugs or 'trifecta')."""
    bad = [
        (c.id, c.surface)
        for c in CATALOG
        if c.surface not in _VALID_SURFACES
    ]
    assert not bad, f"CheckMeta entries with unknown surface: {bad}"


def test_all_catalog_ids_accessible_via_by_id():
    """BY_ID contains every catalog entry (sanity guard against catalog drift)."""
    for c in CATALOG:
        assert c.id in BY_ID


# ── Exactly one check uses trifecta ──────────────────────────────────────────

def test_exactly_one_trifecta_check():
    """Only A1 may use the 'trifecta' surface."""
    trifecta_checks = [c.id for c in CATALOG if c.surface == "trifecta"]
    assert trifecta_checks == ["A1"], (
        f"Expected only A1 with surface='trifecta', got: {trifecta_checks}"
    )


def test_a1_surface_is_trifecta():
    """A1 is the headline lethal-trifecta check — it must use the trifecta surface."""
    assert BY_ID["A1"].surface == "trifecta"


# ── Spot-checks: unambiguous assignments ──────────────────────────────────────

def test_gateway_checks_surface():
    """B2 (gateway auth/exposure), B32 (control-plane mutation), B56 (controlUI origin)
    must all map to 'gateway'."""
    for cid in ("B2", "B32", "B56"):
        assert BY_ID[cid].surface == "gateway", (
            f"{cid} expected surface='gateway', got {BY_ID[cid].surface!r}"
        )


def test_host_watch_checks_surface():
    """B50–B54 (Host Watch Posture: IDS/audit/FIM/EDR/firewall) must all map to 'host'."""
    for cid in ("B50", "B51", "B52", "B53", "B54"):
        assert BY_ID[cid].surface == "host", (
            f"{cid} expected surface='host', got {BY_ID[cid].surface!r}"
        )


def test_mcp_checks_surface():
    """B15 (MCP server trust), B24 (MCP hardening), C047 (non-local MCP) -> 'mcp'."""
    for cid in ("B15", "B24", "C047"):
        assert BY_ID[cid].surface == "mcp", (
            f"{cid} expected surface='mcp', got {BY_ID[cid].surface!r}"
        )


def test_bootstrap_content_checks_surface():
    """B58 (unicode obfuscation), B63 (silent instruction), B64 (hierarchy override),
    B65 (sleeper trigger), B66 (persona jailbreak) -> 'bootstrap'."""
    for cid in ("B58", "B63", "B64", "B65", "B66"):
        assert BY_ID[cid].surface == "bootstrap", (
            f"{cid} expected surface='bootstrap', got {BY_ID[cid].surface!r}"
        )


def test_tools_checks_surface():
    """B3 (least privilege), B8 (human approval), B48 (break-glass overrides) -> 'tools'."""
    for cid in ("B3", "B8", "B48"):
        assert BY_ID[cid].surface == "tools", (
            f"{cid} expected surface='tools', got {BY_ID[cid].surface!r}"
        )


def test_agents_checks_surface():
    """B4 (sandbox), B18 (subagents), B46 (multi-agent trifecta) -> 'agents'."""
    for cid in ("B4", "B18", "B46"):
        assert BY_ID[cid].surface == "agents", (
            f"{cid} expected surface='agents', got {BY_ID[cid].surface!r}"
        )


def test_secrets_checks_surface():
    """B1 (secrets in config), B9 (secret leak / redact), B41 (credential blast-radius),
    C015 (secrets-at-rest scan) -> 'secrets'."""
    for cid in ("B1", "B9", "B41", "C015"):
        assert BY_ID[cid].surface == "secrets", (
            f"{cid} expected surface='secrets', got {BY_ID[cid].surface!r}"
        )


def test_monitoring_checks_surface():
    """B10 (audit log), B16 (threat monitoring), B14 (egress), C014 (egress inventory)
    -> 'monitoring'."""
    for cid in ("B10", "B16", "B14", "C014"):
        assert BY_ID[cid].surface == "monitoring", (
            f"{cid} expected surface='monitoring', got {BY_ID[cid].surface!r}"
        )


def test_hooks_check_surface():
    """C048 (cron scheduler persistence) -> 'hooks'."""
    assert BY_ID["C048"].surface == "hooks"


def test_update_checks_surface():
    """B33 (known-vuln version gate), C4 (update hygiene), C6 (hook-policy-drop patch)
    -> 'update'."""
    for cid in ("B33", "C4", "C6"):
        assert BY_ID[cid].surface == "update", (
            f"{cid} expected surface='update', got {BY_ID[cid].surface!r}"
        )


def test_channels_checks_surface():
    """B26 (untrusted-context / contextVisibility), B30 (sender identity) -> 'channels'."""
    for cid in ("B26", "B30"):
        assert BY_ID[cid].surface == "channels", (
            f"{cid} expected surface='channels', got {BY_ID[cid].surface!r}"
        )


def test_sessions_checks_surface():
    """B38 (browser SSRF), B39 (session visibility) -> 'sessions'."""
    for cid in ("B38", "B39"):
        assert BY_ID[cid].surface == "sessions", (
            f"{cid} expected surface='sessions', got {BY_ID[cid].surface!r}"
        )


def test_skills_checks_surface():
    """B5 (supply chain), B13 (installed skill safety), B25 (update pinning),
    B42 (install policy), B57 (plugin auto-approve), B62 (capability-intent) -> 'skills'."""
    for cid in ("B5", "B13", "B25", "B42", "B57", "B62"):
        assert BY_ID[cid].surface == "skills", (
            f"{cid} expected surface='skills', got {BY_ID[cid].surface!r}"
        )


# ── Count sanity: every surface has at least one check ────────────────────────

def test_every_bucket_surface_has_at_least_one_check():
    """Each of the 13 non-trifecta surfaces must have at least one check assigned."""
    covered = {c.surface for c in CATALOG if c.surface != "trifecta"}
    missing = _BUCKET_SURFACES - covered
    assert not missing, f"Surfaces with no checks assigned: {missing}"


# ── FAMILY_OF look-up for bucket surfaces ─────────────────────────────────────

def test_family_of_lookup_exposure():
    """gateway, channels, sessions all roll up to 'exposure'."""
    for surface in ("gateway", "channels", "sessions"):
        assert FAMILY_OF[surface] == "exposure"


def test_family_of_lookup_privilege():
    """tools, agents roll up to 'privilege'."""
    for surface in ("tools", "agents"):
        assert FAMILY_OF[surface] == "privilege"


def test_family_of_lookup_supply_chain():
    """skills, mcp roll up to 'supply_chain'."""
    for surface in ("skills", "mcp"):
        assert FAMILY_OF[surface] == "supply_chain"


def test_family_of_lookup_content_integrity():
    assert FAMILY_OF["bootstrap"] == "content_integrity"


def test_family_of_lookup_secrets():
    assert FAMILY_OF["secrets"] == "secrets"


def test_family_of_lookup_detection():
    """monitoring, host roll up to 'detection'."""
    for surface in ("monitoring", "host"):
        assert FAMILY_OF[surface] == "detection"


def test_family_of_lookup_automation():
    """hooks, update roll up to 'automation'."""
    for surface in ("hooks", "update"):
        assert FAMILY_OF[surface] == "automation"


def test_trifecta_not_in_family_of():
    """trifecta is cross-cutting — it must NOT appear in FAMILY_OF."""
    assert "trifecta" not in FAMILY_OF
