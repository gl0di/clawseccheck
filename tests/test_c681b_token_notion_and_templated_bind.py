"""C-681 (defects 3 and 4) - one notion of "a gateway credential is configured", and a
templated ``gateway.bind`` that the drift monitor and RISK-20 no longer misread.

Defect 3. B41 (``check_credential_blast_radius``) and the credential surface map
(``report._credential_surface_map``) counted ANY truthy value at ``gateway.auth.token`` /
``gateway.token`` as a gateway token, so they disagreed with B2/B80 about a malformed
SecretRef object, a list, a number, a bool, a whitespace string and an object at the legacy
key. All three now ask the same question (``_gateway_token_configured``, which is
``_gateway_config_token``'s own answer with no ``auth.mode`` in play).

Defect 4. ``monitordims._gateway._gateway_bind`` recorded ``parse_bind_host`` of a template
(the lowercased fragment ``${gw_bind``) - garbled text. It now records a templated bind as
written. The first run after the change must not alert on a mere re-spelling of the same
template (an older baseline holds the fragment). RISK-20 used to chain on an UNRESOLVED
template as "remote exposure"; it now resolves the bind the way the C-653 (b) checks do and,
where the audit cannot know it, produces no chain (risk.py: UNKNOWN inputs yield no chain).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import check_credential_blast_radius, parse_bind_host
from clawseccheck.checks._config import _gateway_config_token
from clawseccheck.collector import Context
from clawseccheck.monitor import diff
from clawseccheck.monitordims import _gateway_bind
from clawseccheck.report import _credential_surface_map
from clawseccheck.risk import _rule_hooks_session_key_takeover, risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_LONG = "x" * 30
_SHAPES = {
    # name: (value, is a credential configured at gateway.auth.token)
    "long-string": (_LONG, True),
    "short-string": ("short", True),
    "reference-long-name": ("${OPENCLAW_GATEWAY_TOKEN}", True),
    "reference-short-name": ("${GW_TOKEN}", True),
    "secretref-env": ({"source": "env", "provider": "default", "id": "GW_TOKEN"}, True),
    "secretref-store": ({"source": "store", "provider": "default", "id": "GW_TOKEN"}, True),
    "secretref-exec": ({"source": "exec", "provider": "vault", "id": "gateway/token"}, True),
    "object-missing-id": ({"source": "env", "provider": "default"}, False),
    "object-missing-source": ({"provider": "default", "id": "GW_TOKEN"}, False),
    "object-unknown-source": ({"source": "carrier-pigeon", "provider": "p", "id": "X"}, False),
    "empty-object": ({}, False),
    "list": ([_LONG], False),
    "number": (12345, False),
    "bool-true": (True, False),
    "bool-false": (False, False),
    "empty-string": ("", False),
    "whitespace-string": ("   ", False),
    "null": (None, False),
}
_KEYS = ["auth", "legacy", "both"]


def _cfg(value, key) -> dict:
    gw: dict = {}
    if key in ("auth", "both"):
        gw["auth"] = {"token": value}
    if key in ("legacy", "both"):
        gw["token"] = value
    return {"gateway": gw}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    return c


def _b41_sees_a_credential(cfg: dict) -> bool:
    # No profiles in these configs, so B41 is UNKNOWN exactly when it sees no credential.
    return check_credential_blast_radius(_ctx(cfg)).status != UNKNOWN


def _map_sees_a_gateway_token(cfg: dict) -> bool:
    cloud = next(e for e in _credential_surface_map(_ctx(cfg)) if e["class"] == "cloud")
    return "gateway token present" in cloud["evidence"]


def _expected(value, ok, key) -> bool:
    """What B2 reads: the first key (auth) wins if truthy whatever its type; the legacy key
    counts only as a string. Written out here, independently of the code under test."""
    if key == "legacy":
        return ok and isinstance(value, str)
    return ok


@pytest.mark.parametrize("key", _KEYS)
@pytest.mark.parametrize("name", sorted(_SHAPES))
def test_b2_b41_and_the_surface_map_agree_on_a_configured_credential(name, key):
    value, ok = _SHAPES[name]
    cfg = _cfg(value, key)
    want = _expected(value, ok, key)
    b2 = _gateway_config_token(cfg, None, _ctx(cfg))[0] is not None
    assert b2 is want, "B2's own notion"
    assert _b41_sees_a_credential(cfg) is want, "B41"
    assert _map_sees_a_gateway_token(cfg) is want, "surface map"


@pytest.mark.parametrize("key", _KEYS)
@pytest.mark.parametrize("name", sorted(_SHAPES))
def test_the_shared_helper_is_b2s_notion(name, key):
    from clawseccheck.checks._config import _gateway_token_configured  # noqa: PLC0415

    value, ok = _SHAPES[name]
    cfg = _cfg(value, key)
    assert _gateway_token_configured(cfg, _ctx(cfg)) is _expected(value, ok, key)


def test_malformed_first_key_is_not_skipped_for_a_good_legacy_string():
    # B2 reads gateway.auth.token first and does not fall through a malformed object.
    cfg = {"gateway": {"auth": {"token": {"source": "env"}}, "token": _LONG}}
    assert _gateway_config_token(cfg, None, _ctx(cfg))[0] is None
    assert _b41_sees_a_credential(cfg) is False
    assert _map_sees_a_gateway_token(cfg) is False


def test_a_configured_gateway_token_still_reads_the_same_in_b41_evidence():
    cfg = {"gateway": {"auth": {"token": _LONG}}}
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status != UNKNOWN
    assert any("gateway-token: present" in str(e) for e in (f.evidence or []))


# --------------------------------------------------------------------------- monitor


@pytest.mark.parametrize(
    "bind",
    ["${GW_BIND}", "${GW_BIND:-lan}", "${GW_BIND:-0.0.0.0:8080}", "${GW_BIND:-}"],
)
def test_a_whole_value_templated_bind_is_recorded_as_written(bind):
    assert _gateway_bind(_ctx({"gateway": {"bind": bind}})) == bind


@pytest.mark.parametrize(
    "bind", ["0.0.0.0:${GW_PORT}", "lan${X}", "127.0.0.1:${P}", "$GW_BIND", "${A}${B}", "${A}:8080"]
)
def test_any_other_templated_bind_is_recorded_exactly_as_before(bind):
    # Only a whole-value ${VAR} / ${VAR:-default} takes the new path; everything else keeps
    # the earlier record (parse_bind_host), so its visible host part stays what is compared.
    assert _gateway_bind(_ctx({"gateway": {"bind": bind}})) == parse_bind_host(bind)


def test_a_template_is_recorded_whole_with_its_original_case_and_trimmed():
    assert _gateway_bind(_ctx({"gateway": {"bind": "  ${GW_BIND:-LAN}  "}})) == "${GW_BIND:-LAN}"


@pytest.mark.parametrize(
    "bind,want",
    [("lan", "lan"), ("LAN", "lan"), ("127.0.0.1:8080", "127.0.0.1"),
     ("0.0.0.0:8080", "0.0.0.0"), ("[::1]:8765", "::1"), ("", "")],
)
def test_a_literal_bind_is_recorded_exactly_as_before(bind, want):
    cfg = {"gateway": {"bind": bind}} if bind else {}
    assert _gateway_bind(_ctx(cfg)) == want


_BASE = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
         "mcp": {}, "channels": {}}


def _snap(bind):
    return {**_BASE, "gateway_bind": bind}


def _bind_alerts(prev, curr):
    return [m for _, m in diff(prev, curr) if "Gateway bind changed" in m]


@pytest.mark.parametrize(
    "template", ["${GW_BIND}", "${GW_BIND:-lan}", "${GW_BIND:-0.0.0.0:8080}"]
)
def test_an_old_format_baseline_does_not_alert_on_a_mere_respelling(template):
    # What the previous build stored for this template: the lowercased first-colon fragment.
    old = parse_bind_host(template)
    assert old != template  # it really is a different spelling
    assert _bind_alerts(_snap(old), _snap(template)) == []
    # ... and the new format is stable against itself.
    assert _bind_alerts(_snap(template), _snap(template)) == []


def test_a_real_template_change_still_alerts_after_the_migration():
    assert _bind_alerts(_snap("${GW_BIND}"), _snap("${OTHER_BIND}"))
    assert _bind_alerts(_snap(parse_bind_host("${GW_BIND}")), _snap("${OTHER_BIND}"))


def test_template_to_a_literal_or_back_still_alerts():
    old = parse_bind_host("${GW_BIND:-lan}")
    assert _bind_alerts(_snap(old), _snap("0.0.0.0"))  # curr is not a template: no migration
    assert _bind_alerts(_snap("127.0.0.1"), _snap("${GW_BIND:-lan}"))
    assert _bind_alerts(_snap("${GW_BIND:-lan}"), _snap("127.0.0.1"))


def test_a_changed_default_is_swallowed_only_on_the_one_migration_run():
    # The old record keeps nothing of the ``:-default`` (documented on the arm), so against an
    # old baseline a changed default cannot be told from an unchanged one; once the baseline
    # holds the new format the same change alerts.
    old = parse_bind_host("${GW_BIND:-loopback}")
    assert old == parse_bind_host("${GW_BIND:-lan}")
    assert _bind_alerts(_snap(old), _snap("${GW_BIND:-lan}")) == []
    assert _bind_alerts(_snap("${GW_BIND:-loopback}"), _snap("${GW_BIND:-lan}"))


@pytest.mark.parametrize("bind", ["0.0.0.0:${GW_PORT}", "lan${X}"])
def test_a_real_move_to_an_embedded_template_bind_keeps_the_alert_dev_raised(bind):
    # Recorded exactly as before, so the alert level is what the earlier build gave: the
    # visible host part decides "now exposed" (CRITICAL); a host that is not an exposed
    # literal stays an ordinary HIGH change.
    curr = _gateway_bind(_ctx({"gateway": {"bind": bind}}))
    alerts = diff(_snap("127.0.0.1"), _snap(curr))
    assert [m for _, m in alerts if "Gateway bind changed" in m]
    levels = [lvl for lvl, m in alerts if "Gateway bind changed" in m]
    if bind.startswith("0.0.0.0"):
        assert curr == "0.0.0.0" and levels == ["CRITICAL"]
        assert any("now exposed" in m for _, m in alerts)
    else:
        assert curr == parse_bind_host(bind) and levels == ["HIGH"]


def test_the_migration_does_not_swallow_a_different_old_value():
    assert _bind_alerts(_snap("${other"), _snap("${GW_BIND:-lan}"))
    assert _bind_alerts(_snap("127.0.0.1"), _snap("${GW_BIND}"))


# --------------------------------------------------------------------------- RISK-20


def _hooks_home(tmp_path: Path, bind, tailscale=None) -> Path:
    home = tmp_path / "home"
    shutil.copytree(FIXTURES / "bad_b288_hooks_session_key_open", home)
    p = home / "openclaw.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg["gateway"]["bind"] = bind
    if tailscale:
        cfg["gateway"]["tailscale"] = {"mode": tailscale}
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    return home


def _risk20(home):
    ctx, findings, _ = audit(str(home), include_native=False, include_host=False)
    return next((p for p in risk_paths(ctx, findings) if p.id == "RISK-20"), None)


@pytest.mark.parametrize("bind", ["lan", "0.0.0.0:8080", "192.168.1.5"])
def test_risk20_literal_remote_binds_still_chain(tmp_path, bind):
    p = _risk20(_hooks_home(tmp_path, bind))
    assert p is not None
    assert "gateway.bind=" in p.chain[0]


@pytest.mark.parametrize("bind", ["loopback", "127.0.0.1:8080", "auto"])
def test_risk20_literal_local_binds_still_do_not_chain(tmp_path, bind):
    assert _risk20(_hooks_home(tmp_path, bind)) is None


@pytest.mark.parametrize(
    "bind", ["${GW_BIND}", "$GW_BIND", "${GW_BIND:-}", "${GW_BIND:-loopback}"]
)
def test_risk20_an_unresolved_template_bind_asserts_no_exposure(tmp_path, bind):
    # Nothing in the audited home says what GW_BIND is: "reachable beyond loopback" is not
    # proven, so the chain (which fires only on positive evidence for every link) is absent.
    assert _risk20(_hooks_home(tmp_path, bind)) is None


@pytest.mark.parametrize("bind", ["0.0.0.0:${GW_PORT}", "lan${X}", "192.168.1.5:${P}"])
def test_risk20_a_template_embedded_in_a_remote_literal_host_still_chains(tmp_path, bind):
    # The host part is visible and not loopback: the variable does not make it unknown, and
    # the chain keeps its earlier label (the template text as written).
    p = _risk20(_hooks_home(tmp_path, bind))
    assert p is not None
    assert p.chain[0] == f"gateway reachable beyond loopback (gateway.bind={bind})"


@pytest.mark.parametrize("bind", ["${A}${B}", "${A}:8080", "${A:-lan}:80"])
def test_risk20_a_template_whose_host_part_is_itself_a_variable_yields_no_chain(tmp_path, bind):
    assert _risk20(_hooks_home(tmp_path, bind)) is None


def test_risk20_a_template_with_a_remote_default_resolves_like_the_literal(tmp_path):
    tpl = _risk20(_hooks_home(tmp_path / "a", "${GW_BIND:-lan}"))
    lit = _risk20(_hooks_home(tmp_path / "b", "lan"))
    assert tpl is not None and lit is not None
    assert tpl.chain == lit.chain and tpl.why == lit.why


def test_risk20_an_unresolved_template_still_chains_on_a_tailscale_publication(tmp_path):
    p = _risk20(_hooks_home(tmp_path, "${GW_BIND}", tailscale="funnel"))
    assert p is not None
    assert "gateway.tailscale.mode=funnel" in p.chain[0]
    assert "${GW_BIND}" not in p.chain[0]


def test_risk20_a_template_resolved_by_the_gateways_environment_chains_like_the_literal():
    cfg = json.loads(
        (FIXTURES / "bad_b288_hooks_session_key_open" / "openclaw.json").read_text("utf-8")
    )
    cfg["gateway"]["bind"] = "${GW_BIND}"
    ctx = _ctx(cfg)
    ctx.unit_env_values = {"GW_BIND": "lan"}
    got = _rule_hooks_session_key_takeover(ctx, cfg)
    assert got is not None and got.chain[0] == "gateway reachable beyond loopback (gateway.bind=lan)"
    # a visible LOOPBACK value never clears anything, but it does not assert exposure either
    ctx.unit_env_values = {"GW_BIND": "loopback"}
    assert _rule_hooks_session_key_takeover(ctx, cfg) is None
