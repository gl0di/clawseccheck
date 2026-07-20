"""B-288: the root-`hooks` session-key / agent-routing family, and RISK-20.

Before this change the package read `hooks.enabled` and stopped: `allowRequestSessionKey`,
`allowedSessionKeyPrefixes`, `allowedAgentIds` and `defaultSessionKey` had ZERO references
anywhere in `clawseccheck/`, and `risk.py` had zero `hooks` references — so a setup that
had opened hook ingress to arbitrary session keys was indistinguishable from one that had
scoped it. RISK-20 was a deliberate numbering hole between RISK-19 and RISK-21.

The interesting part is not that the chain fires; it is that BOTH of its discriminators
are load-bearing. `fixtures/clean_b288_hooks_scoped` has the gateway genuinely exposed and
stays silent because the policy is scoped; `fixtures/clean_b288_hooks_loopback` has the
policy wide open and stays silent because nothing remote can reach it. Each is pinned by
an ablation that flips ONLY its own discriminator and shows the chain then fires, so
neither can pass for an incidental reason.

Offline, read-only; writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import HIGH, UNKNOWN
from clawseccheck.checks import (
    LOOPBACK,
    _canonical_ipv4,
    _gateway_remote_exposure_reason,
    _hooks_agent_ids_unrestricted,
    _hooks_allowed_session_key_prefixes,
    _hooks_session_key_exposures,
    _loopback_ip,
)
from clawseccheck.risk import _rule_hooks_session_key_takeover, risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------- helpers

def _audit(home):
    return audit(str(home), include_native=False, include_host=False)


def _risk20(home):
    ctx, findings, _ = _audit(home)
    return next((p for p in risk_paths(ctx, findings) if p.id == "RISK-20"), None)


def _b179(home):
    _ctx, findings, _sc = _audit(home)
    return next(f for f in findings if f.id == "B179")


def _home(tmp_path: Path, cfg: dict) -> Path:
    """Write a minimal home with *cfg* as openclaw.json (0600, like real fixtures)."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    return home


def _mutate(tmp_path: Path, fixture: str, mutate) -> Path:
    """Copy a fixture home into tmp_path and apply *mutate* to its parsed config."""
    home = tmp_path / fixture
    shutil.copytree(FIXTURES / fixture, home)
    p = home / "openclaw.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    mutate(cfg)
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    return home


# ------------------------------------------------------- the four shipped fixtures

def test_clean_scoped_policy_does_not_fire():
    """Gateway genuinely exposed (bind=lan), but every hook policy field is scoped."""
    assert _risk20(FIXTURES / "clean_b288_hooks_scoped") is None


def test_clean_loopback_does_not_fire():
    """Hook policy wide open, but nothing remote can reach the gateway."""
    assert _risk20(FIXTURES / "clean_b288_hooks_loopback") is None


def test_bad_session_key_arm_fires():
    p = _risk20(FIXTURES / "bad_b288_hooks_session_key_open")
    assert p is not None
    assert p.severity == HIGH
    assert p.id == "RISK-20"
    joined = " | ".join(p.chain)
    assert "gateway.bind=lan" in joined
    assert "arbitrary session keys" in joined
    # This fixture pins allowedAgentIds to an explicit list, so ONLY the session-key
    # arm may appear — otherwise the two arms are not independently demonstrated.
    assert "any configured agent" not in joined


def test_bad_agent_ids_arm_fires_via_tailscale():
    """The agent-routing arm alone, reached through the OTHER exposure path.

    bind is `loopback` here — the exposure comes from tailscale funnel, which the dist
    treats as remote regardless of bind (audit.nondeep.runtime-C3y1Q5Fi.js:281-282).
    """
    p = _risk20(FIXTURES / "bad_b288_hooks_agent_ids_wildcard")
    assert p is not None
    assert p.severity == HIGH
    joined = " | ".join(p.chain)
    assert "tailscale.mode=funnel" in joined
    assert "any configured agent" in joined
    # allowRequestSessionKey is absent in this fixture, so the session-key arm must not
    # appear — the wildcard in allowedAgentIds is doing all the work.
    assert "arbitrary session keys" not in joined


# ------------------------------------------------------- ablations: both legs matter

def test_ablation_scoped_fires_once_prefixes_are_dropped(tmp_path):
    """Flip ONLY the policy on the exposed-but-scoped clean: the chain appears."""
    before = _risk20(FIXTURES / "clean_b288_hooks_scoped")
    assert before is None

    def drop(cfg):
        cfg["hooks"]["allowedSessionKeyPrefixes"] = []

    assert _risk20(_mutate(tmp_path, "clean_b288_hooks_scoped", drop)) is not None


def test_ablation_scoped_fires_once_agent_ids_wildcarded(tmp_path):
    def wildcard(cfg):
        cfg["hooks"]["allowedAgentIds"] = ["*"]

    assert _risk20(_mutate(tmp_path, "clean_b288_hooks_scoped", wildcard)) is not None


def test_ablation_loopback_fires_once_gateway_is_exposed(tmp_path):
    """Flip ONLY the bind on the wide-open-but-local clean: the chain appears."""
    before = _risk20(FIXTURES / "clean_b288_hooks_loopback")
    assert before is None

    def expose(cfg):
        cfg["gateway"]["bind"] = "lan"

    assert _risk20(_mutate(tmp_path, "clean_b288_hooks_loopback", expose)) is not None


def test_ablation_bad_goes_quiet_when_hooks_disabled(tmp_path):
    """hooks.enabled is the gate the product itself applies before any of this."""
    def disable(cfg):
        cfg["hooks"]["enabled"] = False

    assert _risk20(_mutate(tmp_path, "bad_b288_hooks_session_key_open", disable)) is None


def test_ablation_bad_goes_quiet_when_hooks_key_removed(tmp_path):
    """The live-fleet shape: no `hooks` key at all."""
    def strip(cfg):
        cfg.pop("hooks", None)

    assert _risk20(_mutate(tmp_path, "bad_b288_hooks_session_key_open", strip)) is None


# ------------------------------------------------- B179 status is structurally safe

def test_b179_status_never_changes_on_clean_fixtures():
    """The B-288 evidence lines cannot introduce a new WARN.

    They are gated on `hooks.enabled is True`, and that same condition has already
    appended the "hooks.enabled" line — so every config they can reach was WARN before.
    """
    for name in ("clean_b288_hooks_scoped", "clean_b288_hooks_loopback"):
        assert _b179(FIXTURES / name).status == "WARN"


def test_b179_status_never_changes_no_hooks_key(tmp_path):
    """No hooks key -> PASS, exactly as before B-288."""
    f = _b179(_home(tmp_path, {"gateway": {"bind": "lan"}}))
    assert f.status == "PASS"


def test_b179_passes_when_hooks_disabled_even_with_open_policy(tmp_path):
    """A dormant hooks block carrying a wide-open policy must stay PASS.

    This is the false-positive case the `hooks.enabled !== true` gate exists for: the
    fields are present and unconstrained, but nothing is serving.
    """
    f = _b179(_home(tmp_path, {
        "hooks": {"enabled": False, "allowRequestSessionKey": True, "allowedAgentIds": ["*"]},
        "gateway": {"bind": "lan"},
    }))
    assert f.status == "PASS"


def test_b179_evidence_names_the_new_family(tmp_path):
    f = _b179(_home(tmp_path, {
        "hooks": {"enabled": True, "allowRequestSessionKey": True},
        "gateway": {"bind": "loopback"},
    }))
    assert f.status == "WARN"
    blob = " | ".join(f.evidence)
    for field in ("hooks.defaultSessionKey", "hooks.allowedAgentIds",
                  "hooks.allowRequestSessionKey", "hooks.allowedSessionKeyPrefixes"):
        assert field in blob, f"{field} missing from B179 evidence"


# ------------------------------------------------------------------ the UNKNOWN path

def test_unreadable_config_is_unknown_and_never_an_all_clear(tmp_path):
    """A config we cannot parse must yield UNKNOWN for B179 and NO chain.

    Silence from RISK-20 here means "not determined", never "hook ingress is fine".
    """
    home = tmp_path / "broken"
    home.mkdir()
    p = home / "openclaw.json"
    p.write_text("{ this is not valid json", encoding="utf-8")
    p.chmod(0o600)
    assert _b179(home).status == UNKNOWN
    assert _risk20(home) is None


# ------------------------------------------------------------------- helper contracts

def test_agent_ids_unrestricted_matches_dist_resolver():
    """Transcribes resolveAllowedAgentIds (hooks-policy-Tc4l1nSI.js:4-18).

    Its contract is "returns undefined when all agents are allowed": a non-array is
    unrestricted, any list containing a literal '*' is unrestricted, and an explicit
    list is restricted — INCLUDING the empty list, which denies hook agent routing
    outright rather than allowing everything.
    """
    assert _hooks_agent_ids_unrestricted({}) is True
    assert _hooks_agent_ids_unrestricted({"hooks": {}}) is True
    assert _hooks_agent_ids_unrestricted({"hooks": {"allowedAgentIds": "main"}}) is True
    assert _hooks_agent_ids_unrestricted({"hooks": {"allowedAgentIds": ["a", "*"]}}) is True
    assert _hooks_agent_ids_unrestricted({"hooks": {"allowedAgentIds": [" * "]}}) is True
    assert _hooks_agent_ids_unrestricted({"hooks": {"allowedAgentIds": []}}) is False
    assert _hooks_agent_ids_unrestricted({"hooks": {"allowedAgentIds": ["main"]}}) is False


def test_allowed_prefixes_ignores_blank_entries():
    """A list of blanks is not a restriction — the dist trims and filters them away."""
    assert _hooks_allowed_session_key_prefixes({}) == []
    assert _hooks_allowed_session_key_prefixes(
        {"hooks": {"allowedSessionKeyPrefixes": ["  ", ""]}}) == []
    assert _hooks_allowed_session_key_prefixes(
        {"hooks": {"allowedSessionKeyPrefixes": [" hook: "]}}) == ["hook:"]
    # Non-list is an empty policy, not a crash.
    assert _hooks_allowed_session_key_prefixes(
        {"hooks": {"allowedSessionKeyPrefixes": "hook:"}}) == []


def test_exposures_are_gated_on_hooks_enabled():
    wide_open = {"allowRequestSessionKey": True, "allowedAgentIds": ["*"]}
    assert _hooks_session_key_exposures({"hooks": dict(wide_open)}) == []
    assert _hooks_session_key_exposures({"hooks": dict(wide_open, enabled=False)}) == []
    # Truthy-but-not-True must not open the gate either (the dist compares `=== true`).
    assert _hooks_session_key_exposures({"hooks": dict(wide_open, enabled=1)}) == []
    kinds = {k for k, _ in _hooks_session_key_exposures({"hooks": dict(wide_open, enabled=True)})}
    assert kinds == {
        "default_session_key_unset",
        "allowed_agent_ids_unrestricted",
        "request_session_key_enabled",
        "request_session_key_prefixes_missing",
    }


def test_gateway_exposure_covers_both_bind_shapes():
    """`gateway.bind` is the profile enum now, but host:port configs are still in the wild.

    One predicate must read both (CLAUDE.md §2.6). The host:port half must not mistake a
    loopback address for a remote profile name.
    """
    # Absent -> the dist's default is the "loopback" profile.
    assert _gateway_remote_exposure_reason({}) is None
    assert _gateway_remote_exposure_reason({"gateway": {"bind": "loopback"}}) is None
    # `lan` is `return "0.0.0.0"` unconditionally (net-BOKtNTf8.js:147); `tailnet` binds
    # the tailnet IPv4 whenever Tailscale is up (:141-146). Both are remote.
    # `auto` and `custom` are NOT — see test_bind_profile_resolves_via_the_vendor_resolver.
    for profile in ("lan", "tailnet"):
        assert _gateway_remote_exposure_reason({"gateway": {"bind": profile}}) is not None
    # Legacy host:port form. This is the DOMINANT shape in the wild (259 of ~300 `bind`
    # values in fixtures/), so the whole loopback range is pinned here, not just the one
    # canonical address — see test_legacy_host_port_accepts_the_whole_loopback_range.
    assert _gateway_remote_exposure_reason({"gateway": {"bind": "127.0.0.1:8080"}}) is None
    assert _gateway_remote_exposure_reason({"gateway": {"bind": "127.0.1.1:8080"}}) is None
    assert _gateway_remote_exposure_reason({"gateway": {"bind": "[::1]:8765"}}) is None
    assert _gateway_remote_exposure_reason({"gateway": {"bind": "0.0.0.0:8080"}}) is not None
    # Tailscale is remote regardless of bind; "off" is not.
    assert _gateway_remote_exposure_reason(
        {"gateway": {"bind": "loopback", "tailscale": {"mode": "off"}}}) is None
    for mode in ("serve", "funnel"):
        assert _gateway_remote_exposure_reason(
            {"gateway": {"bind": "loopback", "tailscale": {"mode": mode}}}) is not None


#  ----------------------------- C-135: the loopback range, both directions at once

# Addresses that are genuinely loopback and MUST stay silent. Not a hypothetical list:
# Debian/Ubuntu map the machine's own hostname to 127.0.1.1 in /etc/hosts, and
# systemd-resolved listens on 127.0.0.53 — a user binding the gateway to either is
# binding locally.
_LOOPBACK_BINDS = [
    "127.0.0.1:8080",           # the canonical address
    "127.0.1.1:8080",           # Debian/Ubuntu /etc/hosts hostname mapping
    "127.0.0.53:8080",          # systemd-resolved stub listener
    "127.0.0.2:8080",           # multi-instance loopback alias
    "127.255.255.254:8080",     # top of 127.0.0.0/8
    "[::1]:8765",               # IPv6 loopback
    "[::ffff:127.0.0.1]:8080",  # IPv4-mapped IPv6, bracketed
    "::ffff:127.0.0.1",         # IPv4-mapped IPv6, bare
]

# The other direction. 126.255.255.255 and 128.0.0.1 bracket 127.0.0.0/8 on both sides:
# they are the control proving the range was widened to exactly /8 and not further.
_REMOTE_BINDS = [
    "0.0.0.0:8080",
    "192.168.1.10:8080",
    "10.0.0.5:8080",
    "126.255.255.255:8080",     # one below the range
    "128.0.0.1:8080",           # one above the range
    "[::]:8080",
    "1.2.3.4:8080",
]


def test_legacy_host_port_accepts_the_whole_loopback_range():
    """Regression, BOTH directions: 127.0.0.0/8 is local, and nothing wider is.

    The exact-match `LOOPBACK` set rated every 127/8 address except 127.0.0.1 as remote,
    so RISK-20 fired on a Debian box whose gateway was bound to its own hostname. The
    vendor disagrees: `isLoopbackIpAddress` (ip-BvvIlSgO.js:1104-1108) folds IPv4-mapped
    IPv6 down (`normalizeIpv4MappedAddress`, :1048-1052) and asks for the loopback RANGE.

    Widening is only half a fix — the neighbours of the range are asserted remote in the
    same test so a future "just make it not fire" cannot pass by loosening further.
    """
    for bind in _LOOPBACK_BINDS:
        assert _gateway_remote_exposure_reason({"gateway": {"bind": bind}}) is None, bind
    for bind in _REMOTE_BINDS:
        assert _gateway_remote_exposure_reason({"gateway": {"bind": bind}}) is not None, bind


def test_loopback_range_is_consistent_across_bind_shapes():
    """The same address gets the same verdict whichever shape carries it.

    `custom`+`customBindHost` and the legacy host:port form are read by different
    branches; they must not disagree. (`customBindHost` is gated to canonical dotted
    IPv4 by the vendor at io-By0s-a_s.js:3876, so only the IPv4 cases apply there.)
    """
    for host in ("127.0.0.1", "127.0.1.1", "127.0.0.53", "127.255.255.254"):
        assert _gateway_remote_exposure_reason(
            {"gateway": {"bind": "custom", "customBindHost": host}}) is None, host
        assert _gateway_remote_exposure_reason(
            {"gateway": {"bind": f"{host}:8080"}}) is None, host
    for host in ("192.168.1.10", "128.0.0.1", "126.255.255.255"):
        assert _gateway_remote_exposure_reason(
            {"gateway": {"bind": "custom", "customBindHost": host}}) is not None, host
        assert _gateway_remote_exposure_reason(
            {"gateway": {"bind": f"{host}:8080"}}) is not None, host


def test_risk20_silent_on_loopback_range_but_fires_beyond_it():
    """End-to-end at the rule, isolating the bind as the single variable."""
    def cfg(bind):
        return {"gateway": {"bind": bind, "auth": {"mode": "token"}},
                "hooks": {"enabled": True, "token": "t" * 24,
                          "allowRequestSessionKey": True}}

    for bind in _LOOPBACK_BINDS:
        assert _rule_hooks_session_key_takeover(None, cfg(bind)) is None, bind
    for bind in _REMOTE_BINDS:
        path = _rule_hooks_session_key_takeover(None, cfg(bind))
        assert path is not None and path.id == "RISK-20", bind


def test_ipv4_mapped_loopback_verdict_is_python_version_stable():
    """Guards the 3.9-vs-3.12 stdlib divergence this predicate is built on.

    `ipaddress.ip_address("::ffff:127.0.0.1").is_loopback` is True on 3.9 (the property
    delegates to `.ipv4_mapped`) and False on 3.12 (it is `self._ip == 1`). Reading the
    bare property would give the same config two different verdicts depending on the
    interpreter. `_loopback_ip` folds through `.ipv4_mapped` first, which behaves
    identically on both, so this assertion holds on every supported version — and fails
    loudly if anyone "simplifies" it back to the bare property.
    """
    import ipaddress

    assert _loopback_ip("::ffff:127.0.0.1") is True
    assert _loopback_ip("::ffff:127.0.1.1") is True
    # The unmapping must be explicit, not inherited from the property.
    assert ipaddress.ip_address("::ffff:127.0.0.1").ipv4_mapped == ipaddress.ip_address(
        "127.0.0.1")
    # Non-canonical and non-literal forms stay False (vendor parses canonical only).
    for junk in ("127.1", "127.0.0.01", "localhost", "", "loopback", None, 127):
        assert _loopback_ip(junk) is False, junk
    # Wildcards are never loopback — they mean "every interface".
    for wild in ("0.0.0.0", "::"):
        assert _loopback_ip(wild) is False, wild


def test_loopback_set_keeps_literal_members_and_rejects_wildcards():
    """`LOOPBACK` membership stays a superset of the old literals, never of the wildcards."""
    for literal in ("127.0.0.1", "localhost", "::1", "", "loopback", "local"):
        assert literal in LOOPBACK, literal
    for exposed in ("0.0.0.0", "::", "all", "public", "*"):
        assert exposed not in LOOPBACK, exposed
    # The whole range, via the same membership test every check already uses.
    for local in ("127.0.1.1", "127.0.0.53", "127.255.255.254", "::ffff:127.0.0.1"):
        assert local in LOOPBACK, local
    for remote in ("128.0.0.1", "126.255.255.255", "192.168.1.10", "evil.example"):
        assert remote not in LOOPBACK, remote


# ------------------------------------- C-135: bind profiles are resolved, not name-matched

def _wide_open_hooks(bind: dict) -> dict:
    """A config whose ONLY variable is the gateway bind block."""
    return {
        "gateway": dict(bind),
        "hooks": {
            "enabled": True,
            "defaultSessionKey": "hook:ingress",
            "allowRequestSessionKey": True,
        },
    }


def _fires(bind: dict) -> bool:
    """Does RISK-20 chain on a config whose only variable is the bind block?

    Calls the rule directly rather than through `risk_paths`, because this exercises
    the discriminator in isolation — the fixture-driven tests above already cover the
    dispatch path. `ctx` is unused by this rule (it reads config only); if that ever
    stops being true this raises rather than silently passing.
    """
    return _rule_hooks_session_key_takeover(None, _wide_open_hooks(bind)) is not None


def test_bind_profile_resolves_via_the_vendor_resolver():
    """C-135 regression, BOTH directions. The profile NAME is not the verdict.

    The original helper mirrored the vendor's AUDIT helper `isGatewayRemotelyExposed`
    (`bind !== "loopback"` -> remote, audit.nondeep.runtime-C3y1Q5Fi.js:279-283) and was
    verified faithful to it — but faithful-to-the-audit is not correct. The vendor's
    RESOLVER `resolveGatewayBindHost` (net-BOKtNTf8.js:135-160) is what decides the
    socket, and it disagrees on two profiles.

    FALSE-POSITIVE HALF (must stay silent):
      * `auto` -> "0.0.0.0 inside containers; loopback otherwise" (net:154-158). On a
        bare-metal or VM host it is a LOOPBACK bind, and `defaultGatewayBindMode`
        (:174-178) confirms loopback is the bare-metal default.
      * `custom` + a 127.0.0.0/8 `customBindHost` -> that address is what gets bound
        (net:148-153); the vendor itself accepts this as "resolves to loopback"
        (io-By0s-a_s.js:3876).

    TRUE-POSITIVE HALF (must still fire): a `custom` bind pointed at a real LAN or
    wildcard address is genuinely remote, and killing the FP must not kill this.
    """
    # --- FP half: these were HIGH RISK-20 before the fix; they must be silent now.
    assert not _fires({"bind": "auto"})
    assert not _fires({"bind": "custom", "customBindHost": "127.0.0.1"})
    # Loopback is the whole /8 in the dist (`range() === "loopback"`, ip-BvvIlSgO.js:1104).
    assert not _fires({"bind": "custom", "customBindHost": "127.0.0.53"})
    # Unresolvable `custom`: absent or non-canonical-IPv4 customBindHost makes the
    # gateway refuse to start (server-runtime-config-r5ejxORO.js:40-42), so there is
    # nothing serving to escalate and no proof of remoteness either way.
    assert not _fires({"bind": "custom"})
    assert not _fires({"bind": "custom", "customBindHost": "   "})
    assert not _fires({"bind": "custom", "customBindHost": "not-an-ip"})

    # --- TP half: killing the FP must not kill the detection.
    assert _fires({"bind": "custom", "customBindHost": "192.168.1.100"})
    assert _fires({"bind": "custom", "customBindHost": "0.0.0.0"})
    assert _fires({"bind": "lan"})
    assert _fires({"bind": "tailnet"})
    assert _fires({"bind": "0.0.0.0:8080"})
    # The label must name the resolved host, not just the profile, so the report says
    # WHY it is remote rather than asserting it.
    reason = _gateway_remote_exposure_reason(
        {"gateway": {"bind": "custom", "customBindHost": "192.168.1.100"}})
    assert reason == "gateway.customBindHost=192.168.1.100"

    # --- Tailscale serve/funnel is remote regardless of how the bind resolved. The
    # product REQUIRES a loopback bind in that mode (io-By0s-a_s.js:3870-3880), so this
    # leg must survive an `auto`/unproven bind rather than being short-circuited by it.
    assert _fires({"bind": "auto", "tailscale": {"mode": "funnel"}})
    assert _fires({"bind": "custom", "customBindHost": "127.0.0.1",
                   "tailscale": {"mode": "serve"}})


def test_canonical_ipv4_matches_the_dist_predicate():
    """`_canonical_ipv4` mirrors `isCanonicalDottedDecimalIPv4` (ip-BvvIlSgO.js:1083).

    Hand-rolled rather than delegated to `ipaddress` because that module's tolerance for
    leading-zero octets changed inside the 3.9 series, and this must mean the same thing
    on every supported interpreter (CLAUDE.md §6.1).
    """
    assert _canonical_ipv4("192.168.1.100") == "192.168.1.100"
    assert _canonical_ipv4("  10.0.0.1  ") == "10.0.0.1"
    assert _canonical_ipv4("0.0.0.0") == "0.0.0.0"
    assert _canonical_ipv4("255.255.255.255") == "255.255.255.255"
    # Rejected: leading zeros, out-of-range octets, wrong shape, non-ASCII digits, IPv6.
    for bad in ("010.0.0.1", "256.1.1.1", "1.2.3", "1.2.3.4.5", "1.2.3.", "::1",
                "localhost", "", "   ", None, "1.2.3.٤", "1.2.3.4:80"):
        assert _canonical_ipv4(bad) is None, bad


# ------------------------------------------------------- the one known narrow residual

def test_known_residual_enabled_without_token(tmp_path):
    """C-135 residual, pinned deliberately: hooks.enabled + NO hooks.token still fires.

    hooks-Bjrm8pWp.js:332-334 throws "hooks.enabled requires hooks.token", so this config
    serves nothing — the chain describes an endpoint that is not up. It is pinned rather
    than narrowed because such a config does not start at all (a broken config, not a
    working one being maligned), and because adopting the stricter
    audit-UjVvFwCi.js:389 predicate would let a genuinely serving setup go unreported
    the moment its token lived somewhere this reader cannot see. If a later change makes
    the leg stricter, this test is the one that should be updated, consciously.
    """
    home = _home(tmp_path, {
        "gateway": {"bind": "lan"},
        "hooks": {"enabled": True, "allowRequestSessionKey": True,
                  "allowedSessionKeyPrefixes": []},
    })
    assert _risk20(home) is not None


# ------------------------------------------------------------ Golden Rule #5 surfaces

def test_home_safe_does_not_fire():
    """The clean reference home has no `hooks` key — the live-fleet shape."""
    assert _risk20(FIXTURES / "home_safe") is None


def test_risk20_carries_no_check_meta():
    """Chains are advisory and never scored: no CheckMeta, so no grade impact."""
    from clawseccheck.catalog import BY_ID
    assert "RISK-20" not in BY_ID
