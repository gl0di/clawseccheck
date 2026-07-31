"""B-337: B195 must read a Chrome switch the way Chrome does.

Two pre-existing defects, both in the address/flag *recognition* layer of B195 rather
than in its (B-331) severity calibration:

1. FALSE NEGATIVE, the serious half. Chromium's `base::CommandLine` carries a
   `kSwitchPrefixes` table which on POSIX is `{"--", "-"}`, and
   `GetSwitchPrefixLength()` returns the length of the FIRST entry that prefixes the
   argument — so `-remote-debugging-address=0.0.0.0` and
   `--remote-debugging-address=0.0.0.0` reach Chrome as exactly the same switch. B195
   compared against the `--` spelling only, so the single-dash form of its own FAIL
   conditions was reported clean: the precise exposure the check exists to catch,
   spelled one dash differently.

   The "first matching prefix" rule also fixes the *boundary*: `---disable-web-security`
   matches the `--` entry first, so its switch NAME is `-disable-web-security`, which
   Chrome knows nothing about and which disables nothing. Normalising with `lstrip("-")`
   would trade the false negative for a false positive; exactly one or two dashes are
   accepted, and the tests below pin both directions.

2. FALSE POSITIVE, minor. `--remote-debugging-address=::ffff:127.0.0.1` FAILed, but the
   IPv4-mapped IPv6 form denotes 127.0.0.1 and binds loopback. Python's `ipaddress`
   reports `is_loopback` False for it, so the value has to be unmapped before the test.

The same normalisation pass closes a third false positive found while grounding the
first two: the legacy numeric IPv4 spellings (`127.1`, `0177.0.0.1`, `2130706433`,
`0x7f000001`) that Python's strict `ipaddress` rejects but which denote loopback —
handled exactly as `_cdp_url_classify()` already handles them for `cdpUrl` (B322).

And a fourth: a value that is not an address literal at all (a DNS hostname, `*`) can no
longer FAIL. Chrome's switch value is an address literal, not a name to resolve; whether
Chrome rejects such a value or falls back to its default, neither outcome is the off-host
bind a FAIL asserts. It is reported at WARN instead — the project's standing answer to
"applicable, but cannot determine".

Everything B-331 calibrated is unchanged and re-pinned here: loopback in every spelling
still costs no score and emits no evidence line, an empty value still rebinds nothing,
and `0.0.0.0` / `::` still FAIL.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_browser_extra_args
from clawseccheck.checks._egress import _chrome_switch_name, _remote_debug_bind_class
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_BASE_CONFIG = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    "tools": {"profile": "minimal"},
    "logging": {"redactSensitive": "tools"},
    "models": {"main": {"provider": "ollama/llama3"}},
}


def _extra_args_home(tmp_path: Path, name: str, extra_args: list | None) -> Path:
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    cfg = dict(_BASE_CONFIG)
    browser: dict = {"evaluateEnabled": False}
    if extra_args is not None:
        browser["extraArgs"] = extra_args
    cfg["browser"] = browser
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    path.chmod(0o600)
    return home


def _b195(tmp_path: Path, name: str, extra_args: list | None):
    return check_browser_extra_args(collect(_extra_args_home(tmp_path, name, extra_args)))


# ---------------------------------------------------------------------------
# Defect 1 — the single-dash false negative
# ---------------------------------------------------------------------------

def test_single_dash_remote_debugging_address_all_interfaces_warns(tmp_path):
    """The headline regression: `-remote-debugging-address=0.0.0.0` used to PASS
    (recognition defect). Its status is WARN, not FAIL: bedef56 (2026-07-26) retracted
    the offhost/unresolved FAIL rung entirely, in both dash spellings, because Chromium
    removed --remote-debugging-address in M113 and modern Chrome ignores it."""
    r = _b195(tmp_path, "singledash_addr", ["-remote-debugging-address=0.0.0.0"])
    assert r.status == WARN
    assert any("-remote-debugging-address=0.0.0.0" in e for e in r.evidence)


def test_single_dash_disable_web_security_fails(tmp_path):
    r = _b195(tmp_path, "singledash_dws", ["-disable-web-security"])
    assert r.status == FAIL
    assert any("-disable-web-security" in e for e in r.evidence)


def test_single_dash_load_extension_fails(tmp_path):
    r = _b195(tmp_path, "singledash_ext", ["-load-extension=/tmp/ext"])
    assert r.status == FAIL


def test_single_dash_proxy_flags_warn(tmp_path):
    """The WARN tier normalises the prefix too. OpenClaw's own chromeArgName()
    (chrome-DDq_K3xu.js:156-158) lowercases but does NOT normalise the dash prefix, so
    its PROXY_ROUTING_CHROME_ARGS / PROXY_CONTROL_CHROME_ARGS sets do not recognise the
    single-dash spelling either — whichever way Chrome then resolves the resulting
    `--no-proxy-server` + `-proxy-server=...` pair, the operator's config does not do
    what they wrote. That is the WARN tier's remit, not a reason to stay blind."""
    for idx, arg in enumerate((
        "-proxy-server=http://10.0.0.9:8080",
        "-proxy-auto-detect",
        "-proxy-pac-url=http://10.0.0.9/evil.pac",
    )):
        r = _b195(tmp_path, f"singledash_proxy{idx}", [arg])
        assert r.status == WARN, arg


def test_single_dash_matching_is_case_insensitive_too(tmp_path):
    r = _b195(tmp_path, "singledash_upper", ["-REMOTE-DEBUGGING-ADDRESS=0.0.0.0"])
    assert r.status == WARN


def test_single_dash_bad_fixture_fails():
    """On-disk bad fixture: both FAIL-capable switches in their single-dash spelling."""
    r = check_browser_extra_args(collect(FIXTURES / "bad_b195_browser_single_dash_switches"))
    assert r.status == FAIL
    assert any("-disable-web-security" in e for e in r.evidence)
    assert any("-remote-debugging-address" in e for e in r.evidence)


def test_single_dash_offhost_address_costs_a_grade(tmp_path):
    """End-to-end through the real audit(): the single-dash form must move the score
    exactly like the double-dash form, not merely produce a WARN object."""
    _, _, baseline = audit(_extra_args_home(tmp_path, "e2e_baseline", None))
    _, single, single_scored = audit(
        _extra_args_home(tmp_path, "e2e_single", ["-remote-debugging-address=0.0.0.0"]))
    _, double, double_scored = audit(
        _extra_args_home(tmp_path, "e2e_double", ["--remote-debugging-address=0.0.0.0"]))
    assert next(f for f in single if f.id == "B195").status == WARN
    assert single_scored.score < baseline.score
    assert single_scored.score == double_scored.score
    assert single_scored.grade == double_scored.grade


# ---------------------------------------------------------------------------
# Defect 1, boundary — more than two dashes is NOT a switch Chrome honours
# ---------------------------------------------------------------------------

def test_three_dashes_is_not_a_switch_and_does_not_fail(tmp_path):
    """`---disable-web-security` parses as the switch named `-disable-web-security`,
    which Chrome does not know. Peeling every dash would false-FAIL an inert string."""
    for idx, arg in enumerate((
        "---disable-web-security",
        "---remote-debugging-address=0.0.0.0",
    )):
        r = _b195(tmp_path, f"threedash{idx}", [arg])
        assert r.status == PASS, arg


def test_no_leading_dash_is_not_a_switch(tmp_path):
    """A positional argument (a URL to open) is not a switch, however it is spelled."""
    r = _b195(tmp_path, "positional", ["disable-web-security", "https://example.com"])
    assert r.status == PASS


def test_chrome_switch_name_normalisation():
    """Unit-level pin on the prefix rule itself."""
    assert _chrome_switch_name("--Disable-Web-Security") == "disable-web-security"
    assert _chrome_switch_name("-disable-web-security") == "disable-web-security"
    assert _chrome_switch_name("--proxy-server=http://x:1") == "proxy-server"
    assert _chrome_switch_name("-proxy-server=http://x:1") == "proxy-server"
    assert _chrome_switch_name("---disable-web-security") == "-disable-web-security"
    assert _chrome_switch_name("chrome://flags") == ""
    assert _chrome_switch_name("--") == ""
    assert _chrome_switch_name("-") == ""
    assert _chrome_switch_name("") == ""


# ---------------------------------------------------------------------------
# Defect 2 — the IPv4-mapped IPv6 false positive
# ---------------------------------------------------------------------------

def test_ipv4_mapped_loopback_does_not_fail(tmp_path):
    r = _b195(tmp_path, "mapped", ["--remote-debugging-address=::ffff:127.0.0.1"])
    assert r.status == PASS
    assert not any("remote-debugging-address" in e for e in r.evidence)


def test_ipv4_mapped_loopback_bracketed_with_port_does_not_fail(tmp_path):
    r = _b195(tmp_path, "mapped_port", ["--remote-debugging-address=[::ffff:127.0.0.1]:9222"])
    assert r.status == PASS


def test_ipv4_mapped_non_loopback_still_warns(tmp_path):
    """Unmapping must not become a blanket amnesty: ::ffff:10.0.0.5 is still off-host,
    reported at the B-337 WARN rung (bedef56 retracted the FAIL for every offhost
    spelling, mapped included)."""
    r = _b195(tmp_path, "mapped_offhost", ["--remote-debugging-address=::ffff:10.0.0.5"])
    assert r.status == WARN


def test_mapped_loopback_clean_fixture_passes():
    """On-disk clean fixture, also exercising the single-dash spelling of a no-op."""
    r = check_browser_extra_args(
        collect(FIXTURES / "clean_b195_browser_remote_debug_mapped_loopback"))
    assert r.status == PASS


def test_mapped_loopback_does_not_lower_the_score(tmp_path):
    """B-331's calibration, extended to the newly-recognised loopback spellings."""
    _, _, baseline = audit(_extra_args_home(tmp_path, "mapped_base", None))
    for name, arg in (
        ("mapped_v6", "--remote-debugging-address=::ffff:127.0.0.1"),
        ("short_v4", "--remote-debugging-address=127.1"),
        ("padded_v4", "--remote-debugging-address=127.000.000.001"),
        ("decimal_v4", "--remote-debugging-address=2130706433"),
        ("single_dash_lb", "-remote-debugging-address=127.0.0.1"),
    ):
        _, _, scored = audit(_extra_args_home(tmp_path, name, [arg]))
        assert scored.score == baseline.score, name
        assert scored.grade == baseline.grade, name


# ---------------------------------------------------------------------------
# Legacy numeric IPv4 forms, and the "cannot determine" tier
# ---------------------------------------------------------------------------

def test_numeric_shorthand_all_interfaces_still_warns(tmp_path):
    """The numeric fallback must classify BOTH ways — `0` is 0.0.0.0, not loopback,
    so recognising shorthand may not become an evasion route. Reported at WARN, not
    FAIL (bedef56): every offhost spelling is WARN, numeric shorthand included."""
    for idx, arg in enumerate((
        "--remote-debugging-address=0",
        "--remote-debugging-address=0x0",
        "--remote-debugging-address=10.0.0.5",
    )):
        r = _b195(tmp_path, f"numeric_offhost{idx}", [arg])
        assert r.status == WARN, arg


def test_unresolvable_address_warns_rather_than_fails(tmp_path):
    """UNKNOWN-path coverage for the value classifier: a hostname is not an address
    literal, so the effective bind is undetermined and a FAIL would assert a fact the
    evidence does not support."""
    r = _b195(tmp_path, "hostname", ["--remote-debugging-address=chrome-host.internal"])
    assert r.status == WARN
    assert any("cannot be determined" in e for e in r.evidence)


def test_unresolvable_address_does_not_hard_fail_the_audit(tmp_path):
    _, findings, _ = audit(
        _extra_args_home(tmp_path, "hostname_e2e", ["--remote-debugging-address=*"]))
    assert next(f for f in findings if f.id == "B195").status == WARN


def test_remote_debug_bind_class_unit():
    """Unit-level pin on the three-way classification."""
    for loopback in (
        "127.0.0.1", "localhost", "LOCALHOST", "::1", "0:0:0:0:0:0:0:1", "[::1]",
        "[::1]:9222", "127.0.0.1:9222", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]:9222",
        "127.1", "0177.0.0.1", "127.000.000.001", "2130706433", "0x7f000001",
        "127.0.0.53",
    ):
        assert _remote_debug_bind_class(loopback) == "loopback", loopback
    for offhost in ("0.0.0.0", "::", "10.0.0.5", "::ffff:10.0.0.5", "0", "0x0",
                    "192.168.1.10:9222"):
        assert _remote_debug_bind_class(offhost) == "offhost", offhost
    for unresolved in ("", "   ", "chrome-host.internal", "*", "all", "::ffff:zzz"):
        assert _remote_debug_bind_class(unresolved) == "unresolved", unresolved


# ---------------------------------------------------------------------------
# The B-331 calibration this change must not disturb
# ---------------------------------------------------------------------------

def test_b331_prefix_collision_guard_survives_prefix_normalisation(tmp_path):
    """The exact pre-'=' token rule is orthogonal to the dash rule and must survive it,
    in both spellings."""
    r = _b195(tmp_path, "collision", [
        "--proxy-server-bypass-list=*.internal.example.com",
        "-proxy-server-bypass-list=*.internal.example.com",
        "--disable-web-security-warnings",
        "-load-extension-manager=/tmp/x",
    ])
    assert r.status == PASS


def test_b331_empty_and_bare_value_still_rebinds_nothing(tmp_path):
    for idx, arg in enumerate((
        "-remote-debugging-address",
        "-remote-debugging-address=",
        "--remote-debugging-address",
        "--remote-debugging-address=",
    )):
        r = _b195(tmp_path, f"bare{idx}", [arg])
        assert r.status == PASS, arg
