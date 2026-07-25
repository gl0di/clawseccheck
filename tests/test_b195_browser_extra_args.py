"""B195 (E-060 item 2): browser.extraArgs dangerous Chrome launch flags.

browser.extraArgs is pushed verbatim into the Chrome launch command with no validation
by OpenClaw itself (re-verified against the JS bundle: config-DpWXcVmn.js:480 reads it,
chrome-DDq_K3xu.js:1687-1688 spreads it unfiltered into the launch args) -- unlike B38's
own ssrfPolicy/noSandbox keys, which OpenClaw does interpret. See
docs/research/openclaw-schema-recon.md §31.1 (workspace root, not shipped).

Flags matched by exact pre-'=' token, never substring (C-135 guidance: a benign flag
sharing a prefix with a denylisted one, e.g. --proxy-server-bypass-list vs
--proxy-server, must not false-FAIL).

Severity shape:
  - no browser config                                         -> UNKNOWN
  - --disable-web-security / --load-extension present         -> FAIL
  - --remote-debugging-address bound non-loopback              -> FAIL
  - --remote-debugging-address bound loopback                  -> WARN
  - --proxy-server present                                     -> WARN
  - extraArgs absent/empty, or no matched flag                 -> PASS
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_extra_args
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_extra_args(collect(FIXTURES / "clean_b195_browser_extra_args"))
    assert r.status == PASS


def test_bad_fixture_fails():
    r = check_browser_extra_args(collect(FIXTURES / "bad_b195_browser_extra_args"))
    assert r.status == FAIL
    assert any("--disable-web-security" in e for e in r.evidence)
    assert any("--remote-debugging-address" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN / PASS baselines
# ---------------------------------------------------------------------------

def test_no_browser_config_is_unknown(tmp_path):
    r = check_browser_extra_args(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_extra_args(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_extra_args_absent_passes(tmp_path):
    r = check_browser_extra_args(collect(_home(tmp_path, config={"browser": {"noSandbox": False}})))
    assert r.status == PASS


def test_extra_args_empty_passes(tmp_path):
    r = check_browser_extra_args(collect(_home(tmp_path, config={"browser": {"extraArgs": []}})))
    assert r.status == PASS


def test_benign_flags_pass(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--window-size=1024,768", "--lang=en-US"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL: unconditionally dangerous flags
# ---------------------------------------------------------------------------

def test_disable_web_security_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--disable-web-security"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL
    assert any("--disable-web-security" in e for e in r.evidence)


def test_load_extension_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--load-extension=/tmp/ext"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL
    assert any("--load-extension" in e for e in r.evidence)


def test_flag_prefix_collision_does_not_false_fail(tmp_path):
    """--proxy-server-bypass-list must not match the --proxy-server WARN pattern, and
    a made-up --load-extension-like-name flag must not match --load-extension either --
    the split must be on the exact pre-'=' token (C-135 guidance)."""
    home = _home(tmp_path, config={"browser": {"extraArgs": [
        "--proxy-server-bypass-list=*.internal.example.com",
        "--disable-web-security-warnings",
    ]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL vs WARN: --remote-debugging-address loopback classification
# ---------------------------------------------------------------------------

def test_remote_debugging_address_all_interfaces_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_remote_debugging_address_other_host_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=10.0.0.5"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_remote_debugging_address_loopback_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=127.0.0.1"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_localhost_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=localhost"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# WARN: lower-certainty flags
# ---------------------------------------------------------------------------

def test_proxy_server_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--proxy-server=http://10.0.0.9:8080"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN
    assert any("--proxy-server" in e for e in r.evidence)


def test_fail_takes_precedence_over_warn(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": [
        "--proxy-server=http://10.0.0.9:8080",
        "--disable-web-security",
    ]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_proxy_auto_detect_warns(tmp_path):
    """C-135 (2026-07-25): OpenClaw's own PROXY_ROUTING_CHROME_ARGS groups
    --proxy-auto-detect with --proxy-server (both flip resolveBrowserNavigationProxyMode()
    to "explicit-browser-proxy") -- the original WARN set covered only --proxy-server."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--proxy-auto-detect"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN
    assert any("--proxy-auto-detect" in e for e in r.evidence)


def test_proxy_pac_url_warns(tmp_path):
    """C-135 (2026-07-25): same PROXY_ROUTING_CHROME_ARGS grouping as --proxy-auto-detect."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--proxy-pac-url=http://10.0.0.9/evil.pac"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN
    assert any("--proxy-pac-url" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# C-135 (2026-07-25): case-insensitive flag matching
# ---------------------------------------------------------------------------
# Chromium's own base::CommandLine lowercases every switch name during parsing
# (base::ToLowerASCII()), so an uppercase/mixed-case flag reaches Chrome identically
# to its lowercase form -- confirmed by OpenClaw's own chromeArgName() helper
# (chrome-DDq_K3xu.js:156-158) already lowercasing before its internal proxy-arg
# checks. The original exact-case dict lookup let these evade detection entirely.

def test_uppercase_disable_web_security_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--DISABLE-WEB-SECURITY"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_mixedcase_disable_web_security_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--Disable-Web-Security"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_uppercase_proxy_server_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--PROXY-SERVER=http://10.0.0.9:8080"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_uppercase_remote_debugging_address_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--REMOTE-DEBUGGING-ADDRESS=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# C-135 (2026-07-25): --remote-debugging-address loopback classification gaps
# ---------------------------------------------------------------------------
# The original bare {"127.0.0.1", "localhost", "::1"} set false-FAILed on real
# loopback addresses written in valid alternate forms Chrome itself accepts.

def test_remote_debugging_address_with_port_warns(tmp_path):
    """A host:port suffix (e.g. copied from a URL) must still classify 127.0.0.1
    as loopback."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=127.0.0.1:9222"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_ipv6_full_form_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0:0:0:0:0:0:0:1"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_ipv6_bracketed_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=[::1]"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_ipv6_bracketed_with_port_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=[::1]:9222"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_all_zeros_ipv6_still_fails(tmp_path):
    """:: is the IPv6 unspecified/"all interfaces" address (the v6 analogue of
    0.0.0.0), not loopback -- must stay FAIL."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=::"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL
