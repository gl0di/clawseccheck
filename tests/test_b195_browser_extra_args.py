"""B195 (E-060 item 2): browser.extraArgs dangerous Chrome launch flags.

browser.extraArgs is pushed verbatim into the Chrome launch command with no validation
by OpenClaw itself (re-verified against the JS bundle: config-DpWXcVmn.js:480 reads it,
chrome-DDq_K3xu.js:1687-1688 spreads it unfiltered into the launch args) -- unlike B38's
own ssrfPolicy/noSandbox keys, which OpenClaw does interpret. See
docs/research/openclaw-schema-recon.md §31.1 (workspace root, not shipped).

Flags matched by exact pre-'=' token, never substring (C-135 guidance: a benign flag
sharing a prefix with a denylisted one, e.g. --proxy-server-bypass-list vs
--proxy-server, must not false-FAIL).

B-331 -- OpenClaw ALWAYS opens the CDP port itself. `buildOpenClawChromeLaunchArgs`
(chrome-DDq_K3xu.js:1662-1689) unconditionally passes
`--remote-debugging-port=${profile.cdpPort}` (CDP is how OpenClaw drives the browser at
all), and NO dist file anywhere sets `--remote-debugging-address` -- verified by grep
across the installed dist -- so Chrome's default loopback bind applies and OpenClaw's own
`cdpUrlForPort()` is `http://127.0.0.1:${cdpPort}` (chrome-DDq_K3xu.js:1659). Therefore:

  * A loopback-bound operator flag changes NOTHING: it restates the bind already in
    force, which is the defensive thing to write down. It must not cost score. The old
    WARN also mis-attributed causation -- its evidence told the operator their flag
    "opens an unauthenticated ... debug port on loopback" when OpenClaw's own
    always-present --remote-debugging-port opened it, so the user could not act on it
    (removing the flag would not close the port).
  * A NON-loopback operator flag was a FAIL until B-337 RETRACTED it -- see below.

B-337 / C-135 (2026-07-26) -- two defects fixed, one in each direction:

  * FALSE POSITIVE (blocker, Golden Rule #5): --remote-debugging-address DOES NOT EXIST
    in modern Chromium. It was removed in M113, so the old FAIL docked a grade for a
    switch current Chrome silently ignores. Measured on Google Chrome 150.0.7871.186
    (headless, `ss -lnt` on the listening socket): with --remote-debugging-address set to
    0.0.0.0 OR to a real interface address, the debug port still binds 127.0.0.1 -- the
    bind does not move. Corroborated structurally: "remote-debugging-address" is absent
    from the Chrome 150 binary's switch table while "remote-debugging-port",
    "remote-debugging-pipe" and "remote-allow-origins" are all present. Downgraded to
    WARN (an intent signal, and a real exposure only on a pinned pre-M113 Chrome), never
    FAIL.

  * FALSE NEGATIVE: Chromium honours a switch spelled with ONE dash exactly as with two
    (base::CommandLine kSwitchPrefixes is {"--", "-"} on POSIX), and the old
    `flag_lower == "--..."` comparison reported every single-dash spelling as clean.
    Measured on the same Chrome 150 run via the CDP cross-origin handshake:
    `--remote-allow-origins=*` and `-remote-allow-origins=*` both flip 403 -> 101, while
    `---remote-allow-origins=*` stays 403. So one-or-two dashes are honoured and three
    are not -- which is why _chrome_switch_name() peels exactly one or two and must NOT
    lstrip("-") (that would trade the FN for an FP on an inert string).

Severity shape:
  - no browser config                                          -> UNKNOWN
  - --disable-web-security / --load-extension present           -> FAIL
    (in either the one-dash or two-dash spelling)
  - --proxy-server / --proxy-auto-detect / --proxy-pac-url      -> WARN
  - --remote-debugging-address bound non-loopback / unresolved  -> WARN (B-337)
  - --remote-debugging-address bound loopback (a no-op)         -> not flagged (B-331)
  - extraArgs absent/empty, or no matched flag                  -> PASS

--remote-allow-origins is deliberately NOT graded here -- it is about who may reach the
CDP control port, so B330 owns it (tests/test_b330_cdp_control_port.py).
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_extra_args
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Minimal but realistic base config so audit() exercises the whole pipeline. The
# score-comparison homes below differ ONLY by browser.extraArgs.
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


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def _audit_extra_args(tmp_path: Path, name: str, extra_args: list | None):
    """Audit a home whose config is _BASE_CONFIG plus the given browser.extraArgs.

    evaluateEnabled is pinned false so B196 is a constant PASS across the comparison and
    only B195's own contribution can move the score. Perms are pinned 0600 so an at-rest
    permission check cannot make the score depend on the runner's umask.
    """
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
    return audit(home)


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
# B-337: --remote-debugging-address is WARN, never FAIL (M113 removed the switch)
# ---------------------------------------------------------------------------

def test_remote_debugging_address_all_interfaces_warns(tmp_path):
    """Was FAIL. Chrome 150 measurement: the port still binds 127.0.0.1 with this set,
    so a FAIL asserted an off-host bind that provably does not happen."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_other_host_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=10.0.0.5"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_never_fails(tmp_path):
    """The blocker false positive, pinned in one place: no value of this switch may
    reach the FAIL rung, in either dash spelling or any case."""
    values = (
        "0.0.0.0", "::", "10.0.0.5", "192.168.31.233", "example.com", "*", "not-an-ip",
    )
    for idx, value in enumerate(values):
        for prefix in ("--", "-"):
            home = _home(
                tmp_path / f"c{idx}{len(prefix)}",
                config={"browser": {"extraArgs": [f"{prefix}remote-debugging-address={value}"]}},
            )
            r = check_browser_extra_args(collect(home))
            assert r.status != FAIL, f"{prefix}remote-debugging-address={value}"


def test_remote_debugging_address_warn_evidence_states_the_switch_is_removed(tmp_path):
    """The operator must be told WHY this is not a FAIL, or the WARN reads as a
    half-hearted FAIL and they will 'fix' a flag that does nothing."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    line = next(e for e in r.evidence if "remote-debugging-address" in e)
    assert "M113" in line
    assert "OpenClaw itself opens" in line


def test_remote_debugging_address_loopback_passes(tmp_path):
    """B-331: a loopback bind restates OpenClaw's own default -- a no-op, so PASS."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=127.0.0.1"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


def test_remote_debugging_address_localhost_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=localhost"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


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


def test_uppercase_remote_debugging_address_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--REMOTE-DEBUGGING-ADDRESS=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# B-337: Chromium honours one OR two leading dashes, and exactly those
# ---------------------------------------------------------------------------

def test_single_dash_fail_flags_are_caught(tmp_path):
    """The false negative this fix exists to close: `-disable-web-security` is the same
    switch as `--disable-web-security` to real Chrome (kSwitchPrefixes = {"--","-"}),
    and used to be reported as clean."""
    for idx, arg in enumerate(("-disable-web-security", "-load-extension=/tmp/ext")):
        home = _home(tmp_path / f"case{idx}", config={"browser": {"extraArgs": [arg]}})
        r = check_browser_extra_args(collect(home))
        assert r.status == FAIL, arg


def test_single_dash_warn_flags_are_caught(tmp_path):
    for idx, arg in enumerate((
        "-proxy-server=http://10.0.0.9:8080",
        "-proxy-auto-detect",
        "-proxy-pac-url=http://10.0.0.9/evil.pac",
    )):
        home = _home(tmp_path / f"case{idx}", config={"browser": {"extraArgs": [arg]}})
        r = check_browser_extra_args(collect(home))
        assert r.status == WARN, arg


def test_single_dash_mixed_case_still_caught(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["-Disable-Web-Security"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == FAIL


def test_three_or_more_dashes_are_not_a_switch(tmp_path):
    """MEASURED (Chrome 150): `---remote-allow-origins=*` left the CDP endpoint at 403,
    i.e. Chrome did NOT recognize it -- the "--" prefix matches first, leaving the switch
    name "-remote-allow-origins", which Chrome knows nothing about. So peeling every
    leading dash (lstrip("-")) would trade the single-dash false negative for a false
    POSITIVE on an inert string. Exactly one or two dashes, and nothing else."""
    for idx, arg in enumerate((
        "---disable-web-security",
        "----load-extension=/tmp/ext",
        "---proxy-server=http://10.0.0.9:8080",
    )):
        home = _home(tmp_path / f"case{idx}", config={"browser": {"extraArgs": [arg]}})
        r = check_browser_extra_args(collect(home))
        assert r.status == PASS, arg


def test_non_switch_arguments_are_ignored(tmp_path):
    """A bare URL or positional argument is not a switch and must not be parsed as one."""
    home = _home(tmp_path, config={"browser": {"extraArgs": [
        "https://example.com/disable-web-security", "--", "-", "disable-web-security",
    ]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# C-135 (2026-07-25): --remote-debugging-address loopback classification gaps
# ---------------------------------------------------------------------------
# The original bare {"127.0.0.1", "localhost", "::1"} set false-FAILed on real
# loopback addresses written in valid alternate forms Chrome itself accepts.
# B-331 then lowered every loopback form from WARN to "not flagged at all".

def test_remote_debugging_address_with_port_passes(tmp_path):
    """A host:port suffix (e.g. copied from a URL) must still classify 127.0.0.1
    as loopback."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=127.0.0.1:9222"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


def test_remote_debugging_address_ipv6_full_form_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0:0:0:0:0:0:0:1"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


def test_remote_debugging_address_ipv6_bracketed_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=[::1]"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


def test_remote_debugging_address_ipv6_bracketed_with_port_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=[::1]:9222"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS


def test_remote_debugging_address_all_zeros_ipv6_still_flagged(tmp_path):
    """:: is the IPv6 unspecified/"all interfaces" address (the v6 analogue of
    0.0.0.0), not loopback -- so it must still be reported, at the B-337 WARN rung."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=::"]}})
    r = check_browser_extra_args(collect(home))
    assert r.status == WARN


def test_remote_debugging_address_ipv4_mapped_loopback_is_silent(tmp_path):
    """B-337: ::ffff:127.0.0.1 denotes 127.0.0.1 and binds loopback, but Python's
    ipaddress reports is_loopback False for the mapped form unless it is unmapped
    first -- so without the fix a genuinely loopback-bound config drew a finding."""
    home = _home(
        tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=::ffff:127.0.0.1"]}}
    )
    r = check_browser_extra_args(collect(home))
    assert r.status == PASS
    assert not any("remote-debugging-address" in e for e in r.evidence)


def test_remote_debugging_address_legacy_numeric_loopback_is_silent(tmp_path):
    """The legacy numeric IPv4 spellings of loopback that strict `ipaddress` rejects."""
    for idx, value in enumerate(("127.1", "0177.0.0.1", "127.000.000.001", "2130706433")):
        home = _home(
            tmp_path / f"case{idx}",
            config={"browser": {"extraArgs": [f"--remote-debugging-address={value}"]}},
        )
        r = check_browser_extra_args(collect(home))
        assert r.status == PASS, value


# ---------------------------------------------------------------------------
# B-331: the loopback bind is a no-op — it must cost no score, and no evidence
# string may attribute to the operator a condition OpenClaw itself created
# ---------------------------------------------------------------------------

def test_clean_loopback_fixture_passes():
    """On-disk clean fixture for the loopback no-op case."""
    r = check_browser_extra_args(collect(FIXTURES / "clean_b195_browser_remote_debug_loopback"))
    assert r.status == PASS


def test_loopback_address_produces_no_evidence_line(tmp_path):
    """Not merely 'not FAIL' -- it must not appear as a flagged entry at all, since
    surfacing it as a risk is what mis-attributed causation in the first place."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=127.0.0.1"]}})
    r = check_browser_extra_args(collect(home))
    assert not any("--remote-debugging-address" in e for e in r.evidence)


def test_bare_remote_debugging_address_with_no_value_does_not_fail(tmp_path):
    """No address after the '=' (or a bare switch) rebinds nothing, so it cannot be
    evidence that the debug port moved off loopback."""
    for idx, arg in enumerate(("--remote-debugging-address", "--remote-debugging-address=")):
        home = _home(tmp_path / f"case{idx}", config={"browser": {"extraArgs": [arg]}})
        r = check_browser_extra_args(collect(home))
        assert r.status == PASS, arg


def test_loopback_address_does_not_lower_the_score(tmp_path):
    """End-to-end via the real audit(): writing down the default must be free.

    All three loopback spellings the C-135 pass named -- bare, host:port, bracketed
    IPv6 -- must land on exactly the score of a config with no extraArgs at all.
    """
    _, _, baseline = _audit_extra_args(tmp_path, "baseline", None)
    for name, arg in (
        ("bare", "--remote-debugging-address=127.0.0.1"),
        ("hostport", "--remote-debugging-address=127.0.0.1:9222"),
        ("ipv6", "--remote-debugging-address=[::1]:9222"),
    ):
        _, _, scored = _audit_extra_args(tmp_path, name, [arg])
        assert scored.score == baseline.score, name
        assert scored.grade == baseline.grade, name


def test_offhost_address_still_costs_something(tmp_path):
    """The converse of the no-op rule: B-337 downgraded this to WARN, but a WARN still
    counts half, so the fix cannot have made the branch inert."""
    _, _, baseline = _audit_extra_args(tmp_path, "baseline", None)
    for name, arg in (
        ("all_v4", "--remote-debugging-address=0.0.0.0"),
        ("all_v6", "--remote-debugging-address=::"),
    ):
        _, findings, scored = _audit_extra_args(tmp_path, name, [arg])
        b195 = next(f for f in findings if f.id == "B195")
        assert b195.status == WARN, name
        assert scored.score < baseline.score, name


def test_single_dash_fail_costs_a_grade_end_to_end(tmp_path):
    """The false negative closed by B-337, proven through the real audit(): the
    one-dash spelling must cost exactly what the two-dash spelling costs."""
    _, _, baseline = _audit_extra_args(tmp_path, "baseline", None)
    _, two_findings, two = _audit_extra_args(tmp_path, "two", ["--disable-web-security"])
    _, one_findings, one = _audit_extra_args(tmp_path, "one", ["-disable-web-security"])
    assert next(f for f in two_findings if f.id == "B195").status == FAIL
    assert next(f for f in one_findings if f.id == "B195").status == FAIL
    assert one.score < baseline.score
    assert one.score == two.score
    assert one.grade == two.grade


def test_offhost_evidence_does_not_blame_the_operator_for_the_port(tmp_path):
    """The port is opened by OpenClaw's own --remote-debugging-port on every managed
    launch; the operator's flag does not open it (and since M113 does not move it
    either). The evidence must say so."""
    home = _home(tmp_path, config={"browser": {"extraArgs": ["--remote-debugging-address=0.0.0.0"]}})
    r = check_browser_extra_args(collect(home))
    line = next(e for e in r.evidence if "--remote-debugging-address" in e)
    assert "OpenClaw itself opens" in line
    # The retracted wording claimed the operator's flag opened the port.
    assert "opens an unauthenticated Chrome" not in line
