"""B330 (C-298): the Chrome DevTools Protocol control port is unauthenticated.

OpenClaw ALWAYS launches its managed Chrome with `--remote-debugging-port=${cdpPort}`
(buildOpenClawChromeLaunchArgs, chrome-DDq_K3xu.js:1662-1689) -- CDP is how it drives a
browser at all -- and CDP has no authentication step. No dist file passes
--remote-debugging-address, so Chrome's default loopback bind applies and OpenClaw's own
endpoint is cdpUrlForPort() = `http://127.0.0.1:${cdpPort}` (chrome-DDq_K3xu.js:1659).

THE PORT ITSELF IS NOT GRADED. It is vendor design the operator cannot switch off, and
B-331 established that this audit grades the state a config CHOOSES, never one OpenClaw
created. So the ordinary loopback-confined case is a real PASS that states the fact.
What IS graded is the operator's own two levers:

  * WHERE the channel points -> WARN (an off-host top-level browser.cdpUrl, or a managed
    profile's cdpUrl). The corroborated rung for a non-loopback cdpUrl is already owned
    by B322 (existing-session) and B196 (attach-only + evaluate sink), so B330 stays at
    WARN there rather than triple-counting one fact.
  * WHO may reach it from inside the browser -> FAIL (--remote-allow-origins=*).

The FAIL rung is MEASURED, not assumed. Google Chrome 150.0.7871.186, headless, local,
raw WebSocket upgrade carrying `Origin: http://evil.example` against the endpoint taken
from /json/version (2026-07-26):

    (no flag)                   -> HTTP/1.1 403 Forbidden
    --remote-allow-origins=*    -> HTTP/1.1 101 WebSocket Protocol Handshake
    -remote-allow-origins=*     -> HTTP/1.1 101 WebSocket Protocol Handshake
    ---remote-allow-origins=*   -> HTTP/1.1 403 Forbidden

So the wildcard converts a refused cross-origin request into a live CDP session: any page
the agent's browser has open can then drive the browser -- read every origin's cookies
and DOM, navigate it, execute JS in it. Loopback confinement does not contain that, since
the request originates inside the browser, which is already on loopback.

These tests are offline and read-only; the measurement above was a one-off grounding run,
never something the suite performs.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_browser_cdp_control_port,
    check_browser_existing_session_profile,
)
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


def _home(tmp_path: Path, config: dict | None = None, name: str = "home") -> Path:
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        path = home / "openclaw.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
    return home


def _browser(tmp_path: Path, browser: dict, name: str = "home"):
    return check_browser_cdp_control_port(collect(_home(tmp_path, {"browser": browser}, name)))


def _audit_browser(tmp_path: Path, name: str, browser: dict | None):
    cfg = dict(_BASE_CONFIG)
    if browser is not None:
        cfg["browser"] = browser
    return audit(_home(tmp_path, cfg, name))


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_cdp_control_port(collect(FIXTURES / "clean_b330_cdp_control_port"))
    assert r.status == PASS


def test_bad_fixture_fails():
    r = check_browser_cdp_control_port(collect(FIXTURES / "bad_b330_cdp_allow_origins"))
    assert r.status == FAIL
    assert any("remote-allow-origins" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN
# ---------------------------------------------------------------------------

def test_no_config_found_is_unknown(tmp_path):
    assert check_browser_cdp_control_port(collect(_home(tmp_path))).status == UNKNOWN


def test_no_browser_config_is_unknown(tmp_path):
    home = _home(tmp_path, {"tools": {"profile": "minimal"}})
    assert check_browser_cdp_control_port(collect(home)).status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: the ordinary case is a real PASS, not a grudging one
# ---------------------------------------------------------------------------

def test_default_browser_config_passes(tmp_path):
    """The unauthenticated port exists here too -- it always does -- but the operator
    has no lever on it, so it must not cost score (B-331)."""
    assert _browser(tmp_path, {}).status == PASS


def test_loopback_cdp_url_passes(tmp_path):
    assert _browser(tmp_path, {"cdpUrl": "http://127.0.0.1:9222"}).status == PASS


def test_browser_disabled_passes(tmp_path):
    r = _browser(tmp_path, {"enabled": False})
    assert r.status == PASS
    assert r.pass_confidence == "verified"


def test_pass_message_states_the_port_is_unauthenticated(tmp_path):
    """The whole point of the check: PASS still has to TELL the operator the fact."""
    r = _browser(tmp_path, {})
    assert "no authentication" in r.detail
    assert "any process running on this machine" in r.detail


def test_pass_does_not_lower_the_score(tmp_path):
    _, _, baseline = _audit_browser(tmp_path, "baseline", None)
    _, _, browsered = _audit_browser(tmp_path, "browsered", {"cdpUrl": "http://127.0.0.1:9222"})
    assert browsered.grade == baseline.grade


# ---------------------------------------------------------------------------
# FAIL: --remote-allow-origins wildcard
# ---------------------------------------------------------------------------

def test_allow_origins_wildcard_fails(tmp_path):
    r = _browser(tmp_path, {"extraArgs": ["--remote-allow-origins=*"]})
    assert r.status == FAIL


def test_allow_origins_wildcard_single_dash_fails(tmp_path):
    """MEASURED: `-remote-allow-origins=*` flips the CDP endpoint 403 -> 101 exactly as
    the two-dash spelling does, so it must reach the same rung (B-337)."""
    r = _browser(tmp_path, {"extraArgs": ["-remote-allow-origins=*"]})
    assert r.status == FAIL


def test_allow_origins_wildcard_in_a_list_fails(tmp_path):
    """Chromium allows all origins if `*` appears anywhere in the comma-separated list."""
    r = _browser(tmp_path, {"extraArgs": ["--remote-allow-origins=https://a.example,*"]})
    assert r.status == FAIL


def test_allow_origins_wildcard_wrong_case_warns_but_never_fails(tmp_path):
    """C-135 false positive, found by an independent adversarial pass and MEASURED:
    Chromium's switch lookup is case-sensitive on POSIX, so the uppercase/mixed-case
    spelling leaves the cross-origin CDP handshake at 403 -- the flag does nothing.

        --remote-allow-origins=*   -> 101 (honoured)
        --REMOTE-ALLOW-ORIGINS=*   -> 403 (inert)
        --Remote-Allow-Origins=*   -> 403 (inert)

    Hard-capping a grade for an inert switch is the same defect B-337 removed from B195's
    M113 handling, so this reports at WARN instead. It is not silenced, because on
    Windows Chromium lowercases switch names and the spelling WOULD take effect there.
    """
    for idx, arg in enumerate(("--REMOTE-ALLOW-ORIGINS=*", "--Remote-Allow-Origins=*",
                               "-Remote-Allow-Origins=*")):
        r = _browser(tmp_path, {"extraArgs": [arg]}, name=f"case{idx}")
        assert r.status == WARN, arg


def test_allow_origins_wildcard_value_is_trimmed_like_chrome_does(tmp_path):
    """The converse of the case finding: a SPACE before the wildcard does NOT save the
    config -- measured `--remote-allow-origins= *` -> 101, i.e. Chrome trims the value.
    So stripping each comma-split token matches Chrome rather than over-reaching."""
    for idx, arg in enumerate(("--remote-allow-origins= *", "--remote-allow-origins=*,",
                               "--remote-allow-origins= * , ")):
        r = _browser(tmp_path, {"extraArgs": [arg]}, name=f"trim{idx}")
        assert r.status == FAIL, arg


def test_allow_origins_triple_dash_does_not_fail(tmp_path):
    """MEASURED: `---remote-allow-origins=*` left the endpoint at 403 -- Chrome does not
    recognize it, so grading it would be a false positive on an inert string."""
    r = _browser(tmp_path, {"extraArgs": ["---remote-allow-origins=*"]})
    assert r.status == PASS


def test_allow_origins_named_origins_warn_not_fail(tmp_path):
    """A named origin list is a bounded, possibly deliberate trade -- not the 'any page
    at all' hole the wildcard opens."""
    r = _browser(tmp_path, {"extraArgs": ["--remote-allow-origins=https://a.example"]})
    assert r.status == WARN


def test_allow_origins_with_no_value_is_not_flagged(tmp_path):
    """An empty list allows nothing, so it is not a relaxation."""
    for idx, arg in enumerate(("--remote-allow-origins", "--remote-allow-origins=")):
        r = _browser(tmp_path, {"extraArgs": [arg]}, name=f"case{idx}")
        assert r.status == PASS, arg


def test_allow_origins_wildcard_costs_a_grade(tmp_path):
    _, _, baseline = _audit_browser(tmp_path, "baseline", None)
    _, findings, scored = _audit_browser(
        tmp_path, "wild", {"extraArgs": ["--remote-allow-origins=*"]}
    )
    assert next(f for f in findings if f.id == "B330").status == FAIL
    assert scored.score < baseline.score


def test_allow_origins_is_not_double_counted_by_b195(tmp_path):
    """B195 owns extraArgs but deliberately does not grade --remote-allow-origins, so
    the flag must move exactly one check."""
    _, findings, _ = _audit_browser(tmp_path, "wild", {"extraArgs": ["--remote-allow-origins=*"]})
    assert next(f for f in findings if f.id == "B195").status == PASS
    assert next(f for f in findings if f.id == "B330").status == FAIL


# ---------------------------------------------------------------------------
# WARN: off-host CDP endpoints
# ---------------------------------------------------------------------------

def test_offhost_top_level_cdp_url_warns(tmp_path):
    r = _browser(tmp_path, {"cdpUrl": "http://10.0.0.9:9222"})
    assert r.status == WARN
    assert any("browser.cdpUrl" in e for e in r.evidence)


def test_offhost_managed_profile_cdp_url_warns(tmp_path):
    r = _browser(tmp_path, {"profiles": {"work": {"driver": "openclaw", "cdpUrl": "http://10.0.0.9:9222"}}})
    assert r.status == WARN
    assert any("browser.profiles.work" in e for e in r.evidence)


def test_offhost_never_reaches_fail(tmp_path):
    """The corroborated cdpUrl rung belongs to B322/B196. B330 must not add a third
    hard cap on the same underlying fact."""
    for idx, browser in enumerate((
        {"cdpUrl": "http://10.0.0.9:9222"},
        {"cdpUrl": "ws://evil.example:9222"},
        {"profiles": {"w": {"driver": "openclaw", "cdpUrl": "http://10.0.0.9:9222"}}},
    )):
        assert _browser(tmp_path, browser, name=f"case{idx}").status != FAIL


def test_cleartext_scheme_is_called_out(tmp_path):
    r = _browser(tmp_path, {"cdpUrl": "http://10.0.0.9:9222"})
    assert any("cleartext" in e for e in r.evidence)


def test_existing_session_profile_is_left_to_b322(tmp_path):
    """B322 owns driver:"existing-session", including its FAIL. Counting it here too
    would grade one config fact twice."""
    r = _browser(
        tmp_path,
        {"profiles": {"user": {"driver": "existing-session", "cdpUrl": "http://10.0.0.9:9222"}}},
    )
    assert r.status == PASS


def test_extension_profile_is_excluded(tmp_path):
    """driver:"extension" is the one CDP endpoint OpenClaw authenticates: resolveProfile
    (config-DpWXcVmn.js:523-536) hardcodes cdpHost "127.0.0.1"/cdpIsLoopback true and
    embeds the extension relay token in the cdpUrl as HTTP credentials."""
    r = _browser(tmp_path, {"profiles": {"chrome": {"driver": "extension"}}})
    assert r.status == PASS


# ---------------------------------------------------------------------------
# C-135 (2026-07-26): WHATWG-vs-urlparse backslash divergence
# ---------------------------------------------------------------------------
# WHATWG treats "\" as equivalent to "/" inside a special-scheme URL; Python's urlparse
# does not. So the two disagree about where the authority ends, and one string can aim
# them at different hosts. OpenClaw parses cdpUrl with `new URL()` itself
# (normalizeExistingSessionCdpUrl, config-DpWXcVmn.js:326-342), so the BROWSER's reading
# is the one that matters and Python's was the wrong one.

_DECOY = "http://10.0.0.9:9222\\@127.0.0.1"


def test_backslash_decoy_is_classified_as_offhost(tmp_path):
    """Python's urlparse reads this as host 127.0.0.1 (loopback -- apparently safe);
    a browser reads it as 10.0.0.9:9222. Without the fix the check reported clean."""
    r = _browser(tmp_path, {"cdpUrl": _DECOY})
    assert r.status == WARN


def test_backslash_decoy_evidence_names_the_real_host_not_the_decoy(tmp_path):
    """The report must not print the attacker's decoy loopback host: a verdict and the
    host it names have to come from one reading of one string."""
    r = _browser(tmp_path, {"cdpUrl": _DECOY})
    line = next(e for e in r.evidence if "browser.cdpUrl" in e)
    assert "10.0.0.9" in line
    assert "127.0.0.1" not in line


def test_backslash_decoy_in_managed_profile_is_offhost(tmp_path):
    r = _browser(tmp_path, {"profiles": {"w": {"driver": "openclaw", "cdpUrl": _DECOY}}})
    assert r.status == WARN


# The slash RUN, not just the backslash (C-135 second pass). WHATWG's "special authority
# ignore slashes" state consumes ANY run of '/' and '\' between the scheme and the
# authority, so all of `http:HOST`, `http:/HOST`, `http:///HOST`, `http:\HOST`,
# `http:/\/\HOST` resolve to HOST in a browser. urlparse finds no authority in any of
# them and reports hostname None, which this module classified "unparseable" -- and
# _offhost_cdp_endpoints() treats "unparseable" as nothing to report, so B330 returned a
# PASS whose own text asserts "every CDP endpoint it names is loopback". A lying PASS on
# attacker-controllable input (the schema puts no .url() refinement on cdpUrl,
# zod-schema-O9ml_nmo.js:1096), i.e. the B2/B70 `0.0.0.0/0` failure mode.
#
# Verified against the real product oracle -- Node `new URL()` plus OpenClaw's own
# isLoopbackHost imported live from the installed dist -- over a 61-case matrix:
# before this fix 5 false positives / 22 lying passes / 12 false negatives; after it,
# 61/61 agreement.
_SLASH_RUNS = ("", "/", "//", "///", "////", "\\", "\\\\", "\\\\\\", "\\\\\\\\",
               "/\\", "\\/", "/\\/\\", "//\\\\")


def test_slash_run_offhost_cdp_url_is_never_a_silent_pass(tmp_path):
    """Every slash-run spelling of an off-host cdpUrl must be seen as off-host."""
    for idx, run in enumerate(_SLASH_RUNS):
        url = f"http:{run}10.0.0.9:9222"
        r = _browser(tmp_path, {"cdpUrl": url}, name=f"run{idx}")
        assert r.status == WARN, url
        assert any("10.0.0.9" in e for e in r.evidence), url


def test_slash_run_loopback_cdp_url_still_passes(tmp_path):
    """The other direction: the normalization must not invent an off-host host for a
    loopback URL written with an odd slash run."""
    for idx, run in enumerate(_SLASH_RUNS):
        url = f"http:{run}127.0.0.1:9222"
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"lb{idx}").status == PASS, url


def test_slash_run_escalates_b322_scored_fail(tmp_path):
    """Highest blast radius: the shared parser feeds B322's SCORED FAIL, so a slash-run
    off-host cdpUrl on an existing-session profile must reach FAIL, not a soft WARN."""
    for idx, run in enumerate(("", "/", "\\", "///", "/\\/\\")):
        url = f"http:{run}10.0.0.9:9222"
        home = _home(tmp_path, {"browser": {"profiles": {
            "user": {"driver": "existing-session", "cdpUrl": url}}}}, name=f"b322_{idx}")
        r = check_browser_existing_session_profile(collect(home))
        assert r.status == FAIL, url
        assert r.scored is True, url


# WHATWG removes ASCII tab/LF/CR from the input as its very FIRST step, before any
# parsing state runs. Python's urlsplit strips them too (bpo-43882), so the pre-B-337
# code got this right by accident -- but rebuilding the string as `scheme + "://" + rest`
# re-emits the whitespace immediately after the `://`, where it sits inside the authority
# and collapses the netloc, reopening the same lying PASS. That made it a REGRESSION
# introduced by the slash-run rewrite, not a leftover gap: dev classified
# `http:<TAB>//10.0.0.9:9222` as "remote"; the rewrite alone made it "unparseable".
_WS = ("\t", "\n", "\r")


def test_whitespace_in_scheme_run_is_never_a_silent_pass(tmp_path):
    for idx, ws in enumerate(_WS):
        for jdx, url in enumerate((
            f"http:{ws}//10.0.0.9:9222",
            f"http:{ws}\\10.0.0.9:9222",
            f"http:/{ws}/10.0.0.9:9222",
            f"http://{ws}10.0.0.9:9222",
            f"http:{ws}10.0.0.9:9222",
        )):
            r = _browser(tmp_path, {"cdpUrl": url}, name=f"ws{idx}_{jdx}")
            assert r.status == WARN, repr(url)
            assert any("10.0.0.9" in e for e in r.evidence), repr(url)


def test_whitespace_in_scheme_run_escalates_b322_scored_fail(tmp_path):
    """The consequential leg: B322's SCORED FAIL must survive the whitespace trick."""
    for idx, ws in enumerate(_WS):
        url = f"http:{ws}//10.0.0.9:9222"
        home = _home(tmp_path, {"browser": {"profiles": {
            "user": {"driver": "existing-session", "cdpUrl": url}}}}, name=f"wsb322_{idx}")
        r = check_browser_existing_session_profile(collect(home))
        assert r.status == FAIL, repr(url)
        assert r.scored is True, repr(url)


def test_whitespace_does_not_break_a_loopback_url(tmp_path):
    for idx, ws in enumerate(_WS):
        url = f"http:{ws}//127.0.0.1:9222"
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"wslb{idx}").status == PASS, repr(url)


# D1 (C-135, fifth pass): the trim set. The real pipeline removes from each end the
# UNION of `value.trim()` (string-coerce-DW4mBlAt.js:9) and `new URL()`'s own "strip
# leading/trailing C0 control or space". Python's argument-less .strip() is neither set:
# it misses U+0000-U+0008, U+000E-U+001F and U+FEFF (BOM), and it over-strips U+0085
# (NEL). A BOM- or NUL-prefixed cdpUrl therefore parsed as unparseable here while the
# product resolved it happily -- B330 PASS asserting "every CDP endpoint it names is
# loopback", B322 downgraded from scored FAIL to unscored WARN.
_D1_PREFIXES = ("﻿", "\x00", "\x01", "\x08", "\x0e", "\x1b", "\x1f", "\xa0", " ", "　")


def test_exotic_leading_whitespace_is_never_a_silent_pass(tmp_path):
    for idx, ch in enumerate(_D1_PREFIXES):
        for jdx, url in enumerate((
            ch + "http://10.0.0.9:9222",
            ch + "http:\\\\10.0.0.9:9222",
            ch + "http:10.0.0.9:9222",
        )):
            r = _browser(tmp_path, {"cdpUrl": url}, name=f"d1_{idx}_{jdx}")
            assert r.status == WARN, repr(url)
            assert any("10.0.0.9" in e for e in r.evidence), repr(url)


def test_exotic_trailing_whitespace_does_not_break_loopback(tmp_path):
    for idx, ch in enumerate(_D1_PREFIXES):
        url = "http://127.0.0.1:9222" + ch
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"d1t{idx}").status == PASS, repr(url)


def test_nel_is_not_stripped_because_the_product_does_not_strip_it(tmp_path):
    """U+0085 NEL is in neither the C0 range the URL parser strips nor trim()'s set, so
    the product does NOT remove it -- `new URL()` rejects the value outright. Over-
    stripping it here would make us resolve a URL the product never accepts."""
    r = _browser(tmp_path, {"cdpUrl": "\x85http://10.0.0.9:9222"})
    assert r.status != FAIL


# D2 (C-135, fifth pass): a bracket in the USERINFO. Python's urlsplit validates []
# against the whole netloc and raises before userinfo is removed; WHATWG's authority
# state finds the last "@" FIRST and only validates brackets after it. So the original
# `10.0.0.9:9222\@127.0.0.1` decoy just moves one character left of the "@".
_D2_URLS = (
    "http://[x]@10.0.0.9:9222",
    "http://[::1]@10.0.0.9:9222",
    "http://a@[::1]@10.0.0.9:9222",
    "http://u:[::1]@10.0.0.9:9222",
    "http://[x]@10.0.0.9:9222/path",
)


def test_bracket_in_userinfo_is_never_a_silent_pass(tmp_path):
    for idx, url in enumerate(_D2_URLS):
        r = _browser(tmp_path, {"cdpUrl": url}, name=f"d2_{idx}")
        assert r.status == WARN, url
        assert any("10.0.0.9" in e for e in r.evidence), url


def test_bracket_in_userinfo_escalates_b322_scored_fail(tmp_path):
    for idx, url in enumerate(_D2_URLS):
        home = _home(tmp_path, {"browser": {"profiles": {
            "user": {"driver": "existing-session", "cdpUrl": url}}}}, name=f"d2b322_{idx}")
        r = check_browser_existing_session_profile(collect(home))
        assert r.status == FAIL, url
        assert r.scored is True, url


def test_real_ipv6_hosts_still_parse(tmp_path):
    """The userinfo split must not break a genuine bracketed IPv6 authority."""
    assert _browser(tmp_path, {"cdpUrl": "http://[::1]:9222"}, name="v6a").status == PASS
    assert _browser(
        tmp_path, {"cdpUrl": "http://[::ffff:127.0.0.1]:9222"}, name="v6b").status == PASS
    assert _browser(
        tmp_path, {"cdpUrl": "http://[2001:db8::1]:9222"}, name="v6c").status == WARN


def test_credentials_are_not_echoed_in_evidence(tmp_path):
    """Side effect of splitting userinfo off: the displayed URL can no longer carry
    embedded credentials, matching OpenClaw's own redactCdpUrl intent."""
    r = _browser(tmp_path, {"cdpUrl": "http://alice:hunter2@10.0.0.9:9222"})
    assert r.status == WARN
    joined = " ".join(r.evidence)
    assert "hunter2" not in joined
    assert "alice" not in joined


def test_degenerate_dot_host_is_not_treated_as_loopback(tmp_path):
    """LOOPBACK contains "" as a member, so a bare rstrip(".") would strip "." or "..."
    to "" and match it -- calling loopback a host the product rejects
    (measured: the dist's isLoopbackHost(".") is false). The guard keeps the undotting
    genuinely one-directional."""
    for idx, url in enumerate(("http://.:9222", "http://..:9222", "http://...:9222")):
        r = _browser(tmp_path, {"cdpUrl": url}, name=f"dot{idx}")
        # Not loopback => B330 must report it, not emit the "everything is loopback" PASS.
        assert r.status == WARN, url


def test_localhost_trailing_dot_is_not_a_false_positive(tmp_path):
    """OpenClaw's parseHostForAddressChecks strips EVERY trailing dot before comparing
    to "localhost" (net-BOKtNTf8.js), so `http://localhost.:9222` is genuinely loopback
    to the product -- and `localhost.` is a far likelier human typo than `127.0.0.1.`."""
    for idx, url in enumerate(("http://localhost.:9222", "http://localhost..:9222")):
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"ldot{idx}").status == PASS, url


def test_trailing_dot_loopback_is_not_a_false_positive(tmp_path):
    """PRE-EXISTING false positive (predates B-337; found by the same independent
    differential against Node's `new URL()`): WHATWG's IPv4 parser drops one empty
    trailing label, so `http://127.0.0.1.:9222` is hostname "127.0.0.1" to a browser and
    to OpenClaw's own isLoopbackHost -- genuinely loopback -- but both `ipaddress` and
    `inet_aton` reject the dotted string, so it classified "remote". That made B322 emit
    a SCORED FAIL on a loopback-only config."""
    assert _browser(tmp_path, {"cdpUrl": "http://127.0.0.1.:9222"}).status == PASS


def test_trailing_dot_fix_is_one_directional(tmp_path):
    """The fix must never reclassify a genuinely remote host as loopback: a real
    hostname written FQDN-style is still rejected by inet_aton and stays remote."""
    for idx, url in enumerate((
        "http://example.com.:9222", "http://evil.example.:9222", "http://10.0.0.9.:9222",
    )):
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"fqdn{idx}").status == WARN, url


def test_ordinary_loopback_urls_are_unaffected_by_the_normalization(tmp_path):
    """The backslash fix must not reclassify anything that has no backslash in it."""
    for idx, url in enumerate((
        "http://127.0.0.1:9222", "http://localhost:9222", "ws://127.0.0.1:9222",
        "http://127.1:9222", "http://2130706433:9222",
    )):
        assert _browser(tmp_path, {"cdpUrl": url}, name=f"case{idx}").status == PASS, url


# ---------------------------------------------------------------------------
# Garbage in must never FAIL (Golden Rule #5)
# ---------------------------------------------------------------------------

def test_malformed_values_never_fail(tmp_path):
    for idx, browser in enumerate((
        {"cdpUrl": 12345},
        {"cdpUrl": ""},
        {"cdpUrl": "not a url at all"},
        {"extraArgs": "not-a-list"},
        {"extraArgs": [None, 42, ""]},
        {"profiles": "not-a-dict"},
        {"profiles": {"w": "not-a-dict"}},
        {"profiles": {"w": {}}},
    )):
        assert _browser(tmp_path, browser, name=f"case{idx}").status != FAIL, browser
