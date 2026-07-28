"""B322 (E-060 batch, 2026-07-25): browser.profiles.*.{cdpUrl,userDataDir,
driver:"existing-session"}.

driver:"existing-session" spawns a third-party chrome-devtools-mcp subprocess and hands
it cdpUrl/userDataDir as raw CLI args. getBrowserProfileCapabilities()
(cdp-reachability-policy-BLdT5iz3.js:9-19) hardcodes isRemote:false for this driver, so
OpenClaw's own SSRF hostname-allowlist requirement never gates an existing-session
cdpUrl the way it would a genuinely remote managed-Chrome connection.

Severity shape:
  - no openclaw.json found                                         -> UNKNOWN
  - no browser config                                               -> UNKNOWN
  - no profile has an in-effect driver of "existing-session"        -> PASS
  - in-effect existing-session profile, cdpUrl absent/loopback      -> WARN (scored=False)
  - in-effect existing-session profile, cdpUrl unparseable          -> WARN (scored=False)
  - in-effect existing-session profile, cdpUrl non-loopback         -> FAIL (scored=True)

This module is offline, read-only, and writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_existing_session_profile
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
    r = check_browser_existing_session_profile(collect(FIXTURES / "clean_b322_browser_existing_session"))
    assert r.status == PASS


def test_bad_fixture_fails():
    r = check_browser_existing_session_profile(collect(FIXTURES / "bad_b322_browser_existing_session"))
    assert r.status == FAIL
    assert any("remote-debug" in e for e in r.evidence)
    assert r.scored is True


# ---------------------------------------------------------------------------
# UNKNOWN baselines
# ---------------------------------------------------------------------------

def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_existing_session_profile(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_no_browser_config_is_unknown(tmp_path):
    r = check_browser_existing_session_profile(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_unparseable_config_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{not valid json", encoding="utf-8")
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: no in-effect existing-session driver
# ---------------------------------------------------------------------------

def test_no_existing_session_profile_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"noSandbox": False}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == PASS


def test_managed_openclaw_driver_profile_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "main": {"driver": "openclaw", "color": "#123456"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == PASS


def test_dormant_builtin_user_profile_is_not_flagged(tmp_path):
    """The implicit built-in "user" profile (driver:existing-session) always exists
    unless overridden -- but it stays dormant unless explicitly selected via
    defaultProfile or referenced by name at runtime (invisible to static config). Its
    bare, never-selected existence must not WARN on effectively every browser config."""
    home = _home(tmp_path, config={"browser": {"noSandbox": False}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == PASS


def test_user_profile_redefined_to_different_driver_passes(tmp_path):
    """browser.profiles.user explicitly overrides the driver away from existing-session
    -- even with defaultProfile:"user", the built-in existing-session shape no longer
    applies."""
    home = _home(tmp_path, config={"browser": {
        "defaultProfile": "user",
        "profiles": {"user": {"driver": "openclaw", "color": "#123456"}},
    }})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == PASS


def test_cdp_url_on_non_existing_session_profile_is_ignored(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "main": {"driver": "openclaw", "cdpUrl": "http://10.0.0.5:9222", "color": "#123456"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN: existing-session in effect, cdpUrl absent / loopback / unparseable
# ---------------------------------------------------------------------------

def test_explicit_existing_session_no_cdp_url_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "attachOnly": True, "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert r.scored is False
    assert any("no cdpUrl" in e for e in r.evidence)


def test_explicit_existing_session_loopback_cdp_url_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127.0.0.1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert r.scored is False


def test_explicit_existing_session_localhost_cdp_url_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "ws://localhost:9222/devtools/browser/x", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_unparseable_cdp_url_warns_not_fails(tmp_path):
    """Ambiguous suppression -> WARN, not FAIL/UNKNOWN (this project's own precedent):
    a cdpUrl that cannot be classified must not escalate to FAIL on an unproven claim."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "not a url", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert any("not a parseable URL" in e for e in r.evidence)


def test_implicit_user_profile_selected_via_default_profile_warns(tmp_path):
    """No explicit browser.profiles.user block, but defaultProfile explicitly selects
    the built-in "user" profile -- a deliberate driver selection even though no profile
    block is written out."""
    home = _home(tmp_path, config={"browser": {"defaultProfile": "user"}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert any("browser.profiles.user" in e for e in r.evidence)


def test_user_data_dir_disclosed_as_warn_evidence(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {
            "driver": "existing-session",
            "cdpUrl": "http://127.0.0.1:9222",
            "userDataDir": "~/.config/google-chrome/Default",
            "color": "#00AA00",
        }
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert any("userDataDir" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# FAIL: non-loopback cdpUrl
# ---------------------------------------------------------------------------

def test_remote_cdp_url_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://203.0.113.5:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL
    assert r.scored is True
    assert any("203.0.113.5" in e for e in r.evidence)


def test_all_interfaces_cdp_url_fails(tmp_path):
    """0.0.0.0 is "every interface", not loopback -- must FAIL, matching OpenClaw's own
    isLoopbackHost semantics (net-BOKtNTf8.js:219-224)."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://0.0.0.0:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_ipv6_unspecified_cdp_url_fails(tmp_path):
    """:: is the IPv6 analogue of 0.0.0.0 -- must FAIL, not be treated as loopback."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "ws://[::]:9222/devtools/browser/x", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_credentials_in_cdp_url_are_not_echoed(tmp_path):
    """cdpUrl may carry embedded userinfo credentials (OpenClaw's own redactCdpUrl
    strips them before any diagnostic display) -- evidence must never echo them."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {
            "driver": "existing-session",
            "cdpUrl": "ws://admin:s3cr3t-token@203.0.113.5:9222/devtools/browser/x",
            "color": "#00AA00",
        }
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL
    joined = " ".join(r.evidence)
    assert "s3cr3t-token" not in joined
    assert "admin" not in joined
    assert "203.0.113.5" in joined


# ---------------------------------------------------------------------------
# C-135 regression: non-canonical numeric IPv4 loopback forms must WARN, not
# FAIL -- OpenClaw's own `new URL()` (WHATWG host parsing) canonicalizes these
# to a genuine loopback dotted-quad before the URL is ever stored or handed to
# chrome-devtools-mcp, so Python's stricter `ipaddress` module (which rejects
# every one of these forms) was producing a false-positive FAIL on a config
# that actually resolves to, and dials, loopback.
# ---------------------------------------------------------------------------

def test_shorthand_loopback_cdp_url_warns_not_fails(tmp_path):
    """"127.1" is classic BSD/inet_aton shorthand for 127.0.0.1 -- Node's `new URL()`
    (what normalizeExistingSessionCdpUrl actually uses) canonicalizes it to
    "127.0.0.1" before storing cdpHost/cdpIsLoopback, confirmed directly against
    Node. Python's ipaddress module rejects "127.1" outright (non-canonical), which
    without the fix misclassified this as "remote" -> a false-positive FAIL."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127.1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert r.scored is False


def test_zero_padded_loopback_cdp_url_warns_not_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127.000.000.001:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_octal_loopback_cdp_url_warns_not_fails(tmp_path):
    """"0177.0.0.1" -- leading-zero octets are classic-BSD octal (0177 octal = 127
    decimal); Node's URL host parser interprets it the same way and canonicalizes
    to 127.0.0.1."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://0177.0.0.1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_decimal_integer_loopback_cdp_url_warns_not_fails(tmp_path):
    """"2130706433" is the bare 32-bit decimal form of 127.0.0.1."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://2130706433:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_hex_loopback_cdp_url_warns_not_fails(tmp_path):
    """"0x7f000001" is the bare 32-bit hex form of 127.0.0.1."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://0x7f000001:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_non_canonical_form_of_real_remote_ip_still_fails(tmp_path):
    """The fix must only ever ADD a loopback verdict, never remove a "remote" one:
    a canonical, unambiguous public IP must keep failing exactly as before."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://203.0.113.5:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_hostname_that_embeds_a_loopback_literal_still_fails(tmp_path):
    """SSRF-bypass shape check: a hostname that merely CONTAINS "127.0.0.1" as a
    substring/subdomain must not be swept into the new inet_aton fallback and
    reclassified as loopback -- socket.inet_aton legitimately rejects this whole
    string (it is not a bare numeric literal), so it must fall through to "remote"
    unchanged."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127.0.0.1.evil.com:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_fail_takes_precedence_when_multiple_profiles(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127.0.0.1:9222", "color": "#00AA00"},
        "remote": {"driver": "existing-session", "cdpUrl": "http://203.0.113.5:9222", "color": "#AA0000"},
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL
    assert any("remote" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# C-357 regression: IDNA/fullwidth-digit homoglyph forms of 127.0.0.1 must WARN,
# not FAIL -- a browser's WHATWG "domain to ASCII" host parser folds non-ASCII
# label-separator dots (U+3002/U+FF0E/U+FF61) and fullwidth digits (U+FF10-FF19)
# to their ASCII equivalents before isLoopbackHost ever sees the host, so these
# spellings dial genuine loopback in the real product. An IME substituting the
# ideographic full-width dot for ASCII "." while a user types a URL is a
# realistic, non-adversarial way to produce this -- not just a crafted string.
# ---------------------------------------------------------------------------

def test_ideographic_full_stop_loopback_cdp_url_warns_not_fails(tmp_path):
    """U+3002 IDEOGRAPHIC FULL STOP used in place of every ASCII '.' -- measured:
    '127。0。0。1'.encode('idna') == b'127.0.0.1'."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127。0。0。1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN
    assert r.scored is False


def test_fullwidth_full_stop_loopback_cdp_url_warns_not_fails(tmp_path):
    """U+FF0E FULLWIDTH FULL STOP -- NFKC-normalizes straight to ASCII '.' even
    without going through the idna codec, but exercised here via the same path."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127．0．0．1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_halfwidth_ideographic_full_stop_loopback_cdp_url_warns_not_fails(tmp_path):
    """U+FF61 HALFWIDTH IDEOGRAPHIC FULL STOP -- the fourth dot-equivalent RFC 3490
    S3.1 / WHATWG both recognize."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://127｡0｡0｡1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_fullwidth_digit_loopback_cdp_url_warns_not_fails(tmp_path):
    """Fullwidth-digit spelling of 127.0.0.1 (U+FF11 FULLWIDTH DIGIT ONE etc.), ASCII
    dots -- measured: '１２７.0.0.1'.encode('idna') == b'127.0.0.1'."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://１２７.0.0.1:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_fullwidth_digits_and_ideographic_dots_combined_warns_not_fails(tmp_path):
    """Both homoglyph classes at once -- the realistic IME-produced shape."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://１２７。０。０。１:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == WARN


def test_idna_homoglyph_fix_is_one_directional(tmp_path):
    """The fix must only ever ADD a loopback verdict, never remove one: a genuinely
    remote IP written with the same dot-equivalent characters must keep failing."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "cdpUrl": "http://203。0。113。5:9222", "color": "#00AA00"}
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_idna_unencodable_host_never_fails_open_to_loopback(tmp_path):
    """A non-ASCII host idna cannot encode -- a single 70-char Greek-letter label,
    measured to raise UnicodeError("label empty or too long") from the stdlib idna
    codec -- must fall through to the existing logic on the ORIGINAL host unchanged.
    It must not silently become "loopback"; this genuinely non-loopback, non-numeric
    host classifies "remote" exactly as it did before this fix, so existing-session
    still FAILs (Golden Rule #5's "never lie a config clean" cuts the other way here:
    this must not become an accidental loopback PASS/WARN)."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {
            "driver": "existing-session",
            "cdpUrl": "http://" + "α" * 70 + ":9222",
            "color": "#00AA00",
        }
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL


def test_oversized_non_ascii_host_is_never_idna_processed(tmp_path):
    """C-135 perf finding: nameprep walks a whole non-ASCII label doing per-character
    stringprep table lookups BEFORE its own length check can fire, so an
    attacker-controlled non-ASCII host with no dots can force expensive work. Length-
    gated at _IDNA_HOST_MAX_CHARS (512, well above RFC 1035's 253-char DNS ceiling) --
    a host past that gate must classify exactly as it did before this fix (remote,
    via the plain fallthrough), never hang or get reclassified."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {
            "driver": "existing-session",
            "cdpUrl": "http://" + "α" * 600 + ":9222",
            "color": "#00AA00",
        }
    }}})
    r = check_browser_existing_session_profile(collect(home))
    assert r.status == FAIL
