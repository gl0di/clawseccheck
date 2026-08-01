"""Topic module: egress checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import ipaddress
import os
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

from ..catalog import (
    FAIL,
    MEDIUM,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    LIMIT_DOMAIN_CONFIG,
    Context,
    dig,
)
from . import _shared
from ._shared import (
    LOOPBACK,
    OUTBOUND_TOOL_HINTS,
    _channels,
    _config_unreadable,
    _custom,
    _enabled_tools,
    _finding,
    _has_approval_gate,
    _hint,
    _KNOWN_EXFIL_HOST_RE,
    _mcp_has_remote,
    _mcp_servers,
    _mcp_url_is_local,
    _plugins,
    _read_jsonl_tail,
    _surface_absent,
    correlation_indicators,
    parse_bind_host,
)


# ---------- B14: egress surface (advisory) ----------
_EXT_SKILL_HINTS = (
    "slack",
    "github",
    "notion",
    "google",
    "gmail",
    "web",
    "research",
    "http",
    "telegram",
    "obsidian",
    "browser",
    "fetch",
    "discord",
    "1password",
)


# ---------- Shared: egress-allowlist quality (weak-mitigation detection) ----------
# An allowlist entry can be technically "present" yet still a weak mitigation if it
# admits (a) a wildcard pattern, (b) a domain that hosts anonymous/user-generated
# content an attacker could stage a payload on, or (c) a URL-rewriting proxy that will
# relay to an arbitrary attacker-chosen target — despite the host itself being "trusted".
# Used by both B38 (browser.ssrfPolicy.hostnameAllowlist) and C014 (MCP allowedHosts).
#
# C-342 (ESET H1 2026 "AI-fix"): AI-vendor user-content publishing surfaces belong in
# the same category — claude.ai serves arbitrary attacker-controlled pages at
# /public/artifacts/…, and chatgpt.com serves them at /share/… (both confirmed against
# the vendors' own docs, 2026-08-01) — exactly like gist.github.com. Deliberately the
# SPECIFIC consumer-product host, not the vendor's root domain: adding "anthropic.com"
# or "openai.com" here would suffix-match legitimate API/docs subdomains
# (api.anthropic.com, docs.anthropic.com) via the matching below and false-positive on
# every skill that merely calls the provider's API. copilot.microsoft.com included on
# the same reasoning (Copilot Pages sharing is real and documented; the exact share-URL
# path segment could not be independently confirmed, but the host-level match already
# avoids the root-domain over-broadening this note warns about).
_USER_CONTENT_HOSTS = frozenset(
    {
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "gist.github.com",
        "gist.githubusercontent.com",
        "raw.githubusercontent.com",
        "ix.io",
        "transfer.sh",
        "0x0.st",
        "discord.com",
        "webhook.site",
        "claude.ai",
        "chatgpt.com",
        "copilot.microsoft.com",
    }
)

# F-158 (TA488/Void Blizzard OWAReaper, CVE-2026-42897, 2026-07-22 Proofpoint report):
# a URL-rewriting image/CDN proxy in an allowlist is equivalent to an open allowlist —
# the proxy host is trusted, but the target it relays is attacker-chosen. OWAReaper
# exfiltrated over HTTPS by relaying through exactly these hosts. Each grounded
# 2026-08-02:
# - images.weserv.nl / wsrv.nl: open-source image proxy, forwards an arbitrary "?url="
#   target to any origin (github.com/weserv/images — "nginx used as forward proxy").
# - i0-i3.wp.com (Jetpack "Photon"): official docs scope it to WordPress/Jetpack-
#   connected sites, but the Photon URL rewrite form independently proxies images from
#   any external origin regardless of that restriction — exactly the mechanism OWAReaper
#   abused. Not corrected upstream as of this grounding.
# - slack-imgs.com: Slack's own image-proxy/unfurl CDN (api.slack.com/robots,
#   Slack-ImgProxy) — refetches and re-serves the image at any URL posted into Slack.
#   C-135 note (2026-08-02): the exact per-URL scoping of Slack's proxy tokens is not
#   independently confirmed here (unlike Camo's public HMAC scheme below) — inclusion
#   rests on real-world abuse (OWAReaper used it as a live exfil relay per the
#   Proofpoint report), at WARN severity, not on a confirmed "any URL, unscoped" proof.
#   Revisit if Slack's proxy-token scheme is ever independently confirmed either way.
#
# Deliberately does NOT include camo.githubusercontent.com (already in _content.py's
# _B59_BADGE_HOSTS): Camo requires a 40-hex-char SHA1 HMAC over the target URL, keyed
# with a GitHub-only secret, so an attacker cannot mint a valid camo.githubusercontent.com
# URL for an arbitrary target — a materially different, non-abusable mechanism. Grounded
# 2026-08-02; left in _B59_BADGE_HOSTS unchanged.
_URL_PROXY_HOSTS = frozenset(
    {
        "images.weserv.nl",
        "wsrv.nl",
        "slack-imgs.com",
        "i0.wp.com",
        "i1.wp.com",
        "i2.wp.com",
        "i3.wp.com",
    }
)

# Combined lookup for _weak_allowlist_entries — kept as a separate constant so the two
# source categories above stay independently documented and greppable.
_WEAK_ALLOWLIST_HOSTS = _USER_CONTENT_HOSTS | _URL_PROXY_HOSTS


def _weak_allowlist_entries(allowlist) -> list[str]:
    """Return the subset of an allowlist that is a weak mitigation.

    Flags wildcard patterns (bare "*" or "*.example.com"), known user-content /
    anonymous-paste / webhook hosts, and known URL-rewriting image/CDN proxies
    (matched by exact host or domain suffix, after stripping a leading "*." if
    present). Non-string / malformed entries are ignored (best-effort, no FAIL on
    unparseable data).
    """
    weak: list[str] = []
    if not isinstance(allowlist, list):
        return weak
    for entry in allowlist:
        if not isinstance(entry, str) or not entry.strip():
            continue
        host = entry.strip().lower()
        if host == "*" or host.startswith("*."):
            weak.append(entry)
            continue
        bare = host[2:] if host.startswith("*.") else host
        if bare in _WEAK_ALLOWLIST_HOSTS or any(
            bare == h or bare.endswith("." + h) for h in _WEAK_ALLOWLIST_HOSTS
        ):
            weak.append(entry)
    return weak


# B-362: shared not_applicable gate for the "no browser config" UNKNOWN branch that
# B38/B195/B196/B321/B322/B330 all share verbatim (one locus, `ctx.config["browser"]`,
# checked the same way by every one of them). Grounded against the installed dist
# (~/.npm-global/lib/node_modules/openclaw/dist, openclaw@2026.7.1-2, 2026-07-30):
# tools-effective-inventory-D78fLEDu.js:63 `hasExplicitBrowserIntent` --
# `cfg.browser?.enabled !== false && Boolean(cfg.browser || cfg.plugins?.entries?.browser)`
# -- is OpenClaw's OWN definition of "browser is configured/intended", and it ORs two
# loci: the top-level `browser` block these checks already read, AND the bundled
# browser plugin's alternate `plugins.entries.browser` enablement path (browser ships
# as `bundledPluginId: "browser"` per sdk-alias-BJSUcD8n.js:303). A raw config with NO
# `browser` key can still have live browser-tool config through that second path, so
# not_applicable must require both to be absent -- mirrors _plugins()'s own legacy/
# entries-shape handling rather than re-deriving it.
def _browser_surface_absent(ctx: Context) -> bool:
    return not _plugins(ctx.config).get("browser") and _surface_absent(
        ctx, LIMIT_DOMAIN_CONFIG
    )


def check_browser_ssrf(ctx: Context) -> Finding:
    """B38 — Browser control / cookie & SSRF exposure.

    FAIL    — browser is configured AND (dangerouslyAllowPrivateNetwork == true
              OR noSandbox == true). Either flag is a CRITICAL-class primitive:
              private-network access enables cloud-metadata credential theft;
              no-sandbox means the headless browser can escape OS isolation.
    WARN    — browser is configured but ssrfPolicy.hostnameAllowlist is absent
              (open egress surface — the browser can reach any external host);
              OR the hostnameAllowlist is present but contains a wildcard entry or a
              known user-content/anonymous-paste/webhook host — a weak mitigation an
              attacker could stage payloads on despite the host being "trusted".
    PASS    — browser is configured AND sandboxed AND private network is blocked
              AND a hostnameAllowlist is present with no weak entries.
    UNKNOWN — no browser config (not applicable).
    """
    cfg = ctx.config
    browser = cfg.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B38",
            UNKNOWN,
            "No browser config — browser SSRF / cookie exposure not applicable.",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    ssrf_policy = browser.get("ssrfPolicy") if isinstance(browser.get("ssrfPolicy"), dict) else {}
    allow_private = ssrf_policy.get("dangerouslyAllowPrivateNetwork")
    no_sandbox = browser.get("noSandbox")
    allowlist = ssrf_policy.get("hostnameAllowlist")

    fail_ev: list[str] = []
    if allow_private is True:
        fail_ev.append(
            "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork=true — "
            "agent browser can reach internal/metadata IPs (169.254.169.254 cloud-credential theft)"
        )
    if no_sandbox is True:
        fail_ev.append(
            "browser.noSandbox=true — headless browser runs without OS sandbox "
            "(process-escape risk)"
        )

    if fail_ev:
        return _finding(
            "B38",
            FAIL,
            "; ".join(fail_ev),
            "Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false to block "
            "cloud-metadata IP access; set browser.noSandbox to false (or omit it) to "
            "keep the OS sandbox active. Also add browser.ssrfPolicy.hostnameAllowlist "
            "to restrict which hosts the browser may reach.",
            evidence=fail_ev,
        )

    # WARN: browser is configured but no hostnameAllowlist — open egress surface
    has_allowlist = isinstance(allowlist, list) and len(allowlist) > 0
    if not has_allowlist:
        return _finding(
            "B38",
            WARN,
            "Browser is configured with no ssrfPolicy.hostnameAllowlist — the agent "
            "browser can fetch any external URL (open egress / SSRF surface).",
            "Add browser.ssrfPolicy.hostnameAllowlist listing only the domains the "
            "browser legitimately needs to reach; set "
            "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false.",
        )

    # QUALITY: allowlist present but contains a wildcard, known user-content host, or
    # known URL-rewriting proxy — downgrade PASS to WARN. Still additive/advisory: does
    # not touch FAIL behaviour.
    weak_entries = _weak_allowlist_entries(allowlist)
    if weak_entries:
        return _finding(
            "B38",
            WARN,
            "Browser hostnameAllowlist is present but contains weak entries "
            "(wildcard, known user-content/paste/webhook host, and/or URL-rewriting "
            f"image/CDN proxy): {', '.join(weak_entries)} — an attacker could stage a "
            "payload on a wildcard match, an anonymous content host, or relay "
            "exfiltrated data through a proxy host despite the allowlist.",
            "Replace wildcard entries with explicit hostnames, and avoid allowlisting "
            "anonymous paste/gist/webhook hosts (e.g. pastebin.com, gist.github.com, "
            "raw.githubusercontent.com, webhook.site) or URL-rewriting image/CDN "
            "proxies (e.g. images.weserv.nl, i0-i3.wp.com, slack-imgs.com) — an "
            "attacker-controlled target can be reached through them even though the "
            "proxy host itself is 'trusted'.",
            evidence=weak_entries,
        )

    return _finding(
        "B38",
        PASS,
        "Browser is configured: sandboxed, private-network access blocked, "
        "and hostnameAllowlist is present.",
        "Keep browser.noSandbox unset/false, "
        "dangerouslyAllowPrivateNetwork=false, and maintain a tight hostnameAllowlist.",
    )


# B195 (E-060 item 2): flags matched by exact pre-'=' token, never substring -- e.g.
# "--proxy-server-bypass-list" must not match "--proxy-server" (C-135 guidance).
#
# Matched case-INsensitively. C-309 (2026-07-26) corrected the reason recorded here: the
# previous note claimed Chromium's base::CommandLine lowercases every switch name it
# parses. That is NOT universally true -- the lowercasing in base::CommandLine lives
# behind a Windows-only build guard (the `BUILDFLAG(IS_WIN)` path in AppendSwitchNative /
# the switch-map insertion), so on POSIX, where OpenClaw's managed Chrome actually runs,
# switch names are matched case-SENSITIVELY and "--DISABLE-WEB-SECURITY" is NOT
# recognized by Chrome as "--disable-web-security". Case-insensitive matching is
# nonetheless the right behaviour for a DETECTOR and is deliberately kept: this check
# reports operator intent to disable a browser protection, and a scanner that only
# recognizes the exact casing is trivially evaded by a shift key. The cost of being
# generous here is bounded -- the worst case is reporting a flag that Chrome would have
# ignored anyway, which is a strictly safer error than staying silent on one it honours.
# Corroborated from the OpenClaw side independently of Chromium's own casing rule:
# OpenClaw's chromeArgName() helper (chrome-DDq_K3xu.js:156-158) lowercases before its
# internal proxy-arg checks, so mixed case genuinely does change OpenClaw's own
# behaviour even where it would not change Chrome's.
#
# B-337: keys are the DASHLESS switch name, because the leading dashes are not part of
# the name Chrome matches on -- see _chrome_switch_name() below.
_EXTRA_ARGS_FAIL_FLAGS = {
    "disable-web-security": (
        "disables the browser's same-origin policy entirely -- any page can read "
        "any other origin's cookies/DOM/responses"
    ),
    "load-extension": (
        "loads an arbitrary Chrome extension at launch -- an extension has broader "
        "page/cookie/network access than the page content itself"
    ),
}
# --proxy-auto-detect and --proxy-pac-url join --proxy-server in OpenClaw's own
# PROXY_ROUTING_CHROME_ARGS set (chrome-DDq_K3xu.js:161-163, grounded via a C-135 pass,
# 2026-07-25) -- all three flip resolveBrowserNavigationProxyMode() to
# "explicit-browser-proxy" and all three suppress OpenClaw's own defensive
# --no-proxy-server injection. B195 originally covered only --proxy-server.
_EXTRA_ARGS_WARN_FLAGS = {
    "proxy-server": (
        "reroutes all browser traffic through the configured proxy -- confirm the "
        "target is trusted"
    ),
    "proxy-auto-detect": (
        "enables Chrome's automatic proxy detection (WPAD) -- on an untrusted network "
        "WPAD can be spoofed to redirect browser traffic through an attacker proxy"
    ),
    "proxy-pac-url": (
        "points the browser at a proxy auto-config (PAC) script -- confirm the URL is "
        "trusted, since a malicious PAC script can redirect arbitrary traffic through "
        "an attacker-controlled proxy"
    ),
}
_REMOTE_DEBUG_ADDRESS_SWITCH = "remote-debugging-address"


# B-337: a Chrome switch is spelled with ONE or TWO leading dashes, and Chrome honours
# both identically. Chromium's base::CommandLine carries a kSwitchPrefixes table which on
# POSIX is {"--", "-"}; GetSwitchPrefixLength() returns the length of the FIRST entry that
# prefixes the argument, and the switch name is whatever follows it up to the '='. So
# `-remote-allow-origins=*` reaches Chrome as exactly the same switch as
# `--remote-allow-origins=*`, and B195's old `flag_lower == "--..."` comparison reported
# the single-dash spelling of its own FAIL conditions as clean -- a false negative in a
# HIGH check, and the spelling a careless copy-paste is most likely to produce.
#
# MEASURED, not inferred (2026-07-26, Google Chrome 150.0.7871.186, headless, local): a
# cross-origin CDP WebSocket upgrade against the DevTools port returns 403 by default;
# with `--remote-allow-origins=*` it returns 101, and with `-remote-allow-origins=*` --
# one dash -- it ALSO returns 101. The single-dash spelling is honoured by real Chrome.
#
# The "first matching prefix" rule is why this must NOT be written as `lstrip("-")`:
# `---remote-allow-origins=*` matches the "--" entry first, so its switch NAME is
# `-remote-allow-origins`, which matches nothing Chrome knows. That was measured on the
# same run: the triple-dash spelling returned 403, i.e. it changed nothing. Peeling every
# dash would turn that inert string into a finding -- trading the false negative for a
# false positive. Exactly one or two dashes, therefore, and nothing else.
#
# Grounded from the OpenClaw side too: OpenClaw's own chromeArgName()
# (chrome-DDq_K3xu.js:156-158) is `arg.trim().split("=",1)[0]?.toLowerCase()` -- it takes
# the pre-'=' token and lowercases it but does NOT normalize the dash prefix, so its
# PROXY_ROUTING_CHROME_ARGS / PROXY_CONTROL_CHROME_ARGS sets (spelled with "--") do not
# recognize a single-dash proxy arg either. That is an OpenClaw-side blind spot, not a
# reason to copy it: OpenClaw then injects its own --no-proxy-server alongside the
# operator's single-dash -proxy-server=..., and Chromium resolves --no-proxy-server ahead
# of the other proxy switches, so the operator's proxy is silently not used. The config
# does not do what they wrote -- precisely the "real but lower-certainty risk" the WARN
# tier exists for.
def _chrome_switch_name(arg: str, *, casefold: bool = True) -> str:
    """Dashless switch name of a Chrome launch argument, or "" if not a switch.

    "--Proxy-Server=http://x" and "-proxy-server=http://x" both yield "proxy-server";
    "---disable-web-security", "chrome://flags" and a bare "--" yield "".

    *casefold* (default True) lowercases the result, which is what a DETECTOR wants --
    see the C-309 note above _EXTRA_ARGS_FAIL_FLAGS. Pass casefold=False when the caller
    needs the name EXACTLY as Chrome will match it: on POSIX, Chromium's switch lookup is
    case-SENSITIVE, so `--REMOTE-ALLOW-ORIGINS=*` is not the same switch as
    `--remote-allow-origins=*` and does nothing. Measured on Google Chrome 150.0.7871.186
    (cross-origin CDP WebSocket upgrade; 403 = inert, 101 = honoured), 2026-07-26:
        --remote-allow-origins=*   -> 101      --REMOTE-ALLOW-ORIGINS=* -> 403
        --remote-allow-origins= *  -> 101      --Remote-Allow-Origins=* -> 403
    (the space row also shows Chrome trims the value, which is why callers strip it).
    A rung that hard-caps a grade must key on the exact-case name; a rung that merely
    reports intent may use the casefolded one.
    """
    stripped = arg.strip()
    if stripped.startswith("--"):
        body = stripped[2:]
    elif stripped.startswith("-"):
        body = stripped[1:]
    else:
        return ""
    name = body.partition("=")[0]
    return name.lower() if casefold else name


# B-331: OpenClaw ALWAYS launches its managed Chrome with
# `--remote-debugging-port=${profile.cdpPort}` (chrome-DDq_K3xu.js:1662-1689,
# buildOpenClawChromeLaunchArgs) -- CDP is how OpenClaw drives the browser at all -- and NO
# dist file anywhere sets `--remote-debugging-address`, so Chrome's default loopback bind
# applies and OpenClaw's own cdpUrlForPort() is `http://127.0.0.1:${cdpPort}`
# (chrome-DDq_K3xu.js:1659). Two consequences, both grounded in that one fact:
#   * A loopback-bound operator flag (--remote-debugging-address=127.0.0.1 and friends)
#     changes NOTHING -- it restates the default already in force, which is the defensive
#     thing to write down. It therefore costs no score and produces no evidence line. The
#     previous WARN also mis-attributed causation: it told the operator their flag "opens
#     an unauthenticated ... debug port on loopback" when OpenClaw's own always-present
#     --remote-debugging-port opened it, so removing the flag could not have closed it.
#   * A NON-loopback operator flag was, until B-337, treated as a FAIL on the reasoning
#     that the port is always there so moving its bind off-host exposes it. That FAIL has
#     been RETRACTED -- see the measurement note on _remote_debug_bind_class below.
#
# B-337 / C-135 (2026-07-26): --remote-debugging-address NO LONGER EXISTS IN CHROMIUM.
# The FAIL above was a false positive -- it docked a grade for a switch modern Chrome
# silently ignores. Chromium removed the switch in M113 as part of the same hardening
# that made the DevTools endpoint origin-checked; the debug port now always binds
# loopback and can only be moved by an external forwarder, never by a Chrome flag.
# Measured directly rather than taken on faith (2026-07-26, Google Chrome
# 150.0.7871.186, headless, local, `ss -lnt` on the listening socket):
#     --remote-debugging-port=P                                -> 127.0.0.1:P
#     --remote-debugging-port=P --remote-debugging-address=0.0.0.0        -> 127.0.0.1:P
#     --remote-debugging-port=P --remote-debugging-address=192.168.31.233 -> 127.0.0.1:P
# i.e. the bind does not move, for the "all interfaces" value OR for a real interface
# address. Corroborated structurally: the string "remote-debugging-address" does not
# appear anywhere in the Chrome 150 binary's switch table, while its neighbours
# "remote-debugging-pipe", "remote-debugging-port" and "remote-allow-origins" all do.
#
# The flag is therefore reported at WARN, not FAIL, and the loopback spellings stay
# silent as before. WARN rather than silence because the value still carries real
# information -- it records an operator INTENT to expose the control port off-host, and
# on a pre-M113 Chrome binary (which an operator can pin via browser.executablePath) it
# would genuinely bind off-host. What it must not do is assert an off-host bind that
# provably does not happen on any currently-supported Chrome.
def _remote_debug_bind_class(value: str) -> str:
    """Classify a --remote-debugging-address value: "loopback", "offhost" or "unresolved".

    "loopback" -- the value names the bind Chrome uses anyway, so the flag is a no-op
    twice over (once because it restates the default, once because M113 removed the
    switch). Silent, costs nothing. Recognized in every spelling Chrome's own address
    parser accepted and a C-135 pass (2026-07-25) found the original bare
    `{"127.0.0.1","localhost","::1"}` set false-FAILed on: an IPv4 host:port suffix, a
    bracketed IPv6 `[::1]:port`, a bare full-form IPv6 loopback (`0:0:0:0:0:0:0:1`) --
    plus, added by B-337, the IPv4-MAPPED IPv6 form `::ffff:127.0.0.1`. Python's
    `ipaddress` reports `is_loopback` False for the mapped form (its `_ip` is not 1), yet
    it denotes 127.0.0.1, so it has to be unmapped before the test or a loopback-bound
    config draws a spurious finding.

    "offhost" -- the value denotes a real address that is not loopback (0.0.0.0, ::,
    10.0.0.5, ...). Reported at WARN as an intent signal; NOT a FAIL, because the switch
    is inert on modern Chrome (see the measurement above).

    "unresolved" -- not an address literal in any form recognized here (a DNS hostname,
    "*", a typo). Also WARN: the effective bind cannot be determined from the config, and
    "cannot determine" inside an otherwise-applicable check is this project's WARN case.

    The numeric fallback mirrors _cdp_url_classify() in this same module, for the same
    reason and with the same one-way discipline: `socket.inet_aton` implements the legacy
    BSD numeric-host parsing behind the shorthand/octal/hex/bare-decimal IPv4 forms
    ("127.1", "0177.0.0.1", "127.000.000.001", "2130706433", "0x7f000001") which Python's
    strict `ipaddress` rejects outright. Without it, `127.1` -- an ordinary way to write
    loopback -- classified as non-loopback. It only ever ADDS a loopback verdict, never
    removes one, so it cannot mask a genuinely off-host value.
    """
    host = value.strip()
    if not host:
        return "unresolved"
    # rstrip(".") mirrors OpenClaw's parseHostForAddressChecks (see _cdp_url_classify).
    if host.lower().rstrip(".") == "localhost":
        return "loopback"
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            host = host[1:end]
    elif host.count(":") == 1:
        candidate, _, port = host.rpartition(":")
        if port.isdigit():
            host = candidate
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        mapped = getattr(ip, "ipv4_mapped", None)
        return "loopback" if (mapped or ip).is_loopback else "offhost"
    # Trailing dots are dropped on the retry, for the same reason and with the same
    # one-way discipline as _cdp_url_classify() -- see its C-135 note. "127.0.0.1." is
    # loopback to a browser; a hostname written FQDN-style is still rejected by
    # inet_aton and still falls through unchanged.
    for candidate in (host, host.rstrip(".")):
        try:
            canonical = socket.inet_ntoa(socket.inet_aton(candidate))
        except (OSError, UnicodeError):
            continue
        return "loopback" if canonical in LOOPBACK else "offhost"
    return "unresolved"


def check_browser_extra_args(ctx: Context) -> Finding:
    """B195 — browser.extraArgs dangerous Chrome launch flags (E-060 item 2).

    browser.extraArgs is pushed verbatim into the Chrome launch command with no
    validation -- unlike B38's own ssrfPolicy/noSandbox keys, nothing here is
    interpreted by OpenClaw first.

    FAIL    — a flag in _EXTRA_ARGS_FAIL_FLAGS is present.
    WARN    — a flag in _EXTRA_ARGS_WARN_FLAGS is present, OR
              --remote-debugging-address carries a value that is not loopback (B-337:
              an intent signal, downgraded from FAIL because Chromium removed the switch
              in M113 and modern Chrome ignores it -- see _remote_debug_bind_class).
    PASS    — extraArgs is absent/empty, or contains no matched flag. A loopback-bound
              --remote-debugging-address lands here: it restates the bind OpenClaw's own
              launch already uses, so it is a no-op and costs no score (B-331 -- see the
              grounding note above _remote_debug_bind_class).
    UNKNOWN — no browser config (not applicable).

    Flag matching is case-insensitive (a deliberate detector choice -- see the C-309 note
    above _EXTRA_ARGS_FAIL_FLAGS for why, and why the old "Chromium lowercases every
    switch" justification was wrong) and accepts BOTH the one-dash and two-dash spelling
    Chrome itself honours (B-337, see _chrome_switch_name).

    NOT COVERED HERE, on purpose: --remote-allow-origins. It is an extraArgs flag, but
    what it changes is who may reach the CDP control port, so it is graded by B330
    alongside the rest of that surface rather than split across two checks.
    """
    browser = ctx.config.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B195",
            UNKNOWN,
            "No browser config — extraArgs not applicable.",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    extra_args = browser.get("extraArgs")
    if not isinstance(extra_args, list) or not extra_args:
        return _finding(
            "B195",
            PASS,
            "browser.extraArgs is absent or empty — no extra Chrome launch flags configured.",
            "—",
        )

    fail_ev: list[str] = []
    warn_ev: list[str] = []
    for raw in extra_args:
        if not isinstance(raw, str) or not raw.strip():
            continue
        arg = raw.strip()
        flag, _, value = arg.partition("=")
        switch = _chrome_switch_name(arg)
        if not switch:
            continue

        if switch in _EXTRA_ARGS_FAIL_FLAGS:
            fail_ev.append(f"browser.extraArgs has {flag!r} — {_EXTRA_ARGS_FAIL_FLAGS[switch]}")
            continue
        if switch == _REMOTE_DEBUG_ADDRESS_SWITCH:
            # No address after the '=' (or a bare switch): nothing was named, so there is
            # nothing to report.
            if not value.strip():
                continue
            bind_class = _remote_debug_bind_class(value)
            # Loopback-bound: a no-op that restates OpenClaw's own default bind. Costs
            # nothing and produces no evidence line (B-331).
            if bind_class == "loopback":
                continue
            if bind_class == "unresolved":
                # Not an address literal in any recognized form (a DNS hostname, "*", a
                # typo) -- the effective bind cannot be determined from this value at
                # all, which is distinct from "offhost" naming a real non-loopback
                # address below. "cannot be determined" is this project's standing
                # phrasing for an applicable check that cannot resolve a fact.
                warn_ev.append(
                    f"browser.extraArgs has {arg!r} — the effective bind for the "
                    "Chrome DevTools Protocol debug port cannot be determined from "
                    "this value (not a recognized address literal). Chromium REMOVED "
                    "the --remote-debugging-address switch in M113, so current Chrome "
                    "ignores it regardless; this is reported as an unresolvable "
                    "statement of intent, not a confirmed bind."
                )
                continue
            warn_ev.append(
                f"browser.extraArgs has {arg!r} — this names a non-loopback bind for the "
                "Chrome DevTools Protocol debug port that OpenClaw itself opens on every "
                "managed browser launch (--remote-debugging-port). Chromium REMOVED the "
                "--remote-debugging-address switch in M113, so current Chrome ignores it "
                "and the port stays on loopback — this is reported as a statement of "
                "intent, and as a real exposure only if this agent is pinned to a "
                "pre-M113 Chrome via browser.executablePath, not as a confirmed off-host "
                "bind"
            )
            continue
        if switch in _EXTRA_ARGS_WARN_FLAGS:
            warn_ev.append(f"browser.extraArgs has {flag!r} — {_EXTRA_ARGS_WARN_FLAGS[switch]}")

    if fail_ev:
        return _finding(
            "B195",
            FAIL,
            f"browser.extraArgs contains {len(fail_ev)} dangerous Chrome launch "
            "flag(s) — see evidence.",
            "Remove the dangerous flag(s) from browser.extraArgs — neither "
            "--disable-web-security nor --load-extension has a safe setting; if a "
            "workflow needs one, give it a dedicated throwaway browser profile rather "
            "than the profile the agent drives.",
            evidence=(fail_ev + warn_ev)[:6],
        )
    if warn_ev:
        return _finding(
            "B195",
            WARN,
            f"browser.extraArgs contains {len(warn_ev)} flag(s) with a real but "
            "lower-certainty risk — see evidence.",
            "Review the flagged entries: confirm any proxy target or PAC URL is "
            "trusted, and prefer removing the flag if the proxy is not required. Drop "
            "any --remote-debugging-address entirely — Chromium removed that switch in "
            "M113, so it does nothing on current Chrome, and OpenClaw already supplies "
            "--remote-debugging-port on every managed launch with Chrome binding it to "
            "loopback by default.",
            evidence=warn_ev[:6],
        )
    return _finding(
        "B195",
        PASS,
        f"browser.extraArgs is configured with {len(extra_args)} flag(s), none "
        "matching a known-dangerous pattern.",
        "Keep browser.extraArgs free of --disable-web-security, --load-extension, "
        "and unreviewed --proxy-server entries.",
    )


# ---------- B196 corroboration: is the sink pointed at a browser OpenClaw does not own? ----------
# The two drivers below hand the agent a browser process OpenClaw did NOT launch -- the
# operator's own, already-signed-in one. Grounded in the installed dist:
#   * zod-schema-O9ml_nmo.js:1120-1131 -- browser.profiles.<name>.driver is a four-way
#     union, "openclaw" | "clawd" | "existing-session" | "extension". The first two are
#     OpenClaw's own managed Chrome; only these two attach to a foreign browser.
#   * cdp-reachability-policy-BLdT5iz3.js:11-30 getBrowserProfileCapabilities() resolves
#     "existing-session" to mode "local-existing-session" (usesChromeMcp: true) and
#     "extension" to mode "local-extension" -- both explicitly local-attach modes.
#   * The vendor's own field docs say WHICH browser that is: docs/tools/browser.md:324 --
#     `driver: "extension"` "drives your signed-in Chrome through the OpenClaw Chrome
#     extension"; schema-DRyO1XBt.js:279 -- an existing-session `userDataDir` targets
#     "Brave, Edge, Chromium, or non-default Chrome profiles", i.e. a real user profile.
#   * config-DpWXcVmn.js:391-410 -- OpenClaw SYNTHESIZES a `user` profile (driver
#     "existing-session", attachOnly true) and a `chrome` profile (driver "extension") at
#     resolve time whenever the operator's file does not define them. Those synthesized
#     profiles live only in the resolved runtime config, never in the openclaw.json this
#     check reads, and stay dormant until a tool call selects them. So an explicit
#     `driver` written in the operator's OWN file is a rare, deliberate, hand-written
#     signal -- never the vendor default. B322 rests on the identical distinction, and
#     that is exactly why this corroborator does not fire on an ordinary browser config.
#   * config-DpWXcVmn.js:589 -- for the managed "openclaw" driver the effective
#     attach-only flag is `profile.attachOnly ?? resolved.attachOnly`, so a top-level
#     browser.attachOnly is inherited by any profile that does not override it. Combined
#     with a non-loopback cdpUrl that is the "externally managed remote CDP provider"
#     shape the vendor documents at schema-DRyO1XBt.js:273 -- again a browser OpenClaw
#     neither launched nor owns.
_UNOWNED_SESSION_DRIVERS = ("existing-session", "extension")


def _browser_unowned_session_evidence(browser: dict) -> list[str]:
    """Evidence lines for every operator-written signal that the browser tool drives a
    session OpenClaw did not launch. Empty list == no such signal (the ordinary
    managed-Chrome config), which is what keeps this off the fleet-wide false-FAIL path.

    Reads ONLY keys the operator actually wrote; never OpenClaw's synthesized default
    profiles (see the grounding note above). Deliberate v1 scope limit, stated rather
    than hidden: when `browser.profiles` is written but omits "openclaw",
    ensureDefaultProfile() synthesizes that profile from the top-level cdpUrl/cdpPort --
    the top-level attach-only pair is therefore only evaluated when no profiles block
    exists at all, so that synthesized-profile corner is a known false negative, never a
    false positive.
    """
    ev: list[str] = []
    profiles = browser.get("profiles")
    profiles = profiles if isinstance(profiles, dict) else {}
    top_attach_only = browser.get("attachOnly") is True
    top_cdp_url = browser.get("cdpUrl")

    for name, spec in sorted(profiles.items(), key=lambda kv: str(kv[0])):
        if not isinstance(spec, dict):
            continue
        driver = spec.get("driver")
        if driver in _UNOWNED_SESSION_DRIVERS:
            ev.append(
                f"browser.profiles.{name}.driver={driver!r} — this profile attaches to a "
                "browser OpenClaw did not launch (the operator's own, already-signed-in "
                "session), so the evaluate sink runs inside it"
            )
            continue
        attach_only = spec.get("attachOnly")
        if not isinstance(attach_only, bool):
            attach_only = top_attach_only
        cdp_url = spec.get("cdpUrl")
        if not (isinstance(cdp_url, str) and cdp_url.strip()):
            cdp_url = top_cdp_url
        if attach_only and _cdp_url_classify(cdp_url) == "remote":
            ev.append(
                f"browser.profiles.{name} is attach-only against "
                f"cdpUrl={_cdp_url_display(cdp_url)} (non-loopback) — OpenClaw attaches "
                "to an externally managed browser on another host instead of launching "
                "its own, so the evaluate sink runs inside that foreign browser"
            )
    if not profiles and top_attach_only and _cdp_url_classify(top_cdp_url) == "remote":
        ev.append(
            f"browser.attachOnly=true with browser.cdpUrl={_cdp_url_display(top_cdp_url)} "
            "(non-loopback) — OpenClaw attaches to an externally managed browser on "
            "another host instead of launching its own, so the evaluate sink runs inside "
            "that foreign browser"
        )
    return ev


def check_browser_evaluate_enabled(ctx: Context) -> Finding:
    """B196 — browser.evaluateEnabled arbitrary-JS sink (E-060 item 3).

    OpenClaw defaults this to true when the key is absent (grounded:
    dist/config-DpWXcVmn.js:441 `cfg?.evaluateEnabled ?? true`, the defaults table
    dist/config-D9HgDUPt.js:103 `"browser.evaluateEnabled": true`, and the same
    `?? true` resolution in dist/sandbox-DtTssSMH.js:394,1299; enforced at
    dist/routes-VNv3nd0n.js:1274) -- every page the browser tool visits becomes an
    arbitrary-JS execution sink reachable from content injected into that page.

    EFFECTIVE-STATE GRADING (B-331). This check grades what the machine DOES, never
    which keys the operator happened to type. Because the vendor default is true, an
    ABSENT key and an explicit `true` are byte-for-byte the same runtime exposure, so
    they MUST reach the same status. They previously did not (absent -> WARN, explicit
    true -> FAIL), which made the grade gameable by a no-op edit -- deleting the line
    moved a config two letter grades with nothing changing on the machine -- inverted
    the incentive to write your configuration down explicitly, and left the common case
    (nobody writes the key) on the lenient rung.

    FAIL    — the sink is ON **and** the config points the browser tool at a session
              OpenClaw does not launch or own: a hand-written
              browser.profiles.*.driver of "existing-session"/"extension", or an
              attach-only profile against a non-loopback cdpUrl (see
              _browser_unowned_session_evidence and its grounding note). Arbitrary JS
              then executes inside the operator's real, already-signed-in browser, so
              one injected page reaches every cookie and live session in it.
    WARN    — the sink is ON with no such corroboration: evaluateEnabled is absent
              (vendor default true), OR explicitly true, OR set to any other non-`false`
              value (which cannot be confirmed disabled).
    PASS    — evaluateEnabled is explicitly false (the only state that closes the sink).
    UNKNOWN — no browser config at all (the browser tool is not in use).

    WHY THE FAIL IS CORROBORATED RATHER THAN UNCONDITIONAL. Sink-ON alone is the
    documented vendor default of a documented feature (act:evaluate / wait --fn), so an
    unconditional HIGH FAIL would cap the grade of essentially every browser-tool user
    for shipping defaults -- the same two-grade swing on an unchanged machine that the
    effective-state fix above exists to remove, just pointing the other way. The
    corroborators are chosen to be the opposite of that: each is an explicit,
    rare, hand-written key with no vendor-default spelling in the operator's own file,
    and each is orthogonal to the reachability leg B38 grades
    (ssrfPolicy.hostnameAllowlist / dangerouslyAllowPrivateNetwork), so this neither
    fires on ordinary configs nor double-counts B38.

    NOT DELEGATED TO THE RISK ENGINE. An earlier revision of this docstring justified a
    flat WARN by saying the sink-plus-reachability combination was "the risk engine's
    job". No RISK rule reads B196 or evaluateEnabled at all -- both browser chains
    (RISK-03 _rule_browser_ssrf_secrets, RISK-15 _rule_injection_browser_ssrf) gate
    solely on _browser_ssrf(), which is B38-FAIL-or-dangerouslyAllowPrivateNetwork and
    never consults the sink. That hand-off did not exist, so the escalation is graded
    here, where the evidence is.
    """
    browser = ctx.config.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B196",
            UNKNOWN,
            "No browser config — evaluateEnabled not applicable (browser tool not configured).",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    evaluate_enabled = browser.get("evaluateEnabled")

    if evaluate_enabled is False:
        return _finding(
            "B196",
            PASS,
            "browser.evaluateEnabled=false — the browser's arbitrary-JS evaluate "
            "sink is disabled.",
            "Keep browser.evaluateEnabled=false unless a specific workflow needs "
            "page-JS evaluation.",
        )

    if evaluate_enabled is True:
        spelling = "browser.evaluateEnabled=true"
    elif "evaluateEnabled" not in browser:
        spelling = "browser.evaluateEnabled is not set"
    else:
        spelling = (
            "browser.evaluateEnabled is set to a value that is not the boolean false"
        )

    # The corroboration is read the same way for every spelling, so absent and explicit
    # `true` still land on one bar at BOTH levels -- the effective-state fix survives.
    unowned = _browser_unowned_session_evidence(browser)
    if unowned:
        return _finding(
            "B196",
            FAIL,
            f"{spelling} — the browser's arbitrary-JS evaluate sink is ON, and this "
            "config points the browser tool at a session OpenClaw does not launch or "
            "own (see evidence). Content on any page the agent visits can therefore "
            "execute arbitrary JavaScript inside the operator's real, already-signed-in "
            "browser, reaching every cookie and live session in it (browser-tool "
            "prompt-injection → account takeover). OpenClaw applies no extra evaluate "
            "restriction to those drivers: evaluateEnabled is resolved once, globally, "
            "and is the only gate — its vendor default is true, so an absent key and an "
            "explicit true are the same runtime state and only an explicit false "
            "disables it.",
            "Set browser.evaluateEnabled=false — OpenClaw's own field documentation "
            "says to keep it disabled unless a workflow needs evaluate semantics beyond "
            "snapshots/navigation. If a workflow genuinely requires page-JS evaluation, "
            "do not point it at a signed-in session: give the agent a dedicated managed "
            "profile (driver \"openclaw\") instead, and pair the sink with a tight "
            "browser.ssrfPolicy.hostnameAllowlist (B38) to limit which pages reach it.",
            evidence=unowned[:6],
        )

    return _finding(
        "B196",
        WARN,
        f"{spelling} — the browser's arbitrary-JS evaluate sink is ON, so every page "
        "the agent's browser tool visits is an arbitrary-JS execution sink reachable "
        "from content injected into that page (browser-tool prompt-injection → "
        "code-exec). OpenClaw's vendor default for this key is true, so leaving it out "
        "does not turn the sink off — an absent key and an explicit true are the same "
        "runtime state, and only an explicit false disables it.",
        "Set browser.evaluateEnabled=false explicitly unless a specific workflow "
        "genuinely requires page-JS evaluation (act:evaluate / wait --fn); if it does, "
        "pair it with a tight browser.ssrfPolicy.hostnameAllowlist (B38) to limit which "
        "pages can reach the sink.",
    )


# Every field the provider-request TLS object actually has, per the installed dist
# (`ConfiguredProviderRequestTlsSchema`). `insecureSkipVerify` is the only one B155
# JUDGES; the other five are recognized purely as proof that a real TLS transport was
# DECLARED, so a custom-CA / SNI-override config is not mistaken for an empty stub.
# Split by type because "declared" means something different for each: a bool is
# substantive at either value (an explicit `false` is still a declaration), whereas a
# string field is only substantive when non-blank.
_B155_TLS_BOOL_FIELDS = ("insecureSkipVerify",)
_B155_TLS_STR_FIELDS = ("ca", "cert", "key", "passphrase", "serverName")


def _b155_tls_is_substantive(tls: dict) -> bool:
    """True when a ``request.tls`` / ``request.proxy.tls`` object declares a real TLS
    setting, rather than being an empty or unrecognized-shape stub.

    The recognized set is the COMPLETE field list of this schema object, not a guess --
    keeping it complete is what stops a legitimate config from being under-claimed as a
    stub. An earlier revision recognized only ``insecureSkipVerify``, which sent a real
    ``{serverName, ca}`` pin into the stub bucket and reported "no outbound proxy
    configured": fail-safe (never a false PASS) but still a false negative on a declared
    transport.

    ``insecureSkipVerify: false`` DOES count -- the operator explicitly declared
    verification on, which is an assessable, clean setting. That is deliberately different
    from the bare ``request.allowPrivateNetwork: false`` case, which is a loose
    request-level boolean rather than a declared transport object; see the call site.

    Presence only: no value is ever read into detail/evidence, so the secret-shaped
    ``passphrase`` field is tested for declaration and never echoed (§8).
    """
    if any(isinstance(tls.get(f), bool) for f in _B155_TLS_BOOL_FIELDS):
        return True
    return any(
        isinstance(tls.get(f), str) and tls.get(f).strip()
        for f in _B155_TLS_STR_FIELDS
    )


def _b155_proxy_is_substantive(pxy: dict) -> bool:
    """True when a ``request.proxy`` object declares a real transport, not a stub.

    Recognizes the fields this check actually reads or that the provider-request schema
    documents for the object: a non-blank ``url``, a non-blank ``mode`` (e.g.
    ``"explicit-proxy"``), or a nested ``tls`` object that is itself substantive. An empty
    dict, or one carrying only keys we do not recognize, is NOT a transport -- promoting
    it to PASS would claim we assessed something we never parsed.
    """
    for key in ("url", "mode"):
        val = pxy.get(key)
        if isinstance(val, str) and val.strip():
            return True
    nested = pxy.get("tls")
    return isinstance(nested, dict) and _b155_tls_is_substantive(nested)


def check_outbound_proxy(ctx: Context) -> Finding:
    """B155 — Outbound proxy hardening (credential leak / TLS-verify / SSRF-guard bypass).

    Audits OpenClaw's OUTBOUND proxy surface — the top-level managed forward proxy
    (`proxy.*`) plus per-provider request proxy/TLS options and web_fetch's env-proxy
    trust. Distinct from the INBOUND reverse-proxy trust in C032 / gateway.trustedProxies
    (do not conflate). Absence of a proxy is the default and is NEVER a FAIL (§5).

    FAIL    — proxy.proxyUrl (or a provider's request.proxy.url) embeds credentials
              (http://user:pass@host): a secret sits in plaintext in openclaw.json
              (only runtime logs are redacted).
    WARN    — a provider disables proxy/endpoint TLS verification
              (models.providers.*.request.proxy.tls.insecureSkipVerify or
              request.tls.insecureSkipVerify) → MITM; request.allowPrivateNetwork → SSRF;
              tools.web.fetch.useTrustedEnvProxy → bypasses the local SSRF/DNS-rebind guard.
    PASS    — a managed proxy is configured with a clean (credential-free) URL, OR a
              per-provider request.proxy/request.tls transport is configured and clean
              with no top-level proxy.* block.
    UNKNOWN — no outbound proxy configured (the default): advisory nudge, never a FAIL.
              F-140: sets ``not_applicable`` only when the config locus was read
              COMPLETELY and NO proxy surface is declared — neither the top-level
              ``proxy.*`` block nor any per-provider ``models.providers.*.request.proxy``
              / ``.tls`` object.

              Surface presence is evaluated DIRECTLY, never inferred from "the signal
              scan found nothing". Inferring it was a real bug (caught by C-135 review):
              a configured-and-clean per-provider proxy produced no FAIL/WARN, fell to
              this branch, and was reported not-applicable — telling the owner the check
              did not apply to them about a proxy they had actually configured.
              ``allowPrivateNetwork`` and ``tools.web.fetch.useTrustedEnvProxy`` are
              deliberately NOT treated as surface: they are booleans that only signal when
              true, so an explicit ``false`` is the default posture, not a declared proxy.

              There are THREE outcomes on this branch, not two, and the middle one is easy
              to lose in a refactor (a second C-135 round caught it being collapsed into
              PASS):

              * nothing declared anywhere -> UNKNOWN, ``not_applicable=True``.
              * a proxy/TLS object declared but EMPTY or carrying only unrecognized keys
                (a stub) -> UNKNOWN, ``not_applicable=False``. Nothing was assessable, so
                it cannot be PASS; but a proxy key WAS read, so absence was never proven
                and claiming it would be a fabricated negative.
              * a substantive object (see ``_b155_proxy_is_substantive`` /
                ``_b155_tls_is_substantive``) -> PASS/WARN/FAIL as the signals dictate.

              Why absence here is genuine inapplicability and not an unassessed risk:
              every exposure B155 models is a property OF a configured proxy — a
              credential embedded in a proxy URL, a proxy/endpoint TLS verification that
              was switched off, an env proxy the fetch tool was told to trust. None of
              them can exist without a proxy to carry them, so with no proxy declared
              there is no object left to assess. The host of course still has outbound
              traffic; judging THAT surface is a different check's job, and marking this
              one not-applicable makes no claim about it.

              Scope note: the flag rides the same branch as the existing advisory nudge
              and does not silence it. The detail text is unchanged, so this is not a
              claim that a managed proxy is unnecessary — only that this check's specific
              weakening signals have no place to live on this host.
    """
    from ..logsafe import sanitize_url_host_only  # noqa: PLC0415
    cfg = ctx.config

    proxy = dig(cfg, "proxy")
    proxy_url = dig(cfg, "proxy.proxyUrl")
    proxy_enabled = dig(cfg, "proxy.enabled")
    has_proxy_url = isinstance(proxy_url, str) and bool(proxy_url.strip())

    parsed = None
    if has_proxy_url:
        try:
            parsed = urlparse(proxy_url.strip())
        except (ValueError, AttributeError):
            parsed = None

    fails: list[str] = []
    warns: list[str] = []
    notes: list[str] = []

    # FAIL: a credential embedded in the managed-proxy URL is a plaintext secret in config.
    if parsed is not None and (parsed.username or parsed.password):
        fails.append(
            f"proxy.proxyUrl embeds credentials ({sanitize_url_host_only(proxy_url)}) — "
            "a secret sits in plaintext in openclaw.json (only runtime logs are redacted)"
        )

    # NOTE: proxy.enabled with no proxyUrl is NOT flagged — OpenClaw's resolveProxyUrl
    # falls back to the OPENCLAW_PROXY_URL env var, which this static check cannot see, so
    # "enabled without a config URL" is a legitimate (env-supplied) running config (§5, §4).

    # WARN: per-provider TLS-verify-disable / private-network egress. FAIL: an explicit-proxy
    # url can embed credentials — same secret-leak class as the top-level proxy.proxyUrl.
    # F-140 follow-up: the per-provider transport surface is recorded as PRESENT here,
    # independently of whether it produced a signal below. Before this, presence was only
    # ever inferred from `fails`/`warns` being non-empty, so a provider proxy that was
    # configured AND CLEAN fell through to the "no outbound proxy configured" UNKNOWN --
    # and, once F-140 landed, was reported not-applicable. That told the owner this check
    # did not apply to them about a proxy they had actually configured, which is the exact
    # lying-not-applicable shape the flag exists to prevent.
    #
    # Presence means a declared proxy/TLS OBJECT (`request.proxy` / `request.tls`), not any
    # request-level boolean. `allowPrivateNetwork` and `tools.web.fetch.useTrustedEnvProxy`
    # are deliberately excluded: they are only signals when true (and then they already
    # produce a WARN above), so treating an explicit `false` -- the default posture -- as
    # "a proxy exists here" would assert a surface nobody configured.
    #
    # A dict is not automatically a transport. `request.proxy: {}` (or one carrying only
    # unrecognized keys) declares NOTHING assessable, so counting it as surface would
    # promote a stub to "configured and clean" -- the mirror image of the bug above, and a
    # false PASS on a HIGH scored check. It is tracked SEPARATELY as `provider_stub`:
    # neither surface-present (nothing to assess -> no PASS) nor surface-absent (we DID
    # read a proxy key -> no not_applicable). That third state resolves to a plain
    # UNKNOWN, which is the honest answer for unassessable data (Golden Rule #4).
    # Mirrors the top-level block's own guard, which likewise requires
    # `proxy_enabled is True or has_proxy_url` before treating `proxy: {}` as real.
    provider_surface: list[str] = []
    provider_stub: list[str] = []
    providers = dig(cfg, "models.providers")
    if isinstance(providers, dict):
        for pid, pspec in providers.items():
            if not isinstance(pspec, dict):
                continue
            req = pspec.get("request")
            if not isinstance(req, dict):
                continue
            pxy = req.get("proxy")
            if isinstance(pxy, dict):
                if _b155_proxy_is_substantive(pxy):
                    provider_surface.append(
                        f"models.providers.{pid}.request.proxy is configured"
                    )
                else:
                    provider_stub.append(f"models.providers.{pid}.request.proxy")
            ptls_decl = req.get("tls")
            if isinstance(ptls_decl, dict):
                if _b155_tls_is_substantive(ptls_decl):
                    provider_surface.append(
                        f"models.providers.{pid}.request.tls is configured"
                    )
                else:
                    provider_stub.append(f"models.providers.{pid}.request.tls")
            if isinstance(pxy, dict):
                purl = pxy.get("url")
                if isinstance(purl, str) and purl.strip():
                    try:
                        pp = urlparse(purl.strip())
                    except (ValueError, AttributeError):
                        pp = None
                    if pp is not None and (pp.username or pp.password):
                        fails.append(
                            f"models.providers.{pid}.request.proxy.url embeds credentials "
                            f"({sanitize_url_host_only(purl)}) — a secret sits in plaintext in "
                            "openclaw.json (only runtime logs are redacted)"
                        )
            ptls = pxy.get("tls") if isinstance(pxy, dict) else None
            if isinstance(ptls, dict) and ptls.get("insecureSkipVerify") is True:
                warns.append(
                    f"models.providers.{pid}.request.proxy.tls.insecureSkipVerify=true — "
                    "proxy TLS certificate not verified (MITM surface)"
                )
            utls = req.get("tls")
            if isinstance(utls, dict) and utls.get("insecureSkipVerify") is True:
                warns.append(
                    f"models.providers.{pid}.request.tls.insecureSkipVerify=true — "
                    "model-endpoint TLS certificate not verified (MITM surface)"
                )
            if req.get("allowPrivateNetwork") is True:
                warns.append(
                    f"models.providers.{pid}.request.allowPrivateNetwork=true — "
                    "provider requests may reach private/metadata IPs (SSRF surface)"
                )

    # WARN: web_fetch trusts the env proxy → bypasses the local SSRF / DNS-rebind guard.
    if dig(cfg, "tools.web.fetch.useTrustedEnvProxy") is True:
        warns.append(
            "tools.web.fetch.useTrustedEnvProxy=true — web_fetch trusts the environment "
            "HTTP(S)_PROXY and lets it resolve DNS, bypassing the local SSRF/DNS-rebind "
            "guard (safe only if that proxy is operator-controlled)"
        )

    # note (NOT a WARN — §5: a plain http:// CONNECT proxy is documented-normal, TLS stays
    # end-to-end after CONNECT): only flag cleartext-to-proxy for a real non-loopback host.
    if parsed is not None and (parsed.scheme or "").lower() == "http":
        host = (parsed.hostname or "").lower()
        if host and host not in LOOPBACK and not host.startswith("127."):
            notes.append(
                "proxy.proxyUrl uses plain http:// to a non-loopback host "
                f"({sanitize_url_host_only(proxy_url)}) — the CONNECT handshake and any proxy "
                "auth travel in cleartext to the proxy; prefer https:// to the proxy endpoint"
            )

    if fails:
        return _finding(
            "B155", FAIL, "; ".join(fails),
            "Keep the proxy credential out of openclaw.json: use a credential-free proxy URL "
            "and supply auth via OPENCLAW_PROXY_URL / a secret store instead of userinfo in "
            "the config; prefer an https:// proxy endpoint.",
            evidence=fails + warns + notes,
        )
    if warns:
        shown = warns[:4]
        if len(warns) > 4:
            shown = shown + [f"(+{len(warns) - 4} more)"]
        return _finding(
            "B155", WARN,
            f"Outbound-proxy weakening ({len(warns)} signal(s)) — see evidence.",
            "Re-enable TLS verification (remove insecureSkipVerify), avoid "
            "request.allowPrivateNetwork, and only set tools.web.fetch.useTrustedEnvProxy "
            "when the env proxy is operator-controlled and enforces egress policy.",
            evidence=shown + notes,
        )
    if isinstance(proxy, dict) and (proxy_enabled is True or has_proxy_url):
        return _finding(
            "B155", PASS,
            "Managed outbound proxy is configured with no credential-in-URL, "
            "TLS-verify-disable, or SSRF-guard-bypass signals."
            + (f" Note: {notes[0]}" if notes else ""),
            "Keep the proxy URL credential-free (env / secret store), TLS verification on, "
            "and egress policy enforced at the proxy.",
            evidence=notes,
        )
    # F-140 follow-up: a per-provider proxy/TLS transport with no top-level proxy.* block.
    # Deliberately a DISTINCT detail string rather than reusing the sentence above: this
    # host has no managed forward proxy, so claiming one "is configured" would be a
    # different false statement. Only configs that previously landed on the UNKNOWN branch
    # can reach here, so no existing PASS fingerprint moves.
    if provider_surface:
        return _finding(
            "B155", PASS,
            f"Per-provider outbound transport is configured ({len(provider_surface)} "
            "setting(s)) with no credential-in-URL, TLS-verify-disable, or "
            "SSRF-guard-bypass signals; no top-level managed proxy (proxy.*) is set.",
            "Keep per-provider request.proxy URLs credential-free (env / secret store) and "
            "request.tls verification on. Optional: add a top-level managed proxy "
            "(proxy.enabled + a credential-free https:// proxy.proxyUrl) to centralize and "
            "audit egress.",
            evidence=provider_surface[:6] + notes,
        )
    return _finding(
        "B155", UNKNOWN,
        "No outbound proxy configured — the agent's egress goes direct (the default). "
        "A managed proxy (proxy.*) would centralize and log egress; informational, not required.",
        "Optional: set proxy.enabled + a credential-free https:// proxy.proxyUrl to route and "
        "audit the agent's outbound traffic through a controlled egress point.",
        # A stub proxy/TLS object means we DID read a declared proxy key and could not make
        # anything of it. Absence was therefore not established, so the flag stays False and
        # this reports as an ordinary unresolved UNKNOWN.
        not_applicable=(
            not provider_stub and _surface_absent(ctx, LIMIT_DOMAIN_CONFIG)
        ),
    )


# B178 — hosts OpenClaw's own runtime treats as "the local machine" for a model-
# provider baseUrl, beyond literal loopback (LOOPBACK). Grounded against the
# installed dist (~/.npm-global/lib/node_modules/openclaw/dist):
#   selection-JInn13lc.js:10859 isExplicitLocalHostnameBaseUrl — docker.orb.internal /
#     host.docker.internal / host.orb.internal
#   selection-JInn13lc.js:10844 isLocalOllamaBaseUrl's own host===... check — "0.0.0.0"
#   discovery-shared-XxlmIfaG.js:37-46 LOCAL_OLLAMA_HOSTNAMES includes the above plus "::"
#   runtime-C40mDMdO.d.ts:7 LMSTUDIO_DOCKER_HOST_BASE_URL="http://host.docker.internal:1234"
#     — a first-party OpenClaw constant, not a hypothetical attacker value.
# Deliberately NOT merged into the shared LOOPBACK set: LOOPBACK is also read for a
# *gateway bind* (B73, EXPOSED_BINDS) where "0.0.0.0" means "listening on every
# interface" — the opposite of local. These two sets model different questions
# ("is this URL's target host local?" vs "is this bind exposed?") over overlapping
# literals and must stay separate.
_B178_LOCAL_MODEL_HOSTNAMES = {
    "0.0.0.0", "::", "docker.orb.internal", "host.docker.internal", "host.orb.internal",
}

# B178 — IPv4/IPv6 ranges that never leave the private network (RFC1918 + link-local +
# CGNAT + IPv6 ULA). A cleartext http:// baseUrl pointed at one of these can only be
# intercepted by an on-LAN adversary, not the public Internet, so it is WARN, not FAIL.
# Grounded against the same dist: selection-JInn13lc.js:10850 isLoopbackOllamaBaseUrl
# treats 10/8, 172.16/12, 192.168/16 AND 100.64.0.0/10 (CGNAT — the range Tailscale
# hands out) as local; discovery-shared-XxlmIfaG.js:61-66 isIpv4PrivateRange agrees on
# 10/8, 172.16/12, 192.168/16. 169.254.0.0/16 (link-local) and fc00::/7 (IPv6 ULA) are
# RFC1918-equivalent ranges no public router forwards.
_B178_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _b178_classify_host(host: str) -> str:
    """Classify a non-loopback baseUrl host for B178: 'local' (never flagged),
    'private' (WARN — on-LAN-only exposure, ambiguous with a benign homelab/compose
    setup), or 'public' (FAIL — a public IP literal or a dotted hostname, which this
    static, network-free check cannot distinguish from one that resolves publicly)."""
    if host in _B178_LOCAL_MODEL_HOSTNAMES:
        return "local"
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if any(addr.version == net.version and addr in net for net in _B178_PRIVATE_NETS):
            return "private"
        return "public"
    # A bare single-label hostname (no dot, no colon) is a Docker-Compose-style
    # sibling-service DNS name (e.g. "ollama") — resolvable only inside the private
    # compose/orchestrator network, never off it. Grounded: selection-JInn13lc.js
    # :10862 isBareProviderHostnameBaseUrl uses the identical no-dot/no-colon test.
    if "." not in host and ":" not in host:
        return "private"
    return "public"


def check_provider_baseurl(ctx: Context) -> Finding:
    """B178 — cleartext http:// baseUrl on a model provider (API-key + traffic leak).

    Grounded: ModelProviderSchema.baseUrl (zod-schema.core-DviqqtPj.js) — a real,
    optional, per-provider field B155 never reads. Dual-use: a custom https:// baseUrl
    (self-hosted gateway) is indistinguishable from an attacker repoint and is NEVER
    flagged — only cleartext http:// is a signal at all, and even then only to a host
    this check can't place on the local machine or the private network.

    FAIL — a provider's baseUrl is http:// to a host that is neither loopback, nor a
           local-model hostname OpenClaw's own runtime treats as the local machine
           (0.0.0.0, ::, *.docker.internal / *.orb.internal), nor a private/CGNAT/
           link-local IP literal, nor a bare single-label hostname (e.g. a Docker-
           Compose sibling service) — i.e. a public IP or a dotted hostname.
    WARN  — a provider's baseUrl is http:// to a private-range IP or a bare hostname:
           only an on-LAN adversary could intercept it, and the dominant real-world
           instance of this shape (a local Ollama/LM Studio runtime) carries no API
           key to leak in the first place — this check cannot tell that apart from a
           credentialed corporate LiteLLM gateway on the same LAN, so it stays WARN.
    PASS — every configured baseUrl (if any) is https://, loopback, or a recognized
           local-model hostname, or none is set (bundled provider default, https).
    UNKNOWN — openclaw.json could not be parsed.
    """
    if (f := _config_unreadable("B178", ctx)) is not None:
        return f
    from ..logsafe import sanitize_url_host_only  # noqa: PLC0415

    providers = dig(ctx.config, "models.providers")
    fails: list[str] = []
    warns: list[str] = []
    if isinstance(providers, dict):
        for pid, pspec in providers.items():
            if not isinstance(pspec, dict):
                continue
            base_url = pspec.get("baseUrl")
            if not isinstance(base_url, str) or not base_url.strip():
                continue
            try:
                parsed = urlparse(base_url.strip())
            except (ValueError, AttributeError):
                continue
            host = (parsed.hostname or "").lower()
            if (parsed.scheme or "").lower() != "http" or not host:
                continue
            if host in LOOPBACK or host.startswith("127."):
                continue
            shown = sanitize_url_host_only(base_url)
            classification = _b178_classify_host(host)
            if classification == "local":
                continue
            if classification == "private":
                warns.append(
                    f"models.providers.{pid}.baseUrl uses plain http:// to a private-"
                    f"network host ({shown}) — unencrypted, but only reachable from "
                    "the local network; if this provider requires an API key, that "
                    "key would still be visible to any on-LAN observer"
                )
                continue
            fails.append(
                f"models.providers.{pid}.baseUrl uses plain http:// to a non-loopback, "
                f"non-private host ({shown}) — the provider API key and "
                "the full outbound model stream travel in cleartext"
            )

    if fails:
        return _finding(
            "B178", FAIL, "; ".join(fails),
            "Point models.providers.<id>.baseUrl at an https:// endpoint — a cleartext "
            "http:// baseUrl exposes the provider API key (Authorization header) and "
            "the entire model stream to network interception. A self-hosted/private "
            "proxy or gateway with valid TLS (https://) is fine.",
            evidence=fails + warns,
        )
    if warns:
        return _finding(
            "B178", WARN, "; ".join(warns),
            "If this baseUrl is a local model runtime (Ollama/LM Studio/vLLM) or an "
            "internal gateway on your LAN, http:// is standard practice for it — no "
            "action needed. If it carries a real credential, prefer https:// or keep "
            "it behind a network you trust.",
            evidence=warns,
        )
    return _finding(
        "B178", PASS,
        "No model provider baseUrl uses a cleartext http:// endpoint to a "
        "public/unrecognized host.",
        "Keep any custom models.providers.<id>.baseUrl on https:// "
        "(loopback and local-model http:// targets are not flagged).",
    )


def _b82_undeterminable(path: str, value: object, expected: str) -> Finding:
    """B82's single UNKNOWN shape, shared by all three malformed levels.

    ``diagnostics``, ``diagnostics.cacheTrace`` and ``.enabled`` are all declared inside
    ``.strict()`` zod objects (``dist/zod-schema-O9ml_nmo.js:1050-1057``), and the schema
    uses ``.optional()`` with **zero** ``.nullable()`` anywhere, so an explicit ``null``
    is rejected exactly like a string or a list. A config carrying any of these shapes
    does not load at all, which makes the agent's real cache-trace state undeterminable
    from the file — UNKNOWN, never an affirmative claim in either direction.
    """
    return _finding(
        "B82",
        UNKNOWN,
        f"{path} is present but is not {expected}, so whether cache-trace transcripts "
        "are being written cannot be determined. OpenClaw declares it inside a strict "
        "schema and rejects the whole config at load time when the shape is wrong, so "
        "the running agent is not using what this file says.",
        f"Set {path} to {expected}, or remove it entirely to take the built-in default "
        "(cache tracing off), then re-run the audit.",
        evidence=[f"{path}={value!r} (expected {expected})"],
    )


def _b82_env_override(ctx: Context) -> "Finding | None":
    """B-282: reconcile B82's config read against the OPENCLAW_CACHE_TRACE override.

    Returns a Finding that REPLACES the config-derived PASS, or None to let it stand.

    ``resolveCacheTraceConfig`` (dist/selection-JInn13lc.js:1047-1055) computes::

        enabled = parseBooleanValue(env.OPENCLAW_CACHE_TRACE) ?? config?.enabled ?? false

    so the environment genuinely WINS over the config. Before B-282, B82 read only the
    config and therefore stated affirmatively that transcripts "are not being appended to
    disk" while OpenClaw was appending them on every turn — a lying PASS of exactly the
    class B-262 was filed for. The override has an on-disk, hermetic witness, so this is
    observable rather than the unobservable state the old docstring assumed.

    Verdicts:

    * override parses truthy → **WARN**. Not FAIL: the value in a dotenv file applies only
      on the next agent start and only if nothing already exported the key
      (first-wins, dotenv-global-mWLbBl_z.js:44-46,66).
    * override parses falsy → **None**; the config PASS is affirmed and strengthened.
    * override is present but unparseable → **None**. ``parseBooleanValue`` returns
      undefined for an ambiguous token and the ``??`` chain falls through to the config,
      so the config verdict is the correct one. No heuristic guessing.
    * nothing observed, a global dotenv exists, and the audited home is not this user's own
      → **UNKNOWN** rather than an affirmative all-clear (Golden Rule #4).

    A variable exported in the shell of an already-running agent leaves no on-disk trace
    and is not detectable here — a process boundary, not something a wider read could fix.
    The residual is a false negative, so it cannot trip Golden Rule #5.
    """
    from ..collector import (  # noqa: PLC0415
        audits_this_users_own_home,
        dotenv_override,
        parse_boolean_value,
    )

    raw, source = dotenv_override(ctx, "OPENCLAW_CACHE_TRACE")
    if raw is not None:
        parsed = parse_boolean_value(raw)
        if parsed is True:
            sink, _ = dotenv_override(ctx, "OPENCLAW_CACHE_TRACE_FILE")
            where = (
                f"OPENCLAW_CACHE_TRACE_FILE={sink}" if sink
                else "$OPENCLAW_STATE_DIR/logs/cache-trace.jsonl (the default sink)"
            )
            return _finding(
                "B82",
                WARN,
                "Cache-trace diagnostics are switched on by the environment, overriding "
                "the config. OPENCLAW_CACHE_TRACE is set in a file OpenClaw loads at "
                "startup, and the environment takes precedence over "
                "diagnostics.cacheTrace.enabled — so every agent turn appends its prompt, "
                "system prompt and full message payloads to a JSONL file on disk, "
                "whatever the config says.",
                "Remove OPENCLAW_CACHE_TRACE from the dotenv file (or set it to 0) so the "
                "config's setting is the one that applies. The config alone cannot turn "
                "this off while the variable is set.",
                evidence=[
                    f"OPENCLAW_CACHE_TRACE={raw!r} in {source}",
                    f"transcripts written to {where}",
                ],
            )
        # Falsy or ambiguous: the config verdict stands (`?? config?.enabled`).
        return None

    if ctx.dotenv_found and not audits_this_users_own_home(ctx.home):
        return _finding(
            "B82",
            UNKNOWN,
            "The config does not switch cache-trace diagnostics on, but this audit cannot "
            "confirm the running agent agrees: OPENCLAW_CACHE_TRACE overrides the config, "
            "the audited home is not this user's own, and the global dotenv files present "
            "here do not settle the question either way.",
            "Run the audit on the machine and account the agent runs as, with no --home "
            "argument, so the environment that actually applies can be read.",
            evidence=[f"global dotenv present: {', '.join(ctx.dotenv_files)}"],
        )
    return None


def check_cachetrace_redaction(ctx: Context) -> Finding:
    """B82 — cache-trace diagnostics persist full turn transcripts to disk.

    Grounded against the INSTALLED dist, not the recon:

      - config gate: ``diagnostics.cacheTrace.enabled``
        (``dist/zod-schema-O9ml_nmo.js:1050-1056`` declares the ``diagnostics.cacheTrace``
        object; ``dist/selection-JInn13lc.js:1049`` is the runtime read).
      - NOT ``logging.cacheTrace.*``. That path does not exist anywhere in the package
        (``grep -rF "logging.cacheTrace"`` = 0 hits) and the ``logging`` zod object is
        ``.strict()`` (``zod-schema-O9ml_nmo.js:1059-1070``), so a config carrying it is
        rejected outright. Reading it made this check's "not configured" branch an
        affirmative FALSE claim for every user who actually HAD cache tracing on.

    The enable gate is ``enabled``, NOT ``filePath`` — ``resolveCacheTraceConfig`` reads::

        enabled = parseBooleanValue(env.OPENCLAW_CACHE_TRACE) ?? config?.enabled ?? false

    and resolves the destination as ``config?.filePath?.trim() ||
    env.OPENCLAW_CACHE_TRACE_FILE?.trim()``, falling back to
    ``$OPENCLAW_STATE_DIR/logs/cache-trace.jsonl`` when neither is set
    (``selection-JInn13lc.js:1052``). So ``enabled:true`` with no ``filePath`` still
    writes transcripts — the writer bails only on the flag
    (``createCacheTrace``: ``if (!cfg.enabled) return null``, ``:1083``) — and
    ``filePath`` set with ``enabled:false`` writes nothing. Keying on ``filePath`` would
    be a false-positive WARN on the latter, which is why the port is deliberately not 1:1.

    Redaction here is NOT config-gated: every payload field the trace writes goes through
    ``redactAgentDiagnosticPayload`` (``selection-JInn13lc.js:828`` —
    ``redactSecrets(sanitizeDiagnosticPayload(...))``), and ``logging.redactSensitive`` is
    never consulted by that module. This check therefore does not claim the sink is
    unredacted; it reports that a bulk per-turn transcript sink is switched on — which
    OpenClaw's own schema descriptor flags as something to "enable ... temporarily for
    debugging and disable afterward to reduce sensitive log footprint"
    (``dist/schema-DRyO1XBt.js:104``).

    WARN    — ``diagnostics.cacheTrace.enabled`` is ``true``.
    PASS    — it is explicitly ``false``, OR unset (the built-in default is ``false``,
              per ``config?.enabled ?? false``). "Unset" means the key, or either
              enclosing container, is genuinely ABSENT.
    UNKNOWN — ``enabled`` is present but NOT a boolean, or either enclosing container
              (``diagnostics`` / ``diagnostics.cacheTrace``) is present but not an
              object. All three are declared inside ``.strict()`` objects, so such a
              config is rejected at load time and we cannot say what the agent is
              actually running. Note the schema uses ``.optional()`` and contains zero
              ``.nullable()``, so an explicit ``null`` is malformed here, not "unset".

    On "unset" being PASS rather than UNKNOWN: it overrides an explicit ``enabled:false``
    exactly as it overrides an absent key, so the environment cannot distinguish the two.
    Treating "unset" as UNKNOWN on those grounds would mean B82 could never legitimately
    PASS at all. Unset is therefore reported as PASS on the documented default, matching
    the house rule that a valid config declaring nothing dangerous PASSes (the invariant
    tests/test_b228_unknown_on_parse_error.py pins across every ``_config_unreadable``
    guarded check).

    **B-282 correction.** This docstring previously claimed "no config audit can observe"
    the ``OPENCLAW_CACHE_TRACE`` override and reasoned from there. That was wrong, and the
    wrong premise produced a lying PASS: the override has an on-disk, hermetic witness in
    the two global dotenv files OpenClaw loads into ``process.env`` at startup, and this
    tool runs on the same host. Both PASS branches now go through ``_b82_env_override``
    first, and both sentences were softened from the affirmative "transcripts are not
    being appended to disk" to the claim actually supported by the evidence — that no
    override was found where OpenClaw would load one. What remains unobservable is only a
    shell export into an already-running process, which is a process boundary and a false
    NEGATIVE, never a false positive.

    Known limitation, deliberately not branched on: setting ``includeMessages`` /
    ``includePrompt`` / ``includeSystem`` all to ``false`` narrows an enabled trace to
    digests and fingerprints, at which point this WARN overstates the footprint. Reading
    those three would add three more grounded paths for a strictly advisory refinement,
    so the remediation names them instead. WARN never FAILs, so this cannot trip GR#5.
    """
    unreadable = _config_unreadable("B82", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config if isinstance(ctx.config, dict) else {}
    # Walk the two containers by hand rather than through dig(): dig() collapses "key
    # absent" and "key present but malformed" to the same None, and here those two states
    # have OPPOSITE verdicts. Absent is the documented default (`?? false` → PASS), while a
    # container of the wrong type is rejected by the .strict() zod object at load time, so
    # the agent is NOT running this file and its cache-trace state is undeterminable —
    # GR#4 requires UNKNOWN there, not an affirmative "unset and defaults to false".
    diagnostics = cfg.get("diagnostics")
    if "diagnostics" in cfg and not isinstance(diagnostics, dict):
        return _b82_undeterminable("diagnostics", diagnostics, "a JSON object")
    trace_cfg = diagnostics.get("cacheTrace") if isinstance(diagnostics, dict) else None
    if isinstance(diagnostics, dict) and "cacheTrace" in diagnostics:
        if not isinstance(trace_cfg, dict):
            return _b82_undeterminable(
                "diagnostics.cacheTrace", trace_cfg, "a JSON object"
            )
    override = _b82_env_override(ctx)
    if not isinstance(trace_cfg, dict) or "enabled" not in trace_cfg:
        if override is not None:
            return override
        return _finding(
            "B82",
            PASS,
            "Cache-trace diagnostics are not switched on in the config "
            "(diagnostics.cacheTrace.enabled is unset and defaults to false), and no "
            "OPENCLAW_CACHE_TRACE override was found in the files OpenClaw loads at "
            "startup.",
            "Pin diagnostics.cacheTrace.enabled to false so the intent is explicit and "
            "auditable, and keep the OPENCLAW_CACHE_TRACE environment variable unset — "
            "it overrides the config at runtime.",
        )
    enabled = trace_cfg.get("enabled")
    if enabled is False:
        if override is not None:
            return override
        return _finding(
            "B82",
            PASS,
            "Cache-trace diagnostics are explicitly disabled "
            "(diagnostics.cacheTrace.enabled=false), and no OPENCLAW_CACHE_TRACE "
            "override was found in the files OpenClaw loads at startup.",
            "Leave diagnostics.cacheTrace.enabled at false. Note that the "
            "OPENCLAW_CACHE_TRACE environment variable overrides this setting at "
            "runtime, so keep it unset outside debugging sessions.",
        )
    if enabled is True:
        trace_path = trace_cfg.get("filePath")
        if isinstance(trace_path, str) and trace_path.strip():
            where = f"diagnostics.cacheTrace.filePath={trace_path!r}"
        else:
            where = (
                "diagnostics.cacheTrace.filePath unset — written to "
                "$OPENCLAW_CACHE_TRACE_FILE if set, else "
                "$OPENCLAW_STATE_DIR/logs/cache-trace.jsonl"
            )
        return _finding(
            "B82",
            WARN,
            "Cache-trace diagnostics are enabled — every agent turn appends its prompt, "
            "system prompt and full message payloads to a JSONL file on disk. OpenClaw "
            "redacts known secret patterns from those payloads, but the transcript is "
            "still a bulk record of conversation content at rest.",
            "Set diagnostics.cacheTrace.enabled to false once the debugging session that "
            "needed it is over — OpenClaw's own schema recommends enabling it only "
            "temporarily. To keep tracing on with a smaller footprint, set "
            "diagnostics.cacheTrace.includeMessages, .includePrompt and .includeSystem "
            "to false so only digests are recorded.",
            evidence=["diagnostics.cacheTrace.enabled=True", where],
        )
    return _b82_undeterminable(
        "diagnostics.cacheTrace.enabled", enabled, "a JSON boolean"
    )


def check_config_audit_log(ctx: Context) -> Finding:
    import json as _json

    log_path = ctx.home / "logs" / "config-audit.jsonl"
    if not log_path.is_file():
        return _finding(
            "B77",
            UNKNOWN,
            "config audit log not found — cannot verify config change history.",
            "Keep the config-io audit log (logs/config-audit.jsonl) enabled so config "
            "writes stay attributable and reviewable.",
        )
    try:
        raw, _ = _read_jsonl_tail(log_path)
    except OSError:
        return _finding(
            "B77",
            UNKNOWN,
            "config audit log present but unreadable — cannot verify config change history.",
            "Ensure logs/config-audit.jsonl is readable by the owner.",
        )

    evidence: list[str] = []
    total = 0
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = _json.loads(ln)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        total += 1

        suspicious = rec.get("suspicious")
        if isinstance(suspicious, list) and suspicious:
            event = str(rec.get("event", "config.write"))
            labels = ", ".join(str(s) for s in suspicious[:5])
            evidence.append(f"{event}: flagged suspicious [{labels}]")

        argv = rec.get("argv")
        if isinstance(argv, list) and argv:
            if not any("openclaw" in str(a).lower() for a in argv):
                proc = os.path.basename(str(argv[0]))
                evidence.append(f"config written by unexpected process: {proc}")

    if total == 0:
        return _finding(
            "B77",
            UNKNOWN,
            "config audit log present but contains no parseable config-write records.",
            "Keep the config-io audit log (logs/config-audit.jsonl) enabled so config "
            "writes stay attributable and reviewable.",
        )
    if evidence:
        n = len(evidence)
        return _finding(
            "B77",
            WARN,
            f"config-write audit log shows {n} entr{'y' if n == 1 else 'ies'} of concern "
            f"across {total} recorded write(s): suspicious markers and/or writes from an "
            "unexpected process.",
            "Review each flagged config write. A write you did not initiate — or one "
            "carrying a suspicious marker — may indicate config tampering; restore from a "
            "known-good backup and rotate any exposed credentials.",
            evidence=evidence[:10],
        )
    return _finding(
        "B77",
        PASS,
        f"all {total} recorded config write(s) are clean and openclaw-originated.",
        "Periodically review logs/config-audit.jsonl for unexpected config writers.",
    )


# ---------------------------------------------------------------------------
# B78 — Config-health integrity tracker review
# ---------------------------------------------------------------------------
def check_config_health_integrity(ctx: Context) -> Finding:
    import json as _json

    health_path = ctx.home / "logs" / "config-health.json"
    if not health_path.is_file():
        return _finding(
            "B78",
            UNKNOWN,
            "config-health integrity file not found — cannot evaluate config integrity history.",
            "Keep config-health tracking (logs/config-health.json) enabled so OpenClaw can "
            "detect and flag suspicious config states.",
        )
    try:
        data = _json.loads(health_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return _finding(
            "B78",
            UNKNOWN,
            "config-health integrity file present but unreadable or malformed — cannot "
            "evaluate config integrity history.",
            "Ensure logs/config-health.json is valid JSON and owner-readable.",
        )

    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, dict) or not entries:
        return _finding(
            "B78",
            UNKNOWN,
            "config-health file has no tracked config entries — nothing to evaluate.",
            "Keep config-health tracking (logs/config-health.json) enabled so OpenClaw can "
            "detect and flag suspicious config states.",
        )

    evidence: list[str] = []
    for path, info in entries.items():
        if not isinstance(info, dict):
            continue
        if info.get("lastObservedSuspiciousSignature") is not None:
            name = os.path.basename(str(path)) or "config"
            evidence.append(f"suspicious integrity signature observed for {name}")

    if evidence:
        n = len(evidence)
        return _finding(
            "B78",
            WARN,
            f"config integrity alert: {n} tracked config(s) recorded a suspicious signature "
            "— OpenClaw observed a config state it could not verify as known-good.",
            "Treat this as possible config tampering: compare the live config against the "
            "last-known-good, restore from a trusted backup if it diverged, and rotate any "
            "credentials that may have been exposed.",
            evidence=evidence[:10],
        )
    return _finding(
        "B78",
        PASS,
        f"all {len(entries)} tracked config(s) have a clean integrity history "
        "(no suspicious signatures observed).",
        "Keep config-health tracking enabled and review it after any unexpected config change.",
    )


def _other_can_reach_read(home: Path, target: Path) -> bool:
    """True when a NON-owner — world, or a group with members beyond the owner (UPG-safe, cf.
    B22/B-189 `_group_has_other_members`) — can BOTH traverse every directory from *home* down
    to *target* AND read *target*.

    Path-aware on purpose: a loose (umask-default 0o644/0o664) transcript sealed inside a 0o700
    home is UNREACHABLE, so it is never a false at-rest exposure — verified on the reference
    fleet, where ~/.openclaw and the whole agents/ chain are 0o700 even though the nested
    codex-home transcripts are 0o664. POSIX stat-only; never reads content; never raises."""
    try:
        rel = target.relative_to(home)
    except ValueError:
        return False
    chain: list[Path] = [home]
    cur = home
    for part in rel.parts[:-1]:
        cur = cur / part
        chain.append(cur)
    world_ok = True
    group_ok = True
    for d in chain:
        try:
            st = d.stat()
        except OSError:
            return False
        m = st.st_mode
        world_ok = world_ok and bool(m & 0o001)  # o+x to traverse
        # Group leg requires a group KNOWN to have members beyond the owner (`is True`, not
        # `is not False`). B19 is scored, so a false WARN moves the grade — on a umask-002 UPG
        # box the owning group is a private singleton and membership may be undeterminable
        # (None); treating None as "shared" (as the WRITE check B22 does) would false-WARN
        # every such install. Erring toward NOT flagging on None keeps Golden Rule #5. The
        # world leg still catches genuine world-readable exposure unambiguously.
        grp_other = _shared._group_has_other_members(st.st_gid, st.st_uid)
        group_ok = group_ok and bool(m & 0o010) and (grp_other is True)  # g+x, known-shared group
        if not world_ok and not group_ok:
            return False
    try:
        tst = target.stat()
    except OSError:
        return False
    tm = tst.st_mode
    if world_ok and (tm & 0o004):  # reachable + world-readable
        return True
    grp_other_t = _shared._group_has_other_members(tst.st_gid, tst.st_uid)
    return bool(group_ok and (tm & 0o040) and (grp_other_t is True))  # reachable + group-read


def _collect_atrest_transcripts(home: Path, cap: int = 200) -> list[Path]:
    """Bounded, symlink-safe list of secret/PII-bearing at-rest transcript / backup FILES
    (F-120): agents/*/sessions/*.jsonl, agents/*/agent/codex-home/sessions/**/*.jsonl, and
    <home>/.openclaw-install-backups/** (backed-up openclaw.json = secrets). Read-only; the
    ``cap`` bounds a pathological agents/ tree (mirrors _lifecycle.py's 200-file cap)."""
    out: list[Path] = []

    def _grab(root: Path, pattern: str) -> None:
        if len(out) >= cap or not root.is_dir():
            return
        try:
            for f in root.rglob(pattern):  # generator — early break bounds the walk
                if len(out) >= cap:
                    break
                try:
                    if f.is_file() and not f.is_symlink():
                        out.append(f)
                except OSError:
                    continue
        except OSError:
            return

    try:
        agents = home / "agents"
        if agents.is_dir():
            for agent_dir in sorted(agents.iterdir()):
                if len(out) >= cap:
                    break
                if not agent_dir.is_dir() or agent_dir.is_symlink():
                    continue
                _grab(agent_dir / "sessions", "*.jsonl")
                _grab(agent_dir / "agent" / "codex-home" / "sessions", "*.jsonl")
    except OSError:
        pass
    _grab(home / ".openclaw-install-backups", "*")
    return sorted(out)


# ---------- B19: data at-rest protection (POSIX only) ----------
def check_data_atrest(ctx: Context) -> Finding:
    """Memory/log directories and log files are not group/world-readable."""
    if not _shared._is_posix():
        return _finding(
            "B19",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — "
            "ClawSecCheck can't read those read-only (no extra tools), so this is "
            "UNKNOWN, never a false PASS.",
            "Check the ACLs yourself: `icacls <path>` should not grant write to "
            "Users / Everyone / Authenticated Users.",
        )

    loose: list[str] = []

    # Candidate directories: workspace*/memory, workspace*/logs, <home>/logs
    candidates_dirs: list[Path] = []
    try:
        for entry in ctx.home.iterdir():
            if entry.name.startswith("workspace") and entry.is_dir():
                for sub in ("memory", "logs"):
                    d = entry / sub
                    if d.is_dir():
                        candidates_dirs.append(d)
        logs_dir = ctx.home / "logs"
        if logs_dir.is_dir():
            candidates_dirs.append(logs_dir)
    except OSError:
        pass

    for d in candidates_dirs:
        try:
            mode = d.stat().st_mode & 0o777
            if mode & 0o077:
                loose.append(f"{d.relative_to(ctx.home)} (mode {oct(mode)[-3:]})")
        except OSError:
            pass

    # *.log files directly under <home>
    try:
        for f in ctx.home.iterdir():
            if f.is_file() and f.suffix.lower() == ".log":
                try:
                    mode = f.stat().st_mode & 0o777
                    if mode & 0o077:
                        loose.append(f"{f.name} (mode {oct(mode)[-3:]})")
                except OSError:
                    pass
    except OSError:
        pass

    # F-120: session transcripts + install-backups (secret/PII at rest). Path-aware — only a
    # file a NON-owner can actually reach AND read counts, so umask-default 0o644/0o664 files
    # sealed inside a 0o700 home never produce a spurious WARN (Golden Rule #5).
    transcripts = _collect_atrest_transcripts(ctx.home)
    for t in transcripts:
        if _other_can_reach_read(ctx.home, t):
            try:
                rel = t.relative_to(ctx.home)
            except ValueError:
                rel = Path(t.name)
            try:
                mode = t.stat().st_mode & 0o777
            except OSError:
                continue
            loose.append(f"{rel} (mode {oct(mode)[-3:]})")

    if not loose and not candidates_dirs and not transcripts:
        return _finding("B19", UNKNOWN, "No memory/log/transcript stores found to inspect.", "—")
    if loose:
        joined = "; ".join(loose[:8])
        extra = f" (+{len(loose) - 8} more)" if len(loose) > 8 else ""
        return _finding(
            "B19",
            WARN,
            f"Conversation data/PII at rest is group/world-readable (memory/logs, session "
            f"transcripts, or install backups): {joined}{extra}",
            "Run `chmod 700` on the memory/log/session directories and `chmod 600` on the "
            "files (or `chmod 700 ~/.openclaw`) to restrict access to the owner only.",
            evidence=loose,
        )
    return _finding(
        "B19",
        PASS,
        "Memory/log directories, session transcripts, and install backups are not reachable "
        "and readable by other users (owner-only, or sealed inside a tight home).",
        "Keep memory/log/session directories at chmod 700 and their files at 600.",
    )


def _other_can_reach_write(home: Path, target: Path) -> bool:
    """True when a NON-owner can BOTH traverse every directory from *home* down to *target*
    AND write *target*. The write-bit twin of ``_other_can_reach_read`` above, sharing its
    path-awareness: a loose mode sealed inside a 0o700 home is unreachable and therefore not
    an exposure. Group-write counts only when the owning group is KNOWN to have members
    beyond the owner (UPG-safe — same rule as ``_lifecycle._writable_by_others``, which is
    the precedent this mirrors; kept local to avoid a cross-topic import, per CLAUDE.md §3).
    POSIX stat-only; never reads content; never raises."""
    try:
        rel = target.relative_to(home)
    except ValueError:
        return False
    chain: list[Path] = [home]
    cur = home
    for part in rel.parts[:-1]:
        cur = cur / part
        chain.append(cur)
    world_ok = True
    group_ok = True
    for d in chain:
        try:
            st = d.stat()
        except OSError:
            return False
        m = st.st_mode
        world_ok = world_ok and bool(m & 0o001)
        grp_other = _shared._group_has_other_members(st.st_gid, st.st_uid)
        group_ok = group_ok and bool(m & 0o010) and (grp_other is True)
        if not world_ok and not group_ok:
            return False
    try:
        tst = target.stat()
    except OSError:
        return False
    tm = tst.st_mode
    if world_ok and (tm & 0o002):
        return True
    grp_other_t = _shared._group_has_other_members(tst.st_gid, tst.st_uid)
    return bool(group_ok and (tm & 0o020) and (grp_other_t is True))


def _ancestors_allow_other_access(home: Path, stop: "Path | None" = None) -> bool:
    """True when the directory chain ABOVE *home* still lets some non-owner traverse down
    INTO it. Walks from ``home``'s parent upward to *stop* (exclusive) or the filesystem
    root.

    WHY THIS EXISTS, AND WHY IT IS NOT INSIDE ``_other_can_reach_read``: those two twins
    deliberately begin at *home* and model reachability WITHIN the audited tree. That is a
    documented approximation which B19 has shipped with, and widening the shared helpers
    would silently change B19's verdicts as well. B188 needs the stronger guarantee because
    it is the only caller that escalates the answer to a HIGH, scored FAIL, so it must be
    able to PROVE the file is reachable before asserting exposure. On a distro that ships
    $HOME at 0700 (the Fedora/RHEL/Arch default) a 0755 ~/.openclaw with a 0644 database is
    NOT reachable by anyone, and claiming otherwise is a false positive.

    Traversal is modelled per directory as "o+x, OR g+x with a group KNOWN to have members
    beyond the owner". The two legs are OR-ed per directory rather than tracked as two
    separate whole-chain legs (the rule ``_other_can_reach_read`` uses below ``home``)
    because a real non-owner mixes them freely: they cross a root-owned 0755 ``/`` by its
    o+x bit and a 0750 shared-group directory by its g+x bit. Requiring one single leg to
    hold for the entire chain up to ``/`` would report "unreachable" for genuinely reachable
    files.

    Conservative on ignorance: an ancestor that cannot be stat'ed returns False ("cannot
    prove reachable"), which suppresses a FAIL rather than inventing one — Golden Rule #4.

    *stop* bounds the walk. Production passes nothing, so the walk runs to the real
    filesystem root; it exists so a test can pin this function against a directory chain it
    fully controls, because pytest's own tmp root is 0700 and would otherwise dominate every
    fixture chain. Symlinks are resolved so the walk follows the REAL parent chain.
    """
    try:
        cur = home.resolve()
    except (OSError, ValueError, RuntimeError):
        cur = home
    stop_resolved = None
    if stop is not None:
        try:
            stop_resolved = stop.resolve()
        except (OSError, ValueError, RuntimeError):
            stop_resolved = stop
    for parent in cur.parents:
        if stop_resolved is not None and parent == stop_resolved:
            break
        try:
            st = parent.stat()
        except OSError:
            return False  # cannot prove reachability -> do not assert exposure
        m = st.st_mode
        if m & 0o001:
            continue  # world-traversable
        if (m & 0o010) and _shared._group_has_other_members(st.st_gid, st.st_uid) is True:
            continue  # traversable by a known-shared group
        return False
    return True


# B-293 (DISK-2): the shared state SQLite DB and its WAL/SHM siblings. Grounded against the
# installed dist (openclaw-state-db-DzSsA9Ji.js: resolveOpenClawStateSqliteDir ->
# <stateDir>/state/openclaw.sqlite) and against the real file. The -wal sibling matters as
# much as the DB: it holds recently written rows that have not yet been checkpointed in.
_B188_DB_NAMES = ("openclaw.sqlite", "openclaw.sqlite-wal", "openclaw.sqlite-shm")


def check_state_db_atrest(ctx: Context) -> Finding:
    """B188 (B-293, DISK-2) — the shared state SQLite database's at-rest permissions.

    ~/.openclaw/state/openclaw.sqlite stores raw secrets at rest. Verified as real
    ``CREATE TABLE`` statements in the dist's OPENCLAW_STATE_SCHEMA_SQL
    (openclaw-state-db-DzSsA9Ji.js): ``device_identities.private_key_pem`` (:711/715),
    ``device_auth_tokens.token`` (:723), ``web_push_vapid_keys.private_key`` (:878/881),
    plus ``device_bootstrap_tokens.token``, ``apns_registrations.token`` and
    ``auth_profile_stores.store_json``. A backup/rsync/umask slip that leaves the file
    group- or world-readable lets another local account read a paired device's private key
    and forge control-plane auth — and before this check, EVERY ClawSecCheck permission
    check passed over it, because none of them stat'ed the state DB. B19 above covers
    workspace memory/logs, bare *.log files and F-120 transcripts/backups; ``state/`` was
    absent from every leg. B11 reads only ``ctx.config_mode``, i.e. openclaw.json's mode
    alone. B182 is the closest precedent but enumerates only ClawHub CLI token stores.

    SCOPE HONESTY — this is a conventional at-rest FILE-PERMISSION check, closable by a
    static ``stat()``. It is NOT runtime modelling, and it does NOT mine the state DB: the
    database is never opened here, so no secret is ever read, echoed or redacted (§8).
    Mining the DB's behavioural tables is a separate, larger question and is not what this
    check does.

    SEVERITY HONESTY — the dominant reachability gate (the parent directory's mode) IS
    partially watched by OpenClaw's own audit when the native fold-in runs
    (``fs.state_dir.perms_readable``, audit-UjVvFwCi.js:477-489), and OpenClaw creates the
    chain at 0700 itself. So the strongest justification for this check is defence-in-depth
    plus grade participation, not an unguarded hole. Two real gaps remain: native resolves
    ``params.stateDir`` to ``~/.openclaw`` (the ROOT), so it checks the parent gate and never
    the ``state/`` subdir or the DB file itself; and it misses x-without-r chains — a 0711
    ``~/.openclaw`` is traversable but not readable, so native stays silent while a 0644
    ``openclaw.sqlite`` at a known fixed filename is fully readable by any local user.
    Native findings are also excluded from the score, and native is ``status=skipped``
    outright on some installs.

    REACHABILITY IS PROVEN, NOT ASSUMED. Loose mode bits inside ~/.openclaw are only an
    exposure if a non-owner can traverse down to them, and that depends on the directory
    chain ABOVE ~/.openclaw too — a 0700 $HOME (the Fedora/RHEL/Arch default) seals
    everything beneath it. ``_other_can_reach_read`` deliberately starts at ``home`` and
    cannot see that, so this check adds ``_ancestors_allow_other_access`` and requires BOTH
    before it will assert a FAIL or WARN. Reaching a genuine exposure therefore also implies
    OpenClaw's own hardening did not apply: ``ensureOpenClawStatePermissions``
    (openclaw-state-db-DzSsA9Ji.js:1827) best-effort chmods ``state/`` to 0700
    (OPENCLAW_STATE_DIR_MODE = 448, :1811) and every ``openclaw.sqlite*`` file to 0600
    (OPENCLAW_STATE_FILE_MODE = 384, :1812) on each open — which narrows the real-world
    shape to restore-before-first-start, or a filesystem where chmod does not apply
    (CIFS/exFAT/DrvFs), for which the dist has an explicit "skipped permission hardening"
    warn path (:1825). On such a mount the `chmod` remediation is itself a no-op, so the
    FAIL's fix text says so.

    FAIL    — the DB (or a -wal/-shm sibling) is reachable AND readable by another user,
              with the whole directory chain (above and below ~/.openclaw) permitting it.
    WARN    — ``state/`` is reachable and writable by another user: they cannot read the
              secrets, but they can swap the database under the agent (mirrors B182's
              ``swappable`` branch).
    UNKNOWN — no state DB present, or non-POSIX (NTFS ACLs make st_mode meaningless).
    PASS    — present and not reachable-and-readable by others. Loose in-tree modes sealed
              by a restrictive parent directory PASS with a distinct message that names the
              seal, rather than silently reading like a clean 0600 install.
    """
    if not _shared._is_posix():
        return _finding(
            "B188",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — ClawSecCheck "
            "can't read those read-only (no extra tools), so the state database's at-rest "
            "permissions are UNKNOWN, never a false PASS.",
            "Check the ACLs yourself: `icacls %USERPROFILE%\\.openclaw\\state\\"
            "openclaw.sqlite` should not grant read to Users / Everyone / Authenticated "
            "Users.",
        )

    state_dir = ctx.home / "state"
    present: list[Path] = []
    for name in _B188_DB_NAMES:
        p = state_dir / name
        try:
            if p.is_file() and not p.is_symlink():
                present.append(p)
        except OSError:
            continue
    if not present:
        return _finding(
            "B188",
            UNKNOWN,
            "No state database found at ~/.openclaw/state/openclaw.sqlite — cannot assess "
            "its at-rest permissions.",
            "If this install does use the state database, ensure it is readable by the "
            "audit so a future run can check its permissions.",
        )

    # Path-aware on purpose. A 0644 database sealed inside a 0700 home is the routine
    # umask-022 outcome and is NOT exploitable — flagging it would be exactly the false WARN
    # F-120 already solved for transcripts, so this reuses `_other_can_reach_read` rather
    # than testing mode bits in isolation. Empirically: db=0644 inside home=0700 -> a naive
    # mode check FIRES while _other_can_reach_read is False (correctly silent); db=0644
    # inside home=0755 -> both fire (genuinely exposed).
    exposed: list[str] = []
    for p in present:
        if _other_can_reach_read(ctx.home, p):
            try:
                mode = p.stat().st_mode & 0o777
            except OSError:
                continue
            exposed.append(f"state/{p.name} (mode {oct(mode)[-3:]}) is readable by other users")

    # `_other_can_reach_read` stops at ctx.home, so on its own it would call a 0644 database
    # under a 0755 ~/.openclaw "exposed" even when $HOME above it is 0700 and denies o+x to
    # every non-owner. That is a false positive, and B188 is a HIGH scored FAIL, so it must
    # prove the whole chain before asserting it.
    ancestors_open = _ancestors_allow_other_access(ctx.home)
    writable_dir = _other_can_reach_write(ctx.home, state_dir)

    if exposed and ancestors_open:
        return _finding(
            "B188",
            FAIL,
            "The OpenClaw state database holds device private keys, device/bootstrap auth "
            "tokens and web-push VAPID private keys at rest, and another local user can "
            "reach and read it: " + "; ".join(exposed) + ". Anyone who can read this file "
            "can impersonate a paired device and forge control-plane authentication.",
            "Run `chmod 600 ~/.openclaw/state/openclaw.sqlite*` and `chmod 700 "
            "~/.openclaw/state ~/.openclaw`. Then rotate what was exposed: re-pair any "
            "paired devices and re-issue bootstrap tokens, since a copy taken while the "
            "file was readable stays valid. If the state directory lives on a filesystem "
            "that does not implement POSIX modes (CIFS/exFAT/DrvFs), chmod silently does "
            "nothing there — OpenClaw hits the same wall and logs 'skipped permission "
            "hardening' — so move the state directory onto a POSIX filesystem instead.",
            evidence=exposed,
        )

    # Swap vector: the secrets stay unreadable, but a writable state/ lets another user
    # replace the database wholesale under the running agent.
    if writable_dir and ancestors_open:
        try:
            dmode = oct(state_dir.stat().st_mode & 0o777)[-3:]
        except OSError:
            dmode = "?"
        return _finding(
            "B188",
            WARN,
            f"The state database itself is not readable by other users, but its directory "
            f"~/.openclaw/state (mode {dmode}) is writable by another local user — they "
            "cannot read the stored device keys and auth tokens, but they can replace the "
            "database under the running agent.",
            "Run `chmod 700 ~/.openclaw/state` so only the owner can add, remove or replace "
            "files there.",
            evidence=[f"state/ (mode {dmode}) is writable by other users"],
        )

    names = ", ".join(f"state/{p.name}" for p in present)
    if (exposed or writable_dir) and not ancestors_open:
        # Loose modes inside ~/.openclaw, but a directory above it (typically $HOME at 0700)
        # denies traversal to every non-owner, so nothing here is actually reachable. Not a
        # finding — but say so plainly, because the seal is one `chmod 755 ~` away from gone.
        return _finding(
            "B188",
            PASS,
            f"The state database and its siblings ({names}) carry loose permissions inside "
            "~/.openclaw, but a directory above ~/.openclaw denies access to other users, "
            "so they are not reachable and the device keys and auth tokens are not exposed "
            "at rest.",
            "No exposure today, but the only thing sealing these files is the parent "
            "directory. Tighten them at the source too: `chmod 600 "
            "~/.openclaw/state/openclaw.sqlite*` and `chmod 700 ~/.openclaw/state "
            "~/.openclaw`, so loosening your home directory later cannot expose them.",
            pass_confidence="verified",
        )
    return _finding(
        "B188",
        PASS,
        f"The state database and its siblings ({names}) are not reachable and readable by "
        "other users, so the device private keys, auth tokens and VAPID keys stored in them "
        "are not exposed at rest.",
        "Keep ~/.openclaw and ~/.openclaw/state at chmod 700 and the database files at 600.",
        pass_confidence="verified",
    )


# B-295 (DISK-4): the debug-proxy env cluster. Names and truthy semantics grounded verbatim
# in the installed dist (env-DNgUBPBb.js, src/proxy-capture/env.ts):
#   isTruthy(v) === (v === "1" || v === "true" || v === "yes" || v === "on")
#   resolveDebugProxySettings(): enabled = isTruthy(env.OPENCLAW_DEBUG_PROXY_ENABLED),
#   required = isTruthy(env.OPENCLAW_DEBUG_PROXY_REQUIRE), proxyUrl = env.OPENCLAW_DEBUG_
#   PROXY_URL?.trim(), dbPath/blobDir/certDir = env override or the default under stateDir.
# collector.is_truthy_env_value mirrors isTruthy exactly (same four-value set).
_B190_TRUTHY_VARS = (
    (
        "OPENCLAW_DEBUG_PROXY_ENABLED",
        "turns on traffic capture — every request and response the agent makes is written "
        "to the state database, including Authorization headers and request bodies",
    ),
    (
        "OPENCLAW_DEBUG_PROXY_REQUIRE",
        "makes the debug proxy mandatory, so the agent will route through it or fail",
    ),
)
_B190_VALUE_VARS = (
    (
        "OPENCLAW_DEBUG_PROXY_URL",
        "routes the agent's traffic through this proxy — whoever operates it sees every "
        "request the agent makes, which is a man-in-the-middle position over all agent "
        "traffic",
    ),
    (
        "OPENCLAW_DEBUG_PROXY_DB_PATH",
        "redirects captured traffic to a different database file",
    ),
    (
        "OPENCLAW_DEBUG_PROXY_BLOB_DIR",
        "redirects captured request/response bodies to a different directory",
    ),
)


def check_debug_proxy_capture(ctx: Context) -> Finding:
    """B190 (B-295, DISK-4) — the OPENCLAW_DEBUG_PROXY_* cluster and on-disk traffic capture.

    SCOPE, STATED EXACTLY — this check is deliberately NARROWED, because the original
    DISK-4 claim double-counted work B164 already does.

    ALREADY COVERED BY B164, AND NOT REPEATED HERE: the ``cache-trace.jsonl`` FILE sink.
    ``logdiscovery.py`` discovers it both from ``diagnostics.cacheTrace.filePath`` and from
    the conventional ``logs/cache-trace.jsonl`` (deliberately NOT gated on ``enabled``, so a
    trace left by a since-disabled session is still found), and ``logscan.py`` content-scans
    it with the vetted ``_EXFIL_RE`` / ``_KNOWN_EXFIL_HOST_RE`` / ``SECRET_PATTERNS`` /
    ``_CRED_RE`` detectors. So "exfil destinations and leaked auth headers sitting locally
    and unexamined" is FALSE for the cache-trace file — that is exactly what B164 mines.
    This check never re-scans it.

    WHAT IS GENUINELY UNCOVERED, and what this check adds: OpenClaw's debug-proxy capture is
    a DIFFERENT subsystem, and it is enabled SOLELY by environment variable — there is no
    config field for it anywhere in the dist. B155 covers ``proxy.*`` / ``OPENCLAW_PROXY_URL``,
    a different subsystem, and explicitly concedes the env var it cannot see. Its rows land
    in SQLite tables, and ``logdiscovery``'s sink model is file-paths-only, so the E-044
    log-hunt substrate structurally cannot reach them.

    WHAT THIS CHECK STILL DOES NOT DO — say it plainly: it does NOT mine the captured
    traffic. ``capture_events.headers_json`` holds bearer tokens and ``.data_text`` holds
    request bodies; reading them is a §8 disclosure hazard, and flagging the hosts a
    developer legitimately captured (provider APIs, ClawHub) would be a false "exfil"
    signal — the exact false positive this check must not create. The collector therefore
    takes ``COUNT(*)`` and nothing else. Content-mining ``capture_events``/``capture_blobs``
    remains unbuilt. This check answers "was your traffic recorded to disk, and how much",
    never "what was in it".

    WARN    — capture is observably on or has already run: a truthy enablement variable, a
              proxy/redirect URL, or rows already in the capture tables. Advisory and
              ``scored=False``: a developer legitimately running the debug proxy is a real
              and benign case, so this must never FAIL or move the grade.
    UNKNOWN — no evidence found. Never PASS: enablement is env-only, a shell export leaves
              no on-disk trace (the same process boundary B192 documents), and
              ``OPENCLAW_DEBUG_PROXY_DB_PATH`` can point the capture at a database this
              check never counts. Zero rows here is therefore NOT proof capture is off, and
              this check never claims it is.
    """
    from ..collector import dotenv_override, is_truthy_env_value  # noqa: PLC0415

    hits: list[str] = []
    for name, what in _B190_TRUTHY_VARS:
        raw, source = dotenv_override(ctx, name)
        if raw is not None and is_truthy_env_value(raw):
            hits.append(f"{name} is on ({source}) — it {what}")
    for name, what in _B190_VALUE_VARS:
        raw, source = dotenv_override(ctx, name)
        if isinstance(raw, str) and raw.strip():
            # The VALUE is deliberately not echoed: a proxy URL can embed credentials
            # (http://user:pass@host). Naming the variable and its source is enough.
            hits.append(f"{name} is set ({source}) — it {what}")

    rows = ctx.capture_event_rows if ctx.capture_tables_found else 0
    blobs = ctx.capture_blob_rows if ctx.capture_tables_found else 0
    if rows:
        hits.append(
            f"the state database already holds {rows} captured request/response flow(s)"
            + (f" and {blobs} captured body/bodies" if blobs else "")
            + " — this traffic is on disk in plaintext, including any Authorization headers "
            "and request bodies it contained"
        )

    if hits:
        return _finding(
            "B190",
            WARN,
            "OpenClaw's debug traffic-capture proxy is enabled, redirected, or has already "
            "recorded traffic: " + "; ".join(hits) + ". This is a legitimate debugging "
            "feature, but while it is on, every request the agent makes — including the "
            "credentials it sends to model providers and MCP servers — is written to local "
            "storage in plaintext, and a proxy URL puts whoever runs that proxy in a "
            "man-in-the-middle position over all agent traffic.",
            "If you are not actively debugging, unset the OPENCLAW_DEBUG_PROXY_* variables "
            "(check ~/.openclaw/.env and ~/.config/openclaw/gateway.env) and delete the "
            "captured rows, then rotate any credential that was in flight while capture was "
            "on. If you are debugging, confirm you set the proxy URL yourself — a value you "
            "did not set is an interception of all agent traffic.",
            evidence=hits,
        )

    if not ctx.capture_tables_found:
        return _finding(
            "B190",
            UNKNOWN,
            "No capture tables were found in the state database, and no OPENCLAW_DEBUG_"
            "PROXY_* variable was found in the persistent dotenv files — but debug-proxy "
            "capture has NO config field and is enabled by environment variable alone, so "
            "its state cannot be confirmed from disk.",
            "No action needed if you do not use the debug proxy. To rule it out on a "
            "running agent, check its process environment for OPENCLAW_DEBUG_PROXY_ENABLED.",
        )

    return _finding(
        "B190",
        UNKNOWN,
        "The capture tables exist but hold no rows, and no OPENCLAW_DEBUG_PROXY_* variable "
        "was found in the persistent dotenv files. That is NOT an all-clear: capture is "
        "enabled by environment variable only (no config field exists), a variable exported "
        "in the shell that launched the agent leaves no on-disk trace, and "
        "OPENCLAW_DEBUG_PROXY_DB_PATH can point the capture at a database this check never "
        "counted.",
        "No action needed if you do not use the debug proxy. To rule it out on a running "
        "agent, check its process environment for OPENCLAW_DEBUG_PROXY_ENABLED.",
    )


def check_discovery_mdns_mode(ctx: Context) -> Finding:
    """B73 — mDNS full advertisement on non-loopback gateway bind.

    Grounded (docs.openclaw.ai/gateway/discovery): discovery.mdns.mode enum
    ('minimal' default / 'off' / 'full'). 'full' with a non-loopback gateway bind
    broadly advertises the agent on the local network.

    PASS — mode is 'minimal', 'off', unset (default 'minimal'), or 'full' with loopback.
    WARN — mode == 'full' AND gateway bind is non-loopback.
    """
    unreadable = _config_unreadable("B73", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    mode = dig(cfg, "discovery.mdns.mode")
    if mode != "full":
        return _finding(
            "B73",
            PASS,
            "mDNS discovery is minimal, off, or limited to a loopback bind (no broad "
            "advertisement risk).",
            "Keep discovery.mdns.mode at 'minimal' or 'off' when the gateway is exposed "
            "beyond loopback.",
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if bind_host in LOOPBACK:
        return _finding(
            "B73",
            PASS,
            "mDNS discovery is minimal, off, or limited to a loopback bind (no broad "
            "advertisement risk).",
            "Keep discovery.mdns.mode at 'minimal' or 'off' when the gateway is exposed "
            "beyond loopback.",
        )
    return _finding(
        "B73",
        WARN,
        "discovery.mdns.mode is 'full' with the gateway bound to a non-loopback address "
        "— this broadly advertises the agent on the local network.",
        "Set discovery.mdns.mode to 'minimal' or 'off', or bind the gateway to loopback "
        "when using full mDNS advertisement.",
        evidence=[
            "discovery.mdns.mode=full",
            f"gateway.bind host={bind_host!r} (non-loopback)",
        ],
    )


def check_egress(ctx: Context) -> Finding:
    cfg = ctx.config
    surface = []
    chans = [n for n, c in _channels(cfg).items() if isinstance(c, dict)]
    if chans:
        surface.append(f"channels ({', '.join(chans[:4])})")
    ext = [s for s in ctx.installed_skills if any(h in s.lower() for h in _EXT_SKILL_HINTS)]
    if ext:
        surface.append(f"{len(ext)} external-service skill(s)")
    if _hint(_enabled_tools(cfg), OUTBOUND_TOOL_HINTS):
        surface.append("outbound tools (send/webhook/exec)")
    if surface:
        return _custom(
            "B14",
            MEDIUM,
            WARN,
            f"No egress allowlist — the agent can reach out via: {', '.join(surface)}.",
            "OpenClaw has no built-in egress allowlist; minimise send-capable channels and "
            "external-service skills. Every outbound-capable skill can exfiltrate data "
            "(this is the third leg of the Lethal Trifecta).",
        )
    return _custom("B14", MEDIUM, UNKNOWN, "No outbound channels / skills / tools detected.", "—")


def check_egress_inventory(ctx: Context) -> Finding:
    """C014 — read-only inventory of outbound-capable surfaces and restriction signals.

    Complements B14's short summary with per-surface evidence: channels, outbound-capable
    tools, MCP servers, and clearly external-service skills. Advisory only: it surfaces the
    raw egress posture, not a blocking verdict.

    OpenClaw exposes NO global egress-control config field, so every restriction signal
    below is necessarily PER-SURFACE (a channel policy, a sender allowlist, an approval
    gate, an MCP `allowedHosts` / local-stdio transport). This check used to consult four
    would-be global allowlists — `gateway.egress`, `network.egress`, a top-level `egress`,
    and `tools.http.allow` — and none of them exists. Each is rejected at config load with
    a zod `unrecognized_keys` issue: the root object (zod-schema-O9ml_nmo.js:984-1572, 47
    keys) has no `network` and no `egress`, the `gateway` object (:1338-1482, 21 keys) has
    no `egress`, and `ToolsSchema` is `.strict()` with no `http` key
    (zod-schema.agent-runtime-C02vY4RT.js:723-758, plus the `...CommonToolPolicyFields`
    spread at :512-519 — profile/allow/alsoAllow/deny/byProvider/toolsBySender).

    Because clawseccheck reads raw JSON via dig() and never validates against zod, schema
    absence did NOT make those limbs dead code: adding any one of the four to a config
    flipped C014 from WARN to PASS with the evidence "global egress restriction
    configured". A config OpenClaw would refuse to load could therefore launder an
    unrestricted egress posture into a clean verdict. Do not reintroduce them.

    The nearest REAL fields are deliberately not counted as restriction signals here:
    `proxy.*` only routes traffic through an operator-managed forward proxy whose policy
    is enforced off-box and cannot be verified locally (B155 already reports it as
    informational), and `browser.ssrfPolicy.hostnameAllowlist` binds the browser surface
    alone (B38's concern, not an egress-wide control).
    """
    cfg = ctx.config
    evidence = []
    restricted = False

    channels = _channels(cfg)
    for name, chan in channels.items():
        if not isinstance(chan, dict):
            continue
        dm = chan.get("dmPolicy")
        group = chan.get("groupPolicy")
        bits = []
        if dm:
            bits.append(f"dmPolicy={dm}")
            if str(dm).lower() in ("allowlist", "owner", "owner-only"):
                restricted = True
        if group:
            bits.append(f"groupPolicy={group}")
            if str(group).lower() in ("allowlist", "owner", "owner-only"):
                restricted = True
        suffix = ", ".join(bits) if bits else "policy unspecified"
        evidence.append(f"channel {name}: outbound-capable path ({suffix})")

    tool_names = sorted(
        {t for t in _enabled_tools(cfg) if t == "elevated" or _hint([t], OUTBOUND_TOOL_HINTS)}
    )
    for tool in tool_names:
        notes = []
        if tool == "exec":
            if _has_approval_gate(cfg):
                restricted = True
                notes.append("approval gate present")
            else:
                notes.append("no approval gate detected")
        if tool == "elevated":
            allow_from = dig(cfg, "tools.elevated.allowFrom")
            if allow_from:
                restricted = True
                notes.append("sender allowlist configured")
            else:
                notes.append("no sender allowlist detected")
        evidence.append(
            f"tool {tool}: outbound-capable ({'; '.join(notes) or 'no explicit restriction signal'})"
        )

    for name, spec in _mcp_servers(cfg).items():
        if not isinstance(spec, dict):
            continue
        parts = []
        if _mcp_has_remote(spec):
            parts.append("remote MCP endpoint")
            allowed_hosts = spec.get("allowedHosts")
            weak_hosts = _weak_allowlist_entries(allowed_hosts)
            if allowed_hosts and not weak_hosts:
                restricted = True
                parts.append("allowedHosts restricted")
            elif allowed_hosts and weak_hosts:
                parts.append(
                    "allowedHosts present but contains a wildcard/user-content "
                    f"host or URL-rewriting proxy (weak mitigation): {', '.join(weak_hosts)}"
                )
            else:
                parts.append("no allowedHosts restriction")
            url = spec.get("url") or spec.get("endpoint")
            if isinstance(url, str) and _mcp_url_is_local(url):
                restricted = True
                parts.append("local URL")
        else:
            restricted = True
            parts.append("local stdio subprocess")
        evidence.append(f"MCP {name}: {'; '.join(parts)}")

    ext = sorted(s for s in ctx.installed_skills if any(h in s.lower() for h in _EXT_SKILL_HINTS))
    for name in ext:
        evidence.append(f"skill {name}: external-service capability")

    # Every evidence line is now a surface; there is no global-restriction line to skip.
    surface_count = len(evidence)
    if not surface_count:
        return _finding(
            "C014",
            UNKNOWN,
            "No outbound-capable channels, MCP servers, skills, or tools detected.",
            "Run on the OpenClaw home with channels, skills, and MCP config present.",
        )
    if restricted:
        return _finding(
            "C014",
            PASS,
            f"Egress inventory: {surface_count} outbound-capable surface(s) found; at least one "
            "carries a per-surface restriction signal — see evidence. OpenClaw has no global "
            "egress-control setting, so this is not a guarantee that egress is restricted: "
            "read the per-surface lines and treat any unrestricted surface as open.",
            "Keep outbound-capable tools, MCP endpoints, and channels on tight allowlists and retain approval on high-impact actions.",
            evidence=evidence,
        )
    return _finding(
        "C014",
        WARN,
        f"Egress inventory: {surface_count} outbound-capable surface(s) found with no explicit "
        "restriction signal on any of them — see evidence. OpenClaw has no global egress-control "
        "setting, so egress can only be narrowed per surface.",
        "Add per-surface restrictions where OpenClaw supports them — channel dmPolicy/groupPolicy "
        "allowlists, tools.elevated.allowFrom, an exec approval gate, MCP allowedHosts or a local "
        "stdio transport — and keep outbound channels narrow.",
        evidence=evidence,
    )


def check_leak(ctx: Context) -> Finding:
    # Valid values: "off" | "tools" (default when set: "tools")
    # Boolean False never occurs in real configs — the field is always a string or absent.
    redact = dig(ctx.config, "logging.redactSensitive")
    if redact == "off":
        return _finding(
            "B9",
            FAIL,
            'logging.redactSensitive is "off" — secrets/system prompt can surface in tool output/logs.',
            'Set logging.redactSensitive to "tools" to redact secrets from tool output and logs.',
        )
    if redact is None:
        # B-128: the OpenClaw default when the field is unset is already "tools"
        # (redaction ON) — an absent field is secure-by-default, not an exposure.
        # The real (smaller) gap is that the default isn't pinned, so a future
        # OpenClaw default change could silently alter this without the operator
        # noticing. Wording/severity only — the trigger condition is unchanged.
        return _finding(
            "B9",
            WARN,
            'logging.redactSensitive not pinned — default "tools" already redacts '
            "secrets; pin it explicitly for stability against a future default change.",
            'Explicitly set logging.redactSensitive to "tools".',
        )
    if redact == "tools":
        return _finding(
            "B9",
            PASS,
            'Sensitive redaction is enabled (logging.redactSensitive="tools").',
            "Keep redaction on.",
        )
    # Unexpected value — be conservative
    return _finding(
        "B9",
        WARN,
        f'logging.redactSensitive has unexpected value {redact!r} — expected "tools" or "off".',
        'Set logging.redactSensitive to "tools".',
    )


def check_webfetch_redirects(ctx: Context) -> Finding:
    """B83 — web-fetch tool allows excessive redirect following.

    Grounded (recon: tools.web.fetch.enabled, tools.web.fetch.maxRedirects). A high
    redirect ceiling on the built-in fetch tool lets a fetched URL bounce the request
    through redirect chains toward private/internal targets (SSRF-style).

    PASS — fetch disabled, maxRedirects unset, or maxRedirects <= 5.
    WARN — fetch enabled AND maxRedirects > 5.
    """
    unreadable = _config_unreadable("B83", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not dig(cfg, "tools.web.fetch.enabled"):
        return _finding(
            "B83",
            PASS,
            "The built-in web-fetch tool is not enabled, so redirect-chain SSRF is not reachable.",
            "If you enable tools.web.fetch, keep tools.web.fetch.maxRedirects low (<= 5).",
        )
    redirects = dig(cfg, "tools.web.fetch.maxRedirects")
    if not isinstance(redirects, int) or redirects <= 5:
        return _finding(
            "B83",
            PASS,
            "The web-fetch tool follows a bounded number of redirects "
            "(tools.web.fetch.maxRedirects <= 5 or default).",
            "Keep tools.web.fetch.maxRedirects low (<= 5) to limit redirect-chain SSRF.",
        )
    return _finding(
        "B83",
        WARN,
        "tools.web.fetch.maxRedirects is high — a fetched URL can bounce through many "
        "redirects toward private/internal targets (SSRF-style).",
        "Lower tools.web.fetch.maxRedirects to <= 5, or disable the web-fetch tool.",
        evidence=[f"tools.web.fetch.maxRedirects={redirects}"],
    )


# ---------------------------------------------------------------------------
# B164 (F-124/E-044 Phase 1): log threat-hunt — content-scan the agent's OWN log corpus.
# ---------------------------------------------------------------------------
# Distinct from what's already here: B82 (check_cachetrace_redaction) is config-only (is
# redaction ON?), never reads cacheTrace CONTENT; B19 (check_data_atrest) is stat-only
# (file permissions), never reads file content; B77 (check_config_audit_log) reads ONLY
# logs/config-audit.jsonl, not the wider log corpus. B164 is the only one of the four that
# actually content-scans the log corpus for threat signals.
#
# Quiet-by-default (design doc §5.1 — base-rate discipline): a real log corpus is
# dominated by benign lines, so an isolated single-class hit is noise, not a finding. WARN
# fires only when >=2 distinct signal classes co-occur in the SAME sink, or a single class
# that already carries its own strong internal corroboration fires (exfil_evidence is
# already secret+exfil-host paired inside logscan.py — either on the SAME line, or, per
# B-249, a credential-path read earlier in the sink followed by a base64-encoded param to
# a known drop host on a later line; secrets_at_rest additionally needs the sink to be
# world-readable, checked here via the same B19 perm-check helper above).
_LOG_HUNT_PER_FILE_BUDGET_S = 3.0

# B-314: a CUMULATIVE ceiling across ALL sinks combined, checked once per sink before
# spending that sink's own _LOG_HUNT_PER_FILE_BUDGET_S. Before this, N sinks each capped
# individually at 3.0s could still multiply past this check's fair share of the 15s
# per-check hard timeout (DEFAULT_CHECK_BUDGET_S) with no shared ceiling between them —
# measured on a real config: ~4 large sinks each spending close to their full per-file
# allowance summed to 11.6s/15s (89% of budget, effectively no headroom before the next
# check in CHECKS risked degrading to UNKNOWN via the audit-wide cooperative deadline).
# Kept comfortably under the DoD's <=5s/check target so this one check can never itself
# threaten the shared per-check timeout. A sink skipped once this fires is disclosed via
# `_skipped_for_time` below (never silently dropped — Golden Rule #4), same honesty
# discipline `summarize_truncation` already applies to an oversized file/line.
_LOG_HUNT_CHECK_BUDGET_S = 4.5


def _log_hunt_corroborated(nonzero_classes: set, world_readable: bool) -> bool:
    """True when a sink's nonzero signal classes clear the quiet-by-default WARN bar."""
    strong_single = "exfil_evidence" in nonzero_classes or (
        "secrets_at_rest" in nonzero_classes and world_readable
    )
    return strong_single or len(nonzero_classes) >= 2


def check_log_threat_hunt(ctx: Context) -> Finding:
    """B164 — threats surfaced in the agent's own log corpus (content scan, advisory).

    Discovers every log/transcript sink the agent produces (trajectory sidecars,
    logging.file, cacheTrace transcripts, session transcripts, the config-audit log,
    memory files, install backups — see logdiscovery.py) and content-scans each one
    (logscan.py) for six signal classes: injection markers against the agent, exfil
    evidence, dangerous-capability use, environment-compromise IOCs, log
    tamper/anomaly, and secrets at rest.

    WARN  — at least one sink corroborates (see ``_log_hunt_corroborated``): >=2 distinct
            signal classes co-occur in that sink, or a single inherently-strong class
            fires (exfil_evidence, or secrets_at_rest on a world-readable sink).
    PASS  — sinks were found and scanned but no sink corroborated. Isolated/low-
            confidence hits are counted and reported, never WARNed on individually.
    UNKNOWN — no log/transcript sinks found, or none were readable/non-empty.
    Never FAIL — a content heuristic over an attacker-influenced corpus must never hard-
    fail the audit (Golden Rule #5); this check stays advisory (scored=False) — it never
    earns or costs an ordinary scored point, exactly as before.

    I-025/B-309 (Dave's 2026-07-20 ruling) originally carved out an exception to "can
    never move the A-F grade" for a same-line exfil_evidence hit anchored to a known
    drop-host. Across four C-135 rounds the drop-host gate was narrowed repeatedly (a
    named host, then an independent transport verb, then an attacker-exclusive
    OOB/canary set) trying to make that exception sound — and THREE independent
    adversarial reviews of the final attempt converged that it cannot be: this tool's
    own audience (security-conscious operators) legitimately sends secrets to the exact
    OOB/canary infrastructure (interactsh/oast, Burp Collaborator, dnslog,
    Canarytokens) a real attacker would also use, so the benign and malicious cases are
    byte-identical on a single log line. Dave's 2026-07-22 ruling RETRACTED the
    exception entirely (see logscan.py's retraction note above ``_scan_line_content``):
    B164 no longer carries any exfil_evidence-derived cap signal at all — every B164
    corroboration, including exfil_evidence (same-line or cross-line), is WARN-only,
    permanently. See ``scoring.RUNTIME_SIGNAL_CAP`` / ``scoring._runtime_cap_signal``:
    the trajaudit-indicator match is the only remaining I-025/B-309 cap source.
    """
    # Lazy import: logscan.py (a Layer-1 leaf) itself imports from the checks aggregator
    # (`from .checks import ...`) to reuse the engine's vetted indicator regexes — the
    # SAME reason several checks/*.py functions already import `..logsafe` lazily inside
    # the function body instead of at module top (see checks/_vet.py's comment on it).
    # logdiscovery.py has no such dependency, but is imported the same way for symmetry.
    from ..logdiscovery import discover_log_sinks  # noqa: PLC0415
    from ..logsafe import redact  # noqa: PLC0415
    from ..logscan import scan_log_file, summarize_truncation  # noqa: PLC0415
    from ..scanbudget import audit_deadline  # noqa: PLC0415

    sinks = discover_log_sinks(ctx)
    if not sinks:
        return _finding(
            "B164",
            UNKNOWN,
            "No agent log/transcript sinks found (no logging.file, cacheTrace, trajectory "
            "sidecar, session transcript, config-audit log, memory file, or install backup) "
            "— nothing to content-scan.",
            "Enable OpenClaw's default trajectory sidecar (on by default) and/or "
            "logging.file so a future run has a log corpus to threat-hunt.",
        )

    # C-221: cross-artifact correlation — a skill NAMING a high-specificity IOC (a known
    # drop-host or a credential/secret path in its own text) AND that same IOC APPEARING
    # in the agent's own log corpus is strong "declared a target and it was actually used"
    # evidence, folded into B164 as an additional corroboration axis (never its own check;
    # never FAIL; scored=False throughout, same as every other B164 signal).
    skill_iocs = correlation_indicators(ctx.installed_skills)

    corroborated: dict[str, set] = {}
    all_samples: list[str] = []
    all_results: list = []
    any_scanned = False
    isolated_hits = 0
    skipped_for_time = 0

    # B-314: the cumulative ceiling starts once, before the loop — not re-armed per sink
    # (that would defeat the point; see _LOG_HUNT_CHECK_BUDGET_S's docstring).
    check_deadline = audit_deadline(_LOG_HUNT_CHECK_BUDGET_S)

    for sink in sinks:
        remaining = None if check_deadline is None else check_deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            skipped_for_time += 1
            continue
        # B-314: this sink's own deadline is capped at whichever is TIGHTER — its usual
        # per-file allowance, or however much of the cumulative check budget is left — so
        # the last sink before the cumulative deadline can't still spend a full fresh
        # 3.0s and blow past it (a naive "check-then-always-give-3.0s" loop still let the
        # total overshoot by up to one sink's worth).
        per_sink_budget = _LOG_HUNT_PER_FILE_BUDGET_S
        if remaining is not None:
            per_sink_budget = min(per_sink_budget, remaining)
        deadline = audit_deadline(per_sink_budget)
        result = scan_log_file(sink, deadline, skill_iocs)
        all_results.append(result)
        if result.bytes_scanned == 0:
            continue
        any_scanned = True

        nonzero = {cls for cls, n in result.counts.items() if n > 0}
        cross = result.skill_ioc_hits
        if not nonzero and not cross:
            continue

        world_readable = _other_can_reach_read(ctx.home, sink.path)
        try:
            rel = str(sink.path.relative_to(ctx.home))
        except ValueError:
            rel = sink.path.name

        # C-221 / C-135 refinement: a cross-artifact hit on a KNOWN DROP-HOST a skill
        # named (webhook.site / ngrok / pastebin …) is genuinely low-base-rate and
        # qualifies the sink on its own. A hit on a credential/secret PATH is NOT — helper
        # skills legitimately name and read ~/.aws/credentials, ~/.npmrc, … and those paths
        # legitimately appear in the log, so a path cross-hit is only a CORROBORATOR: it
        # counts as one extra signal class (needs a co-occurring class to clear the WARN
        # bar) and can never sole-trigger a WARN on a benign dual-use path (the C-135 false
        # positive: an aws-cost-helper skill naming ~/.aws/credentials + a benign log line).
        # B-384: a named, dated IOC dataset host (../iocdb.py) is at least as
        # high-confidence as the generic drop-host shape list, so it also qualifies on its
        # own — never a sole FAIL trigger (B164 stays advisory/scored=False throughout
        # regardless). It no longer needs its own OR leg here: `_KNOWN_EXFIL_HOST_RE`
        # (checks/_shared.py) now has the IOC dataset's hosts spliced into its own
        # alternation, so a direct `iocdb.is_known_bad_host(t)` call would only ever be
        # True when the regex leg below is already True too — checking both was two
        # definitions of "known-bad host" that could disagree (and always agreed in
        # practice, since precise-match implies substring-match), not two independent
        # signals. One canonical check now covers both.
        strong_cross = {
            t: n for t, n in cross.items()
            if _KNOWN_EXFIL_HOST_RE.search(t)
        }
        weak_cross = {t: n for t, n in cross.items() if t not in strong_cross}
        effective = set(nonzero)
        if weak_cross:
            effective.add("cross-artifact-ioc")

        if strong_cross or _log_hunt_corroborated(effective, world_readable):
            display = set(nonzero)
            if cross:
                display.add("cross-artifact-ioc")
                for tok, count in list(cross.items())[:5]:
                    skill = skill_iocs.get(tok, "?")
                    all_samples.append(
                        f"cross-artifact-ioc: skill '{skill}' names {redact(tok)} "
                        f"— seen {count}x in {sink.kind}"
                    )
            corroborated[rel] = display
            all_samples.extend(result.samples[:5])
        else:
            isolated_hits += len(nonzero) + len(weak_cross)

    if not any_scanned:
        return _finding(
            "B164",
            UNKNOWN,
            f"{len(sinks)} log/transcript sink(s) found but none were readable/non-empty "
            "— nothing to content-scan.",
            "Ensure the agent's log/transcript files are readable by the auditing user.",
        )

    # B-285/LOG-1: a single, quantified truncation disclosure shared with B180 — see
    # logscan.summarize_truncation's docstring for why this replaced the old generic
    # "results may be incomplete" wording.
    note = summarize_truncation(all_results)
    # B-314: same honesty discipline for a sink skipped by the cumulative check-level
    # deadline (_LOG_HUNT_CHECK_BUDGET_S) — never silently omitted from the count.
    if skipped_for_time:
        plural = "sink" if skipped_for_time == 1 else "sinks"
        note += (
            f" {skipped_for_time} log/transcript {plural} not scanned (check time budget "
            "reached) — re-run to include them."
        )

    if corroborated:
        n_sinks = len(corroborated)
        shown = list(corroborated.items())[:5]
        detail = "; ".join(f"{sink}: {', '.join(sorted(classes))}" for sink, classes in shown)
        if n_sinks > 5:
            detail += f" (+{n_sinks - 5} more sink(s))"
        finding = _finding(
            "B164",
            WARN,
            f"Corroborated threat signal(s) in {n_sinks} log sink(s): {detail}.{note}",
            "Review the named log/transcript file(s) manually (see the Log Threat Report "
            "section for redacted-evidence samples). Rotate any credential the matched "
            "indicator could expose, and investigate how it reached the log.",
            evidence=all_samples[:20],
        )
        return finding

    detail = (
        f"{len(sinks) - skipped_for_time} log/transcript sink(s) scanned; "
        "no corroborated threat signal."
    )
    if isolated_hits:
        detail += (
            f" {isolated_hits} low-confidence signal(s) suppressed (isolated, not corroborated)."
        )
    detail += note
    return _finding(
        "B164",
        PASS,
        detail,
        "No action needed. Isolated/low-confidence signals are intentionally not WARNed "
        "on individually (base-rate discipline) — see the Log Threat Report section for "
        "the suppressed count.",
    )


# ---------- B321: browser.executablePath / profiles.*.{executablePath,mcpCommand} ----------
# Grounded directly against the installed dist (E-060 batch, 2026-07-25):
#   resolveBrowserExecutableForPlatform (chrome.executables-DP_XzlNl.js:626-640) accepts
#   a configured executablePath with only an fs.existsSync() gate -- no signature/
#   identity check -- then launchOpenClawChrome (chrome-DDq_K3xu.js:1754-1802) spawns it
#   directly: spawn(preparedSpawn.command, preparedSpawn.args, {...}). Whoever can
#   overwrite that file, or replace it inside its directory, controls what OpenClaw
#   actually launches. profile.executablePath falls back to browser.executablePath
#   (chrome-DDq_K3xu.js:1649-1654 resolveBrowserExecutable).
#
#   Deliberately NOT implemented: an "executablePath looks outside the expected Chrome/
#   Chromium install locations" heuristic. detectDefaultChromiumExecutable's own
#   candidate lists (chrome.executables-DP_XzlNl.js:132-224) already show real installs
#   vary enormously across distros/OSes (snap, Nix store, portable Chromium, custom
#   prefixes are all legitimate) -- an unusual-location heuristic would be a Golden-Rule-
#   #5 false-positive-FAIL waiting to happen. The writable-path signal below is the
#   substitute: same real threat (a swappable binary), far lower false-positive risk.
#
#   Deliberately NOT implemented: resolving each profile's driver/attachOnly chain to
#   suppress a FAIL on an executablePath that is schema-valid but currently inert (e.g.
#   an existing-session profile, which never reaches spawn()). Skipping that refinement
#   is a documented v1 choice, not an oversight: the writable-path signal is still true
#   and worth surfacing even for a presently-inert field, since the profile could be
#   reconfigured to a locally-launching driver later, and the check never claims the
#   binary WILL launch -- only that it is configured and, if it does launch, is not
#   tamper-proof.
def check_browser_executable_path(ctx: Context) -> Finding:
    """B321 — browser.executablePath / browser.profiles.*.{executablePath,mcpCommand}.

    Two distinct sub-signals share this one check ID:

    (A) executablePath (top-level and per-profile) — see the module comment above for
        the grounding. FAIL-capable: a configured, existing path that is writable by
        another local account is a real, narrow, deterministic escalation, closely
        analogous to B186's writable-relocated-code-root precedent
        (checks/_host.py check_bundled_root_override).
    (B) profiles.<name>.mcpCommand (existing-session driver only) overrides the
        subprocess binary OpenClaw hands the Chrome DevTools MCP session to —
        normalizeChromeMcpOptions (chrome-mcp-BZM3Tb7R.js:174-183) passes it through
        with zero validation of any kind (no trustedDirs-style scoping, no existence
        check). The vendor default is itself an unpinned `npx -y
        chrome-devtools-mcp@latest` (DEFAULT_CHROME_MCP_COMMAND/
        DEFAULT_CHROME_MCP_PACKAGE_ARGS, chrome-mcp-BZM3Tb7R.js:35-36) — so an explicit,
        non-default mcpCommand is at least as plausibly a *hardening* move (pinning a
        known binary instead of trusting an unpinned npx auto-install) as a downgrade.
        WARN-only, and `scored=False` on that specific branch (this check's CheckMeta
        otherwise stays scored — see the FAIL branch above), mirroring B192/B324's
        precedent for a legitimate, commonly-wanted customization a FAIL would punish.

    FAIL    — a configured executablePath (top-level or any profile's) exists on disk
              and either the file itself or its containing directory is group/world-
              writable (non-sticky) by another local account
              (checks/_shared._dir_replaceable_by_others on both the file and its
              parent — the file-writable case lets another account overwrite the binary
              in place; the parent-writable case lets another account replace the
              directory entry, e.g. via rename/symlink, even if the file's own mode is
              tight). Requires host-filesystem scanning; see UNKNOWN below when it is
              off.
    WARN    — an existing-session profile's mcpCommand is set to a non-default value
              (scored=False on this branch — see (B) above).
    PASS    — at least one executablePath was configured, host-scanned, and none is
              writable by another account; no mcpCommand override found.
    UNKNOWN — no browser config at all; OR browser is configured but neither an
              executablePath (top-level or per-profile) nor an existing-session
              mcpCommand override is set anywhere — nothing to assess (B-362: sets
              ``not_applicable`` here — the config locus was read COMPLETELY and
              neither sub-signal exists anywhere in the browser block, so there is
              genuinely nothing for this check to assess, not merely an unassessed
              risk); OR an executablePath is configured but host-filesystem scanning
              is disabled (ctx.include_host is False / --no-host) — mirrors C5's own
              --no-host gate (checks/_capability.py check_path_safety): writability
              cannot be assessed without stat()-ing the real path, and this check does
              not fall back to reporting the independent mcpCommand signal alone in
              that specific run to keep the "assessment incomplete" verdict
              unambiguous — a subsequent run without --no-host (the CLI default)
              evaluates both signals normally. This THIRD branch stays a real UNKNOWN
              (not not_applicable) — candidates were found, the scan is merely
              incomplete right now.
    """
    browser = ctx.config.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B321",
            UNKNOWN,
            "No browser config — executablePath / mcpCommand not applicable.",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    candidates: list[tuple[str, str]] = []
    top_level_exe = browser.get("executablePath")
    if isinstance(top_level_exe, str) and top_level_exe.strip():
        candidates.append(("browser.executablePath", top_level_exe.strip()))

    profiles = browser.get("profiles") if isinstance(browser.get("profiles"), dict) else {}
    mcp_warn_ev: list[str] = []
    for name, spec in profiles.items():
        if not isinstance(spec, dict):
            continue
        exe = spec.get("executablePath")
        if isinstance(exe, str) and exe.strip():
            candidates.append((f"browser.profiles.{name}.executablePath", exe.strip()))
        if spec.get("driver") == "existing-session":
            mcp_cmd = spec.get("mcpCommand")
            if isinstance(mcp_cmd, str) and mcp_cmd.strip() and mcp_cmd.strip() != "npx":
                mcp_warn_ev.append(
                    f"browser.profiles.{name}.mcpCommand={mcp_cmd.strip()!r} overrides "
                    "the vendor default (npx -y chrome-devtools-mcp@latest) — OpenClaw "
                    "does not validate this command/path before spawning it"
                )

    if not candidates and not mcp_warn_ev:
        return _finding(
            "B321",
            UNKNOWN,
            "browser is configured but no executablePath (top-level or per-profile) "
            "and no existing-session mcpCommand override is set — nothing to assess.",
            "—",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    if candidates and not getattr(ctx, "include_host", False):
        plural = "y" if len(candidates) == 1 else "ies"
        return _finding(
            "B321",
            UNKNOWN,
            f"{len(candidates)} configured executablePath entr{plural} found but "
            "host-filesystem scanning is disabled (--no-host) — cannot assess whether "
            "the target is writable by another local account.",
            "Re-run without --no-host to assess executablePath writability.",
        )

    fail_ev: list[str] = []
    for label, raw_path in candidates:
        p = Path(raw_path).expanduser()
        try:
            found = p.exists()
        except OSError:
            found = False
        if not found:
            # Matches B186's own precedent: a configured-but-nonexistent path is
            # silently not a finding here — OpenClaw's own exists() check surfaces a
            # clear runtime error at launch time; that is a functionality issue, not a
            # security one.
            continue
        why_file = _shared._dir_replaceable_by_others(p)
        if why_file:
            fail_ev.append(
                f"{label}={p} is {why_file} — another local account can overwrite "
                "this binary in place"
            )
        # C-135 regression (found in adversarial review, 2026-07-25): p.parent is
        # purely syntactic (string-based) and does NOT follow a symlink chain, but
        # p.stat() (inside _dir_replaceable_by_others(p) above, and inside p.exists())
        # DOES follow symlinks -- so a configured executablePath that is itself a
        # symlink (a common real-world install shape: distro packages, Nix profiles,
        # asdf/mise shims, Playwright/Puppeteer browser caches) was checked against
        # the SYMLINK's own containing directory, never against the resolved target
        # file's real containing directory. A symlink sitting in a tight 0755
        # directory but pointing at a binary inside a world-writable directory
        # (e.g. a shared/cache dir on a multi-user host) passed this check with no
        # evidence at all, even though any local account could replace the real
        # binary the symlink resolves to. Path.resolve() follows the full chain (every
        # intermediate component, not just the last hop); its parent is checked in
        # addition to -- not instead of -- the original p.parent, since a writable
        # symlink location is a real, independent replace vector too (an attacker
        # could repoint the symlink itself, no target write access needed).
        parents_to_check = {p.parent}
        try:
            real_p = p.resolve()
        except (OSError, RuntimeError):
            real_p = p
        if real_p != p:
            parents_to_check.add(real_p.parent)
        for parent in sorted(parents_to_check, key=str):
            why_parent = _shared._dir_replaceable_by_others(parent)
            if why_parent:
                via = " (via a symlink target)" if parent != p.parent else ""
                fail_ev.append(
                    f"{label}={p} — containing directory {parent} is {why_parent}"
                    f"{via} — another local account can replace this binary"
                )

    if fail_ev:
        return _finding(
            "B321",
            FAIL,
            f"{len(fail_ev)} configured browser executable path(s) are writable by "
            "another local account — see evidence.",
            "Move the browser executable to a directory only its owner can write to "
            "(0755/0700 with an owner-only-writable parent), or point "
            "browser.executablePath at the OS-managed Chrome/Chromium install instead.",
            evidence=(fail_ev + mcp_warn_ev)[:6],
        )

    if mcp_warn_ev:
        return _finding(
            "B321",
            WARN,
            f"{len(mcp_warn_ev)} existing-session browser profile(s) override the "
            "Chrome DevTools MCP command from the vendor default — see evidence.",
            "Confirm the configured mcpCommand points to a binary you trust; OpenClaw "
            "does not validate it before spawning.",
            evidence=mcp_warn_ev[:6],
            scored=False,
        )

    return _finding(
        "B321",
        PASS,
        f"{len(candidates)} configured browser executable path(s) checked — none "
        "writable by another local account.",
        "Keep browser.executablePath (and any per-profile override) pointed at a "
        "directory only its owner can write to.",
    )


# ---------- B322: browser.profiles.*.{cdpUrl,userDataDir,driver:"existing-session"} ----------
# WHATWG "special schemes" (url.spec.whatwg.org/#special-scheme) that reach the
# "special authority ignore slashes" state this helper models. "file" is deliberately
# ABSENT even though the spec lists it as special: file URLs go through their own
# parsing states (file / file slash / file host), so folding them in here would
# mishandle a scheme the helper claims to support. OpenClaw restricts cdpUrl to
# http/https/ws/wss anyway (normalizeExistingSessionCdpUrl, config-DpWXcVmn.js:332-337).
_WHATWG_SPECIAL_SCHEMES = ("http", "https", "ws", "wss", "ftp")

# The characters the REAL pipeline removes from each end of a cdpUrl, which is the union
# of two steps OpenClaw actually performs: `value.trim()` (normalizeOptionalString,
# string-coerce-DW4mBlAt.js:9) and then `new URL(value)`, whose first step strips leading
# and trailing C0 controls or space.
#   * C0 controls U+0000-U+001F and space -- stripped by the URL parser.
#   * ECMAScript trim()'s WhiteSpace + LineTerminator -- NBSP, BOM, the Zs block,
#     LS/PS -- stripped by trim().
# Python's argument-less str.strip() is NEITHER set: it misses U+0000-U+0008,
# U+000E-U+001F and U+FEFF (so a BOM- or NUL-prefixed cdpUrl parsed as unparseable here
# while the product happily resolved it -- a lying PASS), and it over-strips U+0085 NEL,
# which is in neither the C0 range nor trim()'s set. U+0085 is therefore deliberately
# ABSENT below. Measured against the live pipeline (trim -> new URL -> isLoopbackHost).
_URL_TRIM_CHARS = (
    "".join(chr(c) for c in range(0x00, 0x20))          # C0 controls
    + "   "                              # space, NBSP, OGHAM SPACE MARK
    + "".join(chr(c) for c in range(0x2000, 0x200b))    # EN QUAD .. HAIR SPACE
    + "    　﻿"            # LS, PS, NNBSP, MMSP, IDSP, BOM
)


def _whatwg_url(url) -> str:
    """Rewrite a URL the way a browser's WHATWG parser reads it, before urlparse sees it.

    C-135 false negative (found 2026-07-26, fixed here). WHATWG treats a backslash as
    equivalent to a forward slash inside a special-scheme URL; Python's urllib does not.
    The two therefore disagree about where the authority ENDS, and an attacker can aim
    them at different hosts with one string:

        http://10.0.0.9:9222\\@127.0.0.1

    urlparse keeps the whole thing as the authority and splits userinfo on the LAST '@',
    yielding host "127.0.0.1" -- loopback, apparently safe, and the value this module
    would have both graded and DISPLAYED. A browser terminates the authority at the
    backslash, yielding host "10.0.0.9" port 9222, with "@127.0.0.1" demoted to the path.
    Verified against Node's `new URL()` (host=10.0.0.9, port=9222, path=/@127.0.0.1)
    versus Python's urlparse (host=127.0.0.1, port=None) on 2026-07-26.

    That divergence is exactly load-bearing here, because OpenClaw parses cdpUrl with
    `new URL()` itself -- normalizeExistingSessionCdpUrl (config-DpWXcVmn.js:326-342)
    stores `cdpHost = parsed.hostname` and `cdpIsLoopback = isLoopbackHost(cdpHost)`.
    So the product dials 10.0.0.9 while this check called it loopback: a config that
    should FAIL reported clean, with the report naming the decoy loopback host.

    Normalizing here rather than at each call site keeps _cdp_url_classify() and
    _cdp_url_display() on ONE parse of ONE string -- a verdict and the host it names can
    never again come from different readings of the same value.

    THE SLASH RUN IS THE WHOLE POINT, NOT JUST THE BACKSLASH (C-135, second pass). A
    first version of this helper only rewrote backslashes to slashes, which produced the
    right answer for the exactly-two-backslash decoy above and the wrong answer for every
    other run length -- because WHATWG does not merely alias `\\` to `/`, it has a
    "special authority ignore slashes" state that consumes ANY run of `/` and `\\`
    (zero or more, in any mix) between the scheme and the authority. So `http:10.0.0.9`,
    `http:/10.0.0.9`, `http:///10.0.0.9` and `http:/\\/\\10.0.0.9` ALL resolve to host
    10.0.0.9 in a browser. Python's urlparse instead finds no authority at all in those,
    reports hostname None, and this module classified them "unparseable" -- which
    _offhost_cdp_endpoints() treats as "nothing to report", i.e. B330 returned a PASS
    whose own text asserts "every CDP endpoint it names is loopback". A lying PASS on
    attacker-controllable input, the same failure mode as the historical B2/B70
    `0.0.0.0/0` bug. Reachable: the schema puts no `.url()` refinement on cdpUrl
    (zod-schema-O9ml_nmo.js:1096) and both normalizeExistingSessionCdpUrl
    (config-DpWXcVmn.js:323) and parseBrowserHttpUrl (browser-config-DCrASvM0.js:15)
    call bare `new URL(value)`.

    Hence: strip the whole leading slash/backslash run, then re-attach exactly `://`.
    This stays one-directional in the same sense as the numeric fallbacks below -- it
    cannot invent a host that is not in the string, it can only move a value from
    "unparseable" onto the host a browser's own parser resolves it to.

    TAB/CR/LF ARE REMOVED FIRST, AND THE ORDER MATTERS (C-135, third pass). WHATWG's
    very first step is "remove all ASCII tab or newline from input", before any state
    machine runs -- so `http:<TAB>//10.0.0.9:9222` is host 10.0.0.9 to a browser and to
    OpenClaw's isLoopbackHost. Python's urlsplit strips those characters too (bpo-43882),
    which is why the pre-B-337 code got this right by accident. But rebuilding the string
    as `scheme + "://" + rest` re-emits the tab immediately after the `://`, where it
    lands INSIDE the authority and collapses the netloc to empty -- reintroducing the
    very lying-PASS this helper exists to close. Measured: `http:<TAB>//10.0.0.9:9222`
    classified "remote" before B-337, "unparseable" with the rewrite and no tab removal,
    and "remote" again once the removal is done first. So the removal is not decoration;
    it is what makes the rebuild safe.

    USERINFO IS REMOVED BEFORE urlsplit SEES THE STRING (C-135, fifth pass). Python's
    urlsplit validates `[`/`]` against the WHOLE netloc and raises ValueError if they are
    unbalanced there -- but WHATWG's authority state finds the LAST `@` first and only
    ever validates brackets in what follows it. So `http://[x]@10.0.0.9:9222` is host
    10.0.0.9 to a browser and an exception here, which _cdp_url_classify turns into
    "unparseable" -- the same lying PASS, with the decoy simply moved left of the `@`
    instead of right of it. Splitting userinfo off at the last `@` of the authority
    before handing the string over closes that, and as a side effect stops
    _cdp_url_display() from ever echoing embedded credentials (OpenClaw's own
    redactCdpUrl strips them for the same reason).

    Non-special schemes are left alone apart from the character removals (WHATWG only
    gives backslash its authority meaning for special schemes), as is any value with no
    scheme, which classify/display already handle as unparseable.
    """
    # WHATWG step 1: strip ASCII tab (0x09), LF (0x0A) and CR (0x0D) everywhere; then
    # remove from each end exactly what trim() + the URL parser remove (_URL_TRIM_CHARS).
    text = str(url).translate({9: None, 10: None, 13: None}).strip(_URL_TRIM_CHARS)
    scheme, sep, rest = text.partition(":")
    if not sep or scheme.lower() not in _WHATWG_SPECIAL_SCHEMES:
        return text
    rest = rest.lstrip("/\\").replace("\\", "/")
    # The authority ends at the first "/", "?" or "#"; everything up to the LAST "@"
    # inside it is userinfo and is discarded, exactly as WHATWG's authority state does.
    cut = len(rest)
    for delim in "/?#":
        found = rest.find(delim)
        if found != -1 and found < cut:
            cut = found
    authority, tail = rest[:cut], rest[cut:]
    at = authority.rfind("@")
    if at != -1:
        authority = authority[at + 1:]
    return scheme + "://" + authority + tail


# C-357: length gate for the IDNA/fullwidth-digit homoglyph fold in
# _cdp_url_classify() below -- see the C-135 note at its call site for why nameprep
# walks a whole non-ASCII label before its own length check can fire. No legitimate
# DNS hostname exceeds 253 ASCII characters (RFC 1035); 512 is a generous ceiling that
# only ever excludes pathological input.
_IDNA_HOST_MAX_CHARS = 512


def _cdp_url_classify(url) -> str:
    """Classify a browser.profiles.<name>.cdpUrl value: "loopback", "remote", or
    "unparseable". A non-string/empty value classifies as "loopback" -- OpenClaw's own
    normalizeExistingSessionCdpUrl (config-DpWXcVmn.js:323-343) defaults
    cdpIsLoopback=True when the value is absent, and this check never FAILs on garbage
    input (Golden Rule #5).

    Mirrors OpenClaw's own isLoopbackHost (net-BOKtNTf8.js:219-224), which explicitly
    treats 0.0.0.0 and :: as NOT loopback ("every interface", not local) -- the same
    semantics this module's own LOOPBACK/_loopback_ip (checks/_shared.py) already
    assume elsewhere (check_outbound_proxy, _mcp_url_is_local), so no cross-check drift.
    """
    if not isinstance(url, str) or not url.strip():
        return "loopback"
    try:
        parsed = urlparse(_whatwg_url(url))
        host = (parsed.hostname or "").lower()
    except Exception:
        return "unparseable"
    if not host:
        return "unparseable"
    # C-357: non-ASCII label-separator dots (U+3002 IDEOGRAPHIC FULL STOP, U+FF0E
    # FULLWIDTH FULL STOP, U+FF61 HALFWIDTH IDEOGRAPHIC FULL STOP) and fullwidth-digit
    # spellings of an IPv4 literal (U+FF10-FF19) are exactly what a browser's WHATWG
    # "domain to ASCII" host parser folds to their ASCII equivalents before
    # isLoopbackHost ever sees the string -- so `http://127。0。0。1:9222` dials genuine
    # loopback in the real product, an IME substituting the ideographic full-width dot
    # for ASCII "." while a user types a URL being a realistic, non-adversarial way to
    # produce it. Grounded against Python's stdlib `encodings.idna` codec (RFC 3490
    # ToASCII/nameprep -- the only IDNA implementation Golden Rule #1 allows, no PyPI
    # `idna` package): its `dots` splitter is `re.compile("[.。．｡]")`,
    # the identical RFC 3490 S3.1 / WHATWG dot-equivalence class, and nameprep's NFKC
    # step folds fullwidth digits the same way. Measured directly (2026-07-28):
    #     '127。0。0。1'.encode('idna')  == b'127.0.0.1'
    #     '１２７.0.0.1'.encode('idna') == b'127.0.0.1'
    #     '169.254.169.254。'.encode('idna') == b'169.254.169.254.'  (a real remote
    #         IP keeps its identity -- only the dot form changes, matching the
    #         existing one-trailing-dot handling a few lines below)
    #     'example.com'.encode('idna') == b'example.com'  (real hostnames untouched)
    # ASCII-gated (idna is only invoked on a host that actually contains a non-ASCII
    # code point) so the exhaustively-tested pure-ASCII path below -- LOOPBACK
    # membership, "localhost", the numeric fallback -- is untouched byte-for-byte.
    # One-way, like every other fallback in this function: a host idna cannot encode
    # (UnicodeError -- an empty/oversized label, a bidi violation, ...) falls straight
    # through unchanged to the existing logic below, so this can only ever ADD a
    # loopback verdict, never remove one.
    #
    # C-135 adversarial pass (2026-07-28): length-gated at _IDNA_HOST_MAX_CHARS. The
    # stdlib nameprep step walks the WHOLE label doing per-character stringprep table
    # lookups BEFORE its own "label too long" check ever fires (that check only runs
    # on nameprep's OUTPUT), so an attacker-controlled non-ASCII host with no dots
    # bypasses idna's own early-exit and forces the full pass. Measured: a 5,000,000
    # char single-label non-ASCII host (still inside the pre-existing whole-config
    # 5 MB byte ceiling, collector._MAX_CONFIG_BYTES) took ~19s to classify -- over
    # this project's own 15s per-check budget (scanbudget.DEFAULT_CHECK_BUDGET_S),
    # degrading the check to UNKNOWN under that safety net rather than a lying
    # verdict, but still a real, newly-introduced cost this fix must not impose on an
    # ordinary scan. No legitimate DNS hostname exceeds 253 ASCII characters (RFC
    # 1035); 512 is a generous, RFC-agnostic ceiling that only ever excludes
    # pathological input, never a real cdpUrl host.
    if not host.isascii() and len(host) <= _IDNA_HOST_MAX_CHARS:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    if host in LOOPBACK:
        return "loopback"
    # C-135: "localhost." is genuinely loopback to the product, while a bare
    # set-membership test calls it remote -- a scored false FAIL on B322. Measured
    # against the dist directly (isLoopbackHost imported live from net-BOKtNTf8.js):
    #     isLoopbackHost("localhost.")  -> true      isLoopbackHost("127.0.0.1.")  -> false
    #     new URL("http://localhost.:9222").hostname  -> "localhost."
    #     new URL("http://127.0.0.1.:9222").hostname -> "127.0.0.1"
    # So the two dotted cases are normalized by DIFFERENT layers, and only the hostname
    # one needs handling here: OpenClaw's parseHostForAddressChecks strips trailing dots
    # for its literal "localhost" comparison, whereas for an IP it never sees the dotted
    # form at all because WHATWG's IPv4 parser has already dropped the empty trailing
    # label -- at most one of them, which is why the numeric retry below only strips
    # one trailing dot too, not an unbounded run.
    #
    # C-135 (2026-07-26, round 7): the full-rstrip above was measured against a single
    # trailing dot and over-generalized to the whole LOOPBACK set, which also contains
    # numeric forms ("127.0.0.1", "::1") that do NOT take this path -- WHATWG's IPv4
    # parser removes AT MOST ONE trailing empty label, so "127.0.0.1.." stays remote to
    # the product even though a full rstrip lands it back in LOOPBACK. Restricted to the
    # literal "localhost" comparison, matching OpenClaw's own parseHostForAddressChecks
    # (net-BOKtNTf8.js:255-258), which strips every trailing dot but ONLY for that one
    # string equality check -- never for an IP-shaped host.
    if host.rstrip(".") == "localhost":
        return "loopback"
    # C-135 regression (found in adversarial review, 2026-07-25): OpenClaw's own
    # cdpUrl normalization (normalizeExistingSessionCdpUrl, config-DpWXcVmn.js:326-342)
    # parses the operator's string with JS `new URL()`, whose WHATWG host parser
    # canonicalizes legacy/non-canonical numeric IPv4 forms -- shorthand ("127.1"),
    # octal-looking ("0177.0.0.1"), zero-padded ("127.000.000.001"), and bare
    # decimal/hex 32-bit values ("2130706433" / "0x7f000001") -- to their dotted-quad
    # equivalent BEFORE storing cdpHost/cdpIsLoopback or re-serializing cdpUrl via
    # `parsed.toString()` for the chrome-devtools-mcp handoff. Verified against Node's
    # `new URL()` directly: all five forms above resolve to "127.0.0.1". So a config
    # written as cdpUrl="http://127.1:9222" dials genuine loopback in the real
    # product, but Python's stdlib `ipaddress` module (which backs LOOPBACK/
    # _loopback_ip) deliberately rejects every one of those forms as non-canonical --
    # without this fallback they all misclassified as "remote", producing a FAIL on a
    # config that is not, in fact, remote (Golden Rule #5).
    #
    # socket.inet_aton() implements the same legacy BSD numeric-host parsing WHATWG's
    # algorithm was modeled on (spot-checked against Node's output for the forms
    # above -- identical results); used ONLY to re-test a host the strict path above
    # already failed to place in LOOPBACK. If the canonicalized result is NOT
    # loopback (a real routable address written in an unusual base), or inet_aton
    # itself rejects the string (the common case: an ordinary DNS hostname), this
    # deliberately falls through to "remote" unchanged -- so an actual remote host
    # (a plain hostname, or a canonical dotted-quad public IP) is never reclassified
    # away from "remote" by this fallback; it only ever *adds* a loopback verdict,
    # never removes one.
    #
    # C-135 (2026-07-26), PRE-EXISTING false positive found by an independent adversarial
    # differential against Node's `new URL()`: trailing dots. WHATWG's IPv4 parser drops
    # the empty trailing label, so a browser resolves `http://127.0.0.1.:9222` to hostname
    # "127.0.0.1" -- genuinely loopback -- while both `ipaddress` and `inet_aton` reject
    # the dotted string, so this classified it "remote" and B322 emitted a SCORED FAIL on
    # a loopback-only config. Note the normalization happens in the URL parser, not in
    # OpenClaw: isLoopbackHost("127.0.0.1.") is itself false (measured), it simply never
    # receives that form. It stays one-directional: a real hostname written FQDN-style
    # ("example.com.") is still rejected by inet_aton and still classifies "remote", so
    # no genuinely remote host can be reclassified as loopback by this.
    #
    # C-135 (round 7): only ONE trailing dot is dropped, not `rstrip`'s unbounded run --
    # WHATWG's IPv4 parser removes at most one empty trailing label, so
    # "127.0.0.1.." stays "remote" to the product (measured against the dist's own
    # isLoopbackHost) even though a full rstrip would land it back in LOOPBACK.
    one_dot_stripped = host[:-1] if host.endswith(".") else host
    for candidate in (host, one_dot_stripped):
        try:
            canonical = socket.inet_ntoa(socket.inet_aton(candidate))
        except (OSError, UnicodeError):
            continue
        if canonical in LOOPBACK:
            return "loopback"
    return "remote"


def _cdp_url_display(url) -> str:
    """scheme://host[:port] only -- never the full URL. OpenClaw's own redactCdpUrl
    (browser-config-DCrASvM0.js:56-68) strips embedded username/password before any
    diagnostic display, confirming OpenClaw itself treats cdpUrl as potentially
    credential-bearing; this check goes further and drops the path/query too.

    Parses the same _whatwg_url()-normalized string _cdp_url_classify() grades, so the
    host shown can never disagree with the host judged (see that helper's C-135 note --
    the un-normalized form displayed an attacker's decoy loopback host)."""
    try:
        parsed = urlparse(_whatwg_url(url))
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        scheme = parsed.scheme or "?"
        return f"{scheme}://{host}{port}"
    except Exception:
        return "<unparseable>"


def check_browser_existing_session_profile(ctx: Context) -> Finding:
    """B322 — browser.profiles.*.{cdpUrl,userDataDir,driver:"existing-session"}.

    driver:"existing-session" switches OpenClaw from launching its own managed Chrome to
    spawning a third-party `chrome-devtools-mcp` subprocess (vendor default `npx -y
    chrome-devtools-mcp@latest`, chrome-mcp-BZM3Tb7R.js:35-36) and handing it cdpUrl /
    userDataDir as raw CLI args (chrome-mcp-BZM3Tb7R.js normalizeChromeMcpOptions /
    buildChromeMcpConnectionArgs — confirmed against the installed dist). Two distinct
    concerns live under this one check ID:

    * userDataDir pointed at a real (non-dedicated) browser profile directory would hand
      the agent live cookies/sessions from that profile — but OpenClaw's own field docs
      frame userDataDir as normal usage for "Brave, Edge, Chromium, or non-default
      Chrome profiles", and "is this the user's real daily-driver profile or a
      dedicated automation profile" is not answerable from a bare path string without
      an unsound heuristic (the two look identical on disk) — so userDataDir is
      disclosed as WARN-tier context only, never a FAIL discriminator, and never used to
      suppress or escalate the cdpUrl verdict below.
    * cdpUrl is the FAIL discriminator: getBrowserProfileCapabilities()
      (cdp-reachability-policy-BLdT5iz3.js:9-19) hardcodes isRemote:false for every
      driver:"existing-session" profile; resolveCdpReachabilityPolicy() (same file,
      :17-19) only requires an ssrfPolicy.hostnameAllowlist match when
      capabilities.isRemote is true — so the allowlist requirement that would gate a
      genuinely remote managed-Chrome ("openclaw" driver) connection never triggers for
      an existing-session profile's cdpUrl, confirmed by direct dist read. That cdpUrl
      is then handed to the third-party chrome-devtools-mcp subprocess as a raw CLI arg
      (--wsEndpoint / --browserUrl) with no further OpenClaw-side loopback check at that
      hand-off.

    Scope, stated exactly (v1 — deliberately deferred, not an oversight): only
    browser.profiles.<name>.cdpUrl is evaluated. The legacy top-level browser.cdpUrl ->
    existing-session-default-profile migration path
    (config-DpWXcVmn.js:426-437,479 applyLegacyCdpUrlToExistingSessionDefaultProfile —
    fires only when browser.cdpUrl is a ws(s):// URL AND the resolved default profile is
    driver:"existing-session" AND that profile has no cdpUrl of its own) is not
    evaluated here; a profile relying solely on that legacy migration path is invisible
    to this check.

    "In effect" driver resolution: a profile counts as driver:"existing-session" when
    either (a) browser.profiles.<name>.driver is explicitly "existing-session" — a real,
    operator-written signal, since OpenClaw lets a tool call select any named profile at
    runtime, not only the resolved default, so an explicitly-declared existing-session
    profile is a latent activation regardless of browser.defaultProfile
    (resolveProfile, config-DpWXcVmn.js:512-557) — or (b) browser.defaultProfile is
    explicitly "user" and browser.profiles does not itself redefine "user" with another
    driver. OpenClaw auto-creates a built-in driver:"existing-session", attachOnly:true
    profile named "user" whenever the operator's config does not override it
    (ensureDefaultUserBrowserProfile, config-DpWXcVmn.js:391-400) — but that built-in
    profile stays dormant unless explicitly selected. The bare, never-selected existence
    of the built-in profile is deliberately NOT flagged on its own — every browser
    config would otherwise WARN, which would not be a real signal (see the module
    docstring's own note on this default-dormant channel).

    FAIL    — an in-effect existing-session profile's cdpUrl resolves to a non-loopback
              host (`scored=True` override on this branch — this check's CheckMeta is
              otherwise unscored, mirroring B186's own narrow-FAIL-override precedent:
              the WARN/PASS states here are a legitimate, working-as-intended feature,
              but this one deterministic escalation should still carry real grade
              weight).
    WARN    — an in-effect existing-session profile's cdpUrl is absent, loopback, or
              unparseable (ambiguous classification defaults to WARN, never FAIL/
              UNKNOWN, per this project's own precedent); and/or userDataDir is set on
              an in-effect profile (disclosed context, not a downgrade on its own).
    PASS    — browser is configured but no profile has an in-effect driver of
              "existing-session".
    UNKNOWN — no openclaw.json found; openclaw.json present but unparseable/unreadable;
              or no browser config at all.
    """
    if not ctx.config_found:
        return _finding(
            "B322",
            UNKNOWN,
            "No openclaw.json found — browser existing-session profile exposure "
            "cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B322", ctx)
    if unreadable is not None:
        return unreadable

    browser = ctx.config.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B322",
            UNKNOWN,
            "No browser config — existing-session profile exposure not applicable.",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    profiles_cfg = browser.get("profiles") if isinstance(browser.get("profiles"), dict) else {}
    in_effect: dict = {}
    for name, spec in profiles_cfg.items():
        if isinstance(spec, dict) and spec.get("driver") == "existing-session":
            in_effect[name] = spec
    default_profile = browser.get("defaultProfile")
    if default_profile == "user" and "user" not in profiles_cfg:
        in_effect.setdefault("user", {})

    if not in_effect:
        return _finding(
            "B322",
            PASS,
            "browser is configured but no profile has an in-effect driver of "
            "\"existing-session\" — this agent launches its own managed Chrome rather "
            "than attaching to an existing browser session.",
            "—",
        )

    fail_ev: list[str] = []
    warn_ev: list[str] = []
    for name, spec in in_effect.items():
        cdp_url = spec.get("cdpUrl")
        classification = _cdp_url_classify(cdp_url)
        if classification == "remote":
            fail_ev.append(
                f"browser.profiles.{name} (driver=existing-session) cdpUrl="
                f"{_cdp_url_display(cdp_url)} is not loopback — OpenClaw's own SSRF "
                "hostname-allowlist requirement never applies to an existing-session "
                "profile (getBrowserProfileCapabilities hardcodes isRemote=false for "
                "this driver), so this URL reaches the chrome-devtools-mcp subprocess "
                "with no OpenClaw-side loopback/allowlist enforcement"
            )
        elif classification == "unparseable":
            warn_ev.append(
                f"browser.profiles.{name} (driver=existing-session) cdpUrl is set but "
                "not a parseable URL — could not classify as loopback or remote"
            )
        elif cdp_url:
            warn_ev.append(
                f"browser.profiles.{name} (driver=existing-session) attaches via "
                f"cdpUrl={_cdp_url_display(cdp_url)} (loopback)"
            )
        else:
            warn_ev.append(
                f"browser.profiles.{name} (driver=existing-session) has no cdpUrl set "
                "— auto-detects a locally running Chrome with remote debugging enabled"
            )
        user_data_dir = spec.get("userDataDir")
        if isinstance(user_data_dir, str) and user_data_dir.strip():
            warn_ev.append(
                f"browser.profiles.{name}.userDataDir={user_data_dir.strip()!r} — the "
                "agent attaches to whatever browser profile lives at this path; "
                "confirm it is a dedicated automation profile, not a real "
                "daily-driver profile with live cookies/sessions"
            )

    if fail_ev:
        return _finding(
            "B322",
            FAIL,
            f"{len(fail_ev)} existing-session browser profile(s) attach to a "
            "non-loopback Chrome DevTools Protocol endpoint — see evidence.",
            "Point cdpUrl at a loopback address (127.0.0.1 / localhost), or tunnel the "
            "remote endpoint over SSH/VPN and connect to the local tunnel end instead "
            "of the raw remote host.",
            evidence=(fail_ev + warn_ev)[:6],
            scored=True,
        )

    return _finding(
        "B322",
        WARN,
        f"{len(in_effect)} browser profile(s) use driver=\"existing-session\" — see "
        "evidence.",
        "This is a legitimate feature (attaching to a real, already-signed-in Chrome "
        "session) but review each profile: confirm cdpUrl is loopback-only, and "
        "userDataDir points at a profile you intend the agent to have live access to.",
        evidence=warn_ev[:6],
        # B-315/B186 precedent: forced here rather than left to inherit CheckMeta.scored
        # so this branch stays unscored regardless of how the catalog entry is wired --
        # this is a legitimate, commonly-wanted feature (attaching to an already-
        # signed-in browser), and a FAIL-free WARN here should never dock the grade. The
        # FAIL branch above overrides the other way (scored=True) for the one narrow,
        # deterministic escalation that should carry real weight.
        scored=False,
    )


# ---------- B330 (C-298): the unauthenticated CDP control port OpenClaw always opens ----------
# Grounded in the installed dist, in one line: buildOpenClawChromeLaunchArgs
# (chrome-DDq_K3xu.js:1662-1689) puts `--remote-debugging-port=${profile.cdpPort}` FIRST in
# every managed Chrome launch, unconditionally -- the Chrome DevTools Protocol is how
# OpenClaw drives a browser at all -- and CDP itself carries no authentication step: a
# client that can open the endpoint can drive the browser. OpenClaw's own endpoint for that
# port is cdpUrlForPort() = `http://127.0.0.1:${cdpPort}` (chrome-DDq_K3xu.js:1659), and NO
# dist file anywhere passes --remote-debugging-address, so Chrome's default loopback bind
# applies.
#
# THE DECISION THIS CHECK RECORDS (C-298). The unauthenticated port itself is NOT graded.
# It is a property of the vendor's design that an operator using the browser tool cannot
# switch off, and B-331 established that this audit grades the effective state a config
# CHOOSES, never a condition OpenClaw created -- charging score for the port would punish
# an operator for something they cannot fix and could not act on. So the fact is stated in
# every branch's message, and the ordinary loopback-confined case is a real PASS.
#
# WHAT IS GRADED, THEN. Only what the operator chose, on two axes:
#   * WHERE the control channel points (WARN) -- an off-host cdpUrl.
#   * WHO may reach it from inside the browser (FAIL) -- --remote-allow-origins.
#
# WHY --remote-allow-origins IS THE ONE FAIL RUNG, MEASURED NOT ASSUMED. Chromium added an
# Origin check to the DevTools WebSocket endpoint precisely so that a web page could not
# reach a loopback CDP port through the browser the user is already running.
# --remote-allow-origins turns that check off. Measured on Google Chrome 150.0.7871.186
# (headless, local, raw WebSocket upgrade carrying `Origin: http://evil.example` against
# the endpoint from /json/version), 2026-07-26:
#     (no flag)                      -> HTTP/1.1 403 Forbidden
#     --remote-allow-origins=*       -> HTTP/1.1 101 WebSocket Protocol Handshake
#     -remote-allow-origins=*        -> HTTP/1.1 101 WebSocket Protocol Handshake
#     ---remote-allow-origins=*      -> HTTP/1.1 403 Forbidden
# The wildcard converts a refused cross-origin request into a live CDP session, so ANY
# page the agent's browser has open can then drive that browser -- read every origin's
# cookies and DOM, navigate it, execute JS in it. Loopback confinement does not help: the
# request originates inside the browser, which is already on loopback. That is an
# operator-written flag with a measured effect, so it is graded, and graded firmly.
# (The 1-vs-3-dash rows above are also what pin _chrome_switch_name()'s prefix rule.)
#
# A NAMED origin list is WARN, not FAIL: it still relaxes a protection Chromium added on
# purpose, but only to origins the operator wrote down, which is a bounded and possibly
# deliberate trade -- not the "any page at all" hole the wildcard opens.
#
# WHICH RUNG THIS IS RELATIVE TO ITS NEIGHBOURS. The corroborated off-host cdpUrl rung is
# already owned, twice over, by checks whose evidence is sharper:
#   * B322 FAILs (scored) a driver:"existing-session" profile whose cdpUrl is non-loopback.
#   * B196 FAILs an attach-only profile against a non-loopback cdpUrl while its evaluate
#     sink is on.
# A third hard cap on those same configs would be triple-counting one fact, so this check
# stays at WARN there. What neither neighbour covers is the plain shape: the TOP-LEVEL
# browser.cdpUrl, and a MANAGED (driver "openclaw"/absent) profile's cdpUrl. Both are
# stated as out-of-scope in the neighbours' own docstrings, and both genuinely move the
# unauthenticated control channel off this host -- resolveBrowserConfig stores cdpHost from
# browser.cdpUrl's hostname (config-DpWXcVmn.js:488) and every managed profile without its
# own cdpUrl inherits it (config-DpWXcVmn.js:516,576). That is the gap this check fills.
# The --remote-allow-origins axis is not covered by ANY neighbour, in any spelling.
#
# NO DOUBLE-COUNT WITH B38 OR B195. B38 grades browser.ssrfPolicy / noSandbox -- which
# pages the browser may REACH. B195 grades extraArgs flags that weaken the browser itself.
# This grades who may reach the CONTROL channel. B195 deliberately does not carry
# --remote-allow-origins (its docstring says so), so that flag is scored exactly once.
#
# Two CDP endpoints are deliberately excluded from the off-host evidence:
#   * driver:"existing-session" -- B322 owns it, including the FAIL.
#   * driver:"extension" -- resolveProfile (config-DpWXcVmn.js:523-536) hardcodes
#     cdpHost "127.0.0.1"/cdpIsLoopback true for this driver and, when an extension relay
#     token exists, embeds it in the cdpUrl as HTTP credentials
#     (`http://${EXTENSION_RELAY_CDP_USER}:${encodeURIComponent(token)}@127.0.0.1:${port}`).
#     It is the one CDP endpoint OpenClaw does authenticate, and the operator's own cdpUrl
#     is rejected for it by the schema, so nothing they write can move it. Verified by
#     direct dist read, not inherited from the draft that proposed the exclusion.
_CLEARTEXT_CDP_SCHEMES = ("http", "ws")
_CDP_ALLOW_ORIGINS_SWITCH = "remote-allow-origins"


def _cdp_url_is_cleartext(url) -> bool:
    """True when a CDP URL's scheme carries the control channel without TLS."""
    try:
        return (urlparse(_whatwg_url(url)).scheme or "").lower() in _CLEARTEXT_CDP_SCHEMES
    except Exception:
        return False


def _cdp_allow_origins_findings(browser: dict) -> "tuple[list[str], list[str]]":
    """(fail_ev, warn_ev) for --remote-allow-origins in browser.extraArgs.

    Wildcard -> FAIL evidence; a named origin list -> WARN evidence; absent, or present
    with no value at all (which allows nothing) -> neither. Accepts the one-dash spelling
    Chrome honours, via _chrome_switch_name (B-337).

    CASE IS LOAD-BEARING FOR THE FAIL RUNG ONLY (C-135, 2026-07-26). An independent
    adversarial pass found that this check FAILed on `--REMOTE-ALLOW-ORIGINS=*`, and the
    measurement says Chrome does not: on POSIX, Chromium's switch lookup is
    case-sensitive, so the uppercase spelling returns 403 (origin check still enforced)
    where the lowercase one returns 101. Hard-capping a grade for a switch that provably
    does nothing is precisely the M113 mistake B-337 removed from B195, so the wildcard
    FAIL now requires the exact-case name. A case-variant is still REPORTED at WARN: it
    is operator intent, and it WOULD take effect on Windows, where Chromium lowercases
    switch names (the same BUILDFLAG(IS_WIN) path C-309 corrected the comment about).
    """
    fail_ev: list[str] = []
    warn_ev: list[str] = []
    extra_args = browser.get("extraArgs")
    if not isinstance(extra_args, list):
        return fail_ev, warn_ev
    for raw in extra_args:
        if not isinstance(raw, str) or not raw.strip():
            continue
        arg = raw.strip()
        exact = _chrome_switch_name(arg, casefold=False)
        if exact.lower() != _CDP_ALLOW_ORIGINS_SWITCH:
            continue
        # Exact-case == the spelling Chrome actually honours on POSIX.
        honoured = exact == _CDP_ALLOW_ORIGINS_SWITCH
        _, _, value = arg.partition("=")
        origins = [o.strip() for o in value.split(",") if o.strip()]
        if not origins:
            continue
        if "*" in origins and not honoured:
            warn_ev.append(
                f"browser.extraArgs has {arg!r} — this asks for the wildcard that would "
                "switch off the DevTools Origin check, but Chromium's switch lookup is "
                "case-sensitive on Linux/macOS, so as spelled it does nothing there "
                "(measured: the uppercase form leaves a cross-origin CDP handshake at "
                "403). It is reported rather than graded because on Windows, where "
                "Chromium lowercases switch names, this spelling WOULD take effect"
            )
        elif "*" in origins:
            fail_ev.append(
                f"browser.extraArgs has {arg!r} — the wildcard switches OFF the Origin "
                "check Chromium added to the DevTools endpoint, so any page the agent's "
                "browser has open can open a CDP WebSocket to it and drive the browser: "
                "read every origin's cookies and DOM, navigate it, and execute "
                "JavaScript in it. Binding to loopback does not contain this — the "
                "request comes from inside the browser, which is already on loopback"
            )
        else:
            warn_ev.append(
                f"browser.extraArgs has {arg!r} — this relaxes the Origin check on the "
                f"unauthenticated CDP endpoint for {len(origins)} named origin(s); any "
                "page served from one of them can drive the agent's browser through the "
                "DevTools Protocol"
            )
    return fail_ev, warn_ev


def _offhost_cdp_endpoints(browser: dict) -> list[str]:
    """Evidence for every operator-written CDP endpoint that is not loopback-confined.

    Empty list == the ordinary config, where the unauthenticated port stays on this host.
    Reads only keys the operator actually wrote, never OpenClaw's synthesized default
    profiles (same discipline as _browser_unowned_session_evidence).
    """
    ev: list[str] = []
    top_cdp_url = browser.get("cdpUrl")
    if _cdp_url_classify(top_cdp_url) == "remote":
        ev.append(
            f"browser.cdpUrl={_cdp_url_display(top_cdp_url)} is not loopback — this is "
            "the cdpHost every managed profile without its own cdpUrl inherits, so "
            "OpenClaw drives the browser over the network"
            + (
                ", and over a cleartext scheme, so the whole control channel "
                "(page content, injected JS, cookies read back) crosses it in the clear"
                if _cdp_url_is_cleartext(top_cdp_url)
                else ""
            )
        )
    profiles = browser.get("profiles")
    profiles = profiles if isinstance(profiles, dict) else {}
    for name, spec in sorted(profiles.items(), key=lambda kv: str(kv[0])):
        if not isinstance(spec, dict):
            continue
        if spec.get("driver") in _UNOWNED_SESSION_DRIVERS:
            continue  # B322 owns existing-session; extension is loopback + token-authed
        cdp_url = spec.get("cdpUrl")
        if _cdp_url_classify(cdp_url) != "remote":
            continue
        ev.append(
            f"browser.profiles.{name}.cdpUrl={_cdp_url_display(cdp_url)} is not "
            "loopback — this managed profile's unauthenticated CDP control channel "
            "leaves this host"
            + (" over a cleartext scheme" if _cdp_url_is_cleartext(cdp_url) else "")
        )
    return ev


def check_browser_cdp_control_port(ctx: Context) -> Finding:
    """B330 — the Chrome DevTools Protocol control port is unauthenticated (C-298).

    FAIL    — browser.extraArgs carries --remote-allow-origins with a `*` wildcard,
              which measurably converts a refused cross-origin CDP handshake into a live
              one (403 -> 101, measured on Chrome 150 — see the note above
              _cdp_allow_origins_findings). Any page the browser has open can then drive
              it. This is the one rung the operator both chose and can undo.
    WARN    — the operator's own config points the CDP control channel at a non-loopback
              endpoint (top-level browser.cdpUrl, or a managed profile's cdpUrl), and/or
              --remote-allow-origins names specific origins. The always-unauthenticated
              channel is then reachable beyond a local process.
    PASS    — every CDP endpoint the config names is loopback-confined and the Origin
              check is intact (the ordinary case), or browser.enabled is false so no
              managed launch — and therefore no CDP port — happens at all.
    UNKNOWN — no openclaw.json, an unparseable one, or no browser config (the browser
              tool is not in use, so nothing launches a Chrome to debug).

    The unauthenticated port itself is never graded — it is OpenClaw's design and the
    operator has no lever on it (B-331). See the decision note above
    _cdp_allow_origins_findings for why the off-host cdpUrl rung stops at WARN rather
    than triple-counting B322 and B196.
    """
    if not ctx.config_found:
        return _finding(
            "B330",
            UNKNOWN,
            "No openclaw.json found — the browser's CDP control port cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B330", ctx)
    if unreadable is not None:
        return unreadable

    browser = ctx.config.get("browser")
    if not isinstance(browser, dict):
        return _finding(
            "B330",
            UNKNOWN,
            "No browser config — the browser tool is not in use, so no managed Chrome "
            "and no CDP control port.",
            "—",
            not_applicable=_browser_surface_absent(ctx),
        )

    if browser.get("enabled") is False:
        return _finding(
            "B330",
            PASS,
            "browser.enabled=false — OpenClaw refuses browser control entirely, so it "
            "never launches a managed Chrome and never opens the unauthenticated Chrome "
            "DevTools Protocol port that every managed launch would otherwise open.",
            "Keep browser.enabled=false while no workflow needs the browser tool.",
            pass_confidence="verified",
        )

    origin_fail, origin_warn = _cdp_allow_origins_findings(browser)
    offhost = _offhost_cdp_endpoints(browser)

    if origin_fail:
        return _finding(
            "B330",
            FAIL,
            "The browser tool is in use, so OpenClaw opens a Chrome DevTools Protocol "
            "control port on every managed launch (--remote-debugging-port, supplied "
            "unconditionally), and CDP has no authentication step — the only thing "
            "standing between a web page and that port is the Origin check Chromium "
            "added to the DevTools endpoint. This config turns that check off with a "
            "wildcard --remote-allow-origins, so any page the agent's browser has open "
            "can open a CDP session and drive the browser: read every origin's cookies "
            "and DOM, navigate it, execute JavaScript in it. One injected page is then "
            "enough to take over every session in that browser.",
            "Remove --remote-allow-origins from browser.extraArgs. OpenClaw's own CDP "
            "client does not need it — it connects from Node, which sends no Origin "
            "header, so the check it disables was never in OpenClaw's way. If some "
            "other tool genuinely needs cross-origin CDP access, name that tool's exact "
            "origin instead of the wildcard, and prefer giving it its own browser "
            "profile rather than the one the agent drives.",
            evidence=(origin_fail + origin_warn + offhost)[:6],
        )

    if origin_warn or offhost:
        return _finding(
            "B330",
            WARN,
            "The browser tool is in use, so OpenClaw opens a Chrome DevTools Protocol "
            "control port on every managed launch (--remote-debugging-port, supplied "
            "unconditionally) — and CDP has no authentication step, so whoever reaches "
            "that port drives the agent's browser: reads its DOM and cookies, navigates "
            "it, and executes JavaScript in it. This config does not keep that channel "
            "confined to a local process (see evidence). The port itself is OpenClaw's "
            "design and is not held against you; how far it reaches is your "
            "configuration.",
            "Point the CDP endpoint back at loopback (127.0.0.1 / localhost), or reach a "
            "genuinely remote browser through an SSH/VPN tunnel and give OpenClaw the "
            "local tunnel end — that restores both the authentication boundary and the "
            "encryption the raw endpoint has neither of. Drop any --remote-allow-origins "
            "unless a named tool needs it. If the browser tool is not needed at all, "
            "browser.enabled=false removes the port entirely.",
            evidence=(origin_warn + offhost)[:6],
        )

    return _finding(
        "B330",
        PASS,
        "The browser tool is in use, so OpenClaw opens a Chrome DevTools Protocol "
        "control port on every managed launch (--remote-debugging-port, supplied "
        "unconditionally) and CDP carries no authentication — but this config keeps that "
        "channel on this host: every CDP endpoint it names is loopback, and the Origin "
        "check that stops a web page reaching it through the browser is intact. Worth "
        "knowing rather than fixing: the port cannot be closed while the browser tool is "
        "in use, so it is stated here and costs no score. What it means in practice is "
        "that any process running on this machine can drive the agent's browser through "
        "it, so the port is only as trustworthy as the code you let run locally.",
        "Nothing to change in openclaw.json. Treat it as a host-level boundary: do not "
        "run untrusted code on this machine as this user, keep the agent on a dedicated "
        "managed profile rather than one holding live logins (B322/B196), and set "
        "browser.enabled=false whenever the browser tool is not needed.",
        pass_confidence="no_signal",
    )
