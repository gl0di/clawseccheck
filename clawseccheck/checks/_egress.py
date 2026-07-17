"""Topic module: egress checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import os
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
    _read_jsonl_tail,
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
# admits (a) a wildcard pattern, or (b) a domain that hosts anonymous/user-generated
# content an attacker could stage a payload on despite the host being "trusted".
# Used by both B38 (browser.ssrfPolicy.hostnameAllowlist) and C014 (MCP allowedHosts).
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
    }
)


def _weak_allowlist_entries(allowlist) -> list[str]:
    """Return the subset of an allowlist that is a weak mitigation.

    Flags wildcard patterns (bare "*" or "*.example.com") and known user-content /
    anonymous-paste / webhook hosts (matched by exact host or domain suffix, after
    stripping a leading "*." if present). Non-string / malformed entries are ignored
    (best-effort, no FAIL on unparseable data).
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
        if bare in _USER_CONTENT_HOSTS or any(
            bare == h or bare.endswith("." + h) for h in _USER_CONTENT_HOSTS
        ):
            weak.append(entry)
    return weak


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

    # QUALITY: allowlist present but contains a wildcard or known user-content host —
    # downgrade PASS to WARN. Still additive/advisory: does not touch FAIL behaviour.
    weak_entries = _weak_allowlist_entries(allowlist)
    if weak_entries:
        return _finding(
            "B38",
            WARN,
            "Browser hostnameAllowlist is present but contains weak entries "
            f"(wildcard and/or known user-content/paste/webhook host): {', '.join(weak_entries)} — "
            "an attacker could stage a payload on a wildcard match or an anonymous "
            "content host despite the allowlist.",
            "Replace wildcard entries with explicit hostnames, and avoid allowlisting "
            "anonymous paste/gist/webhook hosts (e.g. pastebin.com, gist.github.com, "
            "raw.githubusercontent.com, webhook.site) — an attacker-controlled payload "
            "can be staged there even though the host itself is 'trusted'.",
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
    PASS    — a managed proxy is configured with a clean (credential-free) URL.
    UNKNOWN — no outbound proxy configured (the default): advisory nudge, never a FAIL.
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
    return _finding(
        "B155", UNKNOWN,
        "No outbound proxy configured — the agent's egress goes direct (the default). "
        "A managed proxy (proxy.*) would centralize and log egress; informational, not required.",
        "Optional: set proxy.enabled + a credential-free https:// proxy.proxyUrl to route and "
        "audit the agent's outbound traffic through a controlled egress point.",
    )


def check_cachetrace_redaction(ctx: Context) -> Finding:
    """B82 — cacheTrace transcripts persisted without tool-output redaction.

    Grounded (recon: logging.cacheTrace.filePath, logging.redactSensitive). The
    cache-trace JSONL persists full prompt/response transcripts to disk; without
    redactSensitive="tools" those transcripts can carry secrets at rest.

    PASS — cacheTrace is not configured, OR redactSensitive == "tools".
    WARN — logging.cacheTrace.filePath is set AND redactSensitive != "tools".
    """
    unreadable = _config_unreadable("B82", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    trace_path = dig(cfg, "logging.cacheTrace.filePath")
    if not trace_path:
        return _finding(
            "B82",
            PASS,
            "No cache-trace transcript file is configured, so full transcripts are not "
            "persisted to disk.",
            "If you enable logging.cacheTrace.filePath, also set logging.redactSensitive "
            'to "tools" so persisted transcripts don\'t carry secrets.',
        )
    redact = dig(cfg, "logging.redactSensitive")
    if redact == "tools":
        return _finding(
            "B82",
            PASS,
            "Cache-trace transcripts are persisted with tool-output redaction "
            '(logging.redactSensitive="tools").',
            'Keep logging.redactSensitive at "tools" while cache-trace logging is on.',
        )
    return _finding(
        "B82",
        WARN,
        "logging.cacheTrace.filePath persists full transcripts to disk but "
        'logging.redactSensitive is not "tools" — secrets can be written at rest.',
        'Set logging.redactSensitive to "tools", or disable logging.cacheTrace.filePath.',
        evidence=[
            f"logging.cacheTrace.filePath={trace_path!r}",
            f"logging.redactSensitive={redact!r}",
        ],
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
    """
    cfg = ctx.config
    evidence = []
    restricted = False

    global_allow = (
        dig(cfg, "gateway.egress")
        or dig(cfg, "network.egress")
        or cfg.get("egress")
        or dig(cfg, "tools.http.allow")
    )
    if global_allow:
        restricted = True
        evidence.append("global egress restriction configured")

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
        if tool != "elevated" and global_allow:
            notes.append("global egress restriction configured")
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
                    f"host (weak mitigation): {', '.join(weak_hosts)}"
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

    surface_count = len(
        [line for line in evidence if not line.startswith("global egress restriction")]
    )
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
            f"Egress inventory: {surface_count} outbound-capable surface(s) found; explicit restriction signals are present — see evidence.",
            "Keep outbound-capable tools, MCP endpoints, and channels on tight allowlists and retain approval on high-impact actions.",
            evidence=evidence,
        )
    return _finding(
        "C014",
        WARN,
        f"Egress inventory: {surface_count} outbound-capable surface(s) found with no explicit restriction signals — see evidence.",
        "Add hostname/egress allowlists where supported, keep outbound channels narrow, and require approval for exec/send-style actions.",
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
# already secret+exfil-host paired inside logscan.py; secrets_at_rest additionally needs
# the sink to be world-readable, checked here via the same B19 perm-check helper above).
_LOG_HUNT_PER_FILE_BUDGET_S = 3.0


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
    fail the audit (Golden Rule #5); this check is advisory (scored=False) precisely so a
    false hit can never move the A-F grade.
    """
    # Lazy import: logscan.py (a Layer-1 leaf) itself imports from the checks aggregator
    # (`from .checks import ...`) to reuse the engine's vetted indicator regexes — the
    # SAME reason several checks/*.py functions already import `..logsafe` lazily inside
    # the function body instead of at module top (see checks/_vet.py's comment on it).
    # logdiscovery.py has no such dependency, but is imported the same way for symmetry.
    from ..logdiscovery import discover_log_sinks  # noqa: PLC0415
    from ..logsafe import redact  # noqa: PLC0415
    from ..logscan import scan_log_file  # noqa: PLC0415
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
    any_scanned = False
    any_truncated = False
    any_timed_out = False
    isolated_hits = 0

    for sink in sinks:
        deadline = audit_deadline(_LOG_HUNT_PER_FILE_BUDGET_S)
        result = scan_log_file(sink, deadline, skill_iocs)
        any_truncated = any_truncated or result.truncated
        any_timed_out = any_timed_out or result.timed_out
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
        strong_cross = {t: n for t, n in cross.items() if _KNOWN_EXFIL_HOST_RE.search(t)}
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

    note = ""
    if any_truncated:
        note += " Some file(s) hit the scan's byte/line cap — results may be incomplete."
    if any_timed_out:
        note += " Some file(s) hit the per-file scan timeout — results may be incomplete."

    if corroborated:
        n_sinks = len(corroborated)
        shown = list(corroborated.items())[:5]
        detail = "; ".join(f"{sink}: {', '.join(sorted(classes))}" for sink, classes in shown)
        if n_sinks > 5:
            detail += f" (+{n_sinks - 5} more sink(s))"
        return _finding(
            "B164",
            WARN,
            f"Corroborated threat signal(s) in {n_sinks} log sink(s): {detail}.{note}",
            "Review the named log/transcript file(s) manually (see the Log Threat Report "
            "section for redacted-evidence samples). Rotate any credential the matched "
            "indicator could expose, and investigate how it reached the log.",
            evidence=all_samples[:20],
        )

    detail = f"{len(sinks)} log/transcript sink(s) scanned; no corroborated threat signal."
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
