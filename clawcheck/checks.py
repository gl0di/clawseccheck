"""Check engine: Block A (Lethal Trifecta) + Block B (hardening) + advisory.

Every check is read-only and grounded on real OpenClaw config fields
(see docs/specs/openclaw-audit-skill-spec.md v2). Heuristics are conservative:
we FAIL only on positive evidence, WARN on likely-insecure defaults, and
UNKNOWN when the config cannot tell us (excluded from score — honesty).
"""
from __future__ import annotations

import base64
import binascii
import os
import re
from pathlib import Path

from .catalog import BY_ID, CRITICAL, FAIL, HIGH, MEDIUM, PASS, UNKNOWN, WARN, Finding
from .collector import Context, _read_skill_text, dig


def _is_posix() -> bool:
    return os.name == "posix"


def _perms_loose(ctx: Context) -> bool:
    """True only on POSIX when the config file is group/world-readable.

    Windows uses NTFS ACLs, not POSIX mode bits, so st_mode is not meaningful
    there — we never raise a false 'world-readable' finding on Windows.
    """
    if not _is_posix() or ctx.config_mode is None:
        return False
    return (ctx.config_mode & 0o077) != 0

LOOPBACK = {"127.0.0.1", "localhost", "::1", "", "loopback", "local"}
EXPOSED_BINDS = {"0.0.0.0", "::", "all", "public", "*"}
SECRET_KEY_RE = re.compile(r"(password|secret|token|api[_-]?key|apikey|bottoken)", re.I)
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-z0-9-]{8,}", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"(?:password|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}", re.I),
]
INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|previous|prior) (instructions|messages)", re.I),
    re.compile(r"obey (all|any|every|whatever)", re.I),
    re.compile(r"follow (all|any|every|whatever) (instruction|command|request)", re.I),
    re.compile(r"do (whatever|anything) (the )?(user|sender|message|email) (says|asks|wants)", re.I),
    re.compile(r"without (asking|confirmation|question)", re.I),
]
INPUT_TOOL_HINTS = ("email", "imap", "gmail", "rss", "feed", "web", "browse", "fetch", "file_read", "inbox")
SENSITIVE_TOOL_HINTS = ("db", "sql", "postgres", "supabase", "secret", "credential", "vault", "fs_read", "files")
OUTBOUND_TOOL_HINTS = ("send", "email_send", "webhook", "http_post", "exec", "shell", "fs_write", "deploy", "publish")


def _meta(cid: str):
    return BY_ID[cid]


def _finding(cid, status, detail, fix, evidence=None) -> Finding:
    m = _meta(cid)
    return Finding(m.id, m.title, m.severity, status, detail, fix,
                   m.framework, m.scored, evidence or [])


def _channels(cfg: dict) -> dict:
    ch = cfg.get("channels")
    return ch if isinstance(ch, dict) else {}


def _open_channels(cfg: dict) -> list[str]:
    out = []
    for name, c in _channels(cfg).items():
        if not isinstance(c, dict):
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if isinstance(node, dict) and (
                node.get("dmPolicy") == "open" or node.get("groupPolicy") == "open"
            ):
                out.append(name)
                break
    return out


def _plugins(cfg: dict) -> dict:
    """Installed plugins, supporting both `plugins.entries.<name>` and legacy shapes."""
    p = cfg.get("plugins")
    if isinstance(p, dict):
        entries = p.get("entries")
        if isinstance(entries, dict):
            return entries
        return p
    return {}


def _secret_paths(obj, prefix="") -> list[str]:
    """Dotted paths of secret-bearing keys holding a non-trivial string (no values)."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str) and len(v) >= 16 and SECRET_KEY_RE.search(k):
                found.append(path)
            else:
                found.extend(_secret_paths(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_secret_paths(v, f"{prefix}[{i}]"))
    return found


def _enabled_tools(cfg: dict) -> list[str]:
    tools = []
    allow = dig(cfg, "tools.elevated.allowFrom")
    if allow:
        tools.append("elevated")
    if dig(cfg, "tools.exec.host_sandbox") is not None or "exec" in str(dig(cfg, "tools.profile", "")):
        tools.append("exec")
    # collect any explicitly listed tool names
    listed = dig(cfg, "tools.allow") or dig(cfg, "gateway.tools.allow") or []
    if isinstance(listed, list):
        tools.extend(str(t) for t in listed)
    return tools


def _hint(names, hints) -> bool:
    blob = " ".join(names).lower()
    return any(h in blob for h in hints)


# ---------------------------------------------------------------- Block A
def check_trifecta(ctx: Context) -> Finding:
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    open_ch = _open_channels(cfg)

    untrusted_input = bool(open_ch) or _hint(tools, INPUT_TOOL_HINTS)
    sensitive_data = (
        _hint(tools, SENSITIVE_TOOL_HINTS)
        or (ctx.home / "credentials").is_dir()
        or bool(dig(cfg, "gateway.password"))
    )
    outbound = (
        _hint(tools, OUTBOUND_TOOL_HINTS)
        or bool(dig(cfg, "tools.elevated.allowFrom"))
    )

    legs = {
        "untrusted input": untrusted_input,
        "sensitive data": sensitive_data,
        "outbound actions": outbound,
    }
    active = [k for k, v in legs.items() if v]
    detail = f"Active legs {len(active)}/3: {', '.join(active) or 'none'}. Rule: keep ≤2 of 3."

    if len(active) >= 3:
        return _finding(
            "A1", FAIL, detail,
            "Break the trifecta: remove one leg. Easiest wins — lock channels to "
            "owner only (no untrusted input), or gate all outbound/exec actions behind "
            "human approval, or move sensitive data out of the agent's reach.",
            evidence=active,
        )
    return _finding("A1", PASS, detail, "Keep it at ≤2 of 3 — do not add the third capability.",
                    evidence=active)


# ---------------------------------------------------------------- Block B
def check_secrets(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # gateway.password / hooks.token in config are flagged by the native audit too
    if dig(cfg, "gateway.password"):
        ev.append("gateway.password set in config")
    if dig(cfg, "hooks.token"):
        ev.append("hooks.token set in config")
    # secrets anywhere in the config are only a real risk if the file is readable by others
    secret_paths = _secret_paths(cfg)
    if secret_paths and _perms_loose(ctx):
        ev.append(f"{len(secret_paths)} secret(s) in config and openclaw.json is "
                  f"group/world-readable ({oct(ctx.config_mode)[-3:]})")
    # secrets hardcoded into bootstrap files (always wrong — injected into the prompt)
    for fname, text in ctx.bootstrap.items():
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                ev.append(f"secret-like string in {fname}")
                break
    if ev:
        return _finding("B1", FAIL, "; ".join(ev),
                        "Move secrets to `openclaw secrets configure` / env vars, never into "
                        "bootstrap files; `chmod 600 ~/.openclaw/openclaw.json` and `chmod 700 "
                        "~/.openclaw` so config-stored tokens are not readable by others.", ev)
    note = ""
    if secret_paths:
        note = f" ({len(secret_paths)} token(s) in config, but file perms are tight)"
    return _finding("B1", PASS, f"No exposed plaintext secrets.{note}",
                    "Keep secrets out of bootstrap files and keep config perms at 600.")


def check_gateway(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    bind = str(dig(cfg, "gateway.bind", "")).split(":")[0]
    auth = dig(cfg, "gateway.auth.mode")
    if bind and bind not in LOOPBACK and auth in (None, "none"):
        ev.append(f"gateway.bind={bind or '?'} exposed with auth.mode={auth}")
    if dig(cfg, "gateway.http.no_auth"):
        ev.append("gateway.http.no_auth enabled")
    if dig(cfg, "gateway.controlUi.allowInsecureAuth"):
        ev.append("gateway.controlUi.allowInsecureAuth enabled")
    if dig(cfg, "gateway.tailscale.funnel"):
        ev.append("gateway.tailscale.funnel exposes the gateway publicly")
    if dig(cfg, "gateway.auth_no_rate_limit"):
        ev.append("gateway.auth_no_rate_limit (no brute-force protection)")
    token = dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token")
    if isinstance(token, str) and 0 < len(token) < 24:
        ev.append("gateway auth token shorter than 24 chars")
    for name in _open_channels(cfg):
        ev.append(f"channel '{name}' has an open dm/group policy (anyone can command it)")
    if ev:
        return _finding("B2", FAIL, "; ".join(ev),
                        "Bind the gateway to loopback or require auth (gateway.auth.mode=token, "
                        "token ≥24 chars), disable tailscale.funnel/http.no_auth, enable rate "
                        "limiting, and set every channel dmPolicy/groupPolicy to allowlist.", ev)
    if not cfg:
        return _finding("B2", UNKNOWN, "No config loaded — cannot assess gateway.", "Run on the host with ~/.openclaw present.")
    return _finding("B2", PASS, "Gateway is loopback/authenticated and channels are not open.",
                    "Keep auth on and channels on allowlist.")


def check_least_privilege(ctx: Context) -> Finding:
    cfg = ctx.config
    allow = dig(cfg, "tools.elevated.allowFrom")
    hard = []   # clear over-privilege -> FAIL
    soft = []   # missing allowlist hygiene -> WARN
    if allow == "*" or (isinstance(allow, list) and "*" in allow):
        hard.append("tools.elevated.allowFrom = '*' (every sender can use elevated tools)")
    elif isinstance(allow, list) and len(allow) > 25:
        hard.append(f"tools.elevated.allowFrom has {len(allow)} entries (too broad)")
    profile = str(dig(cfg, "tools.profile", "")).lower()
    if profile and profile != "minimal":
        hard.append(f"tools.profile='{dig(cfg, 'tools.profile')}' (not minimal)")
    if dig(cfg, "plugins.allow") is None and _plugins(cfg):
        soft.append("no plugins.allow reachability allowlist (plugins.entries present)")
    if dig(cfg, "plugins.tools_reachable_policy") == "permissive":
        hard.append("plugins.tools_reachable_policy is permissive")
    if hard:
        return _finding("B3", FAIL, "; ".join(hard + soft),
                        "Set tools.profile=minimal, restrict tools.elevated.allowFrom to specific "
                        "owner IDs (no '*'), and define a plugins.allow reachability allowlist.",
                        hard + soft)
    if soft:
        return _finding("B3", WARN, "; ".join(soft),
                        "Define plugins.allow so only specific tools are reachable by plugins.", soft)
    return _finding("B3", PASS, "Elevated tools are restricted and tool reachability is constrained.",
                    "Keep least privilege: explicit allowlists only.")


def check_sandbox(ctx: Context) -> Finding:
    cfg = ctx.config
    mode = dig(cfg, "sandbox.mode")
    ev = []
    if mode in ("off", False):
        ev.append("sandbox.mode is off (exec runs on the host)")
    if dig(cfg, "sandbox.network_mode") == "full":
        ev.append("sandbox.network_mode=full")
    if dig(cfg, "sandbox.bind_mount"):
        ev.append("sandbox.bind_mount exposes host paths")
    if mode not in (None,) and not dig(cfg, "sandbox.seccomp_profile") and not dig(cfg, "sandbox.apparmor_profile"):
        ev.append("no seccomp/apparmor profile")
    if mode is None and "exec" in _enabled_tools(cfg):
        return _finding("B4", WARN, "exec tooling present but sandbox.mode not set — likely host execution.",
                        "Enable sandbox.mode and a seccomp/apparmor profile for exec.")
    if ev:
        return _finding("B4", FAIL, "; ".join(ev),
                        "Enable sandbox.mode, set network_mode=bridge, drop host bind_mounts, and "
                        "apply seccomp/apparmor profiles.", ev)
    if mode is None:
        return _finding("B4", UNKNOWN, "No exec tools and no sandbox config — not applicable.", "—")
    return _finding("B4", PASS, "Execution is sandboxed.", "Keep sandbox.mode enabled.")


def check_supply_chain(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    if dig(cfg, "plugins.installs_unpinned_npm_specs") or dig(cfg, "installs_unpinned_npm_specs"):
        ev.append("unpinned npm specs in plugin installs")
    if dig(cfg, "plugins.installs_missing_integrity") or dig(cfg, "installs_missing_integrity"):
        ev.append("plugin installs missing integrity hashes")
    if dig(cfg, "plugins.tools_reachable_policy") == "permissive":
        ev.append("plugins.tools_reachable_policy is permissive")
    if not (cfg.get("plugins") or cfg.get("skills")):
        return _finding("B5", UNKNOWN, "No plugins/skills declared in config.", "—")
    if ev:
        return _finding("B5", FAIL, "; ".join(ev),
                        "Pin npm specs, require integrity hashes, set plugins.allow, and verify each "
                        "skill against ClawHub VirusTotal status before loading (ClawHavoc).", ev)
    return _finding("B5", PASS, "Plugin/skill installs are pinned with integrity and allowlisted.",
                    "Keep verifying skill provenance before install.")


def check_bootstrap_injection(ctx: Context) -> Finding:
    """THE WEDGE: native audit does NOT scan bootstrap-file content."""
    if not ctx.bootstrap:
        return _finding("B6", UNKNOWN, "No bootstrap files found to inspect.",
                        "Run on the host where workspace SOUL.md/AGENTS.md/TOOLS.md live.")
    ev = []
    for fname, text in ctx.bootstrap.items():
        for pat in INJECTION_PATTERNS:
            if pat.search(text):
                ev.append(f"{fname}: matches '{pat.pattern[:40]}…'")
                break
    if ev:
        return _finding("B6", FAIL, "; ".join(ev),
                        "Remove blanket 'obey any instruction' / 'without confirmation' directives "
                        "from SOUL.md/AGENTS.md/TOOLS.md. Add an explicit rule: treat content from "
                        "channels/web/email as untrusted data, never as instructions.", ev)
    return _finding("B6", PASS, "No blanket-obedience / injection-prone directives in bootstrap files.",
                    "Keep a trusted/untrusted separation rule in SOUL.md.")


def check_memory_poisoning(ctx: Context) -> Finding:
    has_mem = any(n.endswith(("MEMORY.md", "memory.md")) for n in ctx.bootstrap)
    if not has_mem:
        return _finding("B7", UNKNOWN, "No memory file found.", "—")
    writable_from_ext = dig(ctx.config, "memory.writeFromChannels") or dig(ctx.config, "memory.untrustedWrite")
    if writable_from_ext:
        return _finding("B7", FAIL, "Memory is writable from external messages without sanitization.",
                        "Disable memory writes from untrusted channels, or sanitize/scope them.")
    return _finding("B7", WARN, "Agent has persistent memory; confirm it is not written from untrusted input.",
                    "Restrict memory writes to the owner; sanitize anything derived from external content.")


def check_human_approval(ctx: Context) -> Finding:
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    destructive = _hint(tools, OUTBOUND_TOOL_HINTS)
    approval = dig(cfg, "tools.confirm") or dig(cfg, "tools.requireApproval") or dig(cfg, "tools.elevated.requireApproval")
    if not destructive:
        return _finding("B8", UNKNOWN, "No destructive/outbound tools detected.", "—")
    if approval in (None, False, "off", "never"):
        return _finding("B8", WARN, "Destructive tools (exec/send/write) present with no clear approval gate.",
                        "Require human approval for exec/send/fs_write/deploy actions "
                        "(confirm the exact field on your install).")
    return _finding("B8", PASS, "Destructive actions require human approval.",
                    "Keep approval gating on all high-impact tools.")


def check_leak(ctx: Context) -> Finding:
    redact = dig(ctx.config, "logging.redactSensitive")
    if redact in (False, "off"):
        return _finding("B9", FAIL, "logging.redactSensitive is off — secrets/system prompt can surface in tool output/logs.",
                        "Set logging.redactSensitive to redact secrets from tool output and logs.")
    if redact is None:
        return _finding("B9", WARN, "logging.redactSensitive not set — default may expose secrets in output.",
                        "Explicitly enable sensitive redaction.")
    return _finding("B9", PASS, "Sensitive redaction is enabled.", "Keep redaction on.")


def check_audit_log(ctx: Context) -> Finding:
    cfg = ctx.config
    enabled = dig(cfg, "logging.audit") or dig(cfg, "audit.enabled")
    redact = dig(cfg, "logging.redactSensitive")
    ev = []
    if not enabled:
        ev.append("audit logging not enabled")
    if redact in (False, "off"):
        ev.append("logs are not redacted (PII / secrets risk — Israel Amendment 13)")
    if ev:
        return _finding("B10", WARN, "; ".join(ev),
                        "Enable audit logging and redaction so actions are traceable without leaking PII.")
    return _finding("B10", PASS, "Audit logging with redaction is enabled.", "Keep audit + redaction on.")


def check_tls(ctx: Context) -> Finding:
    cfg = ctx.config
    bind = str(dig(cfg, "gateway.bind", "")).split(":")[0].lower()
    tls = dig(cfg, "gateway.tls") or dig(cfg, "gateway.https")
    ev = []
    exposed = bind in EXPOSED_BINDS or (bind and bind not in LOOPBACK)
    if exposed and not tls and not dig(cfg, "gateway.tailscale.funnel"):
        ev.append(f"gateway.bind={bind} is non-loopback without TLS configured")
    if _perms_loose(ctx):
        ev.append(f"openclaw.json is group/world-readable ({oct(ctx.config_mode)[-3:]}) — at-rest risk")
    if ev:
        return _finding("B11", WARN, "; ".join(ev),
                        "Terminate TLS (reverse proxy / tailscale) for any non-loopback bind; "
                        "`chmod 600 ~/.openclaw/openclaw.json` and `chmod 700 ~/.openclaw`.", ev)
    return _finding("B11", PASS, "Transport is loopback/TLS and config perms are tight.",
                    "Keep transport encrypted and credential files locked down.")


CLOUD_PROVIDERS = ("openai", "anthropic", "gpt", "claude", "google", "gemini", "grok", "mistral", "cohere")


def _model_names(cfg: dict) -> list[str]:
    names = []
    md = dig(cfg, "agents.defaults.model")  # real OpenClaw location
    if isinstance(md, dict):
        if md.get("primary"):
            names.append(str(md["primary"]))
        fb = md.get("fallbacks")
        if isinstance(fb, list):
            names.extend(str(x) for x in fb)
    models = cfg.get("models")
    if isinstance(models, dict):
        for name, m in models.items():
            names.append(str((m.get("provider") if isinstance(m, dict) else "") or name))
    elif isinstance(models, list):
        names.extend(str(m) for m in models)
    return names


def check_local_first(ctx: Context) -> Finding:
    names = _model_names(ctx.config)
    if not names:
        return _finding("B12", UNKNOWN, "No model config found.", "—")
    cloud = [n for n in names if any(c in n.lower() for c in CLOUD_PROVIDERS)]
    if cloud:
        return _finding("B12", WARN, f"Cloud model(s) in use: {', '.join(sorted(set(cloud)))}.",
                        "For maximum privacy prefer a local model; if cloud is required, ensure no "
                        "sensitive data is sent to it. (Informational — low severity.)")
    return _finding("B12", PASS, "Models are local-first.", "Keep data local where possible.")


def _custom(cid, severity, status, detail, fix, ev=None) -> Finding:
    """Build a finding with an explicit severity (for dynamic-severity checks)."""
    m = BY_ID[cid]
    return Finding(m.id, m.title, severity, status, detail, fix, m.framework, m.scored, ev or [])


# ---------- B13: installed-skill / plugin content vetting (ClawHavoc vector) ----------
# CRITICAL: unambiguous malware signals (paste-staged payloads, credential/wallet theft,
# and the ClawHavoc password-dialog social-engineering trick).
_SKILL_CRIT = [
    ("paste / exfiltration host",
     re.compile(r"\b(glot\.io|pastebin\.com|hastebin|transfer\.sh|0x0\.st|webhook\.site|requestbin)\b", re.I)),
    ("known stealer malware name",
     re.compile(r"\b(AMOS|Atomic\s*Stealer|RedLine\s*Stealer|Lumma\s*Stealer)\b", re.I)),
    ("password-prompt social engineering",
     re.compile(r"(enter|type)\s+your\s+(mac|login|system|sudo)\s*password|osascript[^\n]{0,80}password|display\s+dialog[^\n]{0,80}password", re.I)),
]
# Credential/secret access is only malicious when EXFILTRATED — flag a line that both
# touches a secret path AND ships it out (avoids flagging a skill loading its own .env).
_CRED_RE = re.compile(
    r"find-generic-password|login\.keychain|\.ssh/id_[a-z0-9]+|\.aws/credentials|"
    r"wallet\.dat|keystore\.json|MetaMask", re.I)
_EXFIL_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|netcat|requests?\.post|fetch\(|\bPOST\b|\bscp\b|base64|"
    r"glot\.io|webhook\.site|transfer\.sh|pastebin", re.I)
# HIGH: suspicious but sometimes legitimate — flag for human review, don't hard-fail.
_SKILL_HIGH = [
    ("download-and-run a package over http",
     re.compile(r"npx\s+-y\s+https?://|pip\s+install\s+https?://|bash\s+<\(\s*curl", re.I)),
    ("base64-decode piped to exec / obfuscation",
     re.compile(r"base64\s+-d[^\n]{0,40}\|\s*(ba)?sh|eval\([^\n]{0,40}(atob|b64decode|base64)", re.I)),
    ("powershell download-and-exec",
     re.compile(r"(iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*iex|Invoke-Expression", re.I)),
]
# `curl URL | sh` is how uv/rustup/brew/deno legitimately install — only suspicious when the
# host is NOT a well-known installer domain.
_REPUTABLE_INSTALL_HOSTS = (
    "astral.sh", "sh.rustup.rs", "rustup.rs", "get.docker.com", "brew.sh", "deno.land",
    "bun.sh", "get.pnpm.io", "install.python-poetry.org", "sdk.cloud.google.com",
    "nodejs.org", "get.k3s.io", "starship.rs", "get.helm.sh", "fnm.vercel.app",
)
_PIPE_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]*?https?://([^\s/'\"|]+)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh", re.I)


def _suspicious_pipe_hosts(blob: str) -> list[str]:
    hosts = []
    for host in _PIPE_SHELL_RE.findall(blob):
        h = host.lower()
        if not any(h == r or h.endswith("." + r) or h.endswith(r) for r in _REPUTABLE_INSTALL_HOSTS):
            hosts.append(host)
    return hosts


def _has_cred_exfil(blob: str) -> bool:
    """A single line that touches a secret path AND ships it outward."""
    return any(_CRED_RE.search(ln) and _EXFIL_RE.search(ln) for ln in blob.splitlines())


# Malware base64-encodes `curl <ip> | bash` to hide it. Decode blobs (NEVER execute)
# and re-scan the plaintext for shell/download payloads.
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_DECODED_BAD_RE = re.compile(
    r"/bin/(ba|z)?sh|\bcurl\b|\bwget\b|\bnc\b|powershell|invoke-expression|"
    r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I)


def _decoded_payloads(blob: str) -> list[str]:
    """Return short previews of base64 blobs that decode to shell/download payloads."""
    hits = []
    for token in _B64_BLOB_RE.findall(blob):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= 6 and _DECODED_BAD_RE.search(decoded):
            hits.append(decoded.strip().replace("\n", " ")[:80])
    return hits


def check_installed_skills(ctx: Context) -> Finding:
    skills = ctx.installed_skills
    if not skills:
        return _custom("B13", HIGH, UNKNOWN,
                       "No installed third-party skills found to inspect.",
                       "Run on the host where installed skills live (~/.openclaw/skills, workspace/skills).")
    crit, high = [], []
    for name, blob in skills.items():
        for label, rx in _SKILL_CRIT:
            if rx.search(blob):
                crit.append(f"{name}: {label}")
        if _has_cred_exfil(blob):
            crit.append(f"{name}: secret/credential exfiltration")
        for payload in _decoded_payloads(blob):
            crit.append(f"{name}: hidden base64 payload -> '{payload}'")
        for label, rx in _SKILL_HIGH:
            if rx.search(blob):
                high.append(f"{name}: {label}")
        for host in _suspicious_pipe_hosts(blob):
            high.append(f"{name}: pipe-to-shell from non-reputable host {host}")
    n = len(skills)
    if crit:
        extra = f" (+{len(crit) - 6} more)" if len(crit) > 6 else ""
        return _custom("B13", CRITICAL, FAIL,
                       "Dangerous code in an installed skill — this is the ClawHavoc class: "
                       + "; ".join(crit[:6]) + extra,
                       "Uninstall the flagged skill(s) NOW and rotate any secrets they could reach "
                       "(channel tokens, 1Password, cloud keys). Only reinstall skills whose source "
                       "you have read.", crit)
    if high:
        return _custom("B13", HIGH, FAIL,
                       "Suspicious patterns in installed skill(s): " + "; ".join(high[:6]),
                       "Review the flagged skills' source before trusting them; prefer pinned, "
                       "signed, VirusTotal-clean releases.", high)
    return _custom("B13", HIGH, PASS,
                   f"Scanned {n} installed skill(s); no shell-exec / exfiltration / obfuscation "
                   "patterns found.",
                   "Keep installing only skills whose source you've reviewed — trust no one.")


def vet_skill(path: str | Path) -> Finding:
    """Vet a skill BEFORE installing it: run the B13 scan on a local skill dir or SKILL.md."""
    p = Path(path).expanduser()
    if p.is_dir():
        text, name = _read_skill_text(p), p.name
    elif p.is_file():
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return _custom("B13", HIGH, UNKNOWN, f"could not read {p}: {exc}", "—")
        name = p.parent.name or p.stem
    else:
        return _custom("B13", HIGH, UNKNOWN, f"no skill found at {p}", "Point --vet at a skill dir or SKILL.md.")
    ctx = Context(home=p)
    ctx.installed_skills = {name or "skill": text}
    return check_installed_skills(ctx)


# ---------- B14: egress surface (advisory) ----------
_EXT_SKILL_HINTS = ("slack", "github", "notion", "google", "gmail", "web", "research",
                    "http", "telegram", "obsidian", "browser", "fetch", "discord", "1password")


def check_egress(ctx: Context) -> Finding:
    cfg = ctx.config
    allow = (dig(cfg, "gateway.egress") or dig(cfg, "network.egress")
             or cfg.get("egress") or dig(cfg, "tools.http.allow"))
    surface = []
    chans = list(_channels(cfg))
    if chans:
        surface.append(f"channels ({', '.join(chans[:4])})")
    ext = [s for s in ctx.installed_skills if any(h in s.lower() for h in _EXT_SKILL_HINTS)]
    if ext:
        surface.append(f"{len(ext)} external-service skill(s)")
    if _hint(_enabled_tools(cfg), OUTBOUND_TOOL_HINTS):
        surface.append("outbound tools (send/webhook/exec)")
    if allow:
        return _custom("B14", MEDIUM, PASS,
                       f"Egress allowlist configured. Reachable surface: {', '.join(surface) or 'minimal'}.",
                       "Keep the egress allowlist tight.")
    if surface:
        return _custom("B14", MEDIUM, WARN,
                       f"No egress allowlist — the agent can reach out via: {', '.join(surface)}.",
                       "OpenClaw has no built-in egress allowlist; minimise send-capable channels and "
                       "external-service skills. Every outbound-capable skill can exfiltrate data "
                       "(this is the third leg of the Lethal Trifecta).")
    return _custom("B14", MEDIUM, UNKNOWN, "No outbound channels / skills / tools detected.", "—")


# ---------- B15: MCP server trust ----------
def _mcp_servers(cfg: dict) -> dict:
    out = {}
    for key in ("mcp", "mcpServers", "mcp_servers"):
        v = cfg.get(key)
        if isinstance(v, dict):
            out.update(v)
    v = dig(cfg, "tools.mcp") or dig(cfg, "plugins.mcp")
    if isinstance(v, dict):
        out.update(v)
    for name in _plugins(cfg):
        if "mcp" in str(name).lower():
            out.setdefault(name, {})
    return out


def check_mcp(ctx: Context) -> Finding:
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding("B15", UNKNOWN, "No MCP servers configured.", "—")
    return _finding("B15", WARN,
                    f"{len(servers)} MCP server(s) configured ({', '.join(list(servers)[:5])}). "
                    "Remote MCP servers can carry prompt injection, SSRF and data exposure.",
                    "Verify each MCP server's source and trust boundary, restrict its tool "
                    "reachability, and avoid untrusted remote MCP endpoints.")


# ---------- B16: is threat monitoring / detection set up? ----------
_MONITORING_HINTS = ("clawsec", "security-monitor", "openclaw-security-monitor", "sentinel",
                     "falco", "osquery", "wazuh", "trent", "threat", "intrusion", "watchdog",
                     "-ids", "edr", "monitor")


def check_monitoring(ctx: Context) -> Finding:
    """Does the user actually have threat monitoring / detection in place?"""
    cfg = ctx.config
    signals = []
    for name in list(ctx.installed_skills) + list(_plugins(cfg)):
        if any(h in str(name).lower() for h in _MONITORING_HINTS):
            signals.append(f"'{name}'")
    if dig(cfg, "monitoring") or dig(cfg, "security.monitoring") \
            or dig(cfg, "alerts") or dig(cfg, "security.alerts"):
        signals.append("monitoring/alerts in config")
    if signals:
        return _finding("B16", PASS,
                        f"Threat monitoring present: {', '.join(signals[:5])}.",
                        "Keep it enabled and make sure its alerts actually reach you.")
    return _finding("B16", WARN,
                    "No threat monitoring / detection is set up — if your agent gets compromised "
                    "(e.g. a malicious skill), nothing will alert you.",
                    "Install a monitoring skill (e.g. ClawSec or openclaw-security-monitor), wire "
                    "audit logging to an alert channel, or schedule ClawCheck's own lightweight "
                    "`audit.py --monitor` so changes don't go unnoticed.")


# ---------- C4: version / update hygiene (advisory) ----------
def check_version(ctx: Context) -> Finding:
    ver = dig(ctx.config, "meta.lastTouchedVersion")
    if not ver:
        return _custom("C4", BY_ID["C4"].severity, UNKNOWN,
                       "OpenClaw version not recorded in config.", "—")
    return _custom("C4", BY_ID["C4"].severity, WARN,
                   f"OpenClaw config last touched by version {ver}. Outdated installs are the "
                   "ClawHavoc / CVE-2026-25253 target.",
                   "Keep OpenClaw updated and re-run the installed-skill checks after updating.")


CHECKS = [
    check_trifecta, check_secrets, check_gateway, check_least_privilege,
    check_sandbox, check_supply_chain, check_bootstrap_injection,
    check_memory_poisoning, check_human_approval, check_leak,
    check_audit_log, check_tls, check_local_first,
    check_installed_skills, check_egress, check_mcp, check_monitoring, check_version,
]


def run_all(ctx: Context) -> list[Finding]:
    return [chk(ctx) for chk in CHECKS]
