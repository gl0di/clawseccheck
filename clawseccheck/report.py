"""Render plain-language report + shareable card.

The shareable card NEVER lists findings — only grade + score + trifecta ratio
(tiered disclosure: sharing your card must not publish your vulns to attackers).

Every renderer supports `ascii_only=True` for terminals that can't encode the
unicode icons/box (e.g. a legacy Windows cp1252 console).
"""
from __future__ import annotations

import hashlib
import os
import html
import json
import re
import tempfile
from pathlib import Path

from .catalog import (
    BY_ID,
    FAMILY_LABEL, FAMILY_OF, FAMILY_ORDER,
    ATTESTED, CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding, ast_for, owasp_for, remediation_for,
)
from .ansi import paint
from .brand import BRAND_RED, GRADE_HEX, LOGO_SVG, SEVERITY, WORDMARK
from .dedup import deduplicate_findings
from .dossier import AXIS_LABEL
from .guide import suggest_actions
from .scoring import ScoreResult, assessment_coverage

# Findings, skill names, decoded payload previews and native-audit fields are UNTRUSTED
# data. Strip terminal-control sequences (ANSI/OSC incl. OSC-52 clipboard), bidi overrides
# and zero-width chars so a hostile skill/finding can't attack the terminal or spoof text.
_ANSI_OSC_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b.")
_BAD_CHARS_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")



def _sanitize(s: str) -> str:
    if not s:
        return s
    s = _BAD_CHARS_RE.sub("", _ANSI_OSC_RE.sub("", s))
    for c in "\r\n\t":
        s = s.replace(c, " ")
    # Lazy import avoids the report -> logsafe -> checks import cycle during package
    # initialisation. Every renderer shares this boundary, so secret redaction cannot be
    # accidentally implemented for JSON while remaining absent from text/SARIF/HTML.
    from .logsafe import redact  # noqa: PLC0415
    return redact(s)


def _sanitize_tree(value):
    """Recursively sanitize untrusted strings in machine-readable output trees."""
    if isinstance(value, str):
        return _sanitize(value)
    if isinstance(value, list):
        return [_sanitize_tree(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_tree(item) for item in value]
    if isinstance(value, dict):
        return {
            _sanitize(str(key)): _sanitize_tree(item)
            for key, item in value.items()
        }
    return value


# A finding suppressed via .clawseccheckignore is normally dropped from the score, the
# badge and SARIF. But a suppressed CRITICAL/HIGH FAIL (which caps the score) or a
# sensitive check id must stay VISIBLE on every surface — one ignore line could otherwise
# flip an F into an A silently. This predicate is the single source of that rule, shared by
# the human report, the SVG badge and the SARIF renderer (B-163).
SENSITIVE_SUPPRESSED_IDS = frozenset({"B1", "B2", "B13", "B20"})


def surfaced_despite_suppression(f: Finding) -> bool:
    """True when a suppressed finding must still be surfaced (score-capping or sensitive)."""
    return bool(getattr(f, "suppressed", False)) and (
        (f.status == FAIL and f.severity in (CRITICAL, HIGH))
        or f.id in SENSITIVE_SUPPRESSED_IDS
    )

_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
# Within a family: FAIL/WARN (the actionable items) before PASS/UNKNOWN (context).
_STATUS_ORDER = {FAIL: 0, WARN: 1, UNKNOWN: 2, PASS: 3}
_ICON = {FAIL: "⛔", WARN: "⚠️", PASS: "✅", UNKNOWN: "❔", "SKILL_ARCHIVE_PATH_TRAVERSAL": "❔"}
_ICON_ASCII = {FAIL: "[X]", WARN: "[!]", PASS: "[OK]", UNKNOWN: "[?]", "SKILL_ARCHIVE_PATH_TRAVERSAL": "[?]"}

# Severity dot for FAIL/WARN finding lines (Component-2 mock, B-077): the glyph carries
# SEVERITY, not status — FAIL-before-WARN ordering plus the breakdown counts already carry
# status. PASS/UNKNOWN roster lines keep the ✅/❔ status icons above. --ascii folds the
# dot+word to a single [SEVERITY] bracket (pure ASCII, no info loss).
_SEV_GLYPH = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "⚪"}
_SEV_COLOR = {CRITICAL: "red", HIGH: "red", MEDIUM: "yellow", LOW: "grey"}

# Family → emoji for the chat Dashboard paste ONLY (SKILL.md Step-3 table). The CLI
# report's family headers deliberately stay emoji-less (design-system.md Layer-2 decision).
_FAMILY_EMOJI = {
    "exposure": "🌐", "privilege": "🔑", "supply_chain": "📦",
    "content_integrity": "📝", "secrets": "🔒", "detection": "🛰️",
    "automation": "🔧",
}


def _sev_token(severity: str, *, ascii_only: bool = False, color: bool = False) -> str:
    """`🔴 CRITICAL` severity marker for an issue line; `[CRITICAL]` under --ascii.

    Colour (opt-in) paints the severity word only — the emoji dot is already coloured —
    and stays purely additive (strip_ansi(colored) == plain).
    """
    word = paint(severity, _SEV_COLOR.get(severity, "grey"), "bold",
                 enabled=True) if color else severity
    if ascii_only:
        return f"[{word}]"
    return f"{_SEV_GLYPH.get(severity, '⚪')} {word}"

# ── ANSI colour palette (opt-in; see ansi.py) ────────────────────────────────
# Grade → colour for the header grade letter + score-bar fill.
_GRADE_COLOR = {"A": "green", "B": "green", "C": "yellow", "D": "bright_yellow", "F": "red"}
# Status → colour for finding icons / coverage states.
_STATUS_COLOR = {
    FAIL: "red", WARN: "yellow", PASS: "green", UNKNOWN: "grey",
    "SKILL_ARCHIVE_PATH_TRAVERSAL": "grey",
}

# ── Assurance honesty (R11) ───────────────────────────────────────────────────
# Two human-report-only signals over assessment_coverage() (scoring.py). Neither
# ever touches score/grade/findings or the machine outputs (JSON/card/SVG/SARIF) —
# both are advisory text only. Thresholds grounded against the real-fixture band
# (assessable 0.39-0.52; see fixtures/clean_b13_doc_example ~0.39, home_safe ~0.52).
LOW_COVERAGE_FRAC = 0.35  # below this fraction assessable -> loud caution line (C-166)
DRIFT_UNKNOWN_FRAC = 0.85  # at/above this fraction UNKNOWN -> hedged staleness nudge (C-165)
DRIFT_MIN_SCORED = 20  # minimum scored_total before the staleness nudge is even considered


def _grade_color(grade: str) -> str:
    """Map a grade label (possibly 'A+', 'B-', …) to a palette colour name."""
    return _GRADE_COLOR.get((grade or "")[:1].upper(), "grey")


def _color_icons(icon: dict, color: bool) -> dict:
    """Return an icon map with each glyph pre-painted by status (or the map as-is)."""
    if not color:
        return icon
    return {k: paint(v, _STATUS_COLOR.get(k, "grey"), enabled=True) for k, v in icon.items()}


def _score_bar(score: int, grade: str, *, ascii_only: bool = False, color: bool = False) -> str:
    """Render a 16-cell score bar. Unicode ``█░`` by default; ``[####----]`` under --ascii.

    The fill is proportional to score/100 (rounded, clamped to 0..16). When colour is on
    the filled run takes the grade colour and the empty run is dimmed; brackets stay plain.
    """
    cells = 16
    filled = max(0, min(cells, round(score / 100 * cells)))
    empty = cells - filled
    if ascii_only:
        fill_s, empty_s, lb, rb = "#" * filled, "-" * empty, "[", "]"
    else:
        fill_s, empty_s, lb, rb = "█" * filled, "░" * empty, "", ""
    if color:
        fill_s = paint(fill_s, _grade_color(grade), enabled=True)
        empty_s = paint(empty_s, "grey", enabled=True)
    return f"{lb}{fill_s}{empty_s}{rb}"


# Coverage-map state glyphs (unicode / ascii) + colour, keyed to coverage.py states.
_COV_GLYPH = {"checked": "✅", "partial": "◑", "roadmap": "○", "not_checkable": "⊘"}
_COV_GLYPH_ASCII = {"checked": "[OK]", "partial": "[~]", "roadmap": "[ ]", "not_checkable": "[x]"}
_COV_COLOR = {"checked": "green", "partial": "yellow", "roadmap": "grey", "not_checkable": "grey"}


def _coverage_lines(findings: list[Finding], *, ascii_only: bool = False,
                    color: bool = False) -> list[str]:
    """Render the OpenClaw-surface coverage map for the terminal report.

    Grounded strictly in ``coverage.coverage()`` output — the 13 config surfaces split into
    ``checked``/``partial``, plus the static, recon-grounded ``not_checkable`` names and any
    ``roadmap`` gaps. Nothing is invented: only states the engine actually produced appear.
    """
    from .coverage import coverage as _coverage  # noqa: PLC0415

    cov = _coverage(findings)
    summary = cov["summary"]
    glyph = _COV_GLYPH_ASCII if ascii_only else _COV_GLYPH
    dot, rule = ("|", "--") if ascii_only else ("·", "—")

    def _g(state: str) -> str:
        g = glyph[state]
        return paint(g, _COV_COLOR[state], enabled=True) if color else g

    total = summary["checked"] + summary["partial"]  # the 13 config-checkable surfaces
    lines = [f"{rule} Coverage of OpenClaw surfaces {rule}"]
    lines.append(
        f"{_g('checked')} checked {summary['checked']} {dot} "
        f"{_g('partial')} partial/unknown {summary['partial']}  "
        f"(of {total} config surfaces)"
    )
    not_checkable = cov["gaps"]["not_checkable"]
    if not_checkable:
        names = ", ".join(_sanitize(n) for n in not_checkable)
        lines.append(
            f"{_g('not_checkable')} not-checkable {len(not_checkable)} "
            f"(no OpenClaw config control): {names}"
        )
    roadmap = cov["gaps"]["roadmap"]
    if roadmap:
        names = ", ".join(_sanitize(n) for n in roadmap)
        lines.append(f"{_g('roadmap')} roadmap {len(roadmap)} (no check yet): {names}")
    return lines

_ASCII_MAP = str.maketrans({
    "×": "x", "≤": "<=", "≥": ">=", "—": "-", "–": "-", "…": "...",
    "’": "'", "‘": "'", "“": '"', "”": '"', "≈": "~", "→": "->", "•": "*",
})


def _asciify(text: str) -> str:
    """Fold the unicode we emit down to pure ASCII for legacy consoles."""
    return text.translate(_ASCII_MAP).encode("ascii", "replace").decode("ascii")


def compute_scan_receipt(findings) -> str:
    """Compute a deterministic Merkle-style root hash over all findings.

    Each finding is hashed individually; hashes are sorted then combined.
    Returns a 64-char hex string. Empty/None findings → sha256 of empty bytes.
    Pure stdlib, local-only. Never raises.
    """
    try:
        def finding_digest(f):
            canonical = json.dumps({
                "check_id": str(getattr(f, "check_id", "") or getattr(f, "rule_id", "")),
                "verdict": str(getattr(f, "verdict", "") or getattr(f, "severity", "")),
                "path": str(getattr(f, "path", "") or getattr(f, "file", "")),
                "line": int(getattr(f, "line", 0) or 0),
                "detail": str(getattr(f, "detail", "") or "")[:200],
            }, sort_keys=True, ensure_ascii=True)
            return hashlib.sha256(canonical.encode()).hexdigest()

        if not findings:
            return hashlib.sha256(b"").hexdigest()

        leaf_hashes = sorted(finding_digest(f) for f in findings)
        combined = "".join(leaf_hashes)
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception:  # noqa: BLE001
        return "error-computing-receipt"


def _trifecta_ratio(findings: list[Finding]) -> str:
    for f in findings:
        if f.id == "A1":
            return f"{len(f.evidence)}/3"
    return "?/3"


def _bool_word(value: bool) -> str:
    return "yes" if value else "no"


def _capability_graph(ctx) -> dict:
    """Static capability summary (config + attestation), for the report/json output."""
    from .attest import attested_agents  # noqa: PLC0415
    from .checks import (  # noqa: PLC0415
        INPUT_TOOL_HINTS,
        OUTBOUND_TOOL_HINTS,
        SENSITIVE_TOOL_HINTS,
        _agent_legs,
        _enabled_tools,
        _hint,
        _mcp_has_remote,
        _mcp_servers,
        _untrusted_input_channels,
        _web_fetch_enabled,
    )
    from .collector import dig  # noqa: PLC0415

    cfg = getattr(ctx, "config", {}) or {}
    att = getattr(ctx, "attestation", {}) or {}
    nodes: list[dict] = []
    edges: list[tuple[str, str]] = []

    input_surfaces = sorted({
        *_untrusted_input_channels(cfg),
        *[t for t in _enabled_tools(cfg) if _hint([t], INPUT_TOOL_HINTS)],
        *(["web.fetch"] if _web_fetch_enabled(cfg) else []),
    })
    main_tools = sorted({t for t in _enabled_tools(cfg)})
    main_secrets = bool(
        dig(cfg, "gateway.auth.password")
        or dig(cfg, "gateway.token")
        or (getattr(ctx, "home", None) and (ctx.home / "credentials").is_dir())
        or any(_hint([t], SENSITIVE_TOOL_HINTS) for t in main_tools)
    )
    main_write = bool(
        any(_hint([t], ("fs_write", "write", "apply_patch")) for t in main_tools)
        or dig(cfg, "agents.defaults.sandbox.workspaceAccess") == "rw"
    )
    main_egress = bool(
        any(_hint([t], OUTBOUND_TOOL_HINTS) for t in main_tools)
        or dig(cfg, "tools.elevated.allowFrom")
        or input_surfaces
    )

    nodes.append({
        "id": "input",
        "label": "input",
        "kind": "ingress",
        "tools": input_surfaces,
        "secrets_visible": False,
        "can_write_memory": False,
        "can_egress": bool(input_surfaces),
    })
    nodes.append({
        "id": "main",
        "label": "main",
        "kind": "agent",
        "tools": main_tools,
        "secrets_visible": main_secrets,
        "can_write_memory": main_write,
        "can_egress": main_egress,
    })
    if input_surfaces:
        edges.append(("input", "main"))

    agents = attested_agents(att)
    for agent in agents:
        name = str(agent.get("name") or "<unnamed>")
        tools = [str(t) for t in agent.get("tools") or [] if isinstance(t, (str, bytes))]
        legs = _agent_legs(tools)
        node_id = f"subagent:{name}"
        nodes.append({
            "id": node_id,
            "label": name,
            "kind": "subagent",
            "tools": tools,
            "secrets_visible": bool(legs.get("sensitive data")),
            "can_write_memory": any(_hint([t], ("fs_write", "write", "apply_patch")) for t in tools),
            "can_egress": bool(legs.get("outbound actions")),
        })
        edges.append(("main", node_id))

    for name, spec in sorted(_mcp_servers(cfg).items()):
        if not isinstance(spec, dict):
            continue
        tool_nodes: list[str] = []
        tools = spec.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    tool_name = str(tool.get("name") or "").strip()
                    if tool_name:
                        tool_nodes.append(tool_name)
                elif isinstance(tool, (str, bytes)) and str(tool).strip():
                    tool_nodes.append(str(tool).strip())
        node_id = f"mcp:{name}"
        nodes.append({
            "id": node_id,
            "label": name,
            "kind": "mcp",
            "tools": sorted(dict.fromkeys(tool_nodes)),
            "secrets_visible": bool(spec.get("env") or spec.get("oauth")),
            "can_write_memory": False,
            "can_egress": _mcp_has_remote(spec),
        })
        edges.append(("main", node_id))

    return {"nodes": nodes, "edges": edges}


def _capability_graph_lines(ctx) -> list[str]:
    graph = _capability_graph(ctx)
    if not graph:
        return []
    lines = ["Capability graph", "Static config + attestation summary:"]
    for node in graph["nodes"]:
        # label (MCP server / subagent name) and tool names are untrusted config data —
        # strip terminal-control sequences so they can't spoof/erase the terminal (B-164).
        label = _sanitize(str(node["label"]))
        tools = _sanitize(", ".join(node["tools"])) if node["tools"] else "none"
        lines.append(
            f"- {label} ({node['kind']}): tools={tools}; "
            f"secrets_visible={_bool_word(node['secrets_visible'])}; "
            f"can_write_memory={_bool_word(node['can_write_memory'])}; "
            f"can_egress={_bool_word(node['can_egress'])}"
        )
    if graph["edges"]:
        lines.append("flow: input -> main -> subagents -> MCP -> fs/network")
    return lines


def _credential_surface_map(ctx) -> list[dict]:
    """Path-existence inventory of credential stores reachable from the agent home.

    Checks ONLY whether well-known credential-store paths exist on the filesystem
    (Path.exists / Path.is_file / Path.is_dir) — never opens, reads, hashes, or
    transmits any file contents. Reports relative paths as evidence; no absolute
    paths leave this function. This is a supply-chain reachability check so the
    audit can warn when a powerful agent runs next to accessible secrets — it is
    NOT a credential reader.
    """
    from .checks import SECRET_KEY_RE, _mcp_servers  # noqa: PLC0415
    from .collector import WORKSPACE_DIRS, dig  # noqa: PLC0415

    cfg = getattr(ctx, "config", {}) or {}
    home = getattr(ctx, "home", None)
    home_path = Path(home) if home is not None else None

    def _rel(path: Path) -> str:
        try:
            return str(path.relative_to(home_path)) if home_path is not None else str(path)
        except Exception:
            return str(path)

    def _summarize(items: list[str], label: str) -> str:
        if not items:
            return ""
        items = sorted(dict.fromkeys(items))
        head = ", ".join(items[:4])
        tail = f" (+{len(items) - 4} more)" if len(items) > 4 else ""
        return f"{label}: {head}{tail}" if head else ""

    entries: list[dict] = []

    env_keys = sorted(k for k in os.environ if SECRET_KEY_RE.search(k))
    env_evidence: list[str] = []
    if env_keys:
        env_evidence.append(_summarize(env_keys, "process env secret-like keys"))

    entries.append({"class": "env", "reachable": bool(env_evidence), "evidence": env_evidence})

    mcp_passthrough: list[str] = []
    for name, spec in sorted(_mcp_servers(cfg).items()):
        if not isinstance(spec, dict):
            continue
        env = spec.get("env")
        has_env_passthrough = False
        if isinstance(env, dict):
            if any(str(k) == "*" or str(v) == "*" for k, v in env.items()):
                has_env_passthrough = True
            if any(SECRET_KEY_RE.search(str(k)) for k in env):
                has_env_passthrough = True
        if has_env_passthrough or spec.get("tokenPassthrough") is True or spec.get("token-passthrough") is True:
            mcp_passthrough.append(name)
    mcp_evidence = []
    if mcp_passthrough:
        mcp_evidence.append(_summarize(mcp_passthrough, "MCP env/token passthrough"))
    entries.append({"class": "mcp-passthrough", "reachable": bool(mcp_evidence), "evidence": mcp_evidence})

    dotenv_hits: list[str] = []
    if home_path is not None and home_path.exists():
        candidates = [home_path / ".env", home_path / ".envrc"]
        for ws in WORKSPACE_DIRS:
            candidates.append(home_path / ws / ".env")
            candidates.append(home_path / ws / ".envrc")
        for cand in candidates:
            if cand.is_file():  # path-existence check only — never reads contents
                dotenv_hits.append(_rel(cand))
    entries.append({"class": ".env", "reachable": bool(dotenv_hits), "evidence": dotenv_hits})

    keychain_hits: list[str] = []
    if home_path is not None and home_path.exists():
        for rel in (
            "Library/Keychains",
            ".local/share/keyrings",
            ".gnupg",
        ):
            p = home_path / rel
            if p.exists():  # path-existence check only — never reads contents
                keychain_hits.append(_rel(p))
    entries.append({"class": "keychain", "reachable": bool(keychain_hits), "evidence": keychain_hits})

    cookie_hits: list[str] = []
    if home_path is not None and home_path.exists():
        for rel in (
            ".config/google-chrome/Default/Cookies",
            ".config/chromium/Default/Cookies",
            ".config/BraveSoftware/Brave-Browser/Default/Cookies",
            ".mozilla/firefox",
            "Library/Cookies/Cookies.binarycookies",
        ):
            p = home_path / rel
            if p.is_file():
                cookie_hits.append(_rel(p))
            elif p.is_dir():
                for child in p.rglob("cookies.sqlite"):
                    if child.is_file():
                        cookie_hits.append(_rel(child))
    entries.append({"class": "cookies", "reachable": bool(cookie_hits), "evidence": cookie_hits})

    ssh_hits: list[str] = []
    if home_path is not None and home_path.exists():
        ssh_dir = home_path / ".ssh"
        if ssh_dir.is_dir():  # path-existence check only — never reads key contents
            ssh_hits.append(_rel(ssh_dir))
            for name in ("id_rsa", "id_ed25519", "config", "known_hosts"):
                p = ssh_dir / name
                if p.is_file():  # path-existence check only
                    ssh_hits.append(_rel(p))
    entries.append({"class": "ssh", "reachable": bool(ssh_hits), "evidence": ssh_hits})

    profiles = dig(cfg, "auth.profiles") or {}
    providers: list[str] = []
    if isinstance(profiles, dict):
        seen: set[str] = set()
        for key in profiles:
            provider = str(key).split(":", 1)[0]
            if provider and provider not in seen:
                seen.add(provider)
                providers.append(provider)
    cloud_hits: list[str] = []
    if providers:
        cloud_hits.append(_summarize(sorted(providers), "auth.profiles providers"))
    if dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token"):
        cloud_hits.append("gateway token present")
    entries.append({"class": "cloud", "reachable": bool(cloud_hits), "evidence": cloud_hits})

    return entries


def _log_threat_report_lines(findings: list[Finding]) -> list[str]:
    """B164 (F-124/E-044) quiet-hint surfacing.

    A WARN B164 finding already gets its full detail + up to 12 redacted-evidence
    bullets via the generic FAIL/WARN render path above — nothing extra needed there.
    But a PASS finding renders through ``_render_finding_compact`` (title only, no
    detail), so the base-rate-discipline "N low-confidence signal(s) suppressed" hint
    baked into B164's PASS detail text would otherwise never reach the human report.
    This adds it back, and only when there is something to say.
    """
    b164 = next((f for f in findings if f.id == "B164"), None)
    if b164 is None or b164.status != PASS or not b164.detail:
        return []
    if "low-confidence signal" not in b164.detail:
        return []
    return ["Log Threat Report", _sanitize(b164.detail)]


def _credential_surface_lines(ctx) -> list[str]:
    map_ = _credential_surface_map(ctx)
    lines = ["Credential surface map (path-existence inventory)", "Static config + file-system inventory:"]
    for item in map_:
        # evidence carries untrusted MCP server names / config-derived strings — strip
        # terminal-control sequences before they reach the terminal (B-164).
        evidence = _sanitize("; ".join(item["evidence"])) if item["evidence"] else "none"
        lines.append(f"- {item['class']}: reachable={_bool_word(item['reachable'])}; {evidence}")
    return lines


def compute_blast_radius(cfg: dict, finding_cid: str) -> dict:  # noqa: ARG001
    """Estimate attacker gain if this FAIL finding is exploited.

    Returns a dict with four fields:
      open_channels  – count of messaging channels with dmPolicy or groupPolicy='open'
      has_exec       – True if tools.exec.mode is configured
      has_write      – True if fs_write or apply_patch appears in tools.allow
      secret_paths   – count of dotted config paths that hold a secret-bearing value

    ``finding_cid`` is accepted for future per-check weighting; unused today.
    """
    from .checks import _open_channels, _secret_paths  # noqa: PLC0415
    from .collector import dig  # noqa: PLC0415

    open_channels = len(_open_channels(cfg))
    has_exec = dig(cfg, "tools.exec.mode") is not None
    allow = dig(cfg, "tools.allow") or dig(cfg, "gateway.tools.allow") or []
    has_write = isinstance(allow, list) and any(
        str(item) in ("fs_write", "apply_patch") for item in allow
    )
    secret_paths = len(_secret_paths(cfg))
    return {
        "open_channels": open_channels,
        "has_exec": has_exec,
        "has_write": has_write,
        "secret_paths": secret_paths,
    }


def _family_of(f) -> str | None:
    """Map a finding to one of the 7 Dashboard families via its catalog surface.

    A1 (Lethal Trifecta) is cross-cutting in the catalog (surface="trifecta", no
    family bucket) but it IS an agent-behavior signal, so the Dashboard routes it
    to Privilege & Execution rather than giving it a standalone headline (F-044).
    Findings with an id outside CATALOG (native-audit passthrough, test doubles)
    return None -> the "Other" bucket, so nothing is ever silently dropped.
    """
    if f.id == "A1":
        return "privilege"
    meta = BY_ID.get(f.id)
    if meta is None:
        return None
    return FAMILY_OF.get(meta.surface)


def _render_finding_compact(lines, icon, f):
    """One-line roster entry for PASS/UNKNOWN — full detail would bury the FAILs/WARNs."""
    lines.append(f"  {icon[f.status]} [{f.severity}] {_sanitize(f.title)}")


def _render_finding(lines, f, cfg: dict | None = None, *,
                    ascii_only: bool = False, color: bool = False):
    conf = getattr(f, "confidence", "HIGH")
    tag = f"  (confidence: {conf.lower()})" if conf != "HIGH" and f.status in (FAIL, WARN) else ""
    pc = getattr(f, "pass_confidence", None)
    pass_tag = f"  ({pc.replace('_', ' ')})" if f.status == PASS and pc else ""
    # Issue lines lead with the severity dot (B-077 / Component-2 mock); PASS/UNKNOWN
    # roster lines keep the status icons via _render_finding_compact.
    lines.append(f"{_sev_token(f.severity, ascii_only=ascii_only, color=color)}  "
                 f"{_sanitize(f.title)}{tag}{pass_tag}")
    why_text = _sanitize(f.detail) if f.detail else ""
    if why_text:
        lines.append(f"    why: {why_text}")
    # Surface the concrete evidence (e.g. the exact verbs B43/B44 flagged) when a
    # FAIL/WARN carries it — naming the specific item is the value of the finding.
    # B-078: many checks build `detail` by joining their evidence, so a bullet that is
    # already quoted verbatim inside the why line is pure duplication — skip it. Bullets
    # survive only when they ADD something the why line doesn't literally contain.
    if f.evidence and f.status in (FAIL, WARN):
        for ev in f.evidence[:12]:
            ev_s = _sanitize(ev)
            if ev_s and ev_s not in why_text:
                # Evidence is emitted verbatim (already bidi-stripped by _sanitize).
                lines.append(f"      - {ev_s}")
    # Blast-radius summary: only emitted when the caller supplies cfg (verbose mode).
    if f.status == FAIL and cfg is not None:
        br = compute_blast_radius(cfg, f.id)
        lines.append(
            f"  blast: channels={br['open_channels']} "
            f"exec={str(br['has_exec']).lower()} "
            f"write={str(br['has_write']).lower()} "
            f"secrets={br['secret_paths']}"
        )
    lines.append("")


def render_report(findings: list[Finding], score: ScoreResult,
                  ascii_only: bool = False, native=None,
                  *, risk=None, update_notice: list[str] | None = None,
                  freshness_notice: list[str] | None = None,
                  openclaw_detected: bool = True, ctx=None,
                  verbose: bool = False, color: bool = False,
                  tamper: ScoreResult | None = None) -> str:
    findings = deduplicate_findings(findings)
    icon = _color_icons(_ICON_ASCII if ascii_only else _ICON, color)
    ok = "[OK]" if ascii_only else "✅"
    # Supply cfg to _render_finding only in verbose mode so blast-radius lines appear.
    _blast_cfg: dict | None = (getattr(ctx, "config", {}) or {}) if (verbose and ctx is not None) else None
    suppressed_count = sum(1 for f in findings if getattr(f, "suppressed", False))
    issues = [f for f in findings
              if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))
    grade_disp = paint(score.grade, _grade_color(score.grade), "bold", enabled=True) if color else score.grade
    # Assurance honesty (R11): single source-of-truth coverage tally, computed once and
    # reused by both the C-166 low-coverage line (below) and the C-165 staleness nudge
    # (advisory band, further down) — never a second independent tally.
    cov = assessment_coverage(findings)
    # 🦞 mascot: header line only, once (design-system Foundations); --ascii drops it.
    head = "ClawSecCheck - OpenClaw Security Audit" if ascii_only \
        else "🦞 ClawSecCheck - OpenClaw Security Audit"
    lines = [head, "=" * 44,
             f"Score: {score.score}/100   Grade: {grade_disp}",
             _score_bar(score.score, score.grade, ascii_only=ascii_only, color=color)]
    if score.capped:
        lines.append(f"(capped from {score.raw_score} - open {score.cap_severity or 'CRITICAL'} finding)")

    # C-166: loud caution line when only a small slice of the catalog could be assessed —
    # a high grade over a thin slice can otherwise read as a full clean bill of health.
    # Human-report-only; never alters score/grade. Gated on score.assessable so the N/A
    # path (nothing scorable at all) isn't double-warned.
    if score.assessable and cov["scored_total"] > 0 and cov["assessable_frac"] < LOW_COVERAGE_FRAC:
        warn_icon = "[!]" if ascii_only else "⚠️ "
        pct = round(cov["assessable_frac"] * 100)
        lines.append(
            f"{warn_icon} Low coverage: only {pct}% of scored checks could be evaluated"
            f" ({cov['assessable']}/{cov['scored_total']}). Treat this grade with caution —"
            " it reflects a small slice of your setup."
        )

    # Tamper Score sub-grade — human-report-only addition (like update_notice below).
    # Presentation-layer only: never alters score/grade above; None (default) renders
    # nothing so the main Score/Grade line stays byte-identical to before this existed.
    if tamper is not None:
        lines.append(
            f"Tamper posture: {tamper.grade} ({tamper.score}/100 — tamper-defense"
            " sub-grade over B20/B22/B42/B78/B85/B86/C5 + monitor state)"
        )

    # --- "Why this score" breakdown ---
    scored_findings = [f for f in findings if getattr(f, "scored", True)
                       and f.status not in (UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL")
                       and not getattr(f, "suppressed", False)]
    n_scored = len(scored_findings)
    n_pass = sum(1 for f in scored_findings if f.status == PASS)
    n_warn = sum(1 for f in scored_findings if f.status == WARN)
    n_fail = sum(1 for f in scored_findings if f.status == FAIL)
    # Use the RAW (uncapped) pass-rate as the explained number so the arithmetic
    # reconciles with the pass/warn/fail counts. When a cap fired, the separate
    # `report.capped` line above already discloses raw -> capped, so showing the
    # raw value here is internally consistent instead of self-contradicting (B-013).
    lines.append(
        f"Why {score.raw_score}/100: weighted pass-rate over {n_scored} scored checks"
        f" — {n_pass} pass, {n_warn} warn (half weight), {n_fail} fail."
        " UNKNOWN/advisory checks are excluded."
    )
    if n_fail > 0 or n_warn > 0:
        _sev_counts: dict[str, int] = {}
        for f in scored_findings:
            if f.status in (FAIL, WARN):
                _sev_counts[f.severity] = _sev_counts.get(f.severity, 0) + 1
        sev_parts = []
        for sev in (CRITICAL, HIGH, MEDIUM, LOW):
            if sev in _sev_counts:
                sev_parts.append(f"{_sev_counts[sev]} {sev}")
        sev_summary = ", ".join(sev_parts)
        lines.append(f"({n_fail} FAIL, {n_warn} WARN — incl. {sev_summary})")
    lines.append(
        "This score reflects your configuration. It does not test live"
        " prompt-injection resistance or do a deep MCP supply-chain vet —"
        " run `--canary` / `--redteam` / `--dryrun` (live injection) and"
        " `--vet-mcp` (deep MCP) for those."
    )
    # Capability-vs-behavior honesty (F-038): a static audit bounds what the agent CAN do,
    # not what it DOES at runtime. OpenClaw core ships no runtime egress/taint gate, so a
    # clean Lethal Trifecta here is not a runtime guarantee — a high grade means "not
    # statically lethal-capable", never "protected against the trifecta at runtime".
    lines.append(
        "Static audit — this bounds what your agent *can* do, not how it *behaves* under a"
        " live attack. OpenClaw core has no runtime egress/taint gate, so even a clean"
        " Lethal Trifecta here can still be chained by prompt-injection at runtime: a high"
        " grade means \"not statically lethal-capable\", not \"runtime-proof\". Use the live"
        " tests above to probe actual resistance."
    )
    # C-216 (PASS-semantics doctrine): a clean/high-grade result confirms detection didn't
    # recognize anything, not that nothing is wrong -- distinct from the static-vs-runtime
    # line above (which is about WHAT is checked); this is about what a clean VERDICT
    # means. Numbers per Dave's ratification of C-216 (2026-07-13 backlog-sweep comment):
    # cite the measured recall directly, not just a qualitative caveat. Grounded in
    # eval/oasb/RESULTS.md (2026-07-13, v3.39.0, OASB per-skill FAIL-only recall 0.09) and
    # eval/skilltrustbench/RESULTS.md (SkillTrustBench malicious-class recall 0.412) --
    # both external, dev-only benchmarks (not shipped with this package). The lowest-recall
    # categories that eval identified (privilege-escalation, data-exfiltration, social-
    # engineering prose) have since had dedicated detectors added (B159/B160/B163) but the
    # fix has not yet been re-measured against the same benchmark.
    lines.append(
        "A clean/high-grade result means \"no known attack pattern matched\" — not \"this"
        " setup is safe.\" External benchmarks (SkillTrustBench, OASB) found detection"
        " precision very high (few false alarms) but malicious-sample recall measured"
        " between 0.09 and 0.41 depending on benchmark/artifact type — most misses were"
        " attacks described in prose rather than shipped as code. A clean result means the"
        " scanner didn't recognize a pattern it already knows, not that nothing is wrong."
    )
    # Honest framing for non-OpenClaw / custom setups (B-017): when there is no
    # openclaw.json the config-driven checks come back UNKNOWN. UNKNOWN is neutral
    # (never counted against the score), but without context a hardened custom setup
    # reads as "half-broken". State the non-standard detection explicitly and explain
    # the UNKNOWNs instead of letting them look like failures.
    if not openclaw_detected:
        n_unknown = sum(1 for f in findings if f.status in (UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL"))
        warn_icon = "[!]" if ascii_only else "⚠️"
        lines.append("")
        lines.append(
            f"{warn_icon} No openclaw.json found — this looks like a non-standard or"
            " custom setup. ClawSecCheck is calibrated for OpenClaw, the only"
            " fully-supported target right now, so checks that need the standard"
            " config could not be assessed."
        )
        if n_unknown:
            lines.append(
                f"{n_unknown} check(s) were not assessed (UNKNOWN) and are NOT"
                f" counted against your score — the grade reflects only the"
                f" {n_scored} assessable check(s)."
            )
    lines.append("")
    unsuppressed_all = [f for f in findings if not getattr(f, "suppressed", False)]
    if not unsuppressed_all:
        lines.append(f"No known attack pattern matched. Keep it that way. {ok}")
    else:
        if issues:
            lines.append(f"{len(issues)} issue(s), grouped by area — most urgent first within each:")
        else:
            lines.append(f"No known attack pattern matched. Keep it that way. {ok}")
        lines.append("")
        # Group EVERY finding (not just FAIL/WARN) by its OpenClaw surface family so the
        # Dashboard reads as coverage-by-category rather than a flat severity dump, and so
        # the Lethal Trifecta (A1) shows up as one Privilege & Execution finding among
        # others instead of a standalone headline (F-044). PASS/UNKNOWN are collapsed to a
        # one-line roster per family — still listed (nothing hidden), just not walled in green.
        grouped: dict[str | None, list[Finding]] = {}
        for f in unsuppressed_all:
            grouped.setdefault(_family_of(f), []).append(f)
        for fam_key in (*FAMILY_ORDER, None):
            members = grouped.get(fam_key)
            if not members:
                continue
            members.sort(key=lambda f: (_STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9)))
            label = FAMILY_LABEL.get(fam_key, "Other")
            label_disp = paint(label, "bold", enabled=True) if color else label
            n_bad = sum(1 for f in members if f.status in (FAIL, WARN))
            count_text = f"{n_bad} issue(s)" if n_bad else "clear"
            if ascii_only:
                lines.append(f"[{label_disp}] — {count_text}")
            else:
                _rule = "─" * 30
                lines.append(f"┌{_rule}")
                lines.append(f"│ {label_disp} — {count_text}")
                lines.append(f"└{_rule}")
            n_unknown = 0
            for f in members:
                if f.status in (FAIL, WARN):
                    _render_finding(lines, f, cfg=_blast_cfg,
                                    ascii_only=ascii_only, color=color)
                elif f.status == PASS:
                    _render_finding_compact(lines, icon, f)
                else:
                    # UNKNOWN: tallied, not enumerated one-by-one — a wall of near-identical
                    # "not assessed" lines adds noise, not information; the honest count is
                    # what matters (nothing hidden, just not spelled out per check).
                    n_unknown += 1
            if n_unknown:
                unk_icon = icon.get(UNKNOWN, "?")
                lines.append(f"  {unk_icon} {n_unknown} not assessed (config can't tell) —"
                             " resolve via `--ask` then `--attest`")
            lines.append("")

    # Coverage map — "check OpenClaw the platform" framing: how many config surfaces this
    # run actually assessed, honestly split checked / partial / not-checkable (F-031 data,
    # C-102 terminal render). Read-only derivation over the findings; never alters the score.
    if findings:
        lines.append("")
        lines.extend(_coverage_lines(findings, ascii_only=ascii_only, color=color))
        lines.append("")

    cap_lines = _capability_graph_lines(ctx) if ctx is not None else []
    if cap_lines:
        lines.append("")
        lines.extend(cap_lines)
        lines.append("")
    secret_lines = _credential_surface_lines(ctx) if ctx is not None else []
    if secret_lines:
        lines.append("")
        lines.extend(secret_lines)
        lines.append("")
    log_threat_lines = _log_threat_report_lines(findings)
    if log_threat_lines:
        lines.append("")
        lines.extend(log_threat_lines)
        lines.append("")

    if suppressed_count:
        lines.append(f"({suppressed_count} finding(s) suppressed via .clawseccheckignore)")
        # Surface suppressed findings that either cap the score (a FAILed CRITICAL→49 / HIGH→79)
        # or hit a sensitive check (B1/B2/B13/B20). Hiding these silently could turn an F into an
        # A via one .clawseccheckignore line, so they stay visible no matter what the ignore says.
        # Same rule the badge and SARIF now use (surfaced_despite_suppression) — one source (B-163).
        for f in findings:
            if surfaced_despite_suppression(f):
                lines.append(
                    f"WARNING: a {f.severity} finding ({f.id}) is suppressed via"
                    " .clawseccheckignore — it still counts against your real security;"
                    " review your ignore list."
                )

    if native is not None:
        lines.append("--- Also from OpenClaw's built-in `security audit` ---")
        if getattr(native, "status", "") == "ok":
            nf = sorted(native.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
            if nf:
                lines.append(f"{len(nf)} additional finding(s) the platform's own audit reports:")
                lines.append("")
                for f in nf:
                    _render_finding(lines, f, cfg=_blast_cfg,
                                    ascii_only=ascii_only, color=color)
            else:
                lines.append("Clean — openclaw security audit found nothing.")
        else:
            lines.append(f"(not included: {native.note})")
        lines.append("")

    if risk:
        from .risk import render_risk_paths
        risk_section = render_risk_paths(risk, ascii_only=ascii_only)
        lines.append(risk_section.rstrip())
        lines.append("")

    # Offline staleness advisory (computed by the CLI; never a network call). Untrusted hint
    # text is already sanitized to a clean semver in update.py, but pass through _sanitize too.
    if update_notice:
        bullet = "*" if ascii_only else "⏳"
        lines.append("")
        for i, ln in enumerate(update_notice):
            prefix = f"{bullet} " if i == 0 else "   "
            lines.append(f"{prefix}{_sanitize(ln)}")

    # Coverage freshness advisory — human report only, advisory only. Each element is one
    # complete capability notice; rendered with its own bullet so both can appear together.
    # Never alters score, grade, or findings (purely additive output).
    if freshness_notice:
        bullet = "*" if ascii_only else "⏳"
        lines.append("")
        for ln in freshness_notice:
            lines.append(f"{bullet} {_sanitize(ln)}")

    # C-165: hedged staleness nudge — an overwhelming UNKNOWN share on a detected OpenClaw
    # setup is ambiguous (could be a genuinely minimal install, or ClawSecCheck's checks may
    # be stale against a newer OpenClaw schema) so the wording MUST keep both readings open;
    # never assert drift as fact. Human-report-only, advisory only; makes no network call.
    if (openclaw_detected and cov["scored_total"] >= DRIFT_MIN_SCORED
            and cov["unknown_frac"] >= DRIFT_UNKNOWN_FRAC):
        bullet = "*" if ascii_only else "⏳"
        lines.append("")
        lines.append(
            f"{bullet} Most checks came back not-assessable"
            f" ({cov['unknown']}/{cov['scored_total']}) on a detected OpenClaw setup."
            " Either this is a minimal setup, or ClawSecCheck may be stale against a newer"
            " OpenClaw config schema — worth a second look either way."
            " (offline notice; no network call)"
        )

    # Scan receipt: deterministic Merkle-style hash for audit traceability
    lines.append("")
    lines.append(f"Scan receipt: sha256:{compute_scan_receipt(findings)}")

    out = "\n".join(lines).rstrip() + "\n"
    if ascii_only:
        return _asciify(out)
    return out


def render_dashboard_findings(findings: list[Finding], *, ascii_only: bool = False) -> str:
    """Deterministic, framed Findings block for the chat Dashboard (SKILL.md Step 3, Section 3).

    Emits ONLY what Section 3 must contain, so the host agent PASTES this verbatim instead
    of re-composing it (models drop the open 3-sided frame otherwise):
      - non-suppressed FAIL/WARN findings only (PASS/UNKNOWN live in Sections 4 & 6);
      - MEDIUM/ATTESTED-confidence findings excluded (they surface in Section 4);
      - families with no qualifying finding are omitted (no empty "— clear" headers);
      - each family under the same open 3-sided frame render_report uses.
    """
    findings = deduplicate_findings(findings)
    qualifying = [
        f for f in findings
        if f.status in (FAIL, WARN)
        and not getattr(f, "suppressed", False)
        and getattr(f, "confidence", "HIGH") not in (MEDIUM, ATTESTED)
    ]
    if not qualifying:
        ok = "[OK]" if ascii_only else "✅"
        out = f"No high-confidence issues to fix. {ok}\n"
        return _asciify(out) if ascii_only else out

    grouped: dict = {}
    for f in qualifying:
        grouped.setdefault(_family_of(f), []).append(f)

    lines: list = []
    for fam_key in (*FAMILY_ORDER, None):
        members = grouped.get(fam_key)
        if not members:
            continue
        members.sort(key=lambda f: (_STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9)))
        label = FAMILY_LABEL.get(fam_key, "Other")
        count_text = f"{len(members)} issue(s)"
        if ascii_only:
            lines.append(f"[{label}] — {count_text}")
        else:
            # Chat paste carries the family emoji (SKILL.md Step-3 table, B-077);
            # the CLI report's family headers stay emoji-less by design.
            emoji = _FAMILY_EMOJI.get(fam_key)
            head = f"{emoji} {label}" if emoji else label
            _rule = "─" * 30
            lines.append(f"┌{_rule}")
            lines.append(f"│ {head} — {count_text}")
            lines.append(f"└{_rule}")
        for f in members:
            _render_finding(lines, f, cfg=None, ascii_only=ascii_only)
        lines.append("")

    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def render_dashboard(findings: list[Finding], score: ScoreResult, *,
                     ascii_only: bool = False) -> str:
    """Deterministic chat Dashboard card — Sections 1-2 of SKILL.md Step 3, pasted verbatim.

    Live testing (F-070) showed the host LLM silently drops the 🦞 header and the family
    frame when asked to *compose* them, so the whole card is code-rendered (B-077): grade
    card + score-bar + issue count, then the framed findings block. Reports-only (F-074):
    the card names what is wrong and why — it carries no remediation and no fix offers.
    The host agent pastes this output and only writes its own prose *around* it.
    """
    findings = deduplicate_findings(findings)
    n_issues = sum(
        1 for f in findings
        if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)
    )
    dash, dot = ("-", "-") if ascii_only else ("—", "·")
    mascot = "" if ascii_only else "🦞 "
    issues_word = "issue" if n_issues == 1 else "issues"
    lines = [
        f"{mascot}OpenClaw Security Audit {dash} Grade {score.grade} {dot} {score.score}/100",
        f"{_score_bar(score.score, score.grade, ascii_only=ascii_only)}"
        f"  {dot}  {n_issues} {issues_word}",
    ]
    lines.append("")
    lines.append(f"{dash} Findings {dash}")
    body = render_dashboard_findings(findings, ascii_only=ascii_only).rstrip("\n")
    out = "\n".join(lines) + "\n" + body + "\n"
    return _asciify(out) if ascii_only else out


def render_card(score: ScoreResult, findings: list[Finding], ascii_only: bool = False) -> str:
    """Shareable badge — grade + score + trifecta ONLY. No findings, ever."""
    l1 = f"  OpenClaw Security: {score.grade:<2} ({score.score:>3}/100)"
    l2 = f"  Lethal Trifecta: {_trifecta_ratio(findings)}"
    l3 = "  audited by ClawSecCheck" + ("" if ascii_only else " 🔍")
    width = 39
    # 🦞 mascot header line, once (design-system Foundations); --ascii drops it to
    # stay pure-ASCII, matching render_dashboard's convention.
    header = "" if ascii_only else "🦞 ClawSecCheck\n"
    if ascii_only:
        top = bot = "+" + "-" * width + "+"
        body = "\n".join(f"|{ln:<{width}}|" for ln in (l1, l2, l3))
        return _asciify(f"{top}\n{body}\n{bot}")
    top = "┌" + "─" * width + "┐"
    bot = "└" + "─" * width + "┘"
    # the magnifier emoji is double-width in many terminals; pad l3 one less
    body = "\n".join([
        f"│{l1:<{width}}│",
        f"│{l2:<{width}}│",
        f"│{l3:<{width - 1}}│",
    ])
    return f"{header}{top}\n{body}\n{bot}"


def render_monitor(alerts, score: ScoreResult, ascii_only: bool = False,
                   baseline: bool = False) -> str:
    mark = {"CRITICAL": "[X]", "HIGH": "[!]", "MEDIUM": "[~]", "INFO": "[i]"} if ascii_only \
        else {"CRITICAL": "⛔", "HIGH": "⚠️", "MEDIUM": "🔶", "INFO": "ℹ️"}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    ok = "[OK]" if ascii_only else "✅"
    lines = ["ClawSecCheck - Threat Monitor", "=" * 30,
             f"Current: {score.score}/100  Grade: {score.grade}"]
    if baseline:
        lines += ["", "Baseline saved. Future runs will alert on what changes since now."]
    elif not alerts:
        lines += ["", f"No new threats since last check. {ok}"]
    else:
        lines += ["", f"{len(alerts)} change(s) detected since last check:", ""]
        for level, msg in sorted(alerts, key=lambda a: order.get(a[0], 9)):
            lines.append(f"{mark.get(level, '[*]')} {_sanitize(msg)}")
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def render_events(events, ascii_only: bool = False) -> str:
    """Render the Agent Watch event journal (timeline of what changed when)."""
    mark = {"CRITICAL": "[X]", "HIGH": "[!]", "MEDIUM": "[~]", "INFO": "[i]"} if ascii_only \
        else {"CRITICAL": "⛔", "HIGH": "⚠️", "MEDIUM": "🔶", "INFO": "ℹ️"}
    if not events:
        out = "Agent Watch journal\n" + "=" * 30 + "\n\nNo recorded change events yet.\n"
        return _asciify(out) if ascii_only else out
    lines = ["Agent Watch journal", "=" * 30,
             f"{len(events)} recorded change event(s) (most recent last):", ""]
    for e in events:
        ts = str(e.get("ts", "?"))
        lvl = str(e.get("level", "INFO"))
        msg = _sanitize(str(e.get("message", "")))
        lines.append(f"{mark.get(lvl, '[*]')} {ts}  {msg}")
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


_GRADE_COLOR = {"A": "#4c1", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44"}


def render_svg(score: ScoreResult, findings: list[Finding]) -> str:
    """A shields.io-style SVG badge (grade + score, plus a suppressed-critical marker —
    never finding details)."""
    label = "OpenClaw Security"
    value = f"{score.grade} {score.score}/100"
    # B-163: if a score-capping CRITICAL/HIGH FAIL (or sensitive id) was hidden via
    # .clawseccheckignore, the badge must not read as a clean grade — mark it so a shared
    # badge can't misrepresent the real posture. Count only (never finding details).
    n_hidden = sum(1 for f in findings if surfaced_despite_suppression(f))
    if n_hidden:
        value += f" *{n_hidden} suppressed"
    color = _GRADE_COLOR.get(score.grade, "#9f9f9f")
    lw = 8 + len(label) * 6          # rough text widths
    vw = 8 + len(value) * 7
    w = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
        f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<rect rx="3" width="{w}" height="20" fill="#555"/>'
        f'<rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect rx="3" width="{w}" height="20" fill="url(#s)"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.0f}" y="14">{label}</text>'
        f'<text x="{lw + vw / 2:.0f}" y="14">{value}</text>'
        f'</g></svg>'
    )




# Verdict words for the vetting modes (--vet / --vet-mcp), keyed by worst status.
_VET_VERDICT = {FAIL: "DANGEROUS", WARN: "SUSPICIOUS", PASS: "NO KNOWN ISSUE", UNKNOWN: "UNKNOWN", "SKILL_ARCHIVE_PATH_TRAVERSAL": "UNKNOWN"}
_VET_STATUS_RANK = {FAIL: 3, WARN: 2, UNKNOWN: 1, "SKILL_ARCHIVE_PATH_TRAVERSAL": 1, PASS: 0}


def _finding_to_dict(f: Finding) -> dict:
    """Serialize one Finding to the frozen public JSON shape (shared by every renderer)."""
    _meta = BY_ID.get(f.id)
    return {"id": f.id, "title": _sanitize(f.title), "severity": f.severity,
            "status": f.status, "detail": _sanitize(f.detail),
            "fix": _sanitize(f.fix), "framework": f.framework,
            "confidence": getattr(f, "confidence", "HIGH"),
            "pass_confidence": getattr(f, "pass_confidence", None),
            "scored": bool(getattr(f, "scored", True)),
            "suppressed": bool(getattr(f, "suppressed", False)),
            "owasp": list(owasp_for(f.id)),
            "ast": list(ast_for(f.id)),
            "remediation": remediation_for(f.id),
            "evidence": [_sanitize(e) for e in (f.evidence or [])],
            "surface": _meta.surface if _meta is not None else ""}


# Per-axis status icons for the risk dossier (5 states incl. N/A).
_AXIS_ICON_UNI = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔", "N/A": "➖"}
_AXIS_ICON_ASCII = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]", "N/A": "[-]"}
_TOP_FIX_ORDER = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "PASS": 3, "N/A": 4}


def render_vet_json(profile, *, mode: str, version: str) -> str:
    """Machine-readable risk dossier for the vetting modes (--vet / --vet-* ).

    `mode` is the sub-command ("vet" / "vet-plugin" / "vet-mcp" / "vet-source"); the target
    and everything else come from the ``VetProfile``. The envelope keeps the frozen
    per-finding shape (`_finding_to_dict`) and adds the axis breakdown + overall grade.
    """
    payload = {
        "tool": "clawseccheck",
        "version": version,
        "mode": mode,
        "target": profile.target,
        "target_type": profile.target_type,
        "verdict": _VET_VERDICT.get(profile.overall_status, "UNKNOWN"),
        "grade": profile.overall_grade,
        "score": profile.score,
        "axes": [
            {
                "axis": a.axis,
                "status": a.status,
                "reason": _sanitize(a.reason),
                "fix": _sanitize(a.fix),
                "finding_ids": [f.id for f in a.findings],
            }
            for a in profile.axes
        ],
        "findings": [_finding_to_dict(f) for f in profile.findings],
        "unmapped": list(profile.unmapped),
    }
    return json.dumps(_sanitize_tree(payload), ensure_ascii=True, indent=2)


def _dossier_top_fix(profile) -> str:
    """The remediation of the worst axis that carries one (danger first, then WARN)."""
    for a in sorted(profile.axes, key=lambda x: _TOP_FIX_ORDER.get(x.status, 5)):
        if a.status in (FAIL, WARN) and a.fix:
            return a.fix
    return ""


def render_vet_dossier(profile, ascii_only: bool = False) -> str:
    """Human-readable risk dossier: the overall grade + a line per axis.

    Reframes the vet verdict into how *dangerous* / how *built* / how it *behaves* / what
    it *stores* / whom it *connects with*. N/A axes are shown (dimmed by icon) with their
    reason, so the reader sees exactly what could not be assessed and why.
    """
    icons = _AXIS_ICON_ASCII if ascii_only else _AXIS_ICON_UNI
    verdict = _VET_VERDICT.get(profile.overall_status, "UNKNOWN")
    header_icon = icons.get(profile.overall_status, icons["UNKNOWN"])
    name = _sanitize(Path(profile.target).name or profile.target)
    lines = [
        f"{header_icon}  RISK DOSSIER — {profile.target_type} '{name}'"
        f"    Grade: {profile.overall_grade}  ({verdict})",
        "",
    ]
    for a in profile.axes:
        icon = icons.get(a.status, icons["UNKNOWN"])
        lines.append(f"  {AXIS_LABEL[a.axis]:<13} {icon} {a.status:<5}  {_sanitize(a.reason)}")
    top = _dossier_top_fix(profile)
    if top:
        lines += ["", f"  Fix (top): {_sanitize(top)}"]
    n_find = len(profile.findings)
    n_axes = sum(1 for a in profile.axes if a.status != "N/A")
    sep = "*" if ascii_only else "·"
    lines += ["", f"  {n_find} finding{'' if n_find == 1 else 's'} across {n_axes} axes "
              f"{sep} run --json for full detail"]
    if profile.unmapped:
        lines.append(f"  (unmapped: {', '.join(profile.unmapped)})")
    out = "\n".join(lines)
    # C-179: unlike every other renderer here, this one had no final ASCII safety
    # net — the hardcoded em-dash in the header (line above) leaked through even
    # with --ascii set.
    return _asciify(out) if ascii_only else out


# ---- F-067: --advise — the same VetProfile the risk dossier already computes, reframed
# as an install decision rather than a risk breakdown. DANGEROUS/SUSPICIOUS/SAFE/UNKNOWN
# relabel to INSTALL/CAUTION/DO-NOT-INSTALL; UNKNOWN maps to CAUTION (not INSTALL) — an
# inconclusive assessment is never presented as a green light. "Reasons" reuse each
# finding's own detail text verbatim, which already carries F-055's source->sink trace for
# taint findings — no separate trace plumbing needed. Read-only: this only prints; the
# agent/user decides whether to actually remove the quarantine dir.
_ADVISE_VERDICT = {FAIL: "DO-NOT-INSTALL", WARN: "CAUTION", PASS: "INSTALL", UNKNOWN: "CAUTION"}
_ADVISE_ICON_UNI = {"DO-NOT-INSTALL": "⛔", "CAUTION": "⚠️", "INSTALL": "✅"}
_ADVISE_ICON_ASCII = {"DO-NOT-INSTALL": "[X]", "CAUTION": "[!]", "INSTALL": "[OK]"}
# F-112: a plain-language restatement of the same verdict for readers who don't parse
# DO-NOT-INSTALL/CAUTION/INSTALL as jargon. "{d}" is the em-dash/hyphen, chosen per
# ascii_only so this line honors the same terminal-safety contract as the rest of the file.
_ADVISE_PLAIN_WORDS = {
    "DO-NOT-INSTALL": "I found something dangerous {d} I don't recommend installing this.",
    "CAUTION": "I couldn't fully clear this {d} read the reasons before trusting it.",
    "INSTALL": "Nothing dangerous found {d} this looks safe to install.",
}


def _advise_reasons(profile, limit: int = 5) -> list[str]:
    """Top FAIL/WARN findings' detail text, worst-first, deduplicated by id."""
    worst_first = sorted(
        (f for f in profile.findings if f.status in (FAIL, WARN)),
        key=lambda f: (0 if f.status == FAIL else 1, f.id),
    )
    return [f"{f.id} ({f.status}): {_sanitize(f.detail)}" for f in worst_first[:limit]]


def _looks_like_quarantine(target: str) -> bool:
    """True if *target* sits under the system temp dir (a --vet-plan quarantine copy),
    False otherwise. --advise can be pointed at ANY path, including a real installed
    skill — never suggest an unconditional `rm -rf` outside temp, or a user could paste
    it against their live install."""
    try:
        resolved = Path(target).expanduser().resolve()
        tmp = Path(tempfile.gettempdir()).resolve()
        return resolved == tmp or tmp in resolved.parents
    except OSError:
        return False


def render_advise(profile, ascii_only: bool = False) -> str:
    """Human-readable install recommendation: INSTALL / CAUTION / DO-NOT-INSTALL.

    Built from the exact same VetProfile as render_vet_dossier — a different framing
    of the same signals, not a second analysis pass.
    """
    icons = _ADVISE_ICON_ASCII if ascii_only else _ADVISE_ICON_UNI
    verdict = _ADVISE_VERDICT.get(profile.overall_status, "CAUTION")
    name = _sanitize(Path(profile.target).name or profile.target)
    lines = [f"{icons[verdict]}  {verdict} — {profile.target_type} '{name}'", ""]

    dash = "-" if ascii_only else "—"
    plain = _ADVISE_PLAIN_WORDS.get(verdict, _ADVISE_PLAIN_WORDS["CAUTION"]).format(d=dash)
    lines.append(f"In plain words: {plain}")
    lines.append("How I decided: the verdict is the worst signal found across all checks. "
                  "What drove it:")
    lines.append("")

    reasons = _advise_reasons(profile)
    if reasons:
        lines.append("Reasons:")
        lines.extend(f"  - {r}" for r in reasons)
        lines.append("")
    elif verdict == "CAUTION":
        lines.append("Reasons: assessment is inconclusive (UNKNOWN) — not enough signal "
                      "to say INSTALL; review manually before trusting this source.")
        lines.append("")
    else:
        lines.append("No FAIL/WARN findings across every assessable axis.")
        lines.append("")

    lines.append("Next steps:")
    if verdict != "INSTALL":
        lines.append("  Review the reasons above before proceeding; when you're done:")
    if _looks_like_quarantine(profile.target):
        lines.append(f"  rm -rf {profile.target}    # remove the quarantine copy — do this either way")
    else:
        lines.append(f"  '{profile.target}' is not under the system temp dir — this does not")
        lines.append("  look like a --vet-plan quarantine copy. If it IS one, remove it with:")
        lines.append(f"    rm -rf {profile.target}")
        lines.append("  If this is your real installed skill, do NOT delete it — act on the")
        lines.append("  verdict above instead (e.g. uninstall through your normal flow).")
    lines.append("  (run --json for the full finding list + axis breakdown)")
    return "\n".join(lines)


def render_advise_json(profile, *, version: str) -> str:
    """Machine-readable install recommendation — same envelope as render_vet_json plus
    the advise-specific verdict, reasons, and cleanup command."""
    from .coverage import coverage as _coverage  # noqa: PLC0415

    is_quarantine = _looks_like_quarantine(profile.target)
    payload = json.loads(render_vet_json(profile, mode="advise", version=version))
    payload["advise_verdict"] = _ADVISE_VERDICT.get(profile.overall_status, "CAUTION")
    payload["reasons"] = _advise_reasons(profile)
    payload["is_quarantine_path"] = is_quarantine
    payload["cleanup"] = (
        f"rm -rf {profile.target}" if is_quarantine else
        f"# '{profile.target}' is not under the system temp dir — only run "
        f"'rm -rf {profile.target}' if you're sure this is a --vet-plan quarantine "
        "copy, not your real installed skill"
    )
    payload["coverage"] = _coverage(profile.findings)
    return json.dumps(_sanitize_tree(payload), ensure_ascii=True, indent=2)


# ---- F-065: --vet-plan — the zero-network default path. This tool never fetches
# anything (§2); it only PRINTS the commands a human or host agent would run to fetch a
# source into an isolated quarantine dir, vet it, and clean up — mirroring --fix's
# "prints, never executes" doctrine. Ecosystem detection reuses F-073's own parser
# (_parse_source_target) so the fetch verb matches exactly what --vet-source already
# identified. Only real, standard package-manager verbs are suggested (git/npm/pip);
# for "clawhub" and unresolved bare names there is no single verified CLI flag to name,
# so the plan gives generic guidance rather than fabricating one.
#
# F-112: pure output-readability change — same commands, same ecosystem detection, no
# new verdict/scoring logic. The plain-language preamble (4 numbered steps + a consent
# line) comes first for a reader who doesn't parse shell; the exact commands follow
# underneath, reordered so --vet-source (the pre-download reputation gate) is step 1.
def render_vet_plan(target: str) -> str:
    from .checks import _parse_source_target  # noqa: PLC0415

    info = _parse_source_target(target)
    eco, name, version = info["ecosystem"], info["name"], info.get("version")
    ver_suffix = f"@{version}" if version else ""

    if eco == "npm":
        fetch = f"npm pack {name}{ver_suffix} --pack-destination \"$QUARANTINE\""
    elif eco == "pypi":
        fetch = f"pip download --no-deps -d \"$QUARANTINE\" {name}{'==' + version if version else ''}"
    elif eco == "git":
        # info only keeps host + the repo-name tail, not the full owner/repo path — pull
        # host/path back out of the raw "git:<host>/<path>[@ref]" target instead of
        # reconstructing it from parsed fields (which would drop the owner segment).
        path = target[len("git:"):]
        ref = info.get("ref")
        if ref:
            path = path.rsplit("@", 1)[0]
        branch_flag = f" --branch {ref}" if ref else ""
        fetch = f"git clone --depth 1{branch_flag} https://{path} \"$QUARANTINE/repo\""
    elif eco == "clawhub":
        fetch = (f"# resolve '{name}' via your ClawHub client's normal pull/install path, "
                  "but redirect the output into \"$QUARANTINE\" instead of the live skills dir")
    else:  # "url" or an unresolved bare "registry" name
        fetch = (f"curl -fsSL {target} -o \"$QUARANTINE/download\"" if eco == "url" else
                  f"# '{name}' has no resolvable ecosystem — fetch via your package manager's "
                  "normal lookup, into \"$QUARANTINE\"")
    # the concrete-command ecosystems get a shared "this line varies" annotation; the
    # clawhub/unresolved branches above are already a full "#"-commented explanation, so
    # they are left as-is rather than doubly annotated.
    fetch_note = "   # (git clone / pip download / curl per ecosystem)" if eco in (
        "npm", "pypi", "git", "url") else ""

    return "\n".join([
        f"Before you install \"{name}\", here's what I'll do — nothing lands on your setup",
        "until it passes:",
        "",
        "  1. Check the source's reputation first — no download at all.",
        "  2. Fetch it into a throwaway folder your agent can't auto-load.",
        "  3. Scan that copy and give you a plain verdict: install / be careful / don't install.",
        "  4. Delete the throwaway copy no matter what.",
        "",
        "Say \"yes\" and I'll run all of this for you.",
        "",
        "Commands (for the agent — clawseccheck never touches the network itself):",
        "",
        f"  clawseccheck --vet-source {target}   # 1: reputation, zero network",
        "  QUARANTINE=$(mktemp -d)   # 2: throwaway, outside auto-load",
        f"  {fetch}{fetch_note}",
        "  clawseccheck --advise \"$QUARANTINE\"   # 3: verdict",
        "  rm -rf \"$QUARANTINE\"   # 4: cleanup (always)",
    ])


# ---- B98 / F-083: --emit-manifest — a proposed permission manifest, hand-built YAML-shaped
# text (stdlib only, no PyYAML: this project has zero runtime deps). Never silently renders
# an all-false/empty manifest for an unprofilable skill — that would read as "safe" when the
# truth is "unknown". Every capability field is either a real true/false derived from static
# effect analysis, or an explicit `unknown` — the honesty rule the whole renderer exists for.
_MANIFEST_FAMILY_ALIASES = {
    "eval": "exec",  # skillast folds eval into exec for capability purposes (cf. B62)
}


def _manifest_effect_union(ctx, skill_name: str) -> tuple[set, set, set, int]:
    """Aggregate reachable/unshielded/guarded effect families across all entry points of
    *skill_name* in ctx.effect_profiles. Returns (reachable, unshielded, guarded,
    entry_point_count)."""
    reachable: set = set()
    unshielded: set = set()
    guarded: set = set()
    entry_points = ctx.effect_profiles.get(skill_name, []) if ctx is not None else []
    for ep in entry_points:
        for eff in ep.get("reachable_effects", []):
            reachable.add(_MANIFEST_FAMILY_ALIASES.get(eff, eff))
        for eff in ep.get("unshielded_effects", []):
            unshielded.add(_MANIFEST_FAMILY_ALIASES.get(eff, eff))
        for eff in ep.get("guarded_effects", []):
            guarded.add(_MANIFEST_FAMILY_ALIASES.get(eff, eff))
    return reachable, unshielded, guarded, len(entry_points)


def render_permission_manifest(ctx, target: str) -> str:
    """A proposed permission manifest (YAML-shaped, hand-built text) derived from static
    effect analysis of a single vetted skill — printed by `--vet <skill> --emit-manifest`.

    `target` is the path/name passed to `--vet`; the skill-name key vet_skill() uses in
    ctx.effect_profiles / ctx.installed_skills is that path's basename (`Path(target).name`
    — mirrors vet_skill()'s own `name = p.name` / `p.parent.name` derivation), so that key
    is looked up here rather than the raw path string.

    Never emits a silently-safe manifest: if the skill could not be statically profiled
    (`ctx` is None, or the skill has no entry in `ctx.effect_profiles`), every capability
    field is the explicit string `unknown` (never `false`), plus `unprofilable: true`.

    KNOWN GAP (tracked separately, not fixed here): `shell.exec` reflects only the effect
    simulator's own sink coverage — a bare `eval`/`exec`/`compile` call (or a pickle/
    marshal/dill `load`/`loads`) with a tainted argument. It does NOT track
    `os.system`/`subprocess.*` invocation, which is not one of the simulator's registered
    sink categories. A skill that shells out via `subprocess.run(..., shell=True)` will
    still show `shell.exec: false` here even though B98/B91 may separately flag it. This
    is a genuine blind spot in the manifest's "shell" section, not a `false`-means-safe
    guarantee for that field specifically.
    """
    skill_key = Path(target).expanduser().name or str(target)
    name = _sanitize(skill_key)
    header = [
        f"# proposed-permission-manifest for: {name}",
        "# derived from static analysis (ClawSecCheck effect simulator) "
        "— NOT a guarantee of completeness",
        "# fields marked 'unknown' mean the script was opaque/unparseable, not that the "
        "capability is absent",
        "version: 1",
        f"skill: {name}",
    ]

    effect_profiles = getattr(ctx, "effect_profiles", None) if ctx is not None else None
    # ctx.effect_profiles is keyed by the skill name vet_skill() assigned (the dir/file
    # name), matching _b62_actual_families' own lookup convention.
    entry_points = (effect_profiles or {}).get(skill_key, []) if effect_profiles else []
    unprofilable = ctx is None or not entry_points

    if unprofilable:
        lines = header + [
            "# unable to statically analyze this skill (opaque/unparseable or no Python "
            "source) -- treat every capability below as POSSIBLE, not absent",
            "unprofilable: true",
            "filesystem:",
            "  read: unknown",
            "  write: unknown",
            "  deny: []               # always empty in v1 — we propose grants, not denies "
            "(documented)",
            "network:",
            "  allowlist: []           # host/path extraction not available from static "
            "effect analysis",
            "  reachable: unknown",
            "shell:",
            "  exec: unknown",
            "memory:",
            "  read: unknown           # not profiled by the effect sim -> explicit unknown, "
            "never false",
            "  write: unknown",
            "secrets:",
            "  reads_credentials: unknown",
            "analysis:",
            "  entry_points: 0",
            "  unshielded_effects: []",
            "  guarded_effects: []",
            "  unprofilable: true",
        ]
        return "\n".join(lines)

    reachable, unshielded, guarded, n_entry = _manifest_effect_union(ctx, skill_key)

    def _b(fam: str) -> str:
        return "true" if fam in reachable else "false"

    lines = header + [
        "unprofilable: false",
        "filesystem:",
        f"  read: {_b('read')}",
        f"  write: {_b('write')}",
        "  deny: []               # always empty in v1 — we propose grants, not denies "
        "(documented)",
        "network:",
        "  allowlist: []           # host/path extraction not available from static "
        "effect analysis",
        f"  reachable: {_b('network')}",
        "shell:",
        f"  exec: {_b('exec')}",
        "memory:",
        "  read: unknown           # not profiled by the effect sim -> explicit unknown, "
        "never false",
        "  write: unknown",
        "secrets:",
        f"  reads_credentials: {_b('cred')}",
        "analysis:",
        f"  entry_points: {n_entry}",
        f"  unshielded_effects: [{', '.join(sorted(_sanitize(e) for e in unshielded))}]",
        f"  guarded_effects: [{', '.join(sorted(_sanitize(e) for e in guarded))}]",
        "  unprofilable: false",
    ]
    return "\n".join(lines)


def render_json(findings: list[Finding], score: ScoreResult, *, risk=None,
                ctx=None) -> str:
    actions = suggest_actions(findings, score)
    _json_cfg: dict | None = (getattr(ctx, "config", {}) or {}) if ctx is not None else None

    def _finding_dict_json(f: Finding) -> dict:
        d = _finding_to_dict(f)
        if f.status == FAIL and _json_cfg is not None:
            d["blast_radius"] = compute_blast_radius(_json_cfg, f.id)
        return d

    payload: dict = {
        "score": score.score,
        "grade": score.grade,
        "capped": score.capped,
        "raw_score": score.raw_score,
        "cap_severity": score.cap_severity,
        "assessable": bool(score.assessable),
        "trifecta": _trifecta_ratio(findings),
        "findings": [
            _finding_dict_json(f)
            for f in findings
        ],
        "next_actions": [
            {"id": a.id, "title": _sanitize(a.title), "command": _sanitize(a.command),
             "why": a.why, "priority": a.priority}
            for a in actions
        ],
    }
    if risk is not None:
        payload["risk_paths"] = [
            {
                "id": p.id,
                "severity": p.severity,
                "title": p.title,
                "chain": p.chain,
                "why": p.why,
                "fix": p.fix,
            }
            for p in risk
        ]
    payload["capability_graph"] = _capability_graph(ctx) if ctx is not None else {"nodes": [], "edges": []}
    # F-020: Structured Attestation Requests — always present in --json output.
    # Empty list when no B62 mismatches; one entry per mismatch-flagged skill.
    # Machine-readable only.
    payload["secret_reachability"] = _credential_surface_map(ctx) if ctx is not None else []
    if ctx is not None:
        from .sar import build_sars  # noqa: PLC0415
        payload["intentAttestationRequests"] = build_sars(ctx)
    else:
        payload["intentAttestationRequests"] = []
    # F-031: surface/coverage/projection — Dashboard data (additive, back-compat).
    from .coverage import coverage as _coverage  # noqa: PLC0415
    from .scoring import project as _project  # noqa: PLC0415
    payload["coverage"] = _coverage(findings)
    payload["projection"] = _project(findings)
    # B-166: config read/parse state is machine-visible. A broken openclaw.json must not
    # read as a silent all-clear — config_parse_error is a clean gating boolean and errors
    # carries the human-readable parse message(s) that were previously only in the text run.
    payload["config_found"] = bool(getattr(ctx, "config_found", False)) if ctx is not None else False
    payload["config_parse_error"] = bool(getattr(ctx, "config_parse_error", False)) if ctx is not None else False
    payload["errors"] = [_sanitize(e) for e in getattr(ctx, "errors", [])] if ctx is not None else []
    payload["scan_receipt"] = f"sha256:{compute_scan_receipt(findings)}"
    return json.dumps(_sanitize_tree(payload), ensure_ascii=True, indent=2)


def render_html(findings: list[Finding], score: ScoreResult, native=None) -> str:
    """Standalone self-contained HTML report (inline CSS, no external assets).

    Includes the brand mark + wordmark, a grade badge (colored via
    brand.GRADE_HEX), score, Lethal Trifecta ratio, and FAIL/WARN findings list
    (colored via brand.SEVERITY). Owner view — shows findings with a note that
    this is private and must not be shared publicly.

    All finding text is HTML-escaped.
    """
    issues = [f for f in findings
              if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))

    badge_color = GRADE_HEX.get(score.grade, "#9f9f9f")
    trifecta = _trifecta_ratio(findings)

    label_trifecta = "Lethal Trifecta:"
    label_capped = "Capped:"
    label_why = "Why:"
    # Brand mark + wordmark, split-coloured ("Claw" in BRAND_RED, the rest in the
    # page's --ink token) so the graphical mark and the product name travel
    # together in this HTML-only surface (Tier 3 — see brand.py's module docstring).
    # The logo is aria-hidden: the adjacent wordmark text is the real accessible
    # name, so a screen reader reads "ClawSecCheck Security Audit Report" once,
    # not twice.
    _claw, _rest = WORDMARK[:4], WORDMARK[4:]
    h1_html = (
        f'<span class="logo-mark" aria-hidden="true">{LOGO_SVG}</span>'
        f'<span class="wordmark"><span class="wordmark-claw">{html.escape(_claw)}</span>'
        f'{html.escape(_rest)}</span> Security Audit Report'
    )
    title_text = "ClawSecCheck Security Audit Report"
    private_title = "⚠ Private Report"
    private_body = (
        "This report contains detailed security findings and must"
        " <strong>NOT</strong> be shared publicly."
    )
    section_findings = "Findings"

    esc = html.escape

    # Severity tally across the actionable issues, for the summary strip.
    sev_counts = {sev: sum(1 for f in issues if f.severity == sev)
                  for sev in (CRITICAL, HIGH, MEDIUM, LOW)}

    def _finding_card(f: Finding) -> str:
        sev_style = SEVERITY.get(f.severity)
        color = sev_style.hex if sev_style else "#999"
        icon_char = "✕" if f.status == FAIL else "⚠"
        f_title = esc(_sanitize(f.title))
        f_detail = esc(_sanitize(f.detail)) if f.detail else ""
        why_html = (f'<p class="finding-line"><span class="finding-key">{esc(label_why)}</span> '
                    f'{f_detail}</p>') if f.detail else ""
        return f'''
                <article class="finding" style="--sev:{color};">
                    <div class="finding-head">
                        <span class="finding-icon" aria-hidden="true">{esc(icon_char)}</span>
                        <span class="finding-title">{f_title}</span>
                        <span class="sev-pill">{esc(f.severity)}</span>
                    </div>
                    {why_html}
                </article>'''

    # Build the findings body: grouped by the 7 OpenClaw surface families so a long
    # list (dozens of findings) reads as coverage-by-area, matching the Dashboard.
    if not issues:
        no_issues_text = esc(
            "No known attack pattern matched across the audited surfaces. Keep it that way."
        )
        findings_html = f'<div class="all-clear">✓ {no_issues_text}</div>'
        nav_html = ""
    else:
        grouped: dict = {}
        for f in issues:
            grouped.setdefault(_family_of(f), []).append(f)

        nav_items = []
        sections = []
        for fam_key in (*FAMILY_ORDER, None):
            fam_issues = grouped.get(fam_key)
            if not fam_issues:
                continue
            label = FAMILY_LABEL.get(fam_key, "Other")
            anchor = "fam-" + (fam_key or "other")
            nav_items.append(
                f'<a class="nav-chip" href="#{anchor}">{esc(label)} '
                f'<span class="nav-count">{len(fam_issues)}</span></a>')
            cards = "".join(_finding_card(f) for f in fam_issues)
            sections.append(f'''
            <section class="family" id="{anchor}">
                <h3 class="family-head">{esc(label)}<span class="family-count">{len(fam_issues)}</span></h3>
                {cards}
            </section>''')
        nav_html = f'<nav class="famnav" aria-label="Jump to finding group">{"".join(nav_items)}</nav>'
        findings_html = "".join(sections)

    # Severity summary chips (only the severities that actually occur).
    summary_chips = "".join(
        f'<span class="sev-chip" style="--sev:{SEVERITY[sev].hex};">'
        f'<span class="sev-chip-n">{n}</span>{esc(sev)}</span>'
        for sev, n in sev_counts.items() if n)
    summary_html = f'<div class="summary">{summary_chips}</div>' if summary_chips else ""

    if score.capped:
        sev_str = "CRITICAL" if score.failed_critical else "HIGH"
        capped_html = (f'<p class="capped"><strong>{esc(label_capped)}</strong> '
                       f'from {score.raw_score} (open {sev_str} finding)</p>')
    else:
        capped_html = ""

    pct = max(0, min(100, int(score.score)))

    html_body = f'''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(title_text)}</title>
    <style>
        :root {{
            --bg: #eef1f5;
            --card: #ffffff;
            --ink: #1f2733;
            --muted: #5b6673;
            --line: #e6e9ef;
            --key: #303a47;
            --grade: {badge_color};
            --warn-bg: #fff8e1;
            --warn-line: #f0c040;
            --warn-ink: #7a5c00;
            --shadow: 0 6px 24px rgba(18,28,45,0.10);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: #0f141b;
                --card: #182029;
                --ink: #e7ecf2;
                --muted: #9aa7b4;
                --line: #263140;
                --key: #cdd6e0;
                --warn-bg: #2a2413;
                --warn-line: #6b5713;
                --warn-ink: #e8cf7a;
                --shadow: 0 6px 24px rgba(0,0,0,0.45);
            }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--ink);
            background: var(--bg);
            padding: 2rem 1rem;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            max-width: 880px;
            margin: 0 auto;
            background: var(--card);
            border-radius: 16px;
            box-shadow: var(--shadow);
            padding: 2.25rem;
        }}
        .header {{ text-align: center; padding-bottom: 1.5rem; border-bottom: 1px solid var(--line); }}
        .header h1 {{ font-size: 1.55rem; font-weight: 700; letter-spacing: -0.01em;
            display: flex; align-items: center; justify-content: center; gap: 0.45rem; }}
        .logo-mark {{ display: inline-flex; flex: none; }}
        .logo-mark svg {{ width: 1.6rem; height: 1.6rem; }}
        .wordmark-claw {{ color: {BRAND_RED}; }}
        .grade-badge {{
            display: inline-flex; align-items: center; justify-content: center;
            width: 84px; height: 84px; margin: 1.25rem auto 0.75rem;
            background: var(--grade); color: #fff;
            border-radius: 20px; font-size: 2.6rem; font-weight: 800;
            box-shadow: 0 4px 14px color-mix(in srgb, var(--grade) 45%, transparent);
        }}
        .scorewrap {{ max-width: 360px; margin: 0.5rem auto 0; }}
        .scoreline {{ display: flex; justify-content: space-between; font-size: 0.95rem; color: var(--muted); margin-bottom: 0.35rem; }}
        .scoreline strong {{ color: var(--ink); }}
        .scorebar {{ height: 10px; border-radius: 999px; background: var(--line); overflow: hidden; }}
        .scorebar > i {{ display: block; height: 100%; width: {pct}%; background: var(--grade); border-radius: 999px; }}
        .meta {{ margin-top: 0.85rem; font-size: 0.95rem; color: var(--muted); }}
        .meta strong {{ color: var(--ink); }}
        .capped {{ margin-top: 0.35rem; color: #d9534f; font-size: 0.9rem; }}
        .summary {{ display: flex; flex-wrap: wrap; gap: 0.5rem; justify-content: center; margin-top: 1.1rem; }}
        .sev-chip {{
            display: inline-flex; align-items: center; gap: 0.4rem;
            padding: 0.28rem 0.7rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600;
            color: var(--sev); border: 1px solid color-mix(in srgb, var(--sev) 40%, transparent);
            background: color-mix(in srgb, var(--sev) 12%, transparent);
        }}
        .sev-chip-n {{
            display: inline-flex; align-items: center; justify-content: center; min-width: 1.25rem;
            padding: 0 0.25rem; height: 1.25rem; border-radius: 999px;
            background: var(--sev); color: #fff; font-size: 0.72rem; font-weight: 700;
        }}
        .warning-box {{
            display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.35rem;
            background: var(--warn-bg); border: 1px solid var(--warn-line);
            border-radius: 12px; padding: 0.85rem 1rem; margin: 1.75rem 0;
            color: var(--warn-ink); font-size: 0.92rem;
        }}
        .warning-box .warn-title {{ font-weight: 700; margin-right: 0.25rem; }}
        .warning-box code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; padding: 0.05rem 0.3rem; border-radius: 5px; background: color-mix(in srgb, var(--warn-line) 25%, transparent); }}
        .famnav {{ display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.5rem 0 1.75rem; }}
        .nav-chip {{
            display: inline-flex; align-items: center; gap: 0.4rem; text-decoration: none;
            padding: 0.3rem 0.7rem; border-radius: 999px; font-size: 0.82rem; font-weight: 600;
            color: var(--ink); background: var(--bg); border: 1px solid var(--line);
        }}
        .nav-chip:hover {{ border-color: var(--muted); }}
        .nav-count {{ color: var(--muted); font-weight: 700; }}
        .section-title {{ font-size: 1.15rem; font-weight: 700; margin: 0 0 0.25rem; }}
        .family {{ margin-top: 1.75rem; scroll-margin-top: 1rem; }}
        .family-head {{
            display: flex; align-items: center; gap: 0.6rem;
            font-size: 1.02rem; font-weight: 700; color: var(--ink);
            padding-bottom: 0.5rem; border-bottom: 1px solid var(--line); margin-bottom: 1rem;
        }}
        .family-count {{
            font-size: 0.75rem; font-weight: 700; color: var(--muted);
            background: var(--bg); border: 1px solid var(--line);
            border-radius: 999px; padding: 0.05rem 0.5rem;
        }}
        .finding {{
            border: 1px solid var(--line); border-left: 4px solid var(--sev);
            border-radius: 10px; padding: 0.9rem 1.05rem; margin-bottom: 0.85rem;
            background: color-mix(in srgb, var(--sev) 4%, var(--card));
        }}
        .finding-head {{ display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }}
        .finding-icon {{ color: var(--sev); font-weight: 700; }}
        .finding-title {{ font-weight: 700; color: var(--ink); flex: 1 1 auto; }}
        .sev-pill {{
            background: var(--sev); color: #fff; padding: 0.12rem 0.55rem;
            border-radius: 999px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.02em;
        }}
        .finding-line {{ margin-top: 0.5rem; color: var(--muted); font-size: 0.94rem; }}
        .finding-key {{ color: var(--key); font-weight: 700; }}
        .all-clear {{
            padding: 1.1rem 1.25rem; border-radius: 12px; font-weight: 600;
            color: #1a7f37; background: color-mix(in srgb, #1a7f37 12%, transparent);
            border: 1px solid color-mix(in srgb, #1a7f37 35%, transparent);
        }}
        .footer {{ margin-top: 2rem; padding-top: 1.25rem; border-top: 1px solid var(--line);
            text-align: center; color: var(--muted); font-size: 0.8rem; }}
        @media (max-width: 560px) {{ .container {{ padding: 1.4rem; }} .header h1 {{ font-size: 1.3rem; }} }}
    </style>
</head>
<body>
    <main class="container">
        <header class="header">
            <h1>{h1_html}</h1>
            <div class="grade-badge" aria-label="Grade {esc(score.grade)}">{esc(score.grade)}</div>
            <div class="scorewrap">
                <div class="scoreline"><span>Security score</span><strong>{score.score}/100</strong></div>
                <div class="scorebar" role="img" aria-label="Score {score.score} of 100"><i></i></div>
            </div>
            <p class="meta"><strong>{esc(label_trifecta)}</strong> {esc(trifecta)}</p>
            {capped_html}
            {summary_html}
        </header>

        <div class="warning-box">
            <span class="warn-title">{esc(private_title)}</span>
            <span>{private_body} Use the shareable badge instead (available via <code>--badge</code>).</span>
        </div>

        <h2 class="section-title">{esc(section_findings)}</h2>
        {nav_html}
        {findings_html}

        <footer class="footer">Generated locally by ClawSecCheck · read-only · this report never leaves your machine</footer>
    </main>
</body>
</html>'''

    return html_body
