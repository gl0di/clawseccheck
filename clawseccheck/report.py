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
import time
from pathlib import Path

from . import brand
from .catalog import (
    BY_ID,
    SUBJECT_LABEL, SUBJECT_OF, SUBJECT_ORDER,
    ATTESTED, CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding, ast_for, owasp_for, remediation_for,
)
from .ansi import paint
from .brand import BRAND_RED, FAVICON_DATA_URI, LOGO_SVG, SEVERITY, WORDMARK, grade_ansi, grade_hex
from .dedup import deduplicate_findings
from .dossier import AXIS_LABEL
from .guide import suggest_actions
from .scoring import ScoreResult, assessment_coverage
from .textnorm import ASCII_MAP, asciify

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


# B-381: an absolute path under a user's home directory carries the operator's OS
# username (e.g. "/home/dave/.npm-global/..."). Fine inside the full report / --save
# file (stays on the owner's own machine), but --dashboard --full's card is explicitly
# designed to be pasted into chat (Telegram et al.) -- CLAUDE.md §8 "No PII... in logs,
# reports, fixtures, or test output" applies to that card specifically. Reproduced: a
# MEDIUM-confidence "Native binary PATH safety" finding's `detail` embeds the operator's
# npm-global install path under /home/<user>/... . Scoped to a leading "~" so the
# remainder of the path (still useful context, e.g. ".npm-global/lib/node_modules") is
# preserved -- only the username-bearing prefix is removed, matching the well-known
# shell convention for "my home dir" rather than inventing a new placeholder syntax.
_HOME_PATH_RE = re.compile(
    r"/home/[^/\s]+|/Users/[^/\s]+|[A-Za-z]:\\+Users\\+[^\\\s]+"
)


def _redact_home_paths(text: str) -> str:
    """Collapse a leading user-home path segment to '~' (B-381).

    Applied only to the --dashboard --full "Worth a glance" card section (the
    MEDIUM/ATTESTED-confidence findings render_dashboard_findings's own HIGH-confidence
    filter deliberately excludes) -- the rest of the report/--save/--html output keeps
    full paths, which is correct there: those stay on the owner's own machine and a
    real path is exactly what an owner debugging their own config needs to see.
    """
    if not text:
        return text
    return _HOME_PATH_RE.sub("~", text)


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

def _runtime_cap_phrase(reason: str | None) -> str:
    """Plain-English rendering of scoring's stable ``runtime_cap_reason`` label.

    ``_runtime_cap_signal`` (scoring.py) returns a stable, testable label — the
    trajaudit-indicator match is the only remaining cap source (a same-line
    exfil_evidence cap was tried and RETRACTED, C-135 8th round, Dave's 2026-07-22
    ruling — see logscan.py's retraction note) — and its docstring is explicit that
    the label is never rendered as-is: report.py owns the owner-facing sentence.
    Dumping the raw label would leak an internal check id into owner prose, which
    `test_brand_consistency` forbids. An unrecognized label degrades to a neutral
    phrase, never a raw id.
    """
    r = reason or ""
    if "trajaudit" in r or "indicator" in r:
        return "a trajectory-indicator match"
    return "a corroborated runtime signal"


def _live_injection_cap_phrase(reason: str | None) -> str:
    """Plain-English rendering of scoring's stable ``live_injection_cap_reason`` label.

    `reason` is a bounded, allow-listed ``"tool:id[; tool:id ...]"`` string (see
    `pipeline.live_test_cap_signal`) — already safe to embed directly (no free text ever
    reaches it), but this still routes through the same "report.py owns the sentence,
    the scoring layer only names a stable label" discipline as `_runtime_cap_phrase`.
    """
    if not reason:
        return "a live injection-test scenario reported VULNERABLE"
    return f"a live injection-test scenario reported VULNERABLE ({reason})"


def _behavioral_cap_phrase(reason: str | None) -> str:
    """Plain-English rendering of scoring's stable ``behavioral_cap_reason`` label.

    `reason` is one of `scoring._BEHAVIORAL_LABELS`'s values (e.g. "T1 behavioral
    trifecta"), joined with "; " when more than one detector fired — already safe to
    embed directly (bounded, never free text), but this still routes through the same
    "report.py owns the sentence, the scoring layer only names a stable label"
    discipline as `_runtime_cap_phrase`/`_live_injection_cap_phrase`.
    """
    if not reason:
        return "a behavioral detector fired"
    return f"a behavioral detector fired ({reason})"


# ── Cap-reason cascade (B-380) ──────────────────────────────────────────
#
# Six independent cap-only signals can each tighten a score below its raw value —
# severity FAILs, a blind/unreadable config, a degraded (crashed/timed-out) check, a
# corroborated runtime signal, a submitted VULNERABLE live-injection-test verdict, and
# a fired behavioral detector. `compute()` (scoring.py) documents every one of the
# `*_capped` fields as True ONLY when that specific signal actually bound (tightened
# the score further than whatever had already applied) — `cap_severity` has the
# identical property by construction (only set when its own cap loop actually reduced
# the score) — so more than one of these six can be True on the SAME ScoreResult.
#
# `render_report` and `render_html` used to each hand-roll their own five-branch
# "elif" ladder plus a private "_extra = []; if X: _extra.append(...)" block per
# branch — ten near-identical copies of the same six-signal enumeration, hand-edited
# separately every time a new signal type was added. That duplication is what let two
# real defects ship green: `render_html`'s runtime branch tested `score.capped or
# _rt_capped` (true for ANY cap, not just a runtime one, so a behavioral-only cap fell
# through to it and fabricated a runtime-signal claim), and neither renderer's
# severity-cap branch named a co-occurring runtime cap even when the runtime cap was
# the one that actually set the final number.
#
# `_CAP_SIGNAL_TABLE` is the ONE ordered (flag, phrase) table both renderers read, and
# `_cap_cascade()` is the ONE place that decides which signal leads (the primary
# reason) and which other active signals are named as "also" mentions. A new signal
# type is added to the table exactly once and both renderers pick it up automatically
# — the defect class above becomes structurally impossible to reintroduce.
_CAP_LIVE = "live"
_CAP_CONFIG_BLIND = "config_blind"
_CAP_DEGRADED = "degraded"
_CAP_SEVERITY = "severity"
_CAP_RUNTIME = "runtime"
_CAP_BEHAVIORAL = "behavioral"

# Display-priority order (highest first): also the order in which `_cap_cascade` picks
# the PRIMARY reason, and the order "also" mentions are listed in. This mirrors the
# existing, deliberate priority render_report already used (live > config-blind >
# degraded > severity > runtime > behavioral) — a direct, positive proof of a
# successful attack outranks "cannot rule out a CRITICAL condition", which outranks an
# actual open FAIL, which outranks a corroborated-but-indirect runtime signal, which
# outranks the weakest/most-heuristic behavioral layer.
#
# Each entry's `phrase(score)` returns the unescaped English "also ..." wording for
# that signal — never called unless the signal is active (`_cap_signal_active` below).
# Deliberately free of "(capped from N - ...)" framing and of HTML escaping: both
# renderers reuse the identical English, and `render_html` applies `esc()` itself so
# nothing here duplicates that decision.
_CAP_SIGNAL_TABLE = (
    (_CAP_LIVE, lambda score: _live_injection_cap_phrase(
        getattr(score, "live_injection_cap_reason", None))),
    (_CAP_CONFIG_BLIND, lambda score: "a blind/unreadable config"),
    (_CAP_DEGRADED, lambda score: f"{getattr(score, 'degraded_count', 0)} degraded check(s)"),
    (_CAP_SEVERITY, lambda score: f"an open {score.cap_severity} finding"),
    (_CAP_RUNTIME, lambda score: (
        f"a corroborated runtime signal ({_runtime_cap_phrase(score.runtime_cap_reason)})")),
    (_CAP_BEHAVIORAL, lambda score: _behavioral_cap_phrase(
        getattr(score, "behavioral_cap_reason", None))),
)


def _cap_signal_active(score: ScoreResult) -> dict:
    """Which of the six cap-only signals actually bound the score on *score*.

    `getattr(score, name, default)` throughout — never direct attribute access —
    because some tests build minimal duck-typed ScoreResult stand-ins that predate the
    newer fields; this is the same tolerance every call site already established
    individually (see the B-306/F-154/F-155 comments this replaces).
    """
    return {
        _CAP_LIVE: bool(getattr(score, "live_injection_capped", False)),
        _CAP_CONFIG_BLIND: bool(getattr(score, "config_blind_capped", False)),
        _CAP_DEGRADED: bool(getattr(score, "degraded_capped", False)),
        _CAP_SEVERITY: bool(getattr(score, "cap_severity", None)),
        _CAP_RUNTIME: bool(getattr(score, "runtime_capped", False)),
        _CAP_BEHAVIORAL: bool(getattr(score, "behavioral_capped", False)),
    }


def _cap_cascade(score: ScoreResult) -> tuple[str | None, list[str]]:
    """Decide the primary cap-reason signal and the co-occurring "also" phrases.

    Returns ``(primary, extra_phrases)``: *primary* is one of the six ``_CAP_*``
    names — the highest-priority ACTIVE signal, per `_CAP_SIGNAL_TABLE`'s order — or
    ``None`` when nothing capped the score at all. *extra_phrases* is every OTHER
    active signal's "also ..." wording, already in priority order and ready to
    ``", ".join(...)``.

    This is the ONE place that makes the primary/co-occurring decision — both
    `render_report` and `render_html` call it instead of maintaining their own copy of
    the same six-signal priority ladder (B-380).
    """
    active = _cap_signal_active(score)
    order = [name for name, _phrase in _CAP_SIGNAL_TABLE]
    primary = next((name for name in order if active[name]), None)
    if primary is None:
        return None, []
    extras = [
        phrase(score)
        for name, phrase in _CAP_SIGNAL_TABLE
        if name != primary and active[name]
    ]
    return primary, extras


def _cap_also_clause(extras: list[str]) -> str:
    """``"; also X, Y"`` (or ``""``) — the join both renderers used to hand-roll."""
    return f"; also {', '.join(extras)}" if extras else ""


def _cap_primary_reason_text(primary: str, score: ScoreResult, *,
                             audited_path=None) -> str:
    """The middle clause of "(capped from N - <this>...)" for whichever signal
    `_cap_cascade` chose as primary.

    Unescaped English — `render_html` applies `esc()` around the result;
    `render_report` uses it as-is. `audited_path` is only ever meaningful for the
    config-blind "absent" case (`render_report` passes the resolved would-be config
    path when it has one; `render_html`'s signature has no ctx/path available, so it
    always passes ``None`` and the HTML text stays path-free — matching the pre-
    existing per-renderer wording exactly).
    """
    if primary == _CAP_LIVE:
        return _live_injection_cap_phrase(getattr(score, "live_injection_cap_reason", None))
    if primary == _CAP_CONFIG_BLIND:
        # B-363: word the two config-blind states distinctly — "absent" (nothing to
        # read at all) is strictly less information than "unreadable" (present but
        # broken), so it must never read as if a file was found and opened.
        if getattr(score, "config_blind_reason", None) == "absent":
            if audited_path is not None:
                text = f"no OpenClaw config found at {audited_path}"
            else:
                text = "no OpenClaw config found"
        else:
            text = "openclaw.json unreadable/unparseable this run"
        return f"{text}: cannot rule out a CRITICAL condition"
    if primary == _CAP_DEGRADED:
        # B-399: this cap now also fires on an engine-side-degraded UNKNOWN (a check
        # that ran but couldn't reach a verdict because its own input was unreadable/
        # corrupt) alongside a crashed/timed-out check -- "could not reach a reliable
        # verdict" covers both without claiming a crash/timeout that didn't happen.
        n = getattr(score, "degraded_count", 0)
        return f"{n} check(s) could not reach a reliable verdict this run: cannot rule out a CRITICAL condition"
    if primary == _CAP_SEVERITY:
        return f"open {score.cap_severity} finding"
    if primary == _CAP_RUNTIME:
        return f"corroborated runtime signal: {_runtime_cap_phrase(score.runtime_cap_reason)}"
    if primary == _CAP_BEHAVIORAL:
        return _behavioral_cap_phrase(getattr(score, "behavioral_cap_reason", None))
    raise ValueError(f"unknown cap-cascade primary: {primary!r}")  # pragma: no cover


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

# Subject → emoji for the chat Dashboard paste ONLY (SKILL.md Step-3 table). The CLI
# report / HTML / PDF subject headers deliberately stay emoji-less (design-system.md
# Layer-2 decision); only the chat card carries the emoji.
_SUBJECT_EMOJI = {
    "openclaw": "⚙️", "host": "🖥️", "agents": "🤖", "skills": "🧩",
    "mcp": "🔌", "plugins": "📦", "channels": "📡", "logs": "📝",
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
# Grade → colour for the header grade letter + score-bar fill now comes from
# brand.GRADE_ANSI, called directly at each site — this module used to define its own
# ANSI-name dict here, but a SECOND, later `_GRADE_COLOR = {...}` (hex, for the HTML
# badge — still present further down) silently shadowed it at the module level, so
# the grade lookup always resolved the hex dict and the terminal grade letter/score-
# bar fill rendered bold with no actual colour. Two distinctly-named dicts
# (brand.GRADE_ANSI vs. brand.GRADE_HEX) makes that class of bug structurally
# impossible instead of relying on file-order discipline.
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
        fill_s = paint(fill_s, grade_ansi(grade), enabled=True)
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

# B-484: the table and the function now live in the `textnorm` leaf, because five other
# modules folded output to ASCII too and only one of them mapped anything. Re-exported
# under the private names this module has always used so every existing importer (tests
# included) is unaffected.
_ASCII_MAP = ASCII_MAP
_asciify = asciify


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
        _external_input_channels,
        _hint,
        _mcp_has_remote,
        _mcp_servers,
        _web_fetch_enabled,
    )
    from .collector import dig  # noqa: PLC0415

    cfg = getattr(ctx, "config", {}) or {}
    att = getattr(ctx, "attestation", {}) or {}
    nodes: list[dict] = []
    edges: list[tuple[str, str]] = []

    # B-297/B-371: _external_input_channels (not the narrower _untrusted_input_channels)
    # is what A1/B41/B46/RiskPaths already treat as "untrusted input" for every
    # non-hard-FAIL consumer -- it additionally sees a channel open via an unrestricted
    # groups["*"] entry with no dmPolicy/groupPolicy at all (_open_wildcard_group_channels),
    # the commonest real open-group config (coding_telegram_insecure). Using the narrower
    # helper here left this presentation-only graph showing an inert, edgeless "input" node
    # on a config A1 correctly FAILs as 3/3 trifecta -- a real finding vs. capability_graph
    # invariant mismatch (ClawRange hunt.py, 2026-07-31).
    input_surfaces = sorted({
        *_external_input_channels(cfg),
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


def _credential_surface_rel(path: Path, home_path: Path | None) -> str:
    """Render `path` as evidence text for the credential-surface map without ever
    disclosing an absolute filesystem path (username, mount points, directory
    layout). ClawHub security-audit finding (2026-07-27, v3.58.0, Intent-Code
    Divergence): the previous inline closure fell back to `str(path)` — the
    absolute path — whenever `relative_to()` failed. No call site in
    `_credential_surface_map` actually triggered that fallback (every candidate is
    built as `home_path / suffix`), but that was an invariant of the callers, not
    one this helper enforced — a future credential-surface source could pass an
    out-of-home path and leak silently. Falling back to `path.name` still tells
    the reader WHAT was found, never WHERE on disk."""
    if home_path is not None:
        try:
            return str(path.relative_to(home_path))
        except ValueError:
            pass
    return path.name


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
        return _credential_surface_rel(path, home_path)

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


def _subject_of(f) -> str | None:
    """Map a finding to one of the 8 Inventory-by-subject buckets (F-131 §4.2) via its
    catalog surface. A1 (Lethal Trifecta) needs no special case: its surface is
    "trifecta", already present in SUBJECT_OF (routed to "agents" — an agent-behavior
    signal). Findings with an id outside CATALOG (native-audit passthrough, test doubles)
    return None -> the trailing "Other" bucket in _group_issues_by_subject, so nothing is
    ever silently dropped (C-372 promoted subjects to the single report/HTML/PDF/dashboard
    grouping, retiring the old 7-family view)."""
    meta = BY_ID.get(f.id)
    if meta is None:
        return None
    return SUBJECT_OF.get(meta.surface)


def _group_issues_by_subject(issues):
    """Group findings by their Inventory subject (catalog.SUBJECT_ORDER), lossless: every
    finding lands in exactly one bucket, and any finding whose `_subject_of` is None (an id
    outside CATALOG) falls into a trailing "Other" bucket so nothing is ever silently
    dropped (B-444 class). Returns an ordered list of `(subject_key, label, [findings])`
    for each subject that has >=1 member; empty subjects are skipped so the detail view
    stays focused (the per-subject summary above still names all of them). This is the
    single grouping the terminal, HTML, PDF and chat-dashboard renderers all consume, so
    they cannot drift (F-131 subject taxonomy, promoted from summary-only to every detail
    view — C-372, retiring the old 7-family grouping)."""
    grouped: dict = {}
    for f in issues:
        grouped.setdefault(_subject_of(f), []).append(f)
    out = []
    for subj_key in SUBJECT_ORDER:
        members = grouped.get(subj_key)
        if members:
            out.append((subj_key, SUBJECT_LABEL.get(subj_key, subj_key), members))
    other = grouped.get(None)
    if other:
        out.append((None, "Other", other))
    return out


def _subject_count_text(n_issues: int, n_unassessed: int) -> str:
    """The one phrase every subject rollup uses for "how did this subject do".

    Golden Rule #4: a subject whose checks could not reach a verdict is NOT clear. Saying
    "clear" next to an UNKNOWN marker reads as an assessed all-good — the exact fake-PASS
    this project refuses to emit — and B-472 found the terminal inventory block and the
    by-subject detail header doing precisely that while the card summary (the first caller
    of this rule) already got it right: `Logs & trajectories — [?] clear` printed directly
    above `3 not assessed (config can't tell)` for the same three findings.

    Shared rather than repeated so the three surfaces cannot drift again. `n_unassessed`
    counts genuine UNKNOWNs only — a `not_applicable` finding IS an assessment (the
    surface was positively confirmed absent), so it must not turn a clean subject into an
    unassessed one."""
    if n_issues:
        return f"{n_issues} issue(s)"
    if n_unassessed:
        return "not assessed"
    return "clear"


def _subject_summary_rows(findings, ctx, *, plugin_sweep=None):
    """Uniform per-subject summary rows — one `(label, status, count_text)` tuple per
    catalog.SUBJECT_ORDER entry — for the HTML and PDF report headers. Derived entirely
    from `build_inventory()`, so this summary can never disagree with the JSON `inventory`
    payload or the terminal "Inventory by subject" block (`render_subject_inventory`).
    Returns [] when `ctx` is unavailable (same skip-don't-guess stance those surfaces
    already take)."""
    if ctx is None:
        return []
    inv = build_inventory(findings, ctx, plugin_sweep=plugin_sweep)

    def _issues_count(subj):
        bucket = inv[subj]
        return _subject_count_text(len(bucket.get("findings") or []),
                                   int(bucket.get("unassessed") or 0))

    rows = [
        (SUBJECT_LABEL["openclaw"], inv["openclaw"]["status"], _issues_count("openclaw")),
        (SUBJECT_LABEL["host"], inv["host"]["status"], _issues_count("host")),
    ]
    ag = inv["agents"]
    n_ag = len(ag.get("roster") or [])
    rows.append((SUBJECT_LABEL["agents"], ag["status"],
                 f"{_issues_count('agents')} · {n_ag} agent{'' if n_ag == 1 else 's'}"))

    skills = inv["skills"]
    sk_flagged = [s for s in skills if s.get("status") in (FAIL, WARN, UNKNOWN)]
    sk_status = _worst_of_statuses(s.get("status") for s in sk_flagged) if sk_flagged else PASS
    sk_count = f"{len(sk_flagged)} flagged · {len(skills)} installed" if skills else "none installed"
    rows.append((SUBJECT_LABEL["skills"], sk_status, sk_count))

    mcp = inv["mcp"]
    mcp_bad = [m for m in mcp if m.get("verdict") != "ok"]
    mcp_status = _worst_of_statuses(m.get("verdict") for m in mcp_bad) if mcp_bad else PASS
    mcp_count = f"{len(mcp_bad)} flagged · {len(mcp)} configured" if mcp else "none configured"
    rows.append((SUBJECT_LABEL["mcp"], mcp_status, mcp_count))

    plug = inv["plugins"]
    if not plug.get("scanned"):
        # Distinguish "no sweep ran" from "a sweep ran and found no plugin index" —
        # telling a user who just ran --full to "run --full" is a lie about what happened.
        note = "not scanned — run --full" if plugin_sweep is None else "no plugin index found"
        rows.append((SUBJECT_LABEL["plugins"], UNKNOWN, note))
    else:
        prows = plug.get("rows") or []
        # Fold TRUNCATED/SKIPPED into UNKNOWN for the rollup, as _plugins_inventory_lines
        # does — _worst_of_statuses only recognizes FAIL/WARN/UNKNOWN/PASS (_STATUS_ORDER).
        pstat = [r["status"] if r["status"] in _STATUS_ORDER else UNKNOWN for r in prows]
        p_flagged = sum(1 for s in pstat if s in (FAIL, WARN, UNKNOWN))
        p_status = _worst_of_statuses(pstat) if prows else PASS
        p_count = f"{p_flagged} flagged · {len(prows)} installed" if prows else "none installed"
        rows.append((SUBJECT_LABEL["plugins"], p_status, p_count))

    ch = inv["channels"]
    n_ch = len(ch.get("roster") or [])
    ch_count = _issues_count("channels") + (f" · {n_ch} channel{'' if n_ch == 1 else 's'}" if n_ch else "")
    rows.append((SUBJECT_LABEL["channels"], ch["status"], ch_count))

    rows.append((SUBJECT_LABEL["logs"], inv["logs"]["status"], _issues_count("logs")))
    return rows


def _render_finding_compact(lines, icon, f):
    """One-line roster entry for PASS/UNKNOWN — full detail would bury the FAILs/WARNs."""
    lines.append(f"  {icon[f.status]} [{f.severity}] {_sanitize(f.title)}")


# B-381: --dashboard --full --compact's per-finding "why" text, word-boundary
# truncated so a bad config's Section-2 Findings block (which scales with FAIL/WARN
# count, unlike every other section render_dashboard's docstring already calls
# "already short") can fit the Telegram ~4096-char budget. Tuned against the two
# fixtures --compact is measured against (fixtures/home_safe, fixtures/home_vuln):
# before this fix, --dashboard --full --compact measured 4775/7936 chars respectively
# (already over budget on the CLEAN config too, let alone the 25-issue bad one); after
# this fix (this limit + dropped evidence bullets + a narrower family-frame border
# rule + a lower "Worth a glance" limit under compact), 1976/3788 chars -- both under
# 4096 with headroom. Re-measure and retune if a future change grows a section this
# doesn't already trim.
_COMPACT_WHY_LIMIT = 36

# B-405: the per-item trims above (this file, tuned against two fixtures) are NOT a
# hard guarantee -- a real fleet config with more FAIL/WARN findings than either
# fixture measured this against (many findings * a few chars each still adds up) blew
# straight through the budget (5641 chars measured against a real ~/.openclaw before
# this fix). render_dashboard now enforces the budget itself at render time, as a
# deterministic last line of defence rather than trusting per-item tuning to always be
# enough: the documented Telegram cap.
_COMPACT_CHAR_BUDGET = 4096

# B-405: render_dashboard's reduction ladder once _COMPACT_CHAR_BUDGET is still
# exceeded after the existing per-item trims. Each level is CUMULATIVE and widens
# `why_drop_severities` (dropping the whole why line, not just narrowing it) for one
# more severity, weakest first -- LOW detail is the first thing a reader loses,
# CRITICAL detail is the last. Findings' titles/severity/family structure are never
# dropped by this ladder; only the "why" explanatory line is.
_COMPACT_WHY_DROP_LEVELS = (
    frozenset({LOW}),
    frozenset({LOW, MEDIUM}),
    frozenset({LOW, MEDIUM, HIGH}),
    frozenset({LOW, MEDIUM, HIGH, CRITICAL}),
)


def _hard_truncate_compact(out: str, budget: int = _COMPACT_CHAR_BUDGET) -> str:
    """Absolute last-resort guarantee (B-405): reached only if a config has so many
    findings that even dropping every why line (all four severities) still leaves the
    bare title/family-frame lines over budget. Cuts deterministically at the last
    newline at-or-before the budget (reserving room for the trailing marker) so the
    render NEVER exceeds its own documented cap, even in this pathological case.

    This runs AFTER _finalize_compact_dashboard's own _asciify step (it is the final
    fallback in that function, not wrapped by it -- see _finalize_compact_dashboard),
    so the marker itself must always be pure ASCII: a raw "…" here would silently
    break the documented ascii_only contract in exactly this extreme-fallback case.
    """
    if len(out) <= budget:
        return out
    marker = "\n...(truncated to fit budget)\n"
    room = max(budget - len(marker), 0)
    cut = out[:room]
    nl = cut.rfind("\n")
    if nl > 0:
        cut = cut[:nl]
    result = cut + marker
    return result[:budget] if len(result) > budget else result


def _compact_detail(text: str, limit: int) -> str:
    """Truncate *text* to at most ~*limit* chars at a word boundary, appending an
    ellipsis when cut. Never splits mid-word; falls back to a hard cut only when the
    first word alone already exceeds *limit* (never returns emptystring for
    nonempty input)."""
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip()
    if not cut:
        cut = text[:limit].rstrip()
    return f"{cut}…"


def _render_finding(lines, f, cfg: dict | None = None, *,
                    ascii_only: bool = False, color: bool = False,
                    compact: bool = False, why_drop_severities: frozenset = frozenset()):
    conf = getattr(f, "confidence", "HIGH")
    tag = f"  (confidence: {conf.lower()})" if conf != "HIGH" and f.status in (FAIL, WARN) else ""
    pc = getattr(f, "pass_confidence", None)
    pass_tag = f"  ({pc.replace('_', ' ')})" if f.status == PASS and pc else ""
    # Issue lines lead with the severity dot (B-077 / Component-2 mock); PASS/UNKNOWN
    # roster lines keep the status icons via _render_finding_compact.
    lines.append(f"{_sev_token(f.severity, ascii_only=ascii_only, color=color)}  "
                 f"{_sanitize(f.title)}{tag}{pass_tag}")
    why_text = _sanitize(f.detail) if f.detail else ""
    # B-405: when the per-item --compact trim below still isn't enough to fit the
    # documented 4096-char budget on a large real config, render_dashboard retries
    # with progressively larger `why_drop_severities` sets -- dropping the why line
    # ENTIRELY for the named severities, weakest first, so CRITICAL/HIGH detail is the
    # last thing to go. Default (empty set) reproduces the exact prior behaviour.
    if why_text and not (compact and f.severity in why_drop_severities):
        # B-381: --compact trims the detail text itself -- the growth driver on a bad
        # config is many findings' full "why" paragraphs, not any single fixed section.
        shown_why = _compact_detail(why_text, _COMPACT_WHY_LIMIT) if compact else why_text
        lines.append(f"    why: {shown_why}")
    # Surface the concrete evidence (e.g. the exact verbs B43/B44 flagged) when a
    # FAIL/WARN carries it — naming the specific item is the value of the finding.
    # B-078: many checks build `detail` by joining their evidence, so a bullet that is
    # already quoted verbatim inside the why line is pure duplication — skip it. Bullets
    # survive only when they ADD something the why line doesn't literally contain.
    # B-381: --compact drops evidence bullets entirely -- the same "headline only"
    # trim already applied to Plugins/MCP/RISK-chain detail under --compact.
    if f.evidence and f.status in (FAIL, WARN) and not compact:
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


# ── Inventory by subject (F-131 Phase 1) ────────────────────────────────────────────
# Owner-facing regrouping of the SAME findings by the entities an owner actually owns
# (System / Agents / Skills / MCP / Channels) instead of the 7 analyst-facing families
# rendered below. Purely additive + scoring-neutral (design doc §4.7): never reads
# anything the main audit didn't already collect, never emits a new FAIL, never touches
# score/grade/`scored` findings. Skills and MCP get a per-instance verdict by reusing the
# shipped vet_skill/vet_mcp scoring paths (no second engine); System/Agents/Channels stay
# bucket-level in Phase 1 (no `subject` field on Finding yet — that is Phase 2, design §6).
#
# Design-vs-implementation note: the design doc's §4.6 JSON sketch shows "channels" as a
# list of PER-CHANNEL {name, status, findings} entries, but §4.4 is explicit that Channels
# (like System/Agents) stays BUCKET-level in Phase 1 -- no Finding carries a per-channel
# attribution today, and inventing one via string-matching evidence text would be exactly
# the kind of second, fragile engine the design and CLAUDE.md §2 both warn against. This
# implementation follows §4.4 (the more specific, algorithmic rule): "channels" is one
# bucket dict carrying the channel-name roster + the rolled-up worst status + the
# channels-surface finding ids, mirroring "system"'s shape. Precise per-channel routing is
# exactly what Phase 2's `subject` field is for.

# Skill verdict words reuse the SAME vet-verdict vocabulary `--vet` already ships
# (module-level `_VET_VERDICT`, defined further down next to render_vet_json/
# render_advise) -- referenced lazily inside the functions below (not at class/module
# scope) purely because of file position; it is the exact same table, not a copy, so a
# skill flagged here reads identically to running `--vet <skill>` directly.


def _worst_of_statuses(statuses) -> str:
    """Rolled-up worst status across a plain iterable of status strings; PASS (all-clear)
    when empty or nothing recognized. FAIL < WARN < UNKNOWN < PASS per _STATUS_ORDER."""
    ranked = [s for s in statuses if s in _STATUS_ORDER]
    if not ranked:
        return PASS
    return min(ranked, key=lambda s: _STATUS_ORDER.get(s, 9))


def _worst_status(members) -> str:
    """Rolled-up worst status across a set of findings; PASS (all-clear) when empty."""
    return _worst_of_statuses(f.status for f in members)


def _skill_inventory(ctx) -> list[dict]:
    """Per-skill verdict for the Inventory block (design §4.4): run the SAME scoring
    path `vet_skill()` uses (check_installed_skills + the shared content-security ring)
    against each already-collected skill, WITHOUT re-reading from disk -- reuses
    ctx.installed_skills/_py/_shell/_js exactly as the main audit already populated them.

    Each skill's per-skill Context.home is scoped to THAT skill's own directory
    (ctx.installed_skill_dirs[name], falling back to the whole-home Context.home only
    when a directory wasn't recorded -- e.g. a hand-built test Context), mirroring
    vet_skill()'s `Context(home=<skill dir>)`. Two ring members walk the filesystem
    from ctx.home rather than reading ctx.installed_skills (B42 install-policy dir-perm
    scan, B87 symlink-escape scan) -- without this scoping they silently re-discover the
    SAME home-wide condition for every skill in the loop and `max(pool, key=rank)`
    promotes it to every OTHER skill's headline verdict too, cross-attributing one
    skill's evidence (e.g. a symlink planted inside skill B's own directory) onto an
    unrelated, actually-clean skill A. Scoping home to the single skill directory lets
    both checks' own existing vet-mode branch (a directory carrying a root SKILL.md)
    take over, exactly as it already does for `--vet <skill>`.

    Bound by scanbudget (C-159), mirroring how `run_all` itself is budgeted: a per-skill
    hard wall-clock cap (POSIX) plus a cooperative whole-loop cap. Once either is
    exhausted, remaining skills report UNKNOWN with an explicit reason -- never a false
    "clean" (design §4.4 / §5.5)."""
    from .checks import (  # noqa: PLC0415
        _run_content_ring,
        _VET_MERGE_RANK,
        check_installed_skills,
        coverage_gap_finding,
    )
    from .collector import Context  # noqa: PLC0415
    from .scanbudget import (  # noqa: PLC0415
        DEFAULT_CHECK_BUDGET_S, ScanBudgetExceeded, audit_budget_exceeded, audit_deadline,
        check_deadline,
    )

    skills = getattr(ctx, "installed_skills", None) or {}
    if not skills:
        return []
    home = getattr(ctx, "home", None)
    py_map = getattr(ctx, "installed_skill_py", None) or {}
    sh_map = getattr(ctx, "installed_skill_shell", None) or {}
    js_map = getattr(ctx, "installed_skill_js", None) or {}
    dir_map = getattr(ctx, "installed_skill_dirs", None) or {}
    out: list[dict] = []
    # One check-sized cooperative budget for the WHOLE per-skill loop (mirrors run_all
    # treating this entire block as one "virtual check" against the audit's time budget).
    deadline = audit_deadline(DEFAULT_CHECK_BUDGET_S)
    for name, blob in skills.items():
        if audit_budget_exceeded(deadline):
            out.append({
                "name": name, "verdict": _VET_VERDICT[UNKNOWN], "status": UNKNOWN,
                "reasons": ["scan time budget exhausted before this skill was reached"],
            })
            continue
        skill_ctx = Context(home=dir_map.get(name, home))
        skill_ctx.installed_skills = {name: blob}
        skill_ctx.installed_skill_py = {name: py_map.get(name, [])}
        skill_ctx.installed_skill_shell = {name: sh_map.get(name, [])}
        skill_ctx.installed_skill_js = {name: js_map.get(name, [])}
        # base and ring are budgeted SEPARATELY, and that split is the whole point.
        # Sharing one try meant a deadline firing inside the ring abandoned the block and
        # discarded the verdict `base` had ALREADY produced: measured on a real hostile
        # skill, a genuine DANGEROUS verdict was replaced by "per-skill scan budget
        # exhausted". Reachability was ordinary — any skill vendoring a dependency pushes
        # base+ring past 15 s. Now a truncated ring costs the ring's OWN coverage and
        # never the base verdict. It does still lose ring findings produced before the
        # deadline fired — the exception unwinds the list the ring was building — so the
        # claim is "the base verdict survives", not "nothing is lost". The two deadlines
        # run in sequence, never nested, and the second gets only what the first left, so
        # the per-skill ceiling stays ~15 s total rather than 15 s each (exactly, where
        # the POSIX hard timer is available; cooperatively elsewhere).
        _started = time.monotonic()
        try:
            with check_deadline(DEFAULT_CHECK_BUDGET_S):
                base = check_installed_skills(skill_ctx)
        except ScanBudgetExceeded:
            out.append({
                "name": name, "verdict": _VET_VERDICT[UNKNOWN], "status": UNKNOWN,
                "reasons": ["per-skill scan budget exhausted"],
            })
            continue
        except Exception:  # noqa: BLE001 — a presentation-only block must never break the audit
            out.append({
                "name": name, "verdict": _VET_VERDICT[UNKNOWN], "status": UNKNOWN,
                "reasons": ["could not be assessed"],
            })
            continue

        ring: list = []
        ring_left = DEFAULT_CHECK_BUDGET_S - (time.monotonic() - _started)
        # The gap reason is carried, not assumed. Three different things can cut the ring
        # short here and they are not interchangeable: telling a user "the scan budget was
        # exhausted" when a check actually crashed is a fabricated cause, and this codebase
        # has shipped that class of untruth before.
        ring_gap: str | None = None
        if ring_left <= 0:
            ring_gap = ("content-ring coverage is incomplete: the per-skill scan budget "
                        "was spent before the content-security ring could start")
        else:
            try:
                with check_deadline(ring_left):
                    ring = _run_content_ring(skill_ctx)
            except ScanBudgetExceeded:
                # Deliberately NOT re-raised: this frame owns the deadline, and the honest
                # answer is "keep the base verdict, disclose what we missed" — not "throw
                # the base verdict away too".
                ring_gap = ("content-ring coverage is incomplete: the per-skill scan "
                            "budget was exhausted before every content-security check "
                            "had run")
            except Exception:  # noqa: BLE001 — the ring must never break the audit
                ring_gap = ("content-ring coverage is incomplete: a content-security "
                            "check failed before the ring completed")
        pool = [base, *ring]
        if ring_gap:
            pool.append(coverage_gap_finding(ring_gap))
        primary = max(pool, key=lambda fx: _VET_MERGE_RANK.get(fx.status, 0))
        reasons: list[str] = []
        for fx in pool:
            d = _sanitize(fx.detail) if fx.detail else ""
            if d and d not in reasons:
                reasons.append(d)
        shown_reasons = reasons[:3]
        # C-307: the coverage-gap reason is STICKY — a ring that produced 3+ real
        # findings before being cut short would otherwise push it out of the [:3]
        # window purely by pool order, silently hiding "this scan was incomplete"
        # from the row even though the row still carries an incomplete verdict.
        # Two distinct sources land a VET-COVERAGE finding in `pool`: this frame's
        # own `ring_gap` (appended just above) AND one `_run_content_ring` already
        # folded into `ring` on its OWN internal truncation (checks/_vet.py) —
        # either way, its reason must survive the [:3] window.
        for fx in pool:
            if fx.id != "VET-COVERAGE" or not fx.detail:
                continue
            cov_reason = _sanitize(fx.detail)
            if cov_reason not in shown_reasons:
                shown_reasons = [*shown_reasons[:2], cov_reason]
        out.append({
            "name": name,
            "verdict": _VET_VERDICT.get(primary.status, str(primary.status)),
            "status": primary.status if primary.status in (FAIL, WARN, PASS, UNKNOWN) else UNKNOWN,
            "reasons": shown_reasons,
        })
    return out


def _mcp_inventory(ctx) -> list[dict]:
    """Per-server mini-verdict for the Inventory block (design §4.4): reuse `vet_mcp`'s
    OWN axis logic (`_vet_mcp_server`) directly against the already-parsed roster from
    ctx.config, instead of vet_mcp()'s file-target path (which would re-read config from
    disk). Universal roster shape (§2): `_mcp_servers` already folds mcp.servers (nested)
    and legacy mcpServers/mcp_servers/tools.mcp/plugins.mcp into one dict."""
    from .checks import _mcp_servers, _vet_mcp_server  # noqa: PLC0415

    cfg = getattr(ctx, "config", None) or {}
    servers = _mcp_servers(cfg)
    out: list[dict] = []
    for name, spec in servers.items():
        try:
            dangerous, suspicious = _vet_mcp_server(name, spec if isinstance(spec, dict) else {})
        except Exception:  # noqa: BLE001 — presentation-only block must never break the audit
            out.append({"name": name, "verdict": UNKNOWN, "reasons": ["could not be assessed"]})
            continue
        if dangerous:
            status, raw_reasons = FAIL, dangerous
        elif suspicious:
            status, raw_reasons = WARN, suspicious
        else:
            status, raw_reasons = PASS, []
        prefix = f"{name}: "
        reasons = [
            _sanitize(r[len(prefix):] if r.startswith(prefix) else r) for r in raw_reasons[:3]
        ]
        out.append({
            "name": name,
            "verdict": "ok" if status == PASS else status,
            "reasons": reasons,
        })
    return out


def _agents_roster(ctx) -> tuple[list[str], bool]:
    """Agent roster + whether it is attested (design §4.3): prefer the agent's own
    self-report (`attest.attested_agents`, stronger per-agent detail) over the static
    `agents.list` config roster; fall back to a single-default-agent roster when neither
    is present -- never an empty roster (System is the only true singleton subject)."""
    from .attest import attested_agents  # noqa: PLC0415
    from .collector import dig  # noqa: PLC0415

    att = attested_agents(getattr(ctx, "attestation", None) or {})
    if att:
        return [a["name"] for a in att], True
    agents_list = dig(getattr(ctx, "config", None) or {}, "agents.list")
    if isinstance(agents_list, list) and agents_list:
        names: list[str] = []
        for i, a in enumerate(agents_list):
            name = a.get("name") if isinstance(a, dict) else None
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
            else:
                names.append(f"agent[{i}]")
        return names, False
    return ["(default)"], False


def _channels_roster(ctx) -> list[str]:
    """Channel roster (design §4.3): provider keys of `_channels(ctx.config)`, dropping
    the `defaults` pseudo-provider (not a real channel instance)."""
    from .checks import _channels  # noqa: PLC0415

    cfg = getattr(ctx, "config", None) or {}
    return [k for k in _channels(cfg) if k != "defaults"]


def _empty_inventory() -> dict:
    """A fresh, all-clear inventory shape — every nested list/dict is newly allocated
    per call (no shared mutable state across callers) — for when `ctx` is unavailable."""
    return {
        "openclaw": {"status": PASS, "findings": [], "unassessed": 0},
        "host": {"status": PASS, "findings": [], "unassessed": 0},
        "agents": {"status": PASS, "findings": [], "unassessed": 0,
                   "roster": [], "attested": False},
        "skills": [],
        "mcp": [],
        "plugins": {"scanned": False, "rows": []},
        "channels": {"status": PASS, "findings": [], "unassessed": 0, "roster": []},
        "logs": {"status": PASS, "findings": [], "unassessed": 0},
    }


def _plugin_inventory(plugin_sweep) -> dict:
    """The `"plugins"` inventory bucket (F-163) — the additive-JSON counterpart to
    `_plugins_inventory_lines` (the text/dashboard renderer), built from the SAME
    duck-typed `PluginSweep`-shaped object (`.no_roots`/`.no_targets`/`.rows`), never
    imported here (same report<->pipeline import-cycle precedent that function's own
    docstring sets out).

    `plugin_sweep` is only ever populated by a `--full` run (the plugin sweep phase) —
    a plain audit() never scans plugins at all, so "not scanned" is the honest default,
    not an empty/clear verdict. Present-but-empty (`"scanned": True, "rows": []`) is
    reserved for a real sweep that found zero installed plugins — distinct from
    "scanned": False (never swept this run), matching the same "MCP servers (none
    configured)" vs. "not applicable" distinction `_mcp_inventory` already draws.
    """
    if plugin_sweep is None or getattr(plugin_sweep, "no_roots", True):
        return {"scanned": False, "rows": []}
    if getattr(plugin_sweep, "no_targets", True):
        return {"scanned": True, "rows": []}
    return {
        "scanned": True,
        "rows": [
            {"name": name, "status": status} for name, status, _ev in plugin_sweep.rows
        ],
    }


def build_inventory(findings: list[Finding], ctx, *, plugin_sweep=None) -> dict:
    """Build the additive `"inventory"` JSON payload (design §4.6, extended by F-163).
    Presentation-only: reads only what the main audit already collected on `ctx` (plus
    the optional `--full`-only `plugin_sweep`), and re-groups the SAME `findings` list
    the family view (above) renders — never alters score/grade, never emits a new
    Finding. Every SURFACES slug routes to exactly one of the 8 subjects (SUBJECT_OF
    coherence, mirrored by tests/test_subject_inventory.py)."""
    if ctx is None:
        return _empty_inventory()
    unsuppressed = [f for f in findings if not getattr(f, "suppressed", False)]
    by_subject: dict[str, list[Finding]] = {s: [] for s in SUBJECT_ORDER}
    for f in unsuppressed:
        subj = _subject_of(f)
        if subj in by_subject:
            by_subject[subj].append(f)

    def _bucket(subject: str) -> dict:
        members = by_subject.get(subject, [])
        issues = [f for f in members if f.status in (FAIL, WARN)]
        # B-472: `unassessed` is carried separately from `status` because neither of the
        # two existing fields can answer "was this subject actually looked at". `status`
        # rolls UNKNOWN up over PASS, so it cannot tell one unreachable check among ten
        # clean ones from a subject nothing could read; and it also folds in
        # `not_applicable` members (a surface positively confirmed absent), which ARE
        # assessed. Additive key — every existing consumer of `status`/`findings` is
        # unchanged.
        return {
            "status": _worst_status(members),
            "findings": [f.id for f in issues],
            "unassessed": sum(1 for f in members
                              if f.status == UNKNOWN and not getattr(f, "not_applicable", False)),
        }

    openclaw = _bucket("openclaw")
    host = _bucket("host")
    logs = _bucket("logs")

    agents_roster, attested = _agents_roster(ctx)
    agents = _bucket("agents")
    agents["roster"] = agents_roster
    agents["attested"] = attested

    channels = _bucket("channels")
    channels["roster"] = _channels_roster(ctx)

    return {
        "openclaw": openclaw,
        "host": host,
        "agents": agents,
        "skills": _skill_inventory(ctx),
        "mcp": _mcp_inventory(ctx),
        "plugins": _plugin_inventory(plugin_sweep),
        "channels": channels,
        "logs": logs,
    }


def _inventory_bucket_lines(label: str, bucket: dict, by_id: dict, *, ascii_only: bool) -> list[str]:
    icon = _ICON_ASCII if ascii_only else _ICON
    status = bucket.get("status", PASS)
    fids = bucket.get("findings") or []
    marker = icon.get(status, icon.get(UNKNOWN, "?"))
    count_text = _subject_count_text(len(fids), int(bucket.get("unassessed") or 0))
    out = [f" {label} — {marker} {count_text}"]
    for fid in fids:
        f = by_id.get(fid)
        if f is None:
            continue
        out.append(f"   {icon.get(f.status, '?')} {f.id}  {_sanitize(f.title)}")
    return out


def _skills_inventory_lines(inv: dict, ctx, *, ascii_only: bool = False,
                            clean_roster_limit=None) -> list[str]:
    """Per-skill verdict lines (design §4.4) -- single source of truth shared by
    render_subject_inventory (full report's "Inventory by subject" block) and
    render_dashboard (B-356: the same verdicts, compact, in the chat-pasted card)."""
    icon = _ICON_ASCII if ascii_only else _ICON
    skills = inv["skills"]
    n_skills = len(skills)
    if n_skills == 0:
        return [f" {SUBJECT_LABEL['skills']} (none installed)"]
    # B-268: `inv["skills"]` is built from ctx.installed_skills, which the collector caps at
    # _MAX_SKILLS. Printing its length as "(N installed)" reported the CAP as the inventory
    # total — a home with 311 skills on disk rendered "Skills (300 installed)", and the 11
    # unexamined ones were invisible in the very block whose job is to enumerate what is
    # installed. Disclose the truncation instead of presenting a capped view as a census.
    n_skipped = int(getattr(ctx, "skills_capped_count", 0) or 0)
    installed_text = (
        f"{n_skills} inspected, {n_skipped} NOT inspected — inspection cap reached"
        if n_skipped else f"{n_skills} installed"
    )
    flagged = [s for s in skills if s.get("status") in (FAIL, WARN, UNKNOWN)]
    flagged_names = {s["name"] for s in flagged}
    sk_marker = icon.get(_worst_of_statuses(s["status"] for s in flagged), "?")
    count_text = f"{len(flagged)} flagged" if flagged else "clear"
    lines = [f" {SUBJECT_LABEL['skills']} ({installed_text}) — {sk_marker} {count_text}"]
    if n_skipped:
        lines.append(
            f"   {icon.get(UNKNOWN, '?')} {n_skipped} skill(s) beyond the inspection "
            "cap were not scanned; their verdict is unknown, not clean")
    # Skill names are untrusted (directory names) -- _sanitize() every one before it
    # reaches a line, same as finding title/detail elsewhere in this file (B164: no raw
    # ANSI/control chars may reach the terminal).
    # C-373: the clean roster is the one UNBOUNDED part of this block — it names every
    # clean skill, so a home with hundreds of them produces thousands of characters on
    # its own. The chat card (which must fit ~4096 chars in total) passes a
    # `clean_roster_limit` so the names still appear — B-356 added them deliberately, and
    # a home with a handful of skills should still see them — but a 300-skill home cannot
    # blow the budget with a name list. The count stays exact either way, and the overflow
    # is disclosed, never silently cut. `None` (the full report, `--dashboard --full`)
    # lists them all, exactly as before.
    clean = [_sanitize(s["name"]) for s in skills if s["name"] not in flagged_names]
    if clean:
        shown = clean if clean_roster_limit is None else clean[:clean_roster_limit]
        roster = ", ".join(shown)
        if len(shown) < len(clean):
            roster += f", +{len(clean) - len(shown)} more"
        lines.append(f"   {icon.get(PASS, '?')} {len(clean)} clean: " + roster)
    for s in flagged:
        reason_text = "; ".join(s.get("reasons") or []) or s["verdict"]
        lines.append(f"   {icon.get(s['status'], '?')} {_sanitize(s['name'])}  {s['verdict']} - {reason_text}")
    return lines


def _mcp_inventory_lines(inv: dict, *, ascii_only: bool = False, compact: bool = False) -> list[str]:
    """Per-server verdict lines (design §4.5) -- the MCP counterpart to
    _skills_inventory_lines: single source of truth shared by render_subject_inventory
    (full report's "Inventory by subject" block, always `compact=False`) and
    render_dashboard (F-153: the same verdicts in the chat-pasted combined pipeline
    card, `compact=True` under --compact collapsing to the headline count only)."""
    icon = _ICON_ASCII if ascii_only else _ICON
    mcp = inv["mcp"]
    n_mcp = len(mcp)
    if n_mcp == 0:
        return [f" {SUBJECT_LABEL['mcp']} (none configured)"]
    mcp_ok = [_sanitize(m["name"]) for m in mcp if m["verdict"] == "ok"]
    mcp_bad = [m for m in mcp if m["verdict"] != "ok"]
    mcp_marker = icon.get(_worst_of_statuses(m["verdict"] for m in mcp_bad), "?")
    count_text = f"{len(mcp_bad)} flagged" if mcp_bad else "clear"
    lines = [f" {SUBJECT_LABEL['mcp']} ({n_mcp}) — {mcp_marker} {count_text}"]
    if compact:
        return lines
    if mcp_ok:
        lines.append(f"   {icon.get(PASS, '?')} " + " | ".join(mcp_ok))
    for m in mcp_bad:
        reason_text = "; ".join(m.get("reasons") or []) or m["verdict"]
        lines.append(f"   {icon.get(m['verdict'], '?')} {_sanitize(m['name'])}  {reason_text}")
    return lines


def render_subject_inventory(findings: list[Finding], ctx, *, ascii_only: bool = False,
                              color: bool = False, plugin_sweep=None,
                              plugins_deferred: bool = False) -> str:
    """Owner-facing "Inventory by subject" block (F-131 Phase 1, extended by F-163) --
    OpenClaw core / Host machine / Agents / Skills / MCP / Plugins / Channels / Logs &
    trajectories, each with a rolled-up status; Skills, MCP and Plugins additionally get
    a per-instance verdict (design §4.4/§4.5). Purely additive/presentation: `--ascii`
    degrades cleanly (no unicode/color), and this returns "" when `ctx` is unavailable —
    same "skip, don't guess" precedent `render_report` already uses for the capability-
    graph / credential-surface sections below. `plugin_sweep` is `--full`-only (same
    duck-typed object `render_dashboard` already accepts) — omitted on a plain audit,
    where the Plugins bucket honestly reports "not scanned" rather than a fake clear."""
    if ctx is None:
        return ""
    inv = build_inventory(findings, ctx, plugin_sweep=plugin_sweep)
    by_id = {f.id: f for f in findings}
    rule_char = "=" if ascii_only else "═"
    lines: list[str] = ["== INVENTORY BY SUBJECT " + rule_char * 44]

    lines.extend(_inventory_bucket_lines(SUBJECT_LABEL["openclaw"], inv["openclaw"], by_id,
                                          ascii_only=ascii_only))

    lines.extend(_inventory_bucket_lines(SUBJECT_LABEL["host"], inv["host"], by_id,
                                          ascii_only=ascii_only))

    ag = inv["agents"]
    roster = ag.get("roster") or []
    n = len(roster)
    ag_label = f"{SUBJECT_LABEL['agents']} ({n} agent{'s' if n != 1 else ''}" + (
        ")" if ag.get("attested") else " - roster not attested)"
    )
    lines.extend(_inventory_bucket_lines(ag_label, ag, by_id, ascii_only=ascii_only))
    if not ag.get("attested"):
        lines.append("   note  attest (--attest) for per-agent separation (B45/B47)")

    lines.extend(_skills_inventory_lines(inv, ctx, ascii_only=ascii_only))

    lines.extend(_mcp_inventory_lines(inv, ascii_only=ascii_only))

    if inv["plugins"]["scanned"]:
        lines.extend(_plugins_inventory_lines(plugin_sweep, ascii_only=ascii_only))
    elif plugins_deferred:
        # B-473: on a plain `--full` text run the plugin sweep is pipeline phase P7, which
        # runs AFTER this body is assembled (deliberately — the report-body byte order is
        # the prefix `--full --quiet` is compared against), so this renderer genuinely has
        # no sweep object to show. Printing "run --full to include" there told the reader
        # to run the very flag they had just run, about a sweep whose results were printed
        # a few hundred lines further down the same output.
        lines.append(f" {SUBJECT_LABEL['plugins']} (swept later in this run — "
                     "see the PLUGIN SWEEP section below)")
    else:
        lines.append(f" {SUBJECT_LABEL['plugins']} (not scanned — run --full to include)")

    ch = inv["channels"]
    croster = ch.get("roster") or []
    cn = len(croster)
    ch_label = f"{SUBJECT_LABEL['channels']} ({cn})" if cn else f"{SUBJECT_LABEL['channels']} (none configured)"
    lines.extend(_inventory_bucket_lines(ch_label, ch, by_id, ascii_only=ascii_only))
    if croster:
        lines.append(f"   roster: {', '.join(_sanitize(c) for c in croster)}")

    lines.extend(_inventory_bucket_lines(SUBJECT_LABEL["logs"], inv["logs"], by_id,
                                          ascii_only=ascii_only))

    lines.append(rule_char * 68)
    lines.append(" (details by subject below)")
    out = "\n".join(lines).rstrip() + "\n"
    if ascii_only:
        return _asciify(out)
    return out


def render_report(findings: list[Finding], score: ScoreResult,
                  ascii_only: bool = False, native=None,
                  *, risk=None, update_notice: list[str] | None = None,
                  freshness_notice: list[str] | None = None,
                  openclaw_detected: bool = True, ctx=None,
                  verbose: bool = False, color: bool = False,
                  tamper: ScoreResult | None = None, plugin_sweep=None,
                  plugins_deferred: bool = False) -> str:
    findings = deduplicate_findings(findings)
    icon = _color_icons(_ICON_ASCII if ascii_only else _ICON, color)
    ok = "[OK]" if ascii_only else "✅"
    # Supply cfg to _render_finding only in verbose mode so blast-radius lines appear.
    _blast_cfg: dict | None = (getattr(ctx, "config", {}) or {}) if (verbose and ctx is not None) else None
    suppressed_count = sum(1 for f in findings if getattr(f, "suppressed", False))
    issues = [f for f in findings
              if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))
    grade_disp = paint(score.grade, grade_ansi(score.grade), "bold", enabled=True) if color else score.grade
    # Assurance honesty (R11): single source-of-truth coverage tally, computed once and
    # reused by both the C-166 low-coverage line (below) and the C-165 staleness nudge
    # (advisory band, further down) — never a second independent tally.
    cov = assessment_coverage(findings)
    # Mascot + wordmark: header line only, once (design-system Foundations);
    # --ascii drops the mascot and folds the separator (brand.header()).
    head = brand.header(subtitle="OpenClaw Security Audit", ascii_only=ascii_only)
    lines = [head, "=" * 44]
    # B-313/B-399: disclosed ABOVE the grade, unconditionally whenever any check degraded
    # this run (crashed, timed out, or — B-399 — ran to completion but could not reach a
    # verdict for an engine-side reason, e.g. an input it expected to read that turned out
    # unreadable/corrupt) — regardless of whether DEGRADED_CHECK_CAP ended up strictly
    # "binding" (a tighter cap, e.g. a genuine CRITICAL FAIL, may already apply). The
    # reader still needs to know coverage was incomplete even when the number on screen
    # would have been just as bad anyway; getattr/default tolerates the older duck-typed
    # ScoreResult stand-ins some tests build (same tolerance B-306 established for
    # config_blind_capped/runtime_capped below).
    _degraded_n = getattr(score, "degraded_count", 0)
    if _degraded_n:
        warn_icon = "[!]" if ascii_only else "⚠️ "
        _plural = "check" if _degraded_n == 1 else "checks"
        lines.append(
            f"{warn_icon}{_degraded_n} {_plural} could not reach a reliable verdict this"
            " run (crashed, timed out, or hit unreadable/corrupted input) — this grade is"
            " incomplete. Re-run with --debug for a crash/timeout traceback, or review the"
            " affected finding(s) below for an unreadable-input detail."
        )
    lines.append(f"Score: {score.score}/100   Grade: {grade_disp}")
    lines.append(_score_bar(score.score, score.grade, ascii_only=ascii_only, color=color))
    # B-306 (C-135 follow-up #3, 2026-07-21): gate on the GRANULAR cap signals, not
    # `score.capped` alone. `score.capped` means "score != raw_score" — deliberately FALSE
    # in scoring.py's `total == 0` branch (raw_score and score are both hardcoded 0 there;
    # there is no positive raw value for the cap to have reduced FROM), yet
    # `config_blind_capped`/`runtime_capped`/`degraded_capped` (B-313) can still be True in
    # that exact branch (see scoring.ScoreResult field docs and docs/OUTPUT_SCHEMA.md's
    # documented "can be true alongside capped: false" carve-out for JSON consumers).
    # Relying on `score.capped` alone silently dropped this whole explanation in precisely
    # the scenario B-306 exists to make loud — this is a rendering-gate fix, not a
    # scoring.py semantics change, so the JSON contract/docs above stay exactly as
    # documented.
    # B-281 (ENV-1)/B-363: computed here (ahead of both the cap-reason text below and the
    # "Audited config:" line further down) so both agree on whether a config was ever
    # actually read this run. `_audited_path` is the resolved-or-canonical path either
    # way (see resolve_config_in_home) — `_cfg_found` is what distinguishes "we read
    # this file" from "we looked for this file and it wasn't there".
    _audited_path = getattr(ctx, "config_path", None) if ctx is not None else None
    _cfg_found = getattr(ctx, "config_found", True) if ctx is not None else True
    # B-380: the five-branch "elif" ladder + ten near-identical
    # "_extra = []; if X: _extra.append(...)" blocks that used to live here (one per
    # branch, hand-edited separately every time a signal type was added) are gone —
    # `_cap_cascade` is the single, shared decision both render_report and render_html
    # defer to now. It reads exactly the same six signals the old gate condition named
    # (`score.capped` covers the ordinary severity-cap path; the granular flags cover
    # every cap-only signal, including the `total == 0` branch where `capped` stays
    # False by design — see the B-306 comment this replaces), so `_primary is not
    # None` is the correct, single-source-of-truth gate. B-399: `_CAP_DEGRADED`'s own
    # text (`_cap_primary_reason_text`) already covers an engine-side-degraded UNKNOWN
    # generically ("could not reach a reliable verdict") alongside crashed/timed-out --
    # no renderer-side change needed for the new cause, only scoring.py's cap trigger.
    _primary, _extras = _cap_cascade(score)
    if _primary is not None:
        _reason_text = _cap_primary_reason_text(_primary, score, audited_path=_audited_path)
        lines.append(
            f"(capped from {score.raw_score} - {_reason_text}{_cap_also_clause(_extras)})"
        )

    # B-281 (ENV-1): name the file this grade actually describes. OpenClaw resolves its
    # config through OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR (what
    # `openclaw --profile` sets) and prefers an existing legacy clawdbot.json, so the
    # audited file is a RESOLVED path, not a foregone conclusion. Printing it is what lets
    # a reader notice that a grade describes a stale, dormant config; B183 does the
    # comparison, but this line stands on its own and costs nothing when they agree.
    # B-363: only when a config was actually FOUND and read — `_audited_path` is set to
    # the canonical would-be path even when nothing was there (resolve_config_in_home),
    # so printing it unconditionally used to claim a file was audited when the collector
    # never opened anything at all. `_cfg_found`/`_audited_path` were both computed above,
    # ahead of the cap-reason block, so this line and that one can never disagree.
    if _audited_path is not None and _cfg_found:
        lines.append(f"Audited config: {_audited_path}")

    # B-306 safe-symlink split: openclaw.json is a symlink whose target leaves ~/.openclaw,
    # and that target is a readable regular file the user owns — a benign dotfiles layout
    # (stow/chezmoi/yadm/bare-git). The collector followed it and audited the real bytes, so
    # the grade above is a real verdict, NOT a config-blind F cap. Surface it as an INFO
    # note (never a FAIL) so the reader knows the audited file physically lives outside the
    # config dir. Presentation-only: never touches score/grade.
    if getattr(ctx, "config_symlink_escapes_home", False):
        note_icon = "[i]" if ascii_only else "ℹ️ "
        lines.append(
            f"{note_icon} Your openclaw.json symlinks outside ~/.openclaw; its target is a"
            " readable regular file you own, so it was followed and audited normally"
            " (not treated as an unreadable config)."
        )

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
    # B-464: because UNKNOWNs are excluded, switching a subsystem OFF removes its checks
    # from the denominator — and if any of them were WARNing, the score goes UP (measured:
    # 97 -> 98 with --no-host). Nothing in the number itself reveals that, so a
    # deliberately-narrowed run was indistinguishable from a better-configured one. Name
    # the opt-outs so the figure is not read as comparable to a full audit.
    # Read from an explicit opt-out list the CLI sets, NOT from `ctx.include_host`:
    # that field defaults to False, so a plain library `audit(home)` call would have
    # printed this note while naming a flag the caller never passed.
    _opted_out = list(getattr(ctx, "cli_opt_outs", ()) or ())
    if _opted_out:
        lines.append(
            "Note: " + " and ".join(_opted_out) + " removed whole check groups from that "
            "denominator, so this score is NOT comparable to a full audit — opting a "
            "subsystem out can raise the number without changing your setup."
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
        " `--vet-mcp` (deep MCP) for those. It also doesn't mine what your agent has"
        " already logged — run `--behavioral` (proven-by-log verb-sequence trifecta /"
        " outcome anomaly / capability drift) or `--analyze-trajectory` (skill-indicator"
        " correlation) to check whether a trifecta is already recorded in your"
        " trajectory sidecar."
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
    # I-025/B-309: an exception to "this grade never reflects runtime behaviour" above —
    # a trajaudit-style skill/bootstrap indicator match (--analyze-trajectory) MAY CAP
    # this grade — never raise it, never earn/cost an ordinary scored point. B83, B84,
    # B85, B180, and every B164 corroboration (including exfil_evidence, same-line or
    # cross-line) still cannot move this grade at all, in either direction — see
    # tests/test_i025_runtime_cap.py for the pinned enumeration. (B164's exfil_evidence
    # class was briefly cap-eligible under Dave's original 2026-07-20 ruling; retracted
    # after four C-135 rounds proved no sound host/verb gate exists for this tool's own
    # audience — see logscan.py's retraction note.) F-154: T1/T2/T3/B191 are NO LONGER
    # in the "cannot move it at all" set — see the behavioral exception further below —
    # so this paragraph's own claim is narrowed to name only what it still covers.
    lines.append(
        "Runtime exception (I-025): a trajectory-indicator match MAY CAP this grade"
        " (never raise it) — every other capability-vs-runtime corroboration still"
        " cannot move the grade at all; the behavioral verb-sequence/audit-trail layer"
        " below has a separate exception of its own."
    )
    if score.runtime_capped:
        lines.append(
            f"  This run's grade WAS capped by that exception: "
            f"{_runtime_cap_phrase(score.runtime_cap_reason)}."
        )
    # F-155: a SECOND exception to "this grade never reflects runtime behaviour" — a
    # submitted VULNERABLE verdict from a live injection-test harness (canary/dryrun/
    # redteam/multiturn) MAY CAP this grade, never raise it, and only when actually
    # submitted (self-attestation guard: RESISTANT or no submission at all has ZERO
    # effect — see scoring.LIVE_INJECTION_CAP). Distinct from the I-025 exception above:
    # that one is the engine corroborating its OWN trajectory sidecar; this one is the
    # agent under test self-reporting the outcome of an ACTIVE probe it just ran.
    #
    # Deliberately gated on `live_injection_capped` (unlike the I-025 paragraph above,
    # which is unconditional) — this task's own test plan requires a run with nothing
    # submitted to render byte-identically to before this feature existed, so no new line
    # may appear here unless a VULNERABLE verdict actually capped this run.
    if getattr(score, "live_injection_capped", False):
        lines.append(
            "Live-test exception (F-155): this run's grade WAS capped by a submitted "
            f"VULNERABLE verdict — {_live_injection_cap_phrase(score.live_injection_cap_reason)}."
            " RESISTANT or no submission would have changed nothing."
        )
    # F-154: a THIRD exception to "this grade never reflects runtime behaviour" — a
    # fired T1/T2/T3/B191 behavioral detector (--behavioral or --full) MAY CAP this
    # grade, never raise it, never earn/cost an ordinary scored point. Distinct from
    # both exceptions above: this is proven-by-LOG observation over the trajectory
    # sidecar's own verb sequence/outcome/drift/audit-trail — not a corroborated
    # indicator match (I-025) and not a self-reported ACTIVE-probe verdict (F-155).
    #
    # Deliberately gated on `behavioral_capped` (same discipline as the F-155 paragraph
    # above, unlike the I-025 one) — a run that never executed --behavioral/--full sees
    # no new line here, byte-identical to before this task existed.
    if getattr(score, "behavioral_capped", False):
        lines.append(
            "Behavioral exception (F-154): this run's grade WAS capped by a fired "
            f"behavioral detector — {_behavioral_cap_phrase(score.behavioral_cap_reason)}."
            " A clean --behavioral/--full replay would have changed nothing."
        )
    # B-306 (C-135 follow-up): openclaw.json itself went dark this run (present but
    # unparseable, or unreadable) — every config-derived check (A1/B41/B1/B11/...)
    # correctly degraded to UNKNOWN rather than a fabricated verdict, but that alone lets
    # the grade RISE (fewer FAILs to cap it) even though the audit saw strictly less, not
    # more. This line only ever appears alongside the cap already applied above.
    if score.config_blind_capped:
        lines.append(
            "Config visibility (B-306): openclaw.json could not be read/parsed this run, so"
            " this grade was hard-capped rather than let a config-derived check's honest"
            " UNKNOWN quietly raise it. Fix openclaw.json (valid JSON, owner-readable) and"
            " re-run for a real verdict."
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
    # F-131 Phase 1: "Inventory by subject" sits directly ABOVE the 7-family view (design
    # §3, locked decision 1) — NOT above the whole report. It closes with "(details by
    # security family below)", which only reads correctly when the family view is what
    # follows it; prepending the block to the entire report pushed the header and the
    # grade underneath ~40 lines of findings, which is the one thing that decision
    # forbade ("nothing existing is restructured"). Presentational only, and "" when ctx
    # is unavailable (mirrors the ctx-gated sections above).
    inv_text = render_subject_inventory(findings, ctx, ascii_only=ascii_only, color=color,
                                         plugin_sweep=plugin_sweep,
                                         plugins_deferred=plugins_deferred)
    if inv_text:
        lines.append("")
        lines.extend(inv_text.split("\n"))

    unsuppressed_all = [f for f in findings if not getattr(f, "suppressed", False)]
    if not unsuppressed_all:
        lines.append(f"No known attack pattern matched. Keep it that way. {ok}")
    else:
        if issues:
            lines.append(f"{len(issues)} issue(s), grouped by subject — most urgent first within each:")
        else:
            lines.append(f"No known attack pattern matched. Keep it that way. {ok}")
        lines.append("")
        # Group EVERY finding (not just FAIL/WARN) by its Inventory subject (OpenClaw core /
        # Host / Agents / Skills / MCP / Channels / Logs) so the report reads as coverage-
        # by-subject — matching the "Inventory by subject" block directly above — rather
        # than a flat severity dump. A1 (Lethal Trifecta) routes to Agents via its
        # "trifecta" surface (SUBJECT_OF), so it shows up as one Agents finding among others
        # instead of a standalone headline (F-044). Findings with an id outside CATALOG fall
        # into a trailing "Other" bucket (nothing silently dropped). PASS/UNKNOWN are
        # collapsed to a one-line roster per subject — still listed, just not walled in green.
        grouped: dict[str | None, list[Finding]] = {}
        for f in unsuppressed_all:
            grouped.setdefault(_subject_of(f), []).append(f)
        for subj_key in (*SUBJECT_ORDER, None):
            members = grouped.get(subj_key)
            if not members:
                continue
            members.sort(key=lambda f: (_STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9)))
            label = SUBJECT_LABEL.get(subj_key, "Other")
            label_disp = paint(label, "bold", enabled=True) if color else label
            n_bad = sum(1 for f in members if f.status in (FAIL, WARN))
            # B-472: this header used a bare `else "clear"` and so contradicted the
            # "N not assessed (config can't tell)" line this same block prints a few lines
            # below, for the same members. Same rule as the inventory block above.
            count_text = _subject_count_text(
                n_bad,
                sum(1 for f in members
                    if f.status == UNKNOWN and not getattr(f, "not_applicable", False)),
            )
            if ascii_only:
                lines.append(f"[{label_disp}] — {count_text}")
            else:
                _rule = "─" * 30
                lines.append(f"┌{_rule}")
                lines.append(f"│ {label_disp} — {count_text}")
                lines.append(f"└{_rule}")
            n_unknown = 0
            n_na = 0
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
                    # F-139/B2: split off not_applicable (surface positively confirmed
                    # absent, e.g. no MCP servers) — the --ask/--attest advice below is
                    # meaningless for those, so they get their own line with no advice.
                    if getattr(f, "not_applicable", False):
                        n_na += 1
                    else:
                        n_unknown += 1
            if n_unknown:
                unk_icon = icon.get(UNKNOWN, "?")
                lines.append(f"  {unk_icon} {n_unknown} not assessed (config can't tell) —"
                             " resolve via `--ask` then `--attest`")
            if n_na:
                na_icon = _AXIS_ICON_ASCII["N/A"] if ascii_only else _AXIS_ICON_UNI["N/A"]
                lines.append(f"  {na_icon} {n_na} not applicable (no such surface in your config)")
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


def render_dashboard_findings(findings: list[Finding], *, ascii_only: bool = False,
                              compact: bool = False,
                              why_drop_severities: frozenset = frozenset()) -> str:
    """Deterministic, framed Findings block for the chat Dashboard (SKILL.md Step 3, Section 3).

    Emits ONLY what Section 3 must contain, so the host agent PASTES this verbatim instead
    of re-composing it (models drop the open 3-sided frame otherwise):
      - non-suppressed FAIL/WARN findings only (PASS/UNKNOWN live in Sections 4 & 6);
      - MEDIUM/ATTESTED-confidence findings excluded (they surface in Section 4);
      - families with no qualifying finding are omitted (no empty "— clear" headers);
      - each family under the same open 3-sided frame render_report uses.

    `compact=True` (B-381) is render_dashboard's --dashboard --full --compact mode:
    this block is the one section that SCALES with FAIL/WARN count (a bad config has
    many), so it is the real driver of the Telegram ~4096-char budget being missed —
    every other combined-pipeline section is already bounded/short. `compact` threads
    into `_render_finding`, which trims each finding's "why" text and drops its
    evidence bullets; the family frames, titles and severity tokens are unchanged
    (still the exact literal block the host agent pastes verbatim). Default False
    reproduces the exact prior byte-identical output for every existing caller
    (the standalone `--dashboard-findings` command, and every test).

    `why_drop_severities` (B-405) is render_dashboard's final, hard 4096-char budget
    enforcement: when the per-item trim above still isn't enough on a large real
    config, the caller re-renders with this set widened (weakest severity first) so
    entire why lines are dropped rather than merely narrowed. Empty by default,
    reproducing the exact prior output.
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

    lines: list = []
    for subj_key, label, members in _group_issues_by_subject(qualifying):
        members.sort(key=lambda f: (_STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9)))
        count_text = f"{len(members)} issue(s)"
        if ascii_only:
            lines.append(f"[{label}] — {count_text}")
        else:
            # Chat paste carries the subject emoji (SKILL.md Step-3 table, B-077);
            # the CLI report / HTML / PDF subject headers stay emoji-less by design.
            emoji = _SUBJECT_EMOJI.get(subj_key)
            head = f"{emoji} {label}" if emoji else label
            # B-381: --compact narrows the frame's own border rule (still an open
            # 3-sided box -- same shape, fewer dashes) -- one of several small per-
            # family savings that add up across a bad config's many families/findings.
            _rule = "─" * (10 if compact else 30)
            lines.append(f"┌{_rule}")
            lines.append(f"│ {head} — {count_text}")
            lines.append(f"└{_rule}")
        for f in members:
            _render_finding(lines, f, cfg=None, ascii_only=ascii_only, compact=compact,
                            why_drop_severities=why_drop_severities)
        lines.append("")

    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def _plugins_inventory_lines(sweep, *, ascii_only: bool = False, compact: bool = False) -> list[str]:
    """Per-plugin verdict lines for the combined pipeline Dashboard (F-153) — the
    Plugins counterpart to _skills_inventory_lines/_mcp_inventory_lines. `sweep` is
    duck-typed on checks._mcp.PluginSweep's published surface (.no_roots/.no_targets/
    .counts()/.rows/.findings) and is never imported here — mirrors the precedent
    pipeline.record_skill_sweep's own docstring already sets out for exactly this
    Layer-2/Layer-3 hand-off (and, in this direction, avoids the report<->pipeline
    import cycle: pipeline.py already imports report._sanitize/_sanitize_tree).

    Returns [] when there is genuinely nothing to sweep (no installed-plugin index
    found, or an index naming zero plugins) — the caller omits the whole "Plugins"
    block then, same as "Skills" already does when inv["skills"] is empty.
    `compact=True` (--compact) collapses this to the headline count line plus the
    not-scanned disclosure (when there is one) — the per-plugin roster/reason lines
    are what gets dropped, not the disclosure (B-381).

    B-381 (Golden Rule #4): SKIPPED/TRUNCATED rows are folded into "flagged" for the
    headline marker/count, the same precedent `_skills_inventory_lines` already sets
    for its own UNKNOWN rows. `_worst_of_statuses` only recognizes FAIL/WARN/UNKNOWN/
    PASS (`_STATUS_ORDER`) — "SKIPPED"/"TRUNCATED" aren't in that table, so they used
    to be silently ignored by the rollup, and a sweep where EVERY row was
    SKIPPED/TRUNCATED (no FAIL/WARN at all) rolled up to a bare PASS and rendered a
    green "clear" headline for a sweep that scanned nothing — the exact opposite of
    the truth. Also: the headline count is `len(sweep.rows)`, not `counts()['total']`
    — `counts()` defines `scanned = rows where status != 'SKIPPED'` and `total =
    len(scanned)`, so a sweep with any SKIPPED row under-reported the installed count
    (the same defect B-268 already fixed once for `_skills_inventory_lines`).
    """
    if sweep is None or sweep.no_roots or sweep.no_targets:
        return []
    icon = _ICON_ASCII if ascii_only else _ICON
    by_name = dict(sweep.findings)
    fail_warn = [(name, status) for name, status, _ev in sweep.rows if status in (FAIL, WARN)]
    not_scanned = [name for name, status, _ev in sweep.rows if status in ("TRUNCATED", "SKIPPED")]
    clean = [name for name, status, _ev in sweep.rows if status == PASS]
    flagged_n = len(fail_warn) + len(not_scanned)
    # UNKNOWN stands in for SKIPPED/TRUNCATED in the rollup -- _worst_of_statuses
    # doesn't recognize those two strings, so without this substitution an
    # all-unscanned sweep (fail_warn empty) rolls up to bare PASS.
    worst_statuses = [s for _n, s in fail_warn] + ([UNKNOWN] * len(not_scanned))
    marker = icon.get(_worst_of_statuses(worst_statuses), "?")
    count_text = f"{flagged_n} flagged" if flagged_n else "clear"
    lines = [f" Plugins ({len(sweep.rows)} installed) — {marker} {count_text}"]
    if not_scanned:
        lines.append(
            f"   {icon.get(UNKNOWN, '?')} {len(not_scanned)} plugin(s) not (fully) "
            "scanned — their verdict is unknown, not clean"
        )
    if compact:
        return lines
    if clean:
        lines.append(f"   {icon.get(PASS, '?')} {len(clean)} clean: "
                     + ", ".join(_sanitize(n) for n in clean))
    for name, status in fail_warn:
        f = by_name.get(name)
        verdict = _VET_VERDICT.get(status, status)
        reason = _sanitize(f.detail) if f is not None and f.detail else verdict
        lines.append(f"   {icon.get(status, '?')} {_sanitize(name)}  {verdict} - {reason}")
    return lines


def _risk_chain_lines(paths, *, ascii_only: bool = False, compact: bool = False,
                      limit: int = 8) -> list[str]:
    """Highest-risk capability-chain lines for the combined pipeline Dashboard
    (F-153). `paths` is the same list[RiskPath] risk.risk_paths() already produces —
    duck-typed on .id/.severity/.title/.chain/.why only, so risk.py need not be
    imported here (report.py already renders RISK-chain text for --risk-paths via
    risk.render_risk_paths, which this deliberately does NOT call: that renderer's
    own "No dangerous capability chains detected" sentence is the RIGHT answer for a
    standalone `--risk-paths` run, but on a combined chat card a clean run is the
    common case, Section 2's own findings already speak to it, and repeating it
    here on every single run would just be more channel-limit noise).

    Returns [] when `paths` is empty — the block is omitted entirely, matching the
    other "nothing to show" blocks. `compact=True` (the --compact Telegram-safe
    layout) drops the chain/why detail lines, keeping one line per chain.
    """
    if not paths:
        return []
    arrow = " -> " if ascii_only else " → "
    shown = paths[:limit]
    lines: list[str] = []
    for p in shown:
        lines.append(f"[{_sanitize(p.severity)}] {_sanitize(p.id)}: {_sanitize(p.title)}")
        if not compact:
            lines.append(f"   chain: {arrow.join(_sanitize(step) for step in p.chain)}")
            lines.append(f"   why: {_sanitize(p.why)}")
    if len(paths) > limit:
        lines.append(f"  (+{len(paths) - limit} more — see --risk-paths)")
    return lines


def _behavioral_block_lines(phase, *, ascii_only: bool = False) -> list[str]:
    """One-paragraph behavioural-replay summary for the combined pipeline Dashboard
    (F-153). `phase` is duck-typed on pipeline.PhaseResult's published surface
    (.ran/.detail/.lines) and is never imported here (pipeline.py already imports
    report.py the other way — report.py importing pipeline.py back would be the
    exact cycle pipeline.py's own module docstring says P6 must not reintroduce).

    Always rendered when `phase` is supplied — never silently omitted, even when
    nothing fired. Golden Rule #4: "not run" / "nothing found" are real answers a
    security tool must say out loud, never leave the reader to read a missing
    section as a clean pass.
    """
    if phase is None:
        return []
    marker = "*" if ascii_only else "•"
    lines = [f"{marker} {_sanitize(phase.detail)}"]
    if phase.ran and any("INCIDENT SIGNAL" in ln for ln in phase.lines):
        lines.append(f"{marker} Full detail: --behavioral / --analyze-trajectory.")
    return lines


def _second_opinion_lines(phase, *, ascii_only: bool = False) -> list[str]:
    """One-paragraph adjudication ("Second opinion (advisory)") summary for the
    combined pipeline Dashboard (F-153). Same duck-typing note as
    _behavioral_block_lines; always rendered when `phase` is supplied."""
    if phase is None:
        return []
    marker = "*" if ascii_only else "•"
    return [f"{marker} {_sanitize(phase.detail)}"]


def _second_opinion_item_lines(phase, *, limit: int = 60) -> list[str]:
    """The PER-ITEM judge verdicts behind the Second-opinion summary count (B-470).

    `_second_opinion_lines` renders one summary line, which is right for a chat-sized
    card. But that count was the ONLY thing rendered anywhere: a mandatory judge fan-out
    over dozens of items produced `86 of 86 borderline item(s) judged` and nothing else,
    in the card AND in the PDF, while SKILL.md promised "real per-item verdicts rather
    than a bare pending count" and "per-item annotations". The rows exist all along on
    the phase (`data["secondOpinion"]`, one dict per item) — nothing consumed them.

    The PDF is the right home: it is the attachment, so it has the room the card does not.
    Bounded, with the drop disclosed (Golden Rule #4 — no silent caps).
    """
    data = getattr(phase, "data", None) or {}
    rows = [r for r in (data.get("secondOpinion") or []) if r.get("judge_verdict")]
    if not rows:
        return []
    lines = []
    for row in rows[:limit]:
        target = row.get("target")
        # A config-scoped item's target IS its finding id; printing "B100 [B100]" is noise.
        where = ("" if not target or str(target) == str(row.get("finding_id"))
                 else f" [{_sanitize(str(target))}]")
        line = (f"  - {_sanitize(str(row.get('finding_id')))}{where}: "
                f"{_sanitize(str(row.get('engine_disposition')))} -> "
                f"{_sanitize(str(row.get('judge_verdict')))}")
        note = row.get("annotation")
        if note:
            line += f" ({_sanitize(str(note))})"
        lines.append(line)
    if len(rows) > limit:
        lines.append(f"  - (+{len(rows) - limit} more judged item(s) not listed)")
    return lines


def _glance_qualifying_findings(findings: list[Finding]) -> list[Finding]:
    """The non-suppressed, MEDIUM/ATTESTED-confidence FAIL/WARN findings —
    render_dashboard_findings's own HIGH-confidence filter excludes exactly this set
    from Section 2 (B-444's `_worth_a_glance_lines` renders it instead, `full=True`
    only). Factored out so `_worth_a_glance_lines` and render_dashboard's own
    count-vs-render disclosure (B-444, `full=False`) share ONE filter rather than two
    that could drift apart on the confidence/suppressed rule."""
    return [
        f for f in findings
        if f.status in (FAIL, WARN)
        and not getattr(f, "suppressed", False)
        and getattr(f, "confidence", "HIGH") in (MEDIUM, ATTESTED)
    ]


def _worth_a_glance_lines(findings: list[Finding], *, ascii_only: bool = False,
                          limit: int = 12, compact: bool = False,
                          why_drop_severities: frozenset = frozenset()) -> list[str]:
    """MEDIUM/ATTESTED-confidence findings for the combined pipeline Dashboard
    (F-153) — the exact complement of render_dashboard_findings's own filter (which
    excludes these from Section 2), so nothing is shown twice and nothing is
    dropped. Reuses _render_finding, the SAME per-finding renderer Section 2 uses,
    so the two blocks stay one system rather than two hand-written formatters that
    can drift apart on why/evidence text or the confidence tag.

    B-381 (PII / CLAUDE.md §8): render_dashboard_findings's HIGH-confidence filter has
    always kept MEDIUM/ATTESTED findings off the --dashboard card; this block is the
    deliberate exception (F-153's "nothing dropped" design) and needs its own guard —
    a MEDIUM-confidence "Native binary PATH safety" finding's `detail` embeds an
    absolute path under the operator's home directory (username included), and this
    card is explicitly designed to be pasted into chat (Telegram et al). Every line is
    passed through `_redact_home_paths` before it is returned; keeping these findings
    (redacted) rather than dropping them entirely was the deliberate call here — this
    section exists specifically so a lower-confidence signal is never silently
    invisible, and that "worth a glance" is genuinely useful (e.g. an over-permissive
    npm-global install dir) even once the path is collapsed to '~'.

    `compact=True` (B-381) also lowers the effective `limit` (the caller passes a
    smaller value) and threads `compact` into `_render_finding`, same trims Section 2
    applies under --compact — this block is unbounded by FAIL/WARN family structure,
    so a bad config with many MEDIUM/ATTESTED findings could otherwise blow the
    Telegram ~4096-char budget on its own. `why_drop_severities` (B-405) threads the
    same final-budget-enforcement drop set Section 2 gets — see
    `render_dashboard_findings`'s docstring.
    """
    qualifying = _glance_qualifying_findings(findings)
    if not qualifying:
        return []
    qualifying.sort(key=lambda f: (_STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9)))
    lines: list[str] = []
    for f in qualifying[:limit]:
        raw: list[str] = []
        _render_finding(raw, f, cfg=None, ascii_only=ascii_only, compact=compact,
                        why_drop_severities=why_drop_severities)
        lines.extend(_redact_home_paths(ln) for ln in raw)
    if len(qualifying) > limit:
        lines.append(f"(+{len(qualifying) - limit} more)")
    return lines


def _finalize_compact_dashboard(assemble, *, compact: bool, ascii_only: bool) -> str:
    """B-405: render_dashboard's hard budget enforcement.

    `assemble(why_drop_severities)` builds the full (non-asciified) card for a given
    drop set; this wrapper renders it, applies `_asciify` when requested (the length
    check below runs on the ACTUAL final string the caller emits, not a pre-ascii
    proxy for it — `_asciify` can change length, e.g. "…" -> "..."), and — only when
    `compact=True` — retries with a progressively more aggressive drop set from
    `_COMPACT_WHY_DROP_LEVELS` until the result fits `_COMPACT_CHAR_BUDGET`. If the
    most aggressive level still doesn't fit, `_hard_truncate_compact` is the
    deterministic last resort that guarantees the return value is never over budget.

    `compact=False` (every pre-existing caller) calls `assemble()` exactly once and
    returns it untouched — byte-identical to the pre-B-405 behaviour.
    """
    def _final(why_drop_severities: frozenset = frozenset()) -> str:
        out = assemble(why_drop_severities)
        return _asciify(out) if ascii_only else out

    result = _final()
    if not compact or len(result) <= _COMPACT_CHAR_BUDGET:
        return result
    for drop_set in _COMPACT_WHY_DROP_LEVELS:
        result = _final(drop_set)
        if len(result) <= _COMPACT_CHAR_BUDGET:
            return result
    return _hard_truncate_compact(result, _COMPACT_CHAR_BUDGET)


# ── C-373: the default chat card is an OVERVIEW, not the full findings dump ──────────
#
# Measured on dev@2a78be6: plain `--dashboard` rendered 7225 chars on fixtures/home_vuln
# and 3946 on the CLEAN fixtures/home_safe, against the ~4096 chars a Telegram message
# holds — and the B-381/B-405 budget machinery was unreachable there (`--compact` is a
# no-op without `--full`, so the one output SKILL.md tells the host agent to paste had no
# size control at all). The card now leads with the per-subject overview, names only the
# most urgent findings, and routes full detail to the attachable PDF report.
_CARD_TOP_URGENT = 5
# Longest finding title the card prints, so one long title cannot drive the card's size.
_CARD_TITLE_LIMIT = 78
# Reduction ladder if the card still doesn't fit: fewer named findings, never the
# overview or the where-is-the-detail pointer (those are what make the card useful at
# all). `_hard_truncate_compact` stays the deterministic last resort.
_CARD_TOP_URGENT_LEVELS = (_CARD_TOP_URGENT, 3, 0)
# Most clean skill names the card's Skills block lists by name before collapsing the
# rest to a "+N more" count (see _skills_inventory_lines' clean_roster_limit).
_CARD_CLEAN_SKILLS = 10


def _card_trim_title(title: str, limit: int = _CARD_TITLE_LIMIT) -> str:
    """Word-boundary trim for a card title line. Never raises; returns *title* unchanged
    when it already fits."""
    t = _sanitize(title)
    if len(t) <= limit:
        return t
    cut = t[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return (cut or t[:limit]) + "…"


def _card_summary_lines(findings, ctx, *, plugin_sweep=None, ascii_only: bool = False) -> list[str]:
    """Per-subject overview lines for the chat card — built from the SAME
    `_subject_summary_rows` the HTML and PDF summary tables use, so all three surfaces
    (and the JSON `inventory`) can never disagree. Returns [] when `ctx` is unavailable,
    the same skip-don't-guess stance `render_subject_inventory` already takes."""
    rows = _subject_summary_rows(findings, ctx, plugin_sweep=plugin_sweep)
    if not rows:
        return []
    icon = _ICON_ASCII if ascii_only else _ICON
    # Label -> subject key, so each row can carry its subject emoji. Chat-paste only:
    # the CLI report / HTML / PDF subject headers stay emoji-less by design.
    key_of = {label: key for key, label in SUBJECT_LABEL.items()}
    out = []
    for label, status, count_text in rows:
        marker = icon.get(status, icon.get(UNKNOWN, "?"))
        emoji = "" if ascii_only else f"{_SUBJECT_EMOJI.get(key_of.get(label), '')} "
        out.append(f" {emoji}{label} — {marker} {count_text}")
    return out


def _card_top_urgent_lines(findings, *, limit: int = _CARD_TOP_URGENT,
                           ascii_only: bool = False) -> tuple[list[str], int]:
    """The most urgent findings as ONE line each (severity token + trimmed title, no
    `why:` and no evidence bullets — that is what the PDF is for).

    Draws from the same qualifying set `render_dashboard_findings` renders
    (non-suppressed FAIL/WARN, excluding MEDIUM/ATTESTED confidence) and sorts it the
    same way, so the card's "most urgent" and the full block agree on what is worst.
    Returns `(lines, n_named)`; the caller reconciles `n_named` against the header's own
    issue count and DISCLOSES the difference (Golden Rule #4 — a card that quietly names
    5 of 26 findings would read as a complete list)."""
    qualifying = [
        f for f in findings
        if f.status in (FAIL, WARN)
        and not getattr(f, "suppressed", False)
        and getattr(f, "confidence", "HIGH") not in (MEDIUM, ATTESTED)
    ]
    qualifying.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), _STATUS_ORDER.get(f.status, 9)))
    named = qualifying[:limit] if limit else []
    lines = [
        f"{_sev_token(f.severity, ascii_only=ascii_only)}  {_card_trim_title(f.title)}"
        for f in named
    ]
    return lines, len(named)


def _card_detail_pointer_lines(n_more: int, pdf_path=None, *, ascii_only: bool = False,
                               full: bool = False) -> list[str]:
    """Where the rest of the detail is. Two jobs: disclose how many findings the card did
    NOT name, and point at the full report.

    B-468: this text is PASTED VERBATIM into a chat by the host agent, so it may contain
    only what a human reader should see. It used to carry the absolute report path and the
    line "Attach that PDF file itself into the chat; do not paste its path or re-render its
    contents" — an instruction aimed at the agent, sitting inside the very block the agent
    is ordered to reproduce word for word. That is a contradiction the model has to resolve
    on its own, and the observed resolution was the one this project least wants: a real
    session where the agent handed the user a link, twice, before ever attaching the file.
    The path and the instruction now go to stderr (cli.py), which is the agent's channel;
    the card states only that the report is attached."""
    lines: list[str] = []
    # Under --full the PDF additionally carries the pipeline blocks (Skills/Plugins/MCP/
    # RISK chains/Behavioural/Second opinion/Coverage/Worth a glance) — say so, so the
    # reader knows the attachment is the whole run, not just a findings list.
    full_pipeline = (", plus the skills/plugins/MCP, RISK-chain, behavioural,"
                     " second-opinion and coverage blocks") if full else ""
    if n_more > 0:
        word = "finding" if n_more == 1 else "findings"
        lines.append(f"(+{n_more} more {word} not named above — the full list is in the report.)")
    if pdf_path:
        lines.append(f"Full detail — every finding, with its why and evidence{full_pipeline}"
                     " — is in the attached PDF report.")
    else:
        lines.append("For the full detail, re-run with `--pdf <path>` (an attachable report)"
                     " — or `--save <path>` / `--html <path>`.")
    return lines


def _finalize_card(assemble_with_limit, *, ascii_only: bool) -> str:
    """Hard budget guarantee for the default chat card (C-373).

    Unlike `_finalize_compact_dashboard` (whose ladder drops `why:` lines, which this
    card does not have), the card reduces by naming FEWER findings — the per-subject
    overview and the detail pointer are never what gets dropped, since a card without
    them is a grade and nothing else. `_hard_truncate_compact` remains the deterministic
    last resort, so the return value is never over budget on any input."""
    out = ""
    for limit in _CARD_TOP_URGENT_LEVELS:
        out = assemble_with_limit(limit)
        out = _asciify(out) if ascii_only else out
        if len(out) <= _COMPACT_CHAR_BUDGET:
            return out
    return _hard_truncate_compact(out, _COMPACT_CHAR_BUDGET)


def render_dashboard(findings: list[Finding], score: ScoreResult, *,
                     ascii_only: bool = False, ctx=None, full: bool = False,
                     risk=None, plugin_sweep=None, behavioral=None,
                     adjudication=None, compact: bool = False, pdf_path=None) -> str:
    """Deterministic chat Dashboard card — Sections 1-2 of SKILL.md Step 3, pasted verbatim,
    plus an optional Section 3 (B-356) with per-skill vet verdicts, plus (F-153) the rest
    of --full's pipeline when `full=True`.

    Live testing (F-070) showed the host LLM silently drops the 🦞 header and the family
    frame when asked to *compose* them, so the whole card is code-rendered (B-077): grade
    card + score-bar + issue count, then the framed findings block. Reports-only (F-074):
    the card names what is wrong and why — it carries no remediation and no fix offers.
    The host agent pastes this output and only writes its own prose *around* it.

    B-356: `--full`'s per-skill sweep (v3.57.0) never reached this card, so a user going
    through the normal guided flow never saw it. `ctx` is optional and additive — passing
    None (every pre-existing caller) reproduces the exact prior Sections 1-2 output,
    byte-identical. When `ctx` carries installed skills, a compact "Skills" section is
    appended below Findings, reusing the SAME per-skill verdict lines
    (`_skills_inventory_lines`) the full report's "Inventory by subject" block already
    shows — one source of truth, not a second formatter to drift out of sync.

    F-153: `full=False` (every pre-existing caller, and every `--dashboard` invocation
    that doesn't also pass `--full`) reproduces Sections 1-2 plus the optional Skills
    block, nothing else. (B-444 superseded the "byte-identical" claim this docstring
    used to make here in two deliberate ways: the header now always routes through
    `brand.header()` — bug B, the wordmark was missing — and Section 2 appends a
    "(+N more — run --full for the rest)" disclosure line whenever `n_issues` counts
    MEDIUM/ATTESTED-confidence FAIL/WARN findings that `render_dashboard_findings`
    excludes and `full=False` never reaches `_worth_a_glance_lines` to show instead —
    bug A, the header count and the render used to silently disagree.) Dave settled
    2026-07-30
    that `--dashboard` must fully render everything `--full` does rather than the
    additive-append shape `--full` itself grew first (F-150/F-151/F-152); this is that
    render, reached only via `--dashboard --full`. The fixed order is: Skills (vet) ·
    Plugins (vet) · MCP · RISK chains · Behavioural · "Second opinion (advisory)" ·
    Coverage · "Worth a glance" — each block independently omitted when there is
    genuinely nothing to show for it (Plugins/MCP/RISK chains), except Behavioural and
    Second opinion, which — per Golden Rule #4 — are shown whenever a phase result was
    supplied, even to report "nothing fired". `risk`/`plugin_sweep`/`behavioral`/
    `adjudication` are each independently optional: a caller that skipped a phase
    (`--fast`, or the phase's own budget) passes None for it and only that ONE block
    drops, mirroring the pre-existing `ctx=None` contract for Skills. This function
    never triggers any of that computation itself — cli.py computes each phase once,
    the same functions `--full` already uses, and hands the results in; nothing here
    re-scans anything, so calling this with `full=True` costs only string formatting
    over data the caller already has.

    `compact=True` is ClawSecCheck's Telegram-safe ~4096-char layout (F-153 point 3;
    the spec's suggested flag name `--card` was already taken by the pre-existing
    shareable-badge flag, so the CLI flag is `--compact`). It trims the Plugins/MCP/
    RISK-chain blocks to headline counts only and appends a save-to-file pointer;
    Skills, Behavioural, Second opinion and Coverage are already short (a handful of
    lines) and unaffected.

    B-381: Section 2 (Findings) is NOT one of the short/unaffected sections above — it
    scales with FAIL/WARN count, exactly what a bad config has many of, and measured
    out as the actual driver of --compact missing its own ~4096-char budget (5058/7551
    chars measured for a clean/bad home before this fix, against a documented ~4096
    target Telegram itself enforces). `compact=True` now also threads into
    `render_dashboard_findings` (trims each finding's "why" text and drops evidence
    bullets, narrows the family frame's border rule) and into `_worth_a_glance_lines`
    (lower `limit`, same per-finding trim) — see `_COMPACT_WHY_LIMIT`'s own comment for
    the tuned value and the fixtures it was measured against.

    B-405: the per-item trims above were tuned against two fixtures and are NOT a hard
    guarantee — a real config with more FAIL/WARN findings than either fixture still
    busted the ~4096 budget (5641 chars measured against a real fleet config). When
    `compact=True`, this function now enforces `_COMPACT_CHAR_BUDGET` on the actual
    final rendered string (post-`_asciify`) as a hard cap: if the first render is over
    budget, it retries with `_COMPACT_WHY_DROP_LEVELS` (dropping whole why-lines,
    weakest severity first) until it fits, and if even the most aggressive level still
    doesn't fit, `_hard_truncate_compact` deterministically cuts the string to the
    budget as an absolute last resort. `full=False` output is included in this
    enforcement too (Section 2 alone can already be large); the byte-identical
    guarantees above still hold whenever `compact=False` (the default), since the
    budget loop is a no-op in that case.
    """
    findings = deduplicate_findings(findings)
    n_issues = sum(
        1 for f in findings
        if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)
    )
    # Both separators used to be different characters (an em-dash for the "Audit —
    # Grade"/"— Findings —" spots, a middle-dot for the "Grade F · 49/100" spot) — a
    # visible drift within the same string. One brand separator everywhere now.
    sep = brand.ASCII_SEPARATOR.strip() if ascii_only else brand.SEPARATOR.strip()
    issues_word = "issue" if n_issues == 1 else "issues"
    # B-444 bug B: this used to hand-assemble "{mascot}OpenClaw Security Audit" as an
    # f-string, bypassing brand.header() entirely -- so brand.WORDMARK ("ClawSecCheck")
    # never reached the single most-seen surface (the card a host agent pastes into
    # chat), unlike render_report's header (which already routes through
    # brand.header()). Routing through brand.header() here keeps all three brand tiers
    # consistent and, since brand.header() itself drops the mascot under ascii_only,
    # the wordmark still lands on the ascii path (mascot alone used to become empty
    # there with nothing to replace it).
    head = brand.header(subtitle="OpenClaw Security Audit", ascii_only=ascii_only)
    grade_lines = [
        f"{head} {sep} Grade {score.grade} {sep} {score.score}/100",
        f"{_score_bar(score.score, score.grade, ascii_only=ascii_only)}"
        f"  {sep}  {n_issues} {issues_word}",
    ]
    # B-465 / B-467: the card is the ONLY artifact SKILL.md tells the agent to paste, and it
    # was the one renderer that dropped WHY the grade is what it is. Two measured shapes:
    # a directory with no OpenClaw in it produced a confident `Grade F · 49/100 · 4 issues`
    # (a failing verdict on a setup the tool never located), and a submitted liveTest
    # VULNERABLE self-report took home_safe from `Grade A · 97/100` to `Grade F · 49/100`
    # over the same 11 findings with no explanation anywhere in the card. The terminal
    # report has disclosed both all along, through this exact shared cascade — the card
    # simply never called it. Golden Rule #4.
    _mark = "!" if ascii_only else "⚠️"
    _cap_primary, _cap_extras = _cap_cascade(score)
    if _cap_primary is not None:
        grade_lines.append(
            f"{_mark} capped from {score.raw_score}/100 — "
            f"{_cap_primary_reason_text(_cap_primary, score)}{_cap_also_clause(_cap_extras)}"
        )
    if getattr(score, "config_blind_capped", False):
        grade_lines.append(
            "   This grade reflects what could NOT be checked, not a verdict on your "
            "setup — point --home at the directory that holds your OpenClaw config."
        )
    # `--full` keeps its existing header (grade card + the "· Findings ·" section label
    # immediately below); the C-373 default card opens with the grade lines only and
    # labels its own sections as it goes.
    header_block = "\n".join([*grade_lines, "", f"{sep} Findings {sep}"]) + "\n"
    card_header_block = "\n".join(grade_lines) + "\n"

    # Skills is a fixed block (unaffected by why_drop_severities): computed once.
    inv = None
    skills_block = ""
    card_skills_block = ""
    if ctx is not None:
        inv = build_inventory(findings, ctx, plugin_sweep=plugin_sweep)
        if inv["skills"]:
            skill_lines = _skills_inventory_lines(inv, ctx, ascii_only=ascii_only)
            skills_block = "\n" + f"{sep} Skills {sep}" + "\n" + "\n".join(skill_lines) + "\n"
            # C-373: the card caps the clean roster (the one unbounded part — see
            # _skills_inventory_lines); flagged skills are always named in full, since
            # those are the ones the reader has to act on.
            card_skill_lines = _skills_inventory_lines(
                inv, ctx, ascii_only=ascii_only, clean_roster_limit=_CARD_CLEAN_SKILLS)
            card_skills_block = ("\n" + f"{sep} Skills {sep}" + "\n"
                                 + "\n".join(card_skill_lines) + "\n")

    # C-374: `--dashboard --full --pdf <path>` ALSO renders the overview card. Under
    # `--full` the PDF now carries the whole pipeline (Skills/Plugins/MCP/RISK/
    # Behavioural/Second opinion/Coverage/Worth a glance), so collapsing the card no
    # longer hides anything — it moves it into the attachment. Without `--pdf`, `--full`
    # still renders every block inline: nothing becomes unreachable just because the
    # user didn't ask for a file.
    if not full or pdf_path:
        # C-373: the default card is an OVERVIEW — grade, the per-subject inventory, and
        # only the most urgent findings by name; the full findings list (with why and
        # evidence) lives in the PDF report this run may have written. The old shape
        # pasted the entire grouped findings block and measured 7225 chars against
        # Telegram's ~4096 (see _CARD_TOP_URGENT's comment). `--dashboard-findings` still
        # prints the complete grouped block for anyone who wants it inline, and
        # `--dashboard --full` still renders the whole pipeline.
        #
        # Disclosure (Golden Rule #4, the B-444 lesson): `n_issues` counts EVERY
        # non-suppressed FAIL/WARN, while the named lines come from the HIGH-confidence
        # subset. The pointer block reconciles the two out loud ("+N more not named
        # above") instead of letting the header count and the rendered list silently
        # disagree — and every one of those N IS in the PDF, which renders all
        # FAIL/WARN regardless of confidence.
        summary_lines = _card_summary_lines(findings, ctx, plugin_sweep=plugin_sweep,
                                            ascii_only=ascii_only)
        ok = "[OK]" if ascii_only else "✅"

        def _assemble_card(limit: int) -> str:
            top_lines, n_named = _card_top_urgent_lines(
                findings, limit=limit, ascii_only=ascii_only)
            out = card_header_block
            if summary_lines:
                out += ("\n" + f"{sep} Inventory by subject {sep}" + "\n"
                        + "\n".join(summary_lines) + "\n")
            if top_lines:
                out += ("\n" + f"{sep} Most urgent {sep}" + "\n"
                        + "\n".join(top_lines) + "\n")
            elif n_issues == 0:
                out += f"\nNo known attack pattern matched. Keep it that way. {ok}\n"
            out += ("\n" + "\n".join(_card_detail_pointer_lines(
                n_issues - n_named, pdf_path, ascii_only=ascii_only, full=full)) + "\n")
            return out + card_skills_block

        return _finalize_card(_assemble_card, ascii_only=ascii_only)

    # F-153: the rest of --full's pipeline, fixed order, each block independently
    # omitted when there is genuinely nothing to show for it (see the docstring).
    # None of these depend on why_drop_severities, so they're computed once, outside
    # the budget-retry loop below.
    tail_block = ""
    plugin_lines = _plugins_inventory_lines(plugin_sweep, ascii_only=ascii_only, compact=compact)
    if plugin_lines:
        tail_block += "\n" + f"{sep} Plugins {sep}" + "\n" + "\n".join(plugin_lines) + "\n"

    if inv is not None and inv["mcp"]:
        mcp_lines = _mcp_inventory_lines(inv, ascii_only=ascii_only, compact=compact)
        tail_block += "\n" + f"{sep} MCP {sep}" + "\n" + "\n".join(mcp_lines) + "\n"

    risk_lines = _risk_chain_lines(risk or [], ascii_only=ascii_only, compact=compact)
    if risk_lines:
        tail_block += "\n" + f"{sep} RISK Chains {sep}" + "\n" + "\n".join(risk_lines) + "\n"

    behavioral_lines = _behavioral_block_lines(behavioral, ascii_only=ascii_only)
    if behavioral_lines:
        tail_block += "\n" + f"{sep} Behavioural {sep}" + "\n" + "\n".join(behavioral_lines) + "\n"

    second_opinion_lines = _second_opinion_lines(adjudication, ascii_only=ascii_only)
    if second_opinion_lines:
        tail_block += ("\n" + f"{sep} Second opinion (advisory) {sep}" + "\n"
               + "\n".join(second_opinion_lines) + "\n")

    coverage_lines = _coverage_lines(findings, ascii_only=ascii_only)
    if coverage_lines:
        tail_block += "\n" + "\n".join(coverage_lines) + "\n"

    glance_marker = "" if ascii_only else "👀 "
    footer_block = "\nFull pipeline detail: --save <path> or --html <path>.\n" if compact else ""

    def _assemble(why_drop_severities: frozenset = frozenset()) -> str:
        body = render_dashboard_findings(
            findings, ascii_only=ascii_only, compact=compact,
            why_drop_severities=why_drop_severities).rstrip("\n")
        out = header_block + body + "\n" + skills_block + tail_block

        # B-381: --compact also tightens the "Worth a glance" limit (12 -> 6) -- this
        # block is unbounded by family structure, so a bad config with many MEDIUM/
        # ATTESTED findings could blow the char budget on its own even after Section 2
        # is trimmed.
        glance_lines = _worth_a_glance_lines(
            findings, ascii_only=ascii_only, limit=6 if compact else 12, compact=compact,
            why_drop_severities=why_drop_severities)
        if glance_lines:
            out += ("\n" + f"{sep} {glance_marker}Worth a glance {sep}" + "\n"
                   + "\n".join(glance_lines) + "\n")

        # C-373: `--dashboard --full --pdf <path>` wrote an attachable report this run —
        # say so here rather than letting cli.py print a note the host agent would paste
        # along with the card. n_more is 0: the full card already renders every finding,
        # so this is purely "the attachment exists", not a truncation disclosure.
        if pdf_path:
            out += "\n" + "\n".join(
                _card_detail_pointer_lines(0, pdf_path, ascii_only=ascii_only)) + "\n"

        return out + footer_block

    return _finalize_compact_dashboard(_assemble, compact=compact, ascii_only=ascii_only)


def render_card(score: ScoreResult, findings: list[Finding], ascii_only: bool = False) -> str:
    """Shareable badge — grade + score + trifecta ONLY. No findings, ever."""
    l1 = f"  OpenClaw Security: {score.grade:<2} ({score.score:>3}/100)"
    l2 = f"  Lethal Trifecta: {_trifecta_ratio(findings)}"
    l3 = "  audited by ClawSecCheck" + ("" if ascii_only else f" {brand.MASCOT}")
    width = 39
    # Mascot header line, once (design-system Foundations); --ascii drops it to
    # stay pure-ASCII, matching render_dashboard's convention.
    header = "" if ascii_only else f"{brand.header()}\n"
    if ascii_only:
        top = bot = "+" + "-" * width + "+"
        body = "\n".join(f"|{ln:<{width}}|" for ln in (l1, l2, l3))
        return _asciify(f"{top}\n{body}\n{bot}")
    top = "┌" + "─" * width + "┐"
    bot = "└" + "─" * width + "┘"
    # the mascot emoji is double-width in many terminals; pad l3 one less
    body = "\n".join([
        f"│{l1:<{width}}│",
        f"│{l2:<{width}}│",
        f"│{l3:<{width - 1}}│",
    ])
    return f"{header}{top}\n{body}\n{bot}"


def _header_rule_width(header_line: str, ascii_only: bool) -> int:
    """Rule width for a mascot header line: long enough to span the header text
    plus a one-column buffer, accounting for MASCOT rendering as a double-width
    column in most terminals even though it is a single Python character.

    A hardcoded rule width (the previous approach) under-runs once the header
    carries the mascot — this derives it from the actual line instead, so it
    stays correct if the subtitle text ever changes too.
    """
    width = len(header_line)
    if not ascii_only and brand.MASCOT in header_line:
        width += 1
    return width + 1


def render_monitor(alerts, score: ScoreResult, ascii_only: bool = False,
                   baseline: bool = False, persisted: bool = True,
                   baseline_corrupt: bool = False, live_test_skipped: bool = False) -> str:
    """Render the --monitor body.

    *baseline* — this was a genuine first run (no prior state file at all).

    *persisted* — B-271: the new baseline was actually written to disk. When it was NOT,
    every affirmation this function makes is false, so both of them are withheld: "Baseline
    saved." is a direct lie, and "No new threats since last check ✅" reads as an all-clear
    for ongoing monitoring that is not in fact running. Alerts computed this run ARE still
    real (the comparison happened against a real baseline) and are still shown; the CLI
    prints the failure verdict on stderr and exits non-zero.

    *baseline_corrupt* — B-270: a prior baseline existed but could not be used. This is
    NOT a first run (saying "Baseline saved." there is what made a destroyed baseline look
    like a healthy new one) and NOT a clean comparison. The CLI supplies the explanatory
    alert itself, so that one string reaches the screen and the journal identically; all
    this flag adds is the closing note that a replacement baseline now exists — which is
    printed only when it actually got written.

    *live_test_skipped* — B-379: the F-155 seed gate deliberately excluded this run from
    the journal/baseline (an unseeded/unreproducible VULNERABLE verdict), NOT a write
    failure — `persisted` is False here too (nothing WAS written), but the CLI does not
    treat this as an error (no stderr, exit 0), so this function must not read `persisted=
    False` alone as "the write failed" the way it otherwise would. When True, an explicit
    "not persisted because..." line replaces the generic silence `persisted=False` would
    otherwise produce, so the reader is told WHY rather than left to infer a crash.

    All four default to the pre-B-270/B-271/B-379 behaviour, so existing callers are
    unchanged.
    """
    # LOW is a real catalog severity and must outrank INFO: a LOW check that regressed to
    # FAIL is a security finding, while INFO is an informational counter. Omitting it made
    # a LOW alert render with no glyph and sort as though it were the least important line
    # in the report.
    mark = {"CRITICAL": "[X]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[i]"} \
        if ascii_only \
        else {"CRITICAL": "⛔", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "⚪", "INFO": "ℹ️"}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ok = "[OK]" if ascii_only else "✅"
    head = brand.header(subtitle="Threat Monitor", ascii_only=ascii_only)
    lines = [head, "=" * _header_rule_width(head, ascii_only),
             f"Current: {score.score}/100  Grade: {score.grade}"]
    def _alert_lines() -> list:
        out = ["", f"{len(alerts)} change(s) detected since last check:", ""]
        for level, msg in sorted(alerts, key=lambda a: order.get(a[0], 9)):
            out.append(f"{mark.get(level, '[*]')} {_sanitize(msg)}")
        return out

    if not persisted:
        # B-271: nothing was written, so make no claim about the baseline either way.
        if alerts:
            lines += _alert_lines()
        if live_test_skipped:
            # B-379: distinguish "deliberately not persisted" from "write failed" —
            # the CLI does not treat this as an error, and neither should this text.
            lines += ["", "Not persisted: this run's grade was capped by an unseeded "
                          "(unreproducible) live injection-test verdict — recording it "
                          "would manufacture drift where none exists. Re-run without a "
                          "seed-less verdict, or with a seeded one, to resume monitoring."]
    elif baseline:
        lines += ["", "Baseline saved. Future runs will alert on what changes since now."]
    else:
        if alerts:
            lines += _alert_lines()
        else:
            lines += ["", f"No new threats since last check. {ok}"]
        if baseline_corrupt:
            lines += ["", "A replacement baseline has been saved from this run; future "
                          "runs will alert on what changes since now."]
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def render_events(events, ascii_only: bool = False) -> str:
    """Render the Agent Watch event journal (timeline of what changed when).

    C-250: the header used to print "{len(events)} recorded change event(s)" with no
    hint that ``monitor._rotate_journal`` may have already evicted up to 1002 older
    entries — an authoritative-sounding total that silently started mid-history. When
    the oldest entry is a retention marker (``retention_pruned`` key — always the
    OLDEST surviving entry, since rotation prepends it fresh each time it triggers —
    see ``_rotate_journal``), it is pulled out of the generic per-line loop and folded
    into the header itself instead of rendered as one more anonymous [i] line a reader
    can scroll past without registering what it means.
    """
    # Same severity vocabulary as render_monitor — a journal entry written at LOW must not
    # lose its glyph on the way into the permanent record.
    mark = {"CRITICAL": "[X]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[i]"} \
        if ascii_only \
        else {"CRITICAL": "⛔", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "⚪", "INFO": "ℹ️"}
    if not events:
        out = "Agent Watch journal\n" + "=" * 30 + "\n\nNo recorded change events yet.\n"
        return _asciify(out) if ascii_only else out

    pruned_note = None
    body = events
    if isinstance(events[0], dict) and "retention_pruned" in events[0]:
        pruned_note = events[0]
        body = events[1:]

    header = f"showing {len(body)} event(s) (most recent last)"
    if pruned_note is not None:
        header += f" — {_sanitize(str(pruned_note.get('message', '')))}"
    lines = ["Agent Watch journal", "=" * 30, header + ":", ""]
    for e in body:
        ts = str(e.get("ts", "?"))
        lvl = str(e.get("level", "INFO"))
        msg = _sanitize(str(e.get("message", "")))
        lines.append(f"{mark.get(lvl, '[*]')} {ts}  {msg}")
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


# The badge's mascot mark: a scaled-down nested-<svg> instance of brand.LOGO_SVG's own
# vector paths — NOT the 🦞 mascot glyph. An emoji would break the badge's ASCII-safety
# guarantee (test_features.py's `svg.encode("ascii")`), since shields.io-style badges
# are meant to be embeddable byte-for-byte in Markdown/HTML without an encoding
# declaration. Deriving the icon from LOGO_SVG's own markup (rather than hand-drawing a
# second glyph) means it can never drift from brand.py: if the mark's paths ever change,
# this updates for free.
_LOGO_TAG_RE = re.compile(r"^<svg[^>]*>(.*)</svg>$", re.DOTALL)
_LOGO_MATCH = _LOGO_TAG_RE.match(LOGO_SVG.strip())
_LOGO_INNER = _LOGO_MATCH.group(1) if _LOGO_MATCH else ""  # "" degrades to no icon, never a crash
_LOGO_SIZE = 14  # px — fits the badge's 20px height with a few px of margin


def render_svg(score: ScoreResult, findings: list[Finding]) -> str:
    """A shields.io-style SVG badge (grade + score, plus a suppressed-critical marker —
    never finding details). Carries a small mark derived from brand.LOGO_SVG — Tier 3
    (HTML/badge-only) per brand.py's reach split: a graphical mark cannot reach a chat
    channel, only this static file."""
    label = "OpenClaw Security"
    value = f"{score.grade} {score.score}/100"
    # B-163: if a score-capping CRITICAL/HIGH FAIL (or sensitive id) was hidden via
    # .clawseccheckignore, the badge must not read as a clean grade — mark it so a shared
    # badge can't misrepresent the real posture. Count only (never finding details).
    n_hidden = sum(1 for f in findings if surfaced_despite_suppression(f))
    if n_hidden:
        value += f" *{n_hidden} suppressed"
    color = grade_hex(score.grade)
    icon_w = _LOGO_SIZE + 8 if _LOGO_INNER else 0  # icon + left/right padding; 0 if unavailable
    lw = 8 + len(label) * 6 + icon_w  # rough text widths
    vw = 8 + len(value) * 7
    w = lw + vw
    icon = ""
    if _LOGO_INNER:
        icon_y = (20 - _LOGO_SIZE) / 2
        icon = (
            f'<svg x="4" y="{icon_y:.0f}" width="{_LOGO_SIZE}" height="{_LOGO_SIZE}" '
            f'viewBox="0 0 64 64">{_LOGO_INNER}</svg>'
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
        f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<rect rx="3" width="{w}" height="20" fill="#555"/>'
        f'<rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect rx="3" width="{w}" height="20" fill="url(#s)"/>'
        f'{icon}'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{(icon_w + lw) / 2:.0f}" y="14">{label}</text>'
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
            "surface": _meta.surface if _meta is not None else "",
            "not_applicable": bool(getattr(f, "not_applicable", False))}


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
    out = "\n".join(lines)
    # B-484: this renderer read `ascii_only` for its icon table and its `dash` variable and
    # then emitted hardcoded em dashes anyway (the verdict headline, the CAUTION fallback),
    # plus whatever unicode a finding's own text carries — so `--advise --ascii` was the one
    # mode that still printed raw unicode. Same closing guard every other renderer here ends
    # with, so nothing depends on remembering to use `dash`.
    return asciify(out) if ascii_only else out


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
                ctx=None, skill_sweep: dict | None = None, plugin_sweep=None,
                live_test_vulnerable: bool = False, live_test_reason: str | None = None,
                behavioral_fired_ids=frozenset()) -> str:
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
        # I-025/B-309: whether a corroborated runtime signal (never a config-static
        # finding) drove this cap, and which — see scoring.RUNTIME_SIGNAL_CAP.
        "runtime_capped": score.runtime_capped,
        "runtime_cap_reason": score.runtime_cap_reason,
        # B-306 (C-135 follow-up): true when openclaw.json was unreadable/unparseable
        # this run and that alone hard-capped the grade — see scoring.CONFIG_BLIND_CAP.
        # B-363: also true when openclaw.json was simply ABSENT (no target found at
        # all) — `config_blind_reason` ("unreadable" | "absent" | null) distinguishes
        # the two states without a JSON consumer having to re-derive it from config_found.
        "config_blind_capped": score.config_blind_capped,
        "config_blind_reason": getattr(score, "config_blind_reason", None),
        # B-313/B-399: true when a check that could not reach a reliable verdict this run
        # (crashed, timed out, or hit an engine-side-degraded UNKNOWN — Finding.id
        # prefixed "ERR:", or any UNKNOWN finding with engine_degraded=True) alone
        # hard-capped the grade — see scoring.DEGRADED_CHECK_CAP. `degraded_count` is
        # unconditional (checks did/didn't reach a verdict this many times) even when this
        # bool is False because a tighter cap won.
        "degraded_capped": getattr(score, "degraded_capped", False),
        "degraded_count": getattr(score, "degraded_count", 0),
        # F-155: true when a submitted VULNERABLE live injection-test verdict (canary/
        # dryrun/redteam/multiturn, via --judged-bundle's "liveTest" bucket) alone
        # hard-capped the grade — see scoring.LIVE_INJECTION_CAP. RESISTANT or no
        # submission at all always leaves this False (self-attestation guard).
        "live_injection_capped": getattr(score, "live_injection_capped", False),
        "live_injection_cap_reason": getattr(score, "live_injection_cap_reason", None),
        # F-154: true when a fired T1/T2/T3/B191 behavioral detector (--behavioral or
        # --full, which already runs the analysis) alone hard-capped the grade — see
        # scoring.BEHAVIORAL_SIGNAL_CAP. Always False when the analysis never ran this
        # invocation (the default — a plain audit never sets it).
        "behavioral_capped": getattr(score, "behavioral_capped", False),
        "behavioral_cap_reason": getattr(score, "behavioral_cap_reason", None),
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
    # B-379: thread the SAME cap inputs `score` (above) was computed with, so
    # projection.current can never disagree with the top-level score/grade for a
    # capped run — see this function's `behavioral_fired_ids`/`live_test_*` params.
    payload["projection"] = _project(
        findings, ctx,
        live_test_vulnerable=live_test_vulnerable, live_test_reason=live_test_reason,
        behavioral_fired_ids=behavioral_fired_ids,
    )
    # B-166: config read/parse state is machine-visible. A broken openclaw.json must not
    # read as a silent all-clear — config_parse_error is a clean gating boolean and errors
    # carries the human-readable parse message(s) that were previously only in the text run.
    payload["config_found"] = bool(getattr(ctx, "config_found", False)) if ctx is not None else False
    # B-281 (ENV-1): WHICH file was audited, not merely whether one was found. Every
    # verdict in this payload describes exactly this path; a bare `config_found: true`
    # let a report about a stale, dormant config read as a report about the live agent.
    _audited = getattr(ctx, "config_path", None) if ctx is not None else None
    payload["audited_config_path"] = str(_audited) if _audited is not None else None
    payload["config_parse_error"] = bool(getattr(ctx, "config_parse_error", False)) if ctx is not None else False
    # B-306 safe-symlink split: machine-visible so a JSON consumer can tell a benign
    # dotfiles relocation (config followed + audited) from a genuinely dark config. The
    # reason string is a plain diagnostic, never a secret/path value.
    payload["config_symlink_escapes_home"] = bool(getattr(ctx, "config_symlink_escapes_home", False)) if ctx is not None else False
    _cfg_reason = getattr(ctx, "config_parse_reason", None) if ctx is not None else None
    payload["config_parse_reason"] = _sanitize(_cfg_reason) if _cfg_reason else None
    payload["errors"] = [_sanitize(e) for e in getattr(ctx, "errors", [])] if ctx is not None else []
    # F-131 Phase 1: "Inventory by subject" — additive top-level key (design §4.6).
    # Presentation-only: never alters score/grade/findings above; empty/UNKNOWN-shaped
    # when ctx is unavailable (build_inventory's own ctx-is-None fallback).
    payload["inventory"] = build_inventory(findings, ctx, plugin_sweep=plugin_sweep)
    # F-149 JSON gap: present ONLY under --full (the caller passes None otherwise) —
    # matches the printed SKILL SWEEP section, which likewise only exists under
    # --full. Visibility only, same as the printed section: never folded into
    # score/grade/findings above.
    if skill_sweep is not None:
        payload["skill_sweep"] = skill_sweep
    payload["scan_receipt"] = f"sha256:{compute_scan_receipt(findings)}"
    return json.dumps(_sanitize_tree(payload), ensure_ascii=True, indent=2)


def render_html(findings: list[Finding], score: ScoreResult, native=None,
                *, ctx=None, plugin_sweep=None) -> str:
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

    badge_color = grade_hex(score.grade)
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

    # Build the findings body: grouped by Inventory subject so a long list (dozens of
    # findings) reads as coverage-by-subject, matching the summary table above.
    if not issues:
        no_issues_text = esc(
            "No known attack pattern matched across the audited surfaces. Keep it that way."
        )
        findings_html = f'<div class="all-clear">✓ {no_issues_text}</div>'
        nav_html = ""
    else:
        nav_items = []
        sections = []
        for subj_key, label, subj_issues in _group_issues_by_subject(issues):
            anchor = "subj-" + (subj_key or "other")
            nav_items.append(
                f'<a class="nav-chip" href="#{anchor}">{esc(label)} '
                f'<span class="nav-count">{len(subj_issues)}</span></a>')
            cards = "".join(_finding_card(f) for f in subj_issues)
            sections.append(f'''
            <section class="family" id="{anchor}">
                <h3 class="family-head">{esc(label)}<span class="family-count">{len(subj_issues)}</span></h3>
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

    # F-131 subject taxonomy, promoted into the HTML export: a compact "Inventory by
    # subject" table above the findings, derived from the SAME build_inventory() the JSON
    # payload and the terminal "Inventory by subject" block use (single source of truth).
    # "" when ctx is unavailable (a bare render_html(findings, score) call) — degrades to
    # no table, never a fabricated one.
    summary_rows = _subject_summary_rows(findings, ctx, plugin_sweep=plugin_sweep)
    if summary_rows:
        _st_color = {FAIL: "#d9534f", WARN: "#d9a406", PASS: "#1a7f37", UNKNOWN: "#8a8f98"}
        _inv_rows = "".join(
            f'<tr><td class="subj-name">{esc(label)}</td>'
            f'<td class="subj-count">{esc(count_text)}</td>'
            f'<td class="subj-status"><span class="subj-dot" style="--dot:{_st_color.get(status, "#8a8f98")};"></span>'
            f'{esc(status)}</td></tr>'
            for label, status, count_text in summary_rows)
        subject_inventory_html = (
            '<section class="inventory" aria-label="Inventory by subject">'
            '<h2 class="section-title">Inventory by subject</h2>'
            f'<table class="subj-table"><tbody>{_inv_rows}</tbody></table></section>')
    else:
        subject_inventory_html = ""

    # B-306 (C-135 follow-up #3, 2026-07-21): gate on the granular cap signals, not
    # `score.capped` alone — see the matching comment in render_report for why
    # `score.capped` can be False here while `config_blind_capped`/`runtime_capped` are
    # True (scoring.py's `total == 0` branch). Rendering-gate fix only; scoring.py's
    # documented JSON contract is unchanged. `getattr(..., default)` (not direct attribute
    # access) on the three fields this task newly reads unconditionally: some tests build
    # a minimal duck-typed ScoreResult stand-in that predates these fields, and the OLD
    # code never touched them because `score.capped and ...` short-circuited past them —
    # preserve that tolerance instead of demanding every caller supply every field.
    # B-313/B-399: same "unconditional, above the grade" disclosure as render_report's
    # text banner — a degraded check count is shown whenever it's nonzero, independent of
    # whether it ended up strictly binding the cap.
    _degraded_n = getattr(score, "degraded_count", 0)
    degraded_html = ""
    if _degraded_n:
        _plural = "check" if _degraded_n == 1 else "checks"
        degraded_html = (
            f'<p class="degraded"><strong>⚠️ Incomplete:</strong> {_degraded_n} {_plural}'
            ' could not reach a reliable verdict this run (crashed, timed out, or hit'
            ' unreadable/corrupted input) — this grade is incomplete.</p>'
        )
    # B-380: same shared `_cap_cascade` decision render_report now uses
    # (see the comment there) — this renderer used to keep its OWN five-branch "elif"
    # ladder, which is exactly how it drifted out of sync with render_report: its
    # runtime branch tested `score.capped or _rt_capped` (true for ANY cap, so a
    # behavioral-only cap fell through to it and fabricated a runtime-signal claim —
    # B-380 item 1), and its severity branch never named a co-occurring
    # runtime cap (item 2). Both are structurally impossible now: the primary/extras
    # decision lives in exactly one place. B-399's engine-side-degraded UNKNOWN cause
    # needs no change here either, for the same reason noted in render_report.
    _primary, _extras = _cap_cascade(score)
    if _primary is not None:
        _reason_html = esc(_cap_primary_reason_text(_primary, score))
        _also_html = _cap_also_clause([esc(p) for p in _extras])
        capped_html = (f'<p class="capped"><strong>{esc(label_capped)}</strong> '
                       f'from {score.raw_score} ({_reason_html}{_also_html})</p>')
    else:
        capped_html = ""
    capped_html = degraded_html + capped_html

    pct = max(0, min(100, int(score.score)))

    html_body = f'''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(title_text)}</title>
    <link rel="icon" type="image/png" href="{FAVICON_DATA_URI}">
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
        .inventory {{ margin: 1.75rem 0 0; }}
        .subj-table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; margin-top: 0.5rem; }}
        .subj-table td {{ padding: 0.5rem 0; border-bottom: 1px solid var(--line); }}
        .subj-name {{ font-weight: 700; color: var(--ink); }}
        .subj-count {{ color: var(--muted); }}
        .subj-status {{ text-align: right; white-space: nowrap; color: var(--muted); }}
        .subj-dot {{ display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%;
            background: var(--dot); margin-right: 0.4rem; vertical-align: middle; }}
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

        {subject_inventory_html}

        <h2 class="section-title">{esc(section_findings)}</h2>
        {nav_html}
        {findings_html}

        <footer class="footer">Generated locally by ClawSecCheck · read-only against your OpenClaw config · this report never leaves your machine</footer>
    </main>
</body>
</html>'''

    return html_body
