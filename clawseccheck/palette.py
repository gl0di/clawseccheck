"""Screen 12 — the full capability palette ("everything it can do").

Reached from Welcome (Screen 1, :mod:`menu`) by saying "menu" / "functions", or
from the CLI with ``--functions``. Where Welcome shows only the four common modes,
this lists **every** capability as a speakable mini-prompt grounded to its real CLI
flag, so a normal user never has to know a flag in advance.

The registry below is the single source of truth. ``tests/test_palette.py`` asserts
every ``cli._PRIMARY_MODES`` flag (except the documented container/internal ones in
:data:`EXEMPT_FROM_PALETTE`) appears here, so the palette and ``cli.py`` can't
silently drift (the C-129 concern, one direction).

Read-only, pure stdlib (Python 3.9+), English only — the host agent localizes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Kind tags. The tool only ever EMITS live-test material; running it against the
# agent is the live part and is always confirm-gated — so "live" is disclosed here.
READONLY = "readonly"
LIVE = "live"
DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class PaletteEntry:
    title: str            # short verb column ("Quick scan")
    prompt: str           # what the user says, rendered quoted ("go" / "1")
    flag: str | None      # the real cli.py flag this maps to (None = default audit path)
    blurb: str            # one-line description; "{n}" is filled with the check count
    also: tuple[str, ...] = ()   # folded secondary flags (e.g. --badge also covers --card)


@dataclass(frozen=True)
class PaletteCategory:
    title: str
    kind: str                       # READONLY / LIVE — drives the header tag
    entries: tuple[PaletteEntry, ...] = field(default_factory=tuple)


# ── Grounded registry ────────────────────────────────────────────────────────

_PALETTE: tuple[PaletteCategory, ...] = (
    PaletteCategory("Scan", READONLY, (
        PaletteEntry("Quick scan", 'go / 1', None,
                     "{n} checks across your OpenClaw setup — the default"),
        PaletteEntry("Capability re-check", 'deeper', "--ask",
                     "re-run the agent self-report (Check everything already does this once)"),
        PaletteEntry("Full check", 'full / 3', "--full",
                     "Quick scan + self-test + a vet of your MCP servers"),
        PaletteEntry("What changed", 'what changed', "--monitor",
                     "diff against your last scan"),
        PaletteEntry("Next steps", 'next', "--next",
                     "recommended actions from the result"),
        PaletteEntry("Attack paths", 'risk paths', "--risk-paths",
                     "the highest-risk capability chains"),
        PaletteEntry("Show suppressed", 'suppressed', "--show-suppressed",
                     "findings you've muted, by id"),
        PaletteEntry("Bill of materials", 'bill of materials / sbom', "--sbom",
                     "skills, MCP servers, hashes and pin state as local JSON"),
        PaletteEntry("Incident evidence pack", 'incident pack', "--incident",
                     "findings + hashes + rotation list — a preservation aid, "
                     "never rotates or deletes anything"),
        PaletteEntry("Judge packet", 'judge packet', "--judge-packet",
                     "borderline findings (unknowns, FN-prone warns, dropped taint) as "
                     "JSON for a host-agent second opinion — never changes the grade"),
        PaletteEntry("Trajectory analysis", 'analyze trajectory', "--analyze-trajectory",
                     "post-hoc: did a skill's instruction get acted on at runtime? "
                     "correlates skill indicators against tool.call args"),
        PaletteEntry("Behavioral audit", 'behavioral', "--behavioral",
                     "post-hoc: reconstructs observed tool-call sequences and flags a "
                     "proven-by-log ingress->sensitive->egress trifecta or fail-then-"
                     "succeed outcome anomaly"),
    )),
    PaletteCategory("Live tests", LIVE, (
        PaletteEntry("Canary", 'canary', "--canary",
                     "plant a marker, see if an injection leaks it"),
        PaletteEntry("Red-team", 'red-team', "--redteam",
                     "a payload suite to run against the agent"),
        PaletteEntry("Dry-run", 'dry-run', "--dryrun",
                     "trace what an injection would reach"),
        PaletteEntry("Multi-turn", 'multi-turn', "--multiturn",
                     "plant a poisoned rule, trigger it a turn later"),
        PaletteEntry("Self-test", 'self-test', "--self-test",
                     "all live injection tests at once"),
    )),
    PaletteCategory("Vet before you trust", READONLY, (
        PaletteEntry("Vet anything", 'vet <target>', "--vet",
                     "malware / supply-chain check before you install — "
                     "skill, plugin or MCP, type autodetected"),
        PaletteEntry("Vet a skill", 'vet skill <path>', "--vet-skill",
                     "force the skill engine (dir or SKILL.md)"),
        PaletteEntry("Vet a plugin", 'vet plugin <path>', "--vet-plugin",
                     "force the plugin engine (root dir or openclaw.plugin.json)"),
        PaletteEntry("Vet an MCP server", 'vet-mcp <name>', "--vet-mcp",
                     "the same, for a configured MCP server"),
        PaletteEntry("Vet a source before download", 'vet source <slug|url>', "--vet-source",
                     "reputation gate on the name/URL alone — before anything is fetched"),
        PaletteEntry("Vet everything", 'vet all', "--vet-all",
                     "every installed skill, one verdict each"),
        PaletteEntry("Plan a zero-network vet", 'vet plan <slug|url|pkg>', "--vet-plan",
                     "print the fetch+isolate+advise+cleanup commands — the tool "
                     "never touches the network"),
        PaletteEntry("Get an install recommendation", 'advise <path>', "--advise",
                     "INSTALL / CAUTION / DO-NOT-INSTALL for a quarantined skill or "
                     "plugin, with reasons + a cleanup command"),
    )),
    PaletteCategory("Track over time", READONLY, (
        PaletteEntry("Trend", 'trend', "--trend",
                     "how your score moved across past scans"),
        PaletteEntry("Percentile", 'percentile', "--percentile",
                     "where you stand vs typical setups (offline)"),
        PaletteEntry("Watch log", 'watch log', "--watch-log",
                     "timeline of what changed (Agent Watch journal)"),
    )),
    PaletteCategory("Share & export", READONLY, (
        PaletteEntry("Badge", 'badge', "--badge",
                     "shareable grade badge — SVG or text", ("--card",)),
        PaletteEntry("HTML report", 'html', "--html",
                     "a standalone HTML report"),
        PaletteEntry("SARIF", 'sarif', "--sarif",
                     "findings as SARIF 2.1.0 (CI / code scanning)"),
        PaletteEntry("Save", 'save <path>', "--save",
                     "also write the report to a file"),
    )),
    PaletteCategory("Integrity", READONLY, (
        PaletteEntry("Verify self", 'verify', "--verify-self",
                     "SHA-256 of the engine source — a tamper check"),
        PaletteEntry("Verify history", 'verify history', "--verify-history",
                     "check the score history's hash-chain hasn't been tampered with"),
    )),
    PaletteCategory("Maintenance", DESTRUCTIVE, (
        PaletteEntry("Purge local data", 'purge', "--purge",
                     "delete ClawSecCheck's local store (history, events, state) — "
                     "confirms first, or --yes to skip the prompt", ("--yes",)),
    )),
)

# Modifiers you add to any command (not standalone modes, so not in _PRIMARY_MODES).
# (prompt, flag-or-None, blurb).
_MODIFIERS: tuple[tuple[str, str | None, str], ...] = (
    ('private', "--no-history", "don't record this run to history"),
    ('ascii', "--ascii", "plain ASCII, no emoji or box"),
    ('update', None, "ask your agent to check ClawHub for a newer version (agent-driven)"),
)

# Power / CI flags deliberately NOT expanded into the palette — pointed at `help`
# so the palette stays readable. Listed in the footer line.
_POWER_FLAGS = "--json, --fail-under, --exit-code, --home, --seed, --no-host"

# cli._PRIMARY_MODES flags that legitimately have no palette row:
#   --menu / --functions  → the container screens themselves (Welcome / this palette)
#   --dashboard / --dashboard-findings → internal agent-only render hooks (SKILL.md
#                            Step 3), not user-speakable capabilities.
#   --judged → an internal continuation flag: it consumes a judge panel's verdicts
#              JSON (produced by the SKILL.md "Judge-panel fan-out" flow, itself
#              triggered from --judge-packet), not something a user says on its own.
EXEMPT_FROM_PALETTE: frozenset[str] = frozenset(
    {"--menu", "--functions", "--dashboard", "--dashboard-findings", "--judged"})


def grounded_flags() -> set[str]:
    """Every real cli flag the palette (rows + folded `also` + modifiers) grounds to.

    Used by the drift guard to prove the palette covers _PRIMARY_MODES.
    """
    flags: set[str] = set()
    for cat in _PALETTE:
        for e in cat.entries:
            if e.flag:
                flags.add(e.flag)
            flags.update(e.also)
    for _, flag, _ in _MODIFIERS:
        if flag:
            flags.add(flag)
    return flags


# ── Rendering ─────────────────────────────────────────────────────────────────

def _ascii(text: str) -> str:
    """Fold the few non-ASCII glyphs we emit down to safe ASCII for --ascii mode."""
    return (text
            .replace("🦞 ", "").replace("🦞", "")
            .replace("✅ ", "").replace("✅", "")
            .replace("⚠ ", "").replace("⚠", "")
            .replace("⚡", "(live)")
            .replace("·", "-").replace("—", "-").replace("…", "..."))


def _flag_col(entry: PaletteEntry) -> str:
    """The parenthetical grounding column: the flag(s), or '(default)'."""
    if entry.flag is None and not entry.also:
        return "(default)"
    parts = ([entry.flag] if entry.flag else []) + list(entry.also)
    return f"({' / '.join(parts)})"


def _header_tag(kind: str, ascii_only: bool) -> str:
    if kind == LIVE:
        tag = "⚡ exercises your running agent — I confirm first"
    elif kind == DESTRUCTIVE:
        tag = "⚠ deletes local files — I confirm first"
    else:
        tag = "✅ read-only"
    return _ascii(tag) if ascii_only else tag


def render_palette(*, n_checks: int | None = None, ascii_only: bool = False) -> str:
    """Render the full capability palette as plain text. Pure — no I/O, no clock read.

    ``n_checks`` fills the "{n} checks" phrase (falls back to "all" when unknown).
    """
    count = str(n_checks) if n_checks else "all"
    entries = [e for cat in _PALETTE for e in cat.entries]

    def _q(prompt: str) -> str:
        return f'"{prompt}"'

    # Global column widths so every row lines up under its section header.
    tw = max(len(e.title) for e in entries)
    pw = max(len(_q(e.prompt)) for e in entries)
    bw = max(len(e.blurb.replace("{n}", count)) for e in entries)

    sep = " - " if ascii_only else " · "
    head = f"ClawSecCheck{sep}everything it can do" if ascii_only \
        else f"🦞 ClawSecCheck{sep}everything it can do"
    lines = [head]

    for cat in _PALETTE:
        lines.append("")
        lines.append(f"{cat.title}  {_header_tag(cat.kind, ascii_only)}")
        for e in cat.entries:
            blurb = e.blurb.replace("{n}", count)
            row = f"  {e.title:<{tw}}  {_q(e.prompt):<{pw}}  {blurb:<{bw}}  {_flag_col(e)}"
            lines.append(row.rstrip())

    lines.append("")
    lines.append("Add to any:")
    mod_pw = max(len(_q(p)) for p, _, _ in _MODIFIERS)
    for prompt, flag, blurb in _MODIFIERS:
        tail = f"  ({flag})" if flag else ""
        lines.append(f"  {_q(prompt):<{mod_pw}}  {blurb}{tail}")

    lines.append("")
    lines.append(f'Power / CI flags ({_POWER_FLAGS}…): say "help".')

    out = "\n".join(lines)
    return _ascii(out) if ascii_only else out
