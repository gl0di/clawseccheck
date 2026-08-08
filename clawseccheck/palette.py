"""Screen 12 — the full capability palette ("everything it can do"), by mode.

Reached from Welcome (Screen 1, :mod:`menu`) by saying "menu" / "functions", or
from the CLI with ``--functions``. Where Welcome shows only the three modes, this
lists **every** capability grounded to its real CLI flag, so a normal user never
has to know a flag in advance.

Organised by the product's one primary axis — **frequency**, i.e. how often you
reach for it — not by the flat list of instruments it used to be:

    A · Full check       how safe is this setup?          run once, deliberately
    B · Watch            what changed since last time?    run repeatedly
    C · Before install   is this thing safe to add?       run on the event

Everything else is an instrument *inside* one of those, or works with any of them.
**No flag was removed** — the flags remain the CI/power surface and keep working;
what is organised here is what a human reads.

Two registries, both single-source-of-truth:

* :data:`_PALETTE` — the rendered rows, each grounded to its flag.
* :data:`_UNLISTED_FLAG_MODES` — every remaining CLI flag and the mode it belongs
  to, so ``FLAG_MODES`` covers the parser **totally**. ``tests/test_palette.py``
  derives the flag list from ``cli.py``'s own ``add_argument`` calls and fails if
  any flag is unassigned or claimed twice, so a new flag cannot be silently
  orphaned from the presentation.

Read-only, pure stdlib (Python 3.9+), English only — the host agent localizes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import brand

# Kind tags. The tool only ever EMITS live-test material; running it against the
# agent is the live part and is always confirm-gated — so "live" is disclosed here.
READONLY = "readonly"
LIVE = "live"
DESTRUCTIVE = "destructive"

# ── The three modes ──────────────────────────────────────────────────────────
# One axis, frequency. A flag belongs to exactly one of these (CROSS = it works
# with any of them), which is what makes the completeness guard meaningful.
MODE_A = "full-check"
MODE_B = "watch"
MODE_C = "before-install"
CROSS = "cross-cutting"

MODE_ORDER: tuple[str, ...] = (MODE_A, MODE_B, MODE_C, CROSS)

# (heading, the question it answers, what it produces). The "produces" line is the
# honesty invariant in the palette: mode A says a grade is conditional, mode B says
# there is never a number, mode C says a verdict is not a letter.
MODE_HEADING: dict[str, tuple[str, str, str]] = {
    MODE_A: ("A · Full check", "how safe is this setup?",
             "findings — and a grade only when all five layers ran"),
    MODE_B: ("B · Watch", "what changed since last time?",
             "events, never a number"),
    MODE_C: ("C · Before you install", "is this thing safe to add?",
             "INSTALL / CAUTION / DO-NOT-INSTALL — not a letter grade"),
    CROSS: ("Works with any mode", "", ""),
}


@dataclass(frozen=True)
class PaletteEntry:
    title: str            # what you say — the speakable name ("Vet anything <target>")
    flag: str | None      # the real cli.py flag this maps to (None = default audit path)
    blurb: str            # one-line description; "{n}" is filled with the check count
    also: tuple[str, ...] = ()   # folded secondary flags (e.g. --badge also covers --card)


@dataclass(frozen=True)
class PaletteCategory:
    title: str
    kind: str                       # READONLY / LIVE / DESTRUCTIVE — drives the header tag
    mode: str                       # MODE_A / MODE_B / MODE_C / CROSS
    entries: tuple[PaletteEntry, ...] = field(default_factory=tuple)


# ── Grounded registry ────────────────────────────────────────────────────────
#
# Blurbs are deliberately bounded (see _MAX_BLURB_COL): this screen is an index,
# not documentation. Anything that needs a paragraph lives in docs/USAGE.md.

_PALETTE: tuple[PaletteCategory, ...] = (
    # ── A · Full check ───────────────────────────────────────────────────────
    PaletteCategory("Scan", READONLY, MODE_A, (
        PaletteEntry("Quick scan", None,
                     "{n} checks over config, files and permissions"),
        PaletteEntry("Fast pass", "--fast",
                     "the quickest possible look — static config only"),
        PaletteEntry("Full check", "--full",
                     "adds installed skills, plugins and logged behaviour"),
        PaletteEntry("Capability re-check", "--ask",
                     "re-run the agent's own capability self-report"),
    )),
    PaletteCategory("Dig deeper", READONLY, MODE_A, (
        PaletteEntry("Next steps", "--next",
                     "recommended actions from the result"),
        PaletteEntry("Attack paths", "--risk-paths",
                     "the highest-risk capability chains"),
        PaletteEntry("Percentile", "--percentile",
                     "where you stand vs typical setups (offline)"),
        PaletteEntry("Show suppressed", "--show-suppressed",
                     "findings you've muted, by id"),
        PaletteEntry("Behavioral audit", "--behavioral",
                     "mine your own logs for a proven-by-log trifecta"),
        PaletteEntry("Trajectory analysis", "--analyze-trajectory",
                     "was a skill's instruction acted on at runtime?"),
        PaletteEntry("Bill of materials", "--sbom",
                     "skills, MCP servers, hashes and pin state as JSON"),
        PaletteEntry("Incident pack", "--incident",
                     "findings + hashes + a rotation list, to preserve"),
        PaletteEntry("Judge packet", "--judge-packet",
                     "borderline findings, for a host-agent 2nd opinion"),
        PaletteEntry("Propose ignores", "--propose-ignore",
                     "a judge panel's SAFE verdicts as proposed entries"),
    )),
    PaletteCategory("Live behaviour tests", LIVE, MODE_A, (
        PaletteEntry("Canary", "--canary",
                     "plant a marker, see if an injection leaks it"),
        PaletteEntry("Red-team", "--redteam",
                     "a payload suite to run against the agent"),
        PaletteEntry("Dry-run", "--dryrun",
                     "trace what an injection would reach"),
        PaletteEntry("Multi-turn", "--multiturn",
                     "plant a poisoned rule, trigger it a turn later"),
        PaletteEntry("Self-test", "--self-test",
                     "all live injection tests at once"),
    )),
    PaletteCategory("Report & export", READONLY, MODE_A, (
        PaletteEntry("Badge", "--badge",
                     "shareable badge — SVG or text", ("--card",)),
        PaletteEntry("HTML report", "--html",
                     "a standalone HTML report"),
        PaletteEntry("SARIF", "--sarif",
                     "findings as SARIF 2.1.0 (CI / code scanning)"),
        PaletteEntry("PDF report", "--pdf",
                     "the audit as a paginated PDF — attach, don't paste"),
        PaletteEntry("Save to a file", "--save",
                     "also write the report to a path you give"),
    )),
    # ── B · Watch ────────────────────────────────────────────────────────────
    PaletteCategory("Watch", READONLY, MODE_B, (
        PaletteEntry("What changed", "--monitor",
                     "diff against your last scan"),
        PaletteEntry("Trend", "--trend",
                     "how your graded scans moved over time"),
        PaletteEntry("Watch log", "--watch-log",
                     "timeline of what changed (Agent Watch journal)"),
        PaletteEntry("Verify history", "--verify-history",
                     "the score history's hash-chain is untampered"),
        PaletteEntry("Verify events", "--verify-events",
                     "the same check, on the Agent Watch journal"),
    )),
    # ── C · Before you install ───────────────────────────────────────────────
    PaletteCategory("Vet before you trust", READONLY, MODE_C, (
        PaletteEntry("Vet anything <target>", "--vet",
                     "malware / supply-chain check, type autodetected"),
        PaletteEntry("Vet a skill <path>", "--vet-skill",
                     "force the skill engine (dir or SKILL.md)"),
        PaletteEntry("Vet a plugin <path>", "--vet-plugin",
                     "force the plugin engine (dir or manifest)"),
        PaletteEntry("Vet an MCP server <name>", "--vet-mcp",
                     "the same, for a configured MCP server"),
        PaletteEntry("Vet a source <slug|url>", "--vet-source",
                     "reputation gate before anything is fetched"),
        PaletteEntry("Vet everything", "--vet-all",
                     "every installed skill, one verdict each"),
        PaletteEntry("Plan a vet <slug|url>", "--vet-plan",
                     "the fetch+isolate+cleanup commands, to review"),
        PaletteEntry("Install advice <path>", "--advise",
                     "INSTALL / CAUTION / DO-NOT-INSTALL, with reasons"),
    )),
    # ── Works with any mode ──────────────────────────────────────────────────
    PaletteCategory("Integrity", READONLY, CROSS, (
        PaletteEntry("Verify self", "--verify-self",
                     "SHA-256 of the engine source — a tamper check"),
    )),
    PaletteCategory("Maintenance", DESTRUCTIVE, CROSS, (
        PaletteEntry("Purge local data", "--purge",
                     "delete ClawSecCheck's own store — confirms first",
                     ("--yes",)),
    )),
)

# Modifiers you add to any command (not standalone modes, so not in _PRIMARY_MODES).
# (prompt, flag-or-None, blurb).
_MODIFIERS: tuple[tuple[str, str | None, str], ...] = (
    ('private', "--no-history", "don't record this run to history"),
    ('ascii', "--ascii", "plain ASCII, no emoji or box"),
    ('update', None, "ask your agent to check ClawHub for a newer version (agent-driven)"),
)

# Power / CI flags deliberately NOT expanded into a row — pointed at `help` so the
# palette stays readable. Listed in the footer line. Every one of them is still
# assigned a mode below, so the completeness guard sees it.
_POWER_FLAGS = "--json, --fail-on, --exit-code, --home, --seed, --no-host"

# cli._PRIMARY_MODES flags that legitimately have no palette row:
#   --menu / --functions  → the container screens themselves (Welcome / this palette)
#   --dashboard / --dashboard-findings → internal agent-only render hooks (SKILL.md
#                            Step 3), not user-speakable capabilities.
#   --judged → an internal continuation flag: it consumes a judge panel's verdicts
#              JSON (produced by the SKILL.md "Judge-panel fan-out" flow, itself
#              triggered from --judge-packet), not something a user says on its own.
#   --apply-ignore-proposals → same shape as --judged: an internal continuation flag
#              consuming a --propose-ignore output, not something a user reaches for
#              without having run --propose-ignore first.
EXEMPT_FROM_PALETTE: frozenset[str] = frozenset(
    {"--menu", "--functions", "--dashboard", "--dashboard-findings", "--judged",
     "--apply-ignore-proposals"})

# Every CLI flag that has no palette row of its own, and the mode it belongs to.
# Together with the rows above this makes FLAG_MODES total over cli.py's parser —
# the guard that stops a flag being added without anyone deciding where a human
# would look for it. A comment is required wherever the placement isn't obvious.
_UNLISTED_FLAG_MODES: dict[str, str] = {
    # ── A · Full check: instruments that modify or continue a check ──────────
    "--attest": MODE_A,          # feeds layer 4, the agent's self-report
    "--judged": MODE_A,          # continuation of --judge-packet
    "--judged-bundle": MODE_A,   # the same verdicts, as a bundle file
    "--apply-ignore-proposals": MODE_A,   # continuation of --propose-ignore
    "--dashboard": MODE_A,       # the agent-facing render of a check
    "--dashboard-findings": MODE_A,
    "--compact": MODE_A,         # only with --dashboard --full
    "--exhaustive": MODE_A,      # raises this check's scan caps
    # ── B · Watch: where the periodic state lives ────────────────────────────
    "--state": MODE_B,           # snapshot file for --monitor
    "--events": MODE_B,          # the Agent Watch event journal
    "--history": MODE_B,         # the score-history file --trend reads
    # ── C · Before you install: vet-only modifiers ───────────────────────────
    "--recursive": MODE_C,       # alias of --vet-all
    "--vet-judge-packet": MODE_C,
    "--vet-judged": MODE_C,
    "--emit-manifest": MODE_C,   # proposed permission manifest for a vetted skill
    # ── Works with any mode ──────────────────────────────────────────────────
    "--home": CROSS,
    "--json": CROSS,
    "--exit-code": CROSS,
    "--fail-on": CROSS,
    "--ascii": CROSS,
    "--no-color": CROSS,
    "--quiet": CROSS,
    "--verbose": CROSS,
    "--debug": CROSS,
    "--log": CROSS,
    "--seed": CROSS,
    # --yes is not listed here: the Purge row folds it, so a row already claims it.
    "--no-history": CROSS,
    "--no-host": CROSS,
    "--no-native": CROSS,
    "--no-sockets": CROSS,
    "--no-deptree": CROSS,
    "--no-update-notice": CROSS,
    "--no-freshness-notice": CROSS,
    "--menu": CROSS,
    "--functions": CROSS,
    "--version": CROSS,
}


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


def flag_modes() -> dict[str, str]:
    """Map every CLI flag to the one mode a human would look for it under.

    Rows take their category's mode; everything else comes from
    :data:`_UNLISTED_FLAG_MODES`. ``tests/test_palette.py`` asserts this is total
    over ``cli.py``'s parser and that no flag is claimed twice.
    """
    modes: dict[str, str] = {}
    for cat in _PALETTE:
        for e in cat.entries:
            for flag in ([e.flag] if e.flag else []) + list(e.also):
                modes[flag] = cat.mode
    for flag, mode in _UNLISTED_FLAG_MODES.items():
        modes.setdefault(flag, mode)
    return modes


#: Flags a palette row already grounds, so the unlisted table must not repeat them.
def duplicated_flag_assignments() -> set[str]:
    """Flags claimed by both a palette row and the unlisted table (should be empty)."""
    rows: set[str] = set()
    for cat in _PALETTE:
        for e in cat.entries:
            if e.flag:
                rows.add(e.flag)
            rows.update(e.also)
    return rows & set(_UNLISTED_FLAG_MODES)


# ── Rendering ─────────────────────────────────────────────────────────────────

def _ascii(text: str) -> str:
    """Fold the few non-ASCII glyphs we emit down to safe ASCII for --ascii mode."""
    return (text
            .replace(f"{brand.MASCOT} ", "").replace(brand.MASCOT, "")
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


# B-471: the blurb column used to be padded to the longest blurb in the WHOLE
# palette, so a single 200-character entry stretched every row to 273 characters.
# In a wrapping chat client — and SKILL.md tells the host agent to present this
# output — that shreds the layout for all 60 rows to align one. Two changes fix
# it for good: the speakable-prompt column was folded into the title (they said
# the same thing twice), and blurbs are now written to fit. The cap below bounds
# the padding; `tests/test_palette.py` bounds the rendered row itself, so a future
# over-long blurb fails the build instead of quietly stretching the screen.
_MAX_BLURB_COL = 54


def render_palette(*, n_checks: int | None = None, ascii_only: bool = False) -> str:
    """Render the full capability palette as plain text. Pure — no I/O, no clock read.

    ``n_checks`` fills the "{n} checks" phrase (falls back to "all" when unknown).
    """
    count = str(n_checks) if n_checks else "all"
    entries = [e for cat in _PALETTE for e in cat.entries]

    # Global column widths so every row lines up under its section header.
    tw = max(len(e.title) for e in entries)
    bw = min(max(len(e.blurb.replace("{n}", count)) for e in entries), _MAX_BLURB_COL)

    head = brand.header(subtitle="everything it can do", ascii_only=ascii_only)
    lines = [head]

    for mode in MODE_ORDER:
        cats = [c for c in _PALETTE if c.mode == mode]
        if not cats:
            continue
        heading, question, produces = MODE_HEADING[mode]
        lines.append("")
        # A mode with exactly one category would otherwise print its own name
        # twice; give the kind tag to the mode line instead.
        solo = len(cats) == 1
        title_line = f"{heading} — {question}" if question else heading
        if solo:
            title_line = f"{title_line}  {_header_tag(cats[0].kind, ascii_only)}"
        lines.append(title_line)
        if produces:
            lines.append(f"  gives you: {produces}")

        for cat in cats:
            if not solo:
                lines.append("")
                lines.append(f"  {cat.title}  {_header_tag(cat.kind, ascii_only)}")
            for e in cat.entries:
                blurb = e.blurb.replace("{n}", count)
                row = f"    {e.title:<{tw}}  {blurb:<{bw}}  {_flag_col(e)}"
                lines.append(row.rstrip())

    lines.append("")
    lines.append("Add to any:")
    quoted = [f'"{p}"' for p, _, _ in _MODIFIERS]
    mod_pw = max(len(q) for q in quoted)
    for (_prompt, flag, blurb), q in zip(_MODIFIERS, quoted):
        tail = f"  ({flag})" if flag else ""
        lines.append(f"  {q:<{mod_pw}}  {blurb}{tail}")

    lines.append("")
    lines.append("Say the name on the left, or pass the flag — nothing here was removed.")
    lines.append(f'Power / CI flags ({_POWER_FLAGS}…): say "help".')

    out = "\n".join(lines)
    return _ascii(out) if ascii_only else out
