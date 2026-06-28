"""Deterministic next-action recommendation engine for ClawSecCheck.

Driven only by findings + score (no network). Returns a sorted list of
Action dataclasses that the render layer turns into the "What you can do
next" guidance block.

Pure stdlib, no deps.
"""
from __future__ import annotations

from dataclasses import dataclass

from .catalog import FAIL, UNKNOWN, WARN, Finding
from .scoring import ScoreResult


@dataclass
class Action:
    id: str
    title: str
    command: str
    why: str
    priority: int


def _by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def suggest_actions(findings: list[Finding], score: ScoreResult) -> list[Action]:
    """Build a list of recommended next steps from the audit result.

    All trigger logic is deterministic — no network, no side effects.
    Returns actions sorted by (priority, id).
    """
    idx = _by_id(findings)
    actions: list[Action] = []

    # fix_guidance: any unsuppressed FAIL or WARN
    unsuppressed_issues = [
        f for f in findings
        if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)
    ]
    if unsuppressed_issues:
        has_fail = any(f.status == FAIL for f in unsuppressed_issues)
        priority = 0 if (has_fail or score.capped) else 2
        actions.append(Action(
            id="fix_guidance",
            title="See exactly how to fix each issue, most urgent first",
            command="clawseccheck --prompts",
            why="Get a copy-paste fix you can hand to your agent.",
            priority=priority,
        ))

    # vet_skills: B13 is FAIL or WARN
    b13 = idx.get("B13")
    if b13 is not None and b13.status in (FAIL, WARN):
        actions.append(Action(
            id="vet_skills",
            title="Double-check your installed skills for malware",
            command="clawseccheck --vet <skill-folder>",
            why="Installed skills run with your agent's full permissions.",
            priority=1,
        ))

    # setup_monitoring: B16 is FAIL or WARN
    b16 = idx.get("B16")
    if b16 is not None and b16.status in (FAIL, WARN):
        actions.append(Action(
            id="setup_monitoring",
            title="Turn on ongoing monitoring so you're alerted if something changes",
            command="clawseccheck --monitor",
            why="An agent with no monitoring won't warn you if it's compromised.",
            priority=3,
        ))

    # live_test: A1 evidence count >= 2, or B17 in (FAIL,WARN), or B21 in (FAIL,WARN)
    a1 = idx.get("A1")
    b17 = idx.get("B17")
    b21 = idx.get("B21")
    a1_trifecta = a1 is not None and len(getattr(a1, "evidence", [])) >= 2
    b17_hit = b17 is not None and b17.status in (FAIL, WARN)
    b21_hit = b21 is not None and b21.status in (FAIL, WARN)
    if a1_trifecta or b17_hit or b21_hit:
        actions.append(Action(
            id="live_test",
            title="Run a live prompt-injection test to see if your agent actually resists",
            command="clawseccheck --canary   (then --dryrun / --redteam)",
            why="Passive checks tell you the config; this tests real behavior.",
            priority=4,
        ))

    # review_mcp: B15 status not UNKNOWN, or B24 status not UNKNOWN
    b15 = idx.get("B15")
    b24 = idx.get("B24")
    b15_active = b15 is not None and b15.status != UNKNOWN
    b24_active = b24 is not None and b24.status != UNKNOWN
    if b15_active or b24_active:
        actions.append(Action(
            id="review_mcp",
            title="Vet your connected MCP servers for supply-chain risk",
            command="clawseccheck --vet-mcp",
            why="MCP servers can inject prompts or reach internal services.",
            priority=5,
        ))

    # track_trend: ALWAYS
    actions.append(Action(
        id="track_trend",
        title="Track your security score over time",
        command="clawseccheck --trend",
        why="See if you're getting safer or drifting.",
        priority=8,
    ))

    # share_grade: ALWAYS
    actions.append(Action(
        id="share_grade",
        title="Share your grade (safe — findings stay private)",
        command="clawseccheck --badge grade.svg",
        why="Only the grade + score is shared, never your findings.",
        priority=9,
    ))

    actions.sort(key=lambda a: (a.priority, a.id))
    return actions


def render_next_actions(
    actions: list[Action],
    ascii_only: bool = False,
    limit: int = 5,
) -> str:
    """Render a plain-language "What you can do next" block.

    Up to *limit* numbered items, each with a run-command line and a why
    explanation. If *actions* is empty, returns a single friendly line.
    *ascii_only* avoids unicode.
    """
    if not actions:
        return "You're in good shape — re-run anytime to stay safe.\n"

    header = "What you can do next:"
    run_label = "run:"

    lines = [header]
    for i, action in enumerate(actions[:limit], 1):
        title = action.title
        why = action.why
        lines.append(f"{i}. {title}")
        lines.append(f"   {run_label} {action.command}")
        lines.append(f"   {why}")
        lines.append("")

    out = "\n".join(lines).rstrip() + "\n"
    if ascii_only:
        out = out.encode("ascii", "replace").decode("ascii")
    return out
