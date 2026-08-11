"""Deterministic next-action recommendation engine for ClawSecCheck.

Driven only by findings + score (no network). Returns a sorted list of
Action dataclasses that the render layer turns into the "What you can do
next" guidance block.

Pure stdlib, no deps.
"""
from __future__ import annotations

from dataclasses import dataclass

from .catalog import FAIL, WARN, Finding
from .scoring import ScoreResult
from .textnorm import asciify


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
    # Reports-only doctrine (F-074): every suggestion below is a further CHECK
    # (vet, monitor, live test, trend) — never remediation. `score` stays in the
    # signature for API stability even though no current rule reads it.
    _ = score

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

    # review_mcp: B15/B24 "active" means MCP surface may exist or we simply can't
    # tell (blind pass) — silent only once not_applicable has POSITIVELY confirmed
    # no MCP surface. B15/B24 status is ALWAYS UNKNOWN (that never changes; status
    # is not a proxy for "is there MCP surface" — not_applicable is orthogonal to
    # status), so the old `status != UNKNOWN` gate never fired regardless of
    # whether MCP surface actually existed (F-139/B2 semantic-bug fix).
    b15 = idx.get("B15")
    b24 = idx.get("B24")
    b15_active = b15 is not None and not getattr(b15, "not_applicable", False)
    b24_active = b24 is not None and not getattr(b24, "not_applicable", False)
    if b15_active or b24_active:
        actions.append(Action(
            id="review_mcp",
            title="Vet your connected MCP servers for supply-chain risk",
            command="clawseccheck --vet-mcp",
            why="MCP servers can inject prompts or reach internal services.",
            priority=5,
        ))

    # C-428: both of these always-on actions promised a grade. On an ungraded run
    # (fewer than five layers ran) `--trend` plots nothing for it and the badge
    # renders "no grade yet" — so the promise was one the tool could not keep.
    # Same fact, wording that matches what the user will actually get.
    graded = bool(getattr(score, "graded", True))

    # track_trend: ALWAYS
    actions.append(Action(
        id="track_trend",
        title=("Track your security score over time" if graded
               else "Track your posture over time"),
        command="clawseccheck --trend",
        why=("See if you're getting safer or drifting." if graded else
             "Only graded runs plot on the trend — this run is recorded, not plotted. "
             "Complete all five layers to put a point on the line."),
        priority=8,
    ))

    # share_grade: ALWAYS
    actions.append(Action(
        id="share_grade",
        title=("Share your grade (safe — findings stay private)" if graded
               else "Share your result (safe — findings stay private)"),
        command="clawseccheck --badge grade.svg",
        why=(
            # C-428 follow-up: the second sentence used to be carried over verbatim from
            # the graded branch — "Only the grade + score is ever shared" two words after
            # "this run has no grade". The privacy promise is load-bearing, so it is
            # reworded to what the badge actually contains (measured: its only text nodes
            # are "OpenClaw Security" and "no grade yet"), never dropped.
            ("Only the grade + score is shared, never your findings. " if graded else
             "This run has no grade, so the badge reads \"no grade yet\" — that phrase "
             "is the whole of what it carries. Your findings are never in it. ")
            + "This writes a real SVG file — attach grade.svg itself, do not redraw "
              "or regenerate the badge image yourself."
        ),
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
        # C-216 (PASS-semantics doctrine): "good shape"/"stay safe" overstates what a clean
        # result means — reframed to what's actually true (no known pattern matched).
        return (
            "No further action suggested — nothing here matched a known attack"
            " pattern. Re-run after any change to your setup.\n"
        )

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
        out = asciify(out)
    return out


# ── F-172: a native OpenClaw cron job, printed for the agent to create ────────────
#
# "Watch continuously and tell me when something is wrong" needs periodicity and delivery.
# This tool supplies neither and must not: a resident daemon breaks the skill shape, and
# any delivery of our own would be a network call. OpenClaw already provides both.
#
# GROUNDED against the installed dist, because Golden Rule #4 forbids inventing a field's
# contract. Job schema: cron-tool-C9qaFGtt.js:830-875. `schedule.kind` is one of
# at|every|cron|on-exit; `payload.kind` is systemEvent|agentTurn; `delivery.mode` is
# none|announce|webhook.
#
# WHY THERE IS NO `trigger` BLOCK, recorded so the next attempt starts from an answer:
# `trigger.script` exists and would be the better design — it polls headlessly and wakes
# the agent only when it returns {fire: true}, i.e. zero token cost while nothing is wrong.
# Traced: the script is passed as `code` to `runCodeModeScriptHeadless`
# (server-cron-Cwg2hJro.js:3714), which runs it in a **QuickJS/WASI sandbox**
# (agents/code-mode.worker.js imports `quickjs-wasi`) — so it is JavaScript, not shell and
# not Python. It must return a boolean `fire`, may return `message`/`state`, and is bounded
# to 30s wall clock, 5 tool calls and 16KB of persisted state
# (server-cron-Cwg2hJro.js:3461-3464).
#
# What is NOT established is whether that sandbox's tool catalog can execute an external
# binary and read its exit status. Without that a trigger cannot consult
# `clawseccheck --exit-code`, which is the whole point of using one. A full monitor run
# measures 7.7-7.9s on a real machine, so the 30s ceiling is not the obstacle — the exec
# route is. Until someone grounds it, this emits the plain `every` + `agentTurn` variant,
# which is fully grounded today.

_CRON_JOB_NAME = "clawseccheck-watch"
_CRON_EVERY_MS = 21_600_000        # six hours


def render_cron_recipe(ascii_only: bool = False,
                       data_dir: str = "~/.clawseccheck") -> str:
    """A copy-paste OpenClaw cron job that runs the drift check on a schedule.

    Prints only. This never writes a file, never edits openclaw.json and never invokes
    `openclaw cron` — creating the job is the agent's or the user's act, and a security
    tool that installs a recurring job as a side effect of being asked how to install one
    has helped itself to a decision that was not offered.

    Deterministic: no clock, no randomness, so the same input always prints the same text.
    """
    job = (
        '{\n'
        f'  "name": "{_CRON_JOB_NAME}",\n'
        f'  "schedule": {{ "kind": "every", "everyMs": {_CRON_EVERY_MS} }},\n'
        '  "payload": {\n'
        '    "kind": "agentTurn",\n'
        '    "message": "Run: clawseccheck --monitor --exit-code --data-dir '
        f'{data_dir}\\nExit 0 means nothing changed — say nothing and stop. Exit 3 means '
        'drift was recorded: report what changed, quoting the tool\'s own output. Exit 1 '
        'means monitoring is NOT established (the run could not write its state) — say so, '
        'it is more urgent than drift. Exit 2 is a usage error in this job, not a finding."\n'
        '  },\n'
        '  "delivery": { "mode": "announce", "channel": "<your-channel>", "to": "<you>" },\n'
        '  "sessionTarget": "isolated"\n'
        '}'
    )
    lines = [
        "Watch this setup on a schedule",
        "",
        "OpenClaw runs the schedule and delivers the message; this tool only checks. Ask",
        "your agent to create this job with its own `cron` tool — nothing here is created",
        "for you:",
        "",
        job,
        "",
        "Before you agree to it:",
        "",
        "  - It runs every 6 hours. Change everyMs if you want a different interval.",
        f"  - It writes three local files under {data_dir} — the drift baseline, the event",
        "    journal and the score history. Nothing leaves the machine.",
        "  - Replace <your-channel> and <you>. Delivery is OpenClaw's, not this tool's; set",
        '    "mode": "none" if you would rather read the result in the session.',
        '  - "sessionTarget": "isolated" keeps the check out of your working conversation.',
        "",
        "The first run records a baseline and reports nothing. Every run after it compares",
        "against that baseline.",
    ]
    out = "\n".join(lines).rstrip() + "\n"
    return asciify(out) if ascii_only else out
