"""Deterministic next-action recommendation engine for ClawSecCheck.

Driven only by findings + score (no network). Returns a sorted list of
Action dataclasses that the render layer turns into the "What you can do
next" guidance block.

Pure stdlib, no deps.
"""
from __future__ import annotations

import json

from dataclasses import dataclass

from .catalog import ACTIONABLE_STATUSES, BY_ID, FAIL, FAIL_WEIGHT_STATUSES, WARN, Finding
from .invocation import cmd, machine_command_prefix
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


def _surface_failed(findings: list[Finding], surface: str) -> bool:
    """True when any check belonging to *surface* reported FAIL (B-566).

    Derived from the catalog's own `surface` slug rather than from a list of check ids.
    The id-keyed rules this supplements see 7 of 188 checks, so a FAIL on any other check
    produced no next step at all, and the trigger set could not help falling further
    behind — every new check needed a new rule to become visible here. Keying on the
    surface means a new skills-surface check inherits its next step for free.

    FAIL only, deliberately, and this is the whole calibration. Measured over 40 fixtures:
    the current B13-keyed trigger fires on 22; adding every skills-surface FAIL *or* WARN
    takes it to 35, which makes the action near-universal and costs it the signal a
    prioritised list exists to carry. FAIL alone takes it to 24. The filed defect was a
    FAIL that produced no next step, so FAIL is what closes it.

    A suppressed finding does not count: the user has already said they do not want to be
    told about it, and re-surfacing it as a recommended action would route around that.
    """
    for f in findings or []:
        if getattr(f, "suppressed", False):
            continue
        meta = BY_ID.get(f.id)
        # B-751: FAIL-weight, not the literal — a confirmed zip-slip could drop the whole
        # surface block, not just one line.
        if meta is not None and meta.surface == surface and f.status in FAIL_WEIGHT_STATUSES:
            return True
    return False


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

    # vet_skills: ANY skills-surface check is FAIL or WARN.
    #
    # B-566: this used to key on B13 alone, so a run could carry a skills-surface FAIL and
    # produce no next step at all. The measured case was B181 ("installed skill files no
    # longer match the SHA-256 digests ClawHub recorded") — a possible-compromise
    # indicator that the command whose whole job is "what should I do now" had nothing to
    # say about. B181 and B13 share surface="skills"; there was never a reason for one to
    # reach this action and the other not.
    #
    # Derived from the catalog's own `surface`, deliberately NOT from a list of ids. A
    # per-id rule set is what froze this trigger at 7 of 188 checks in the first place,
    # and it would need a new rule every time a check is added. This way a new
    # skills-surface check inherits the next step for free.
    #
    # Still inside the reports-only doctrine (F-074): the suggestion is to run a further
    # CHECK (--vet), never to remediate. For B181 specifically the honest next step is to
    # vet the skill, not "reinstall it".
    #
    # B13's own FAIL-or-WARN trigger is kept as it was, so nothing that reached this
    # action before stops reaching it; the surface term only ADDS the FAILs that reached
    # nothing. See _surface_failed for why that term is FAIL-only.
    b13 = idx.get("B13")
    # B-751: B13 is the SOLE producer of SKILL_ARCHIVE_PATH_TRAVERSAL, so this was False
    # exactly when B13 convicted: the guide advised on a hardcoded temp-file path and said
    # nothing about a confirmed zip-slip (measured against that WARN as a positive control).
    b13_hit = b13 is not None and (b13.status in ACTIONABLE_STATUSES)
    if b13_hit or _surface_failed(findings, "skills"):
        actions.append(Action(
            id="vet_skills",
            title="Double-check your installed skills for malware",
            command=cmd("--vet <skill-folder>"),
            why="Installed skills run with your agent's full permissions.",
            priority=1,
        ))

    # setup_monitoring: B16 is FAIL or WARN
    b16 = idx.get("B16")
    if b16 is not None and b16.status in (FAIL, WARN):
        actions.append(Action(
            id="setup_monitoring",
            title="Turn on ongoing monitoring so you're alerted if something changes",
            command=cmd("--monitor"),
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
            command=cmd("--canary   (then --dryrun / --redteam)"),
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
            command=cmd("--vet-mcp"),
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
        command=cmd("--trend"),
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
        command=cmd("--badge grade.svg"),
        why=(
            # C-428 follow-up: the second sentence used to be carried over verbatim from
            # the graded branch — "Only the grade + score is ever shared" two words after
            # "this run has no grade". The privacy promise is load-bearing, so it is
            # reworded to what the badge actually contains (measured: its only text nodes
            # are "OpenClaw Security" and "no grade yet"), never dropped.
            #
            # C-428 fixed the ungraded branch's PROSE and left the graded branch's
            # COMMAND promising what it cannot deliver. A grade needs all five layers,
            # and per B-586 an export never honours `--full` on its own — it rides the
            # run that genuinely completed those layers. So the bare command below opens
            # a NEW, ungraded audit: on a run that had just earned "Grade A · 96/100" it
            # wrote aria-label="OpenClaw Security: no grade yet" (measured). Telling a
            # user to share the grade they just earned, with a command that cannot carry
            # it, is worse than saying nothing.
            # The wording deliberately does not quote the ungraded badge's own text
            # here: tests/test_b604_dashboard_next_actions.py discriminates the two
            # blocks by that phrase, and it is right to — a graded block that quotes
            # it reads like an ungraded one to a user skimming.
            ("Only the grade + score is shared, never your findings. As written this "
             "command starts a fresh audit that will not complete all five layers, so "
             "its badge would not carry this grade — add `--badge grade.svg` to the "
             "same command that produced it. " if graded else
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

# B-658: the severity the emitted job pages on, named ONCE so the flag in the command and
# the sentence describing exit 0 cannot drift apart. They did: the recipe said "Exit 0
# means nothing changed" while a bare `--exit-code` pages only at HIGH and above, and the
# arm that reports a check leaving PASS emits at MEDIUM unconditionally. Measured on this
# tree: `gateway.auth.mode` token -> none printed `1 change(s) detected` on screen and
# exited 0, so an agent following this very recipe stayed silent about the gateway losing
# authentication — which is the case B-273's own source comment names as its
# reason for existing.
#
# MEDIUM, not HIGH, because HIGH excludes the entire PASS->WARN/UNKNOWN regression arm, and
# that arm is where a config edit lands when it degrades a control rather than removing it.
# Not LOW: INFO and LOW carry routine advisories (a counter moving, a skill version bump)
# and paging on those is what gets a scheduled check switched off, which the epic this
# recipe belongs to counts as 0% coverage.
#
# It does NOT change what a bare `--exit-code` does — that stays at HIGH, documented and
# depended on. This only sets the threshold for the job we hand the agent.
_CRON_FAIL_ON = "medium"

#: How often the low-latency job POLLS. The probe measures 13.1-13.8 s on a real
#: machine against OpenClaw's 30 s trigger deadline (HEADLESS_TRIGGER_WALL_CLOCK_MS),
#: so five minutes keeps the duty cycle near one twenty-fifth and leaves better than
#: 2x headroom on the deadline.
_CRON_POLL_MS = 300000

#: The trigger script. OpenClaw runs it in an isolated quickjs-wasi sandbox with a
#: budget of 5 tool calls and a 30 s wall clock. Grounded against the installed dist,
#: not invented: `runHeadless` resolves to `runCodeModeScriptHeadless`
#: (server-cron-Cwg2hJro.js:3647), whose own tool description states that Node modules
#: and require/import are NOT available and that any shell action must go through
#: `tools.search` / `tools.describe` / `tools.call` (code-mode-D5mNEiYV.js:731). It must
#: return an object carrying a boolean `fire` (server-cron:3572).
#:
#: THE EXIT CODE IS READ OUT OF THE COMMAND'S OWN OUTPUT, not out of a result field.
#: What `tools.call` hands back for an exec tool is a shape we have NOT pinned, and
#: guessing a field name is the kind of invention that fails silently. `echo CSC_RC=$?`
#: puts the answer in stdout, which every exec tool returns in some readable form, and
#: the script greps the stringified result for it.
#:
#: The one guess left is the exec tool's INPUT field (`command`). It is the common
#: name, and a wrong one throws, which the catch turns into fire:true with an explicit
#: message -- loud, not silent. That is the whole reason the error paths fire.
_CRON_TRIGGER_JS = r"""// ClawSecCheck drift probe. Runs on every poll; the agent turn below runs only if
// this returns fire:true. --probe means the check reports drift WITHOUT recording it,
// so the turn it wakes still sees the same drift and is the run that records it.
// This fails OPEN on purpose: anything it cannot determine returns fire:true, because
// OpenClaw treats a trigger error or timeout as fire:false, and a watch that goes
// quiet on error is worse than one that occasionally wakes you for nothing.
const CMD = "__CSCCMD__ --monitor --probe --exit-code --fail-on __FAILON__ --data-dir __DATADIR__ >/dev/null 2>&1; echo CSC_RC=$?";
try {
  const hits = await tools.search("run a shell command");
  if (!hits || !hits.length) {
    return { fire: true, message: "ClawSecCheck watch: no shell tool is available to this job, so it could not check for drift." };
  }
  const raw = JSON.stringify(await tools.call(hits[0].id, { command: CMD }));
  const m = raw.match(/CSC_RC=(\d+)/);
  if (!m) {
    return { fire: true, message: "ClawSecCheck watch: the drift probe returned no exit code, so this run could not tell whether anything changed." };
  }
  const rc = Number(m[1]);
  if (rc === 0) return { fire: false };
  if (rc === 3) return { fire: true, message: "ClawSecCheck: drift was found and deliberately NOT recorded. The run below reports and records it." };
  return { fire: true, message: "ClawSecCheck watch: the drift probe exited " + rc + ", which is not a normal result for a probe." };
} catch (e) {
  return { fire: true, message: "ClawSecCheck watch: the drift probe could not run (" + String(e) + ")." };
}"""


def _json_inner(value: str) -> str:
    """*value* escaped for embedding INSIDE a hand-built JSON string literal.

    `_json_str` returns a quoted JSON string; these recipe fields are assembled by hand and
    need the escaped body without the quotes. Not cosmetic: B-679 puts a resolved
    filesystem path in there, and on Windows that path carries backslashes, which are a
    JSON escape character — `C:\\Users\\...` unescaped makes the emitted job unparseable.
    """
    return json.dumps(value)[1:-1]


def _json_str(value: str) -> str:
    """JSON-encode a string for embedding in the hand-built recipe.

    The trigger script is multi-line JavaScript going into a JSON string field, so it
    needs real JSON escaping rather than a hand-rolled replace. `json.dumps` on a bare
    string is exactly that and nothing more.
    """
    return json.dumps(value)


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
        f'    "message": "Run: {_json_inner(machine_command_prefix())} --monitor --exit-code --fail-on {_CRON_FAIL_ON} '
        f'--data-dir {data_dir}\\nExit 0 means nothing at {_CRON_FAIL_ON} severity or above '
        'was recorded — say nothing and stop; anything below that is advisory and is '
        f'counted by `{_json_inner(machine_command_prefix())} --brief`. Exit 3 means drift was '
        'recorded: report what '
        'changed, quoting the tool\'s own output. Exit 1 means monitoring is NOT established '
        '(the run could not write its state) — say so, it is more urgent than drift. '
        'Exit 2 is a usage error in this job, not a finding."\n'
        '  },\n'
        '  "delivery": { "mode": "announce", "channel": "<your-channel>", "to": "<you>" },\n'
        '  "sessionTarget": "isolated"\n'
        '}'
    )
    # F-181: the low-latency half. `trigger.script` polls headlessly and the agent turn --
    # the part that costs tokens and sends you a message -- runs only when the probe finds
    # drift. The interval is the alert latency, so this is what takes it from six hours to
    # minutes without a resident process and without writing anything into openclaw.json.
    # B-679: the machine form -- absolute interpreter, absolute script. A cron job
    # inherits neither the user's PATH nor their cwd, and the bare console-script name
    # does not exist at all on a ClawHub install (measured: rc=127). The trigger maps any
    # code outside {0, 3} to fire:true, so a command that cannot be found became a
    # wake-up every five minutes, forever.
    trigger_script = (_CRON_TRIGGER_JS
                      .replace("__CSCCMD__", machine_command_prefix())
                      .replace("__FAILON__", _CRON_FAIL_ON)
                      .replace("__DATADIR__", data_dir))
    fast_job = (
        '{\n'
        f'  "name": "{_CRON_JOB_NAME}-now",\n'
        f'  "schedule": {{ "kind": "every", "everyMs": {_CRON_POLL_MS} }},\n'
        f'  "trigger": {{ "script": {_json_str(trigger_script)}, "once": false }},\n'
        '  "payload": {\n'
        '    "kind": "agentTurn",\n'
        f'    "message": "Run: {_json_inner(machine_command_prefix())} --monitor --exit-code --fail-on {_CRON_FAIL_ON} '
        f'--data-dir {data_dir}\\nThe probe that woke you already saw drift but did NOT '
        'record it, so this run is the one that reports and records it. Exit 3 means drift: '
        "report what changed, quoting the tool's own output. Exit 1 means monitoring is NOT "
        'established — say so, it is more urgent than drift. Exit 0 here means the change '
        'was resolved between the probe and this run; say that plainly rather than nothing."\n'
        '  },\n'
        '  "delivery": { "mode": "announce", "channel": "<your-channel>", "to": "<you>" },\n'
        '  "sessionTarget": "isolated"\n'
        '}'
    )
    lines = [
        "Watch this setup on a schedule",
        "",
        "OpenClaw runs the schedule and delivers the message; this tool only checks. Ask",
        "your agent to create these jobs with its own `cron` tool — nothing here is created",
        "for you.",
        "",
        "TWO jobs, and you want both. The first tells you quickly; the second is the one",
        "that cannot fail quietly.",
        "",
        "1. Tell me quickly (polls, wakes you only when something changed):",
        "",
        fast_job,
        "",
        "2. The backstop (runs whatever the poll did or did not do):",
        "",
        job,
        "",
        "Why both, and this is the part worth reading:",
        "",
        "  - OpenClaw treats a trigger script that errors or times out as 'do not fire'.",
        "    So if the probe ever fails to run, job 1 goes SILENT rather than loud — and a",
        "    security watch that goes quiet on error looks exactly like one with nothing to",
        "    report. The script itself fires on anything it cannot determine, which covers",
        "    the errors it can see; it cannot cover being killed or timing out. Job 2 is",
        "    what covers that, which is why it runs unconditionally.",
        "  - The probe takes about 13 s against OpenClaw's 30 s trigger deadline. That is",
        "    comfortable on an idle machine and not guaranteed on a loaded one.",
        "",
        "Before you agree to them:",
        "",
        "  - Job 1 polls every 5 minutes; that interval IS your alert latency. Job 2 runs",
        "    every 6 hours. Change either everyMs.",
        f"  - It messages you at {_CRON_FAIL_ON} severity and above. Change --fail-on to",
        "    widen or narrow that; changes below the line are still recorded, and --brief",
        "    counts them. Nothing at all is silently discarded.",
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
