<!-- markdownlint-disable MD040 MD032 -->

## Playbook: modes, the pre-scan menu and updates

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it before you run mode 2, 3 or 4, a report export, or the private / update modifiers.

### Step 1 - Pre-scan menu (show every time)

Show this screen **every time** the user requests an audit. Do NOT auto-run the scan - present the
menu and wait for a choice. Answering this screen with "check", "go", or "1" runs item 1 - Full check (the default).

The one exception is `--brief` at session start (see the "Session start" row of the Mode map
below) - it is not a mode reached from this menu at all. It never reads your OpenClaw config,
bootstrap files, or any of the paths § "When to use this skill" gates consent on; it reads only
this tool's own local store under `~/.clawseccheck/`. That narrower scope is what earns it the
one unprompted, no-menu path in this document.

**The three modes.** ClawSecCheck is organised on one axis - how often you reach for it - and every
other capability is an instrument *inside* a mode, not a peer of one:

| Mode | Question it answers | Cadence | Produces |
| --- | --- | --- | --- |
| **A · Full check** | How safe is this setup? | once, deliberately | findings - and a grade **only when all five layers ran** |
| **B · Watch** | What changed since last time? | repeatedly | events, **never a number** |
| **C · Before you install** | Is this thing safe to add? | on the event | INSTALL / CAUTION / DO-NOT-INSTALL - **not a letter** |

**A full check has five layers**, and a letter grade is issued only when all five ran:

| # | Layer | Automatic? | How it runs |
| --- | --- | --- | --- |
| 1 | Static: config, files, permissions | yes | the default run |
| 2 | Sweep of what is installed: skills + plugins | yes | `--full` |
| 3 | Logs and trajectories: what already happened | yes, budget-bounded | `--full` (also `--behavioral`, `--analyze-trajectory`) |
| 4 | Agent self-report | **no** - you must answer it | `--ask` -> `--attest` (Step 2) |
| 5 | Live behaviour test | **no** - pokes the running agent | `--canary` / `--dryrun` / `--redteam` / `--multiturn` |

Short of all five **no security score or grade is printed** - not a capped one. The report leads with the most
urgent finding in words, then a mandatory line naming which layers did not run. Relay both; never
substitute a grade of your own, and never describe an ungraded run as an error. It is a result:
the tool has still told the user the most important thing it knows. The text report may still print
a `Tamper posture: N/100` line: that is the sub-score of one defence and is labelled as not this
run's verdict - relay it as that, never as the grade.

**The honesty invariant - state it as a promise the user can hold us to.** Every mode ends by
naming what it did not check, as part of the verdict rather than as fine print. No mode prints
"clear" about a subject it did not look at. A *graded* run can still carry a `Not fully covered: ...`
line - that means a layer ran without exhausting its subject (log scans are budget-bounded by
construction), which is a different fact from a layer never having run.

**"Complete" rule.** Never tell the user "complete audit" / "audit finished" / "all N layers done"
unless the card you are looking at is actually graded, names no missing layers, and carries no
blindness/sandbox cap - say so from the card itself, never from what you asked for or attempted.
Running every command in this flow is not the same as the run having covered everything; a
refused live test, a sandboxed session, or a self-report you had to leave `unknown` all still end
in a real, honest, INCOMPLETE result, and that is what gets relayed.

Get the version and build age from:

```
python3 {baseDir}/audit.py --version
```

This prints `clawseccheck X.Y.Z (YYYY-MM-DD)`. Compute the age in days from the release date to today.

Present (or just run `python3 {baseDir}/audit.py --menu`, which renders this exact
screen with the version, last-check age, and offline staleness nudge already
filled in). Render the menu as ordinary text - do NOT wrap it in a code block or
monospace fence:

> &#x1F99E; ClawSecCheck · v{version}
>
>   1  &#x1F50D; Full check            how safe is this setup?
>   2  &#x1F440; Watch                 what changed since last time?
>   3  &#x1F4E6; Before you install    is this thing safe to add?
>   4  &#x1F4CB; Everything else       the full list of instruments
>
>   A grade only when all five layers ran - otherwise findings, and what's missing.
>
>   &#x1F552; Last check: {N} days ago        <- "not checked yet" when there's no history
>   &#x1F199; Say "update" to check for a newer version   <- always shown; when the build is stale it gets louder: "Build is {N} days old - say update"

Keep it tiny: the three modes, and "Everything else" for the instruments inside
them. Don't dump a wall of flags - let item 4 reveal the rest on demand. The
grade-rule line is part of the screen, not decoration: it tells the user what
earns a letter *before* they choose, instead of leaving them to discover a
missing number at the end of a report. The number, the phrase, or a tap all
select an item; free phrasing ("scan me", "am I safe?") maps to the nearest one.

**Mode map - each choice maps to existing flags:**

| Choice | Flag(s) | Notes |
|--------|---------|-------|
| 1 Full check (mode A, "check" / "go") | `--dashboard --full` (+ auto capability self-report AND a mandatory judge panel, see Step 2) | Runs every layer that needs no live test, in one go (a letter grade also needs the opt-in live test, which is not part of this item): audit **+** capability self-report (B43/B44 resolved inline instead of UNKNOWN - F-043) **+** MCP vet **+** per-skill/per-plugin sweeps (`Skills`/`Plugins`, one merged verdict per item, F-150) **+** the highest-risk chains (`RISK Chains`) **+** a behavioral/trajectory replay (`Behavioural`, F-151) **+** a MANDATORY judge-panel second opinion (`Second opinion (advisory)` - see "Judge-panel fan-out" in JUDGE_PANEL.md). Everything here is **visibility/advisory-only** - it never moves the score or grade - except two disclosed, cap-only exceptions: a fired behavioral detector (F-154) and a VULNERABLE live-test verdict (F-155, DASHBOARD.md Section 6). All rendered as ONE fixed-order Dashboard card by the merged Step 2+3 command (F-153) - see Step 2/3 of SKILL.md for the exact protocol, and [`docs/USAGE.md`](../USAGE.md) for the full flag-by-flag composition. The live injection test (&#x26A1;, DASHBOARD.md Section 6 item a) stays a separate, opt-in step - not part of item 1. |
| Session start (no prompt needed) | `--brief --exit-code` | **Run this once at the start of a session, before the pre-scan menu above and without asking first.** This is the one exception to "Do NOT auto-run the scan" (Step 1): it never touches your OpenClaw config, bootstrap files, or any path that menu's consent covers - it only reads ClawSecCheck's own local store under `~/.clawseccheck/` (the last drift baseline, the event journal, the score history), and it **writes nothing** - no audit, no snapshot, no journal append. **Check the exit code, not the text.** A healthy, recently-checked setup with nothing notable in the journal prints nothing and exits 0 - say nothing to the user and move on; a manufactured "all clear" line would be a claim this tool cannot back. A nonzero exit means there is something to relay (one to five lines) - print those verbatim. It answers two questions nothing else does: *is the watch still running* (the cheapest attack on a scheduled monitor is to stop it, which touches none of the files it watches), and *did it record anything while nobody was looking* (an alert is written once; if the human missed that moment the signal never existed). Silence past three days is not "fine": it is above the longest gap ever measured on a real machine. |
| 2 Watch (mode B) | `--monitor` · `--trend` · `--watch-log` · `--verify-history` · `--verify-events` | What changed since last time (`--monitor --probe` shows it without recording anything) - a snapshot diff, the graded-scan trend, the Agent Watch timeline, and the two hash-chain integrity checks over the local stores. Those two have **three** outcomes, not two: an absent, empty or unreadable store reports `NOT VERIFIED` ("no chain here"), which is neither a pass nor a tamper finding and must never be relayed as "chain OK". `--trend`/`--watch-log` disclose that same journal's chain provenance inline, too - silence there means it verified in full; a line appears only if it's broken or carries a caveat (e.g. rows recorded before this tool began chaining, unconfirmed but not evidence of tampering). **Watch never produces a number**; zero events renders as "nothing has changed since \<date\>", which is not the same sentence as "all clear" and must not be relayed as one. |
| 3 Before you install (mode C) | `--vet <path>` (autodetects skill · plugin · MCP spec; `--vet-skill` / `--vet-plugin` force an engine) · `--vet-mcp [name]` (configured MCP) · `--vet-source <slug\|url>` (before anything is even downloaded) · `--vet-all` · `--vet-plan` · `--advise` | Supply-chain check on something you're about to trust. Its verdict is **INSTALL / CAUTION / DO-NOT-INSTALL - never a letter grade**; a letter here would collide with mode A's on a different scale. See the vet flow in Step 5 -> [`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md). **Offer this BEFORE the user installs or updates anything** - whenever they mention adding a skill, plugin or MCP server, say you can check it first and name the target. That is the whole point of the mode, and it is worth nothing if it is only ever reached after the fact. **Never say or imply that you blocked, prevented or quarantined an install:** this skill cannot stop one. OpenClaw's real pre-install gate is the `before_install` plugin hook, and this is not a plugin. What it does is tell the user what it found, before or after, so they can decide. |
| 4 Everything else | `--functions` (Screen 12 - the full palette) | Saying "menu" / "functions" / "more" expands the complete capability list - run `python3 {baseDir}/audit.py --functions` (or present its output). It is grouped by the three modes, and every capability is a speakable name grounded to its real flag, so there's no wall of raw flags. (`--menu` itself renders *this* Welcome screen; the palette is one level deeper.) **It is ~6 KB** - send it as its own message, and if the channel still truncates, split on the blank line between sections and say which sections you left out. Never let the host silently cut it. |
| Reports & exports | `--save <path>` · `--badge <path>` · `--html` · `--sarif` · `--pdf` | **Not a mode** - these are instruments inside mode A, and they used to sit on the menu as if they were a peer of one. Offer them after a check, on the result the user just got - and pass them ON that command (`--dashboard --full ... --badge b.svg`), which is what makes the artifact carry the check's own grade instead of a fresh bare run's (B-586). Asked for alone, they render a bare run, and the badge then reads "no grade yet"; do not describe that one as sharing a grade. |
| "private" modifier | Add `--no-history` to any mode | "1 private" = Full check + `--no-history`. Nothing written to `~/.clawseccheck/` for the audit/vet/self-test modes - but `--trend` always writes its own row, and `--monitor` records its snapshot, regardless of `--no-history`; it is not a suppressor for those two. To see what changed WITHOUT recording anything, run `--monitor --probe` (it prints `persisted: false`). |
| "update" | Offline notice + agent check | ClawSecCheck never phones home. On "update" the **host agent** checks ClawHub for a newer version and, if there is one, offers `openclaw skills update clawseccheck` - the tool itself stays offline. |

After the user chooses (or says "check" / "go"), proceed to Step 2.

## Keeping ClawSecCheck current (advisory only)

A **stale security scanner is itself a risk**, so the tool nudges honestly **without breaking its
own promises**: every staleness signal is 100% offline (a local-clock/build-date report line plus
an optional local hint file it never fetches, and a hedged "mostly UNKNOWN" nudge) - the exact
mechanics are in [`docs/USAGE.md`](../USAGE.md) under "Staleness reminder (offline)".
**Updating is the user's own action, never an automatic step** - never check for or install
updates as a side effect of running an audit; if the user explicitly asks, they run the tool they
installed it with (`openclaw skills update clawseccheck` / `clawhub update --all`), and can
confirm integrity afterward with `--verify-self` (SHA-256 against the trusted release digest). The
contract stays simple: the audit is **local-only and read-only**; anything that reaches the
network is an **explicit, user-initiated** action - never something the skill does on its own.
