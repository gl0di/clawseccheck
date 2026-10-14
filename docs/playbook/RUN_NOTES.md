<!-- markdownlint-disable MD040 MD032 -->

# Playbook: run notes - welcome screen, sandbox notice, tool errors, judge pull

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it when a run printed a welcome or sandbox screen or failed, and before the judge-packet pull.

**Which part applies.** Read only the part that matches what the run printed. A first-run welcome screen, a sandbox notice, an error or an empty result: the two blocks directly below, and nothing after them - relay, stop. The capability self-report and the judge-panel pull after them apply ONLY to a normal item-1 run that produced a real audit.

**No OpenClaw config yet?** If `~/.openclaw` is missing or empty, a **bare** default run prints a
short first-run **welcome** screen (Screen 13) instead of a Dashboard - "I looked for an OpenClaw
setup at ... but there's nothing there", with how to point it at the config (`--home <path>`). Relay
that as-is and stop; there's nothing to score. **Sandboxed variant:** when this chat session runs
inside an OpenClaw sandbox, that same screen (and the Dashboard card, if a mode flag skipped the
welcome) says so plainly instead - no `--home <path>` advice, because no path on this filesystem
reaches the host's real config. Relay THAT wording as-is too, and see the stop rule in SKILL.md Step 2 - it
governs this case, not just the welcome screen. Any CI/artifact/work flag (`--json`, `--save`,
`--full`, `--fail-on`, `--badge`, ...) skips the welcome and runs the real audit, so those flags
are always honored. (A home that *exists* but can't be read is a different case - a plain
"Cannot read the OpenClaw home" error, exit code 1.)

**The command errors, hangs, or produces nothing at all?** That means ClawSecCheck *itself* has a
problem - not the audited OpenClaw setup. Tell the user plainly that the tool hit a snag (not their
config), then ask them to run one diagnostic command and share what it prints:

```
python3 {baseDir}/audit.py --debug
```

Relay its output and point to [`docs/TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) for the fix, or
filing an issue if nothing there applies. Never guess at a fix or edit the user's OpenClaw config to
work around it yourself - remediation is out of scope here the same way it is in Step 4/5 of SKILL.md.

**If item 1 (Check everything) was chosen**, first resolve the capability self-report so B43/B44
come back assessed instead of UNKNOWN - this used to be a separate post-scan "deeper" pick; now it's
folded into the single scan itself (F-043). Run the interrogation protocol documented in full in
[`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md) -> `Choice: deeper / capability check` - **read that
section before you run it**: answer your own tool/verb inventory, `approval_gates`,
and `untrusted_to_action` from your own runtime (you already know these), self-probe
`host_monitors` with your own shell access and fall back to asking the user only if the probe is
inconclusive, then assemble the attestation into a file (or have it ready for stdin) - you feed
the SAME attestation into both commands below, in the SAME turn.

Then, still before showing anything to the user, run the now-**mandatory** judge-panel pull
(Dave, 2026-07-30 - this used to be an opt-in extra the user had to ask for; it now runs every
time item 1 is chosen, the same posture the capability self-report already has):

```
python3 {baseDir}/audit.py --judge-packet --attest <path-or- ->
```

**This command's stdout is internal-only: parse it to run the panel (JUDGE_PANEL.md), but never paste,
quote, or summarize its raw JSON to the user** - the panel's own output (the "Second opinion"
block Step 3 pastes) is the user-facing artifact, not this packet. It is a cheap, own-config-only
pull - it never runs `--full`'s heavier sweep/behavioral phases, so it adds no real cost on top
of Step 3's own `--full` render, and it does not by itself replace Step 3 (it consumes the
attestation for THIS command only; Step 3's command needs the same `--attest` again, since
each invocation is its own fresh process - attestation is never persisted between them). Parse
the `judgePacket` array and run the "Judge-panel fan-out for `--judge-packet` items" protocol
in JUDGE_PANEL.md **now, unconditionally** - 3 lensed judge subagents per borderline item, majority vote per
item - building the verdicts JSON Step 3 will feed back. An empty `judgePacket` just means
nothing was in the borderline band this run; proceed to Step 3 with no verdicts file (omit
`--judged-bundle` entirely).

**For any other item**, run the flag for that mode directly - no self-report and no audit judge panel
needed (a pre-install check has its own panel: `VET_JUDGE_PANEL.md`). Pick the right interpreter for the OS:

- **Linux / macOS:** `python3 {baseDir}/audit.py`
- **Windows:** `python {baseDir}\audit.py` (or `py {baseDir}\audit.py`)

Capture the output. The script is read-only and safe to run without any flags.
