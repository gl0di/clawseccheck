<!-- markdownlint-disable MD040 MD032 -->

# Playbook: natural-language to tool quick map

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it before you relay the output of a named row.

## Natural-language to tool quick map

Use this to map what the user says to the right command. This table is the always-loaded
dispatcher; the full protocol behind each row is the matching `## Choice:` section in
[`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md) - read that section before you run the command.

| User says | Run |
|---|---|
| "fix", "how do I fix", "what should I do" | out of scope - reports only; explain, don't generate fixes |
| "vet", "scan this skill", "is this safe to install", "check before I install" | `--vet <path>` - type autodetected; `--vet-skill <path>` forces the skill engine (add `--json` or `--sarif PATH` for machine-readable / CI output) |
| "vet this plugin", "is this plugin safe" | `--vet-plugin <path>` (plugin root or `openclaw.plugin.json`; `--vet <path>` autodetects too) |
| "is this safe to download", "check this link / package before I fetch it" | `--vet-source <slug\|url\|pkg>` - zero network, identity only; then quarantine + `--vet` the fetched copy |
| "walk me through vetting this before I install it", "should I install this" | `--vet-source` -> `--vet-plan <target>` (prints the fetch+isolate commands, you run them) -> `--advise <quarantine-path>` for an INSTALL/CAUTION/DO-NOT-INSTALL call |
| "is my MCP safe", "check my connected servers", "vet my MCP", "are my MCP servers trusted", "MCP supply chain" | `--vet-mcp` (add `--json` or `--sarif PATH` for machine-readable / CI output) |
| "what dangerous actions can my agent take", "least privilege", "check my tools", "capability", "blast radius", "deeper check" | `--ask` then `--attest <filled.json>` |
| "monitor", "watch", "alert me", "ongoing", "keep checking" | `--monitor` (ask first) |
| "canary", "injection test", "am I vulnerable", "try an attack" | `--canary` then `--dryrun` - the standalone equivalent of DASHBOARD.md's Section 6 menu item a. A submitted VULNERABLE verdict fed back via `--dashboard --full --judged-bundle <file>`'s `liveTest` bucket hard-caps the grade (F-155); RESISTANT never raises anything, and submitting nothing leaves this run ungraded rather than unaffected (five-layer ledger) - see Step 3, Section 6. |
| "red team", "adversarial", "attack suite" | `--redteam` |
| "trend", "history", "am I improving", "getting better" | `--trend` - plots the **graded** scans only. Ungraded runs are still recorded (so "last check was N days ago" stays honest) but carry no point to plot, and the trend never draws a line across the rule change. Say so rather than letting a short line read as a short history. |
| "percentile", "compare", "above average", "how do I rank" | `--percentile` - needs a score, so an ungraded run answers "no rank yet" instead of a number. Relay that; do not estimate one. |
| "badge", "share my grade", "shareable", "certificate" | `--badge` or `--card` - on an ungraded run the badge reads "no grade yet"; offer it as sharing the *result*, not the grade. Attach the SVG file itself; never redraw or regenerate the image. |
| "why no grade", "where's my score", "why didn't it give me a letter" | Not an error - read the missing-layers line back. Layers 4 and 5 need the user: run `--ask` -> `--attest` for the self-report, and one of `--canary` / `--dryrun` / `--redteam` / `--multiturn` for the live behaviour test. Offer them; never fabricate a grade or present a capped number in its place. |
| "HTML report", "full report" | `--html report.html` |
| "PDF", "send me a PDF", "phone", "mobile", "attach the report" | `--pdf report.pdf` - attach the file itself, never paste the path |
| "JSON", "machine readable", "raw data" | `--json` |
| "what did my agent actually do", "behavioral", "runtime audit", "did it really do that", "prove it happened" | `--behavioral` - post-hoc, proof-by-log tool-call sequences from the trajectory sidecar; metadata-only, WARN-only, never scored. **Always relay the output - never drop it.** (Item 1's `--dashboard --full` also runs this as its "Behavioural" block - F-151 - but that block is a one-paragraph summary; a fired T1/T2/T3/B191 detector there also caps the grade, F-154. A user asking for this by name should still get the standalone command for the full per-line detail.) |
| "did a suspicious skill's instructions actually run", "was this indicator acted on" | `--analyze-trajectory` - post-hoc, correlates installed-skill indicators against real tool-call arguments. **Any <code>&#x26A0; INCIDENT SIGNAL</code> line is a real incident finding - never drop it.** (Folded into item 1's `--dashboard --full` "Behavioural" block too, F-151 - same one-paragraph-summary caveat as the row above; ask for the standalone command for full detail.) |
| "second opinion", "judge packet", "review the borderline findings" | Outside item 1's flow: `--judge-packet` - JSON list of borderline findings for host-agent review; summarize item count + per-item verdicts, offer to save large output to a file, **never paste raw JSON, never drop it** - then feed panel verdicts back with `--judged <file>` (see `docs/FLOW_CHOICES.md`). Inside item 1's flow this already ran, MANDATORY, in Step 2 - its verdicts are already in the pasted "Second opinion (advisory)" block, nothing further to do (C-297). |
| "scan everything", "maximum coverage", "don't skip anything", "check the full logs" | add `--exhaustive` to whatever command is already running (composes with `--full`; has effect on its own too, since B164/B180 run on every audit) - raises the trajectory-file / log-sink / per-line scan caps instead of the interactive-fast defaults. Slower; offer it after a normal run's own disclosure names something skipped (a file-count cap, a time-budget skip, an oversized-line gap) and the user wants that specific gap narrowed, not as a default suggestion on every run. It raises the budget substantially rather than removing it, and states its own coverage either way - so relay what the `--exhaustive` run itself reports and don't promise it scanned everything. |
