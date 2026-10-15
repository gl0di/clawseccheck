<!-- markdownlint-disable MD040 MD032 -->

# Playbook: what each block of the card contains

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it when you are asked about, or need to explain, a block of the pasted card.

It emits, in this fixed order (F-153):

- **Section 1 - Headline card**, in one of two shapes depending on whether all five layers ran:
  - **graded** - <code>&#x1F99E; ClawSecCheck · OpenClaw Security Audit · Grade {grade} · {score}/100</code>, a
    16-cell score-bar carrying the count of non-suppressed FAIL/WARN findings, and - whenever the
    score was capped - a disclosure line naming the reason
    (<code>&#x26A0;&#xFE0F; capped from 70/100 &#x2014; open CRITICAL finding</code>).
  - **ungraded** - the most urgent finding in words in that same position, then the mandatory
    missing-layers line: `No grade yet - 2 of 5 layers did not run: agent self-report (not
    submitted), live behaviour test (not submitted).` There is no letter, no `/100` and
    no score-bar anywhere in this shape. Paste both lines; do not compose a grade, do not treat
    the absence of one as a failure of the tool, and do not offer a number of your own.
  Either shape may be followed by `Not fully covered: ...`, which is a layer that ran without
  exhausting its subject - a different fact from a layer that never ran. Relay it too.
  **No standalone Lethal Trifecta chip (F-044)** - trifecta state is one **Agents** finding
  among others in Section 2.
- **Section 2 - Findings, grouped by subject** (details below).
- **Skills** (B-356, when skills are installed): a compact per-skill vet verdict - install
  count, a `clean:` list, and a `verdict - reason` line for anything flagged. Reuses the
  same scoring path `--vet-skill` uses.
- **Plugins** (F-150): the same shape, one merged vet verdict per installed plugin.
- **MCP**: a per-server verdict, reusing `--vet-mcp`'s own axis logic against the config
  already in memory (no second re-read).
- **RISK Chains**: the highest-risk capability chains `--risk-paths` would show.
- **Behavioural** (F-151): a one-paragraph summary folding in both `--behavioral`'s
  metadata-only T1/T2/T3 signals and `--analyze-trajectory`'s indicator-vs-tool-call
  correlation - shown even to say "nothing fired" (Golden Rule #4), never silently
  omitted. A fired T1/T2/T3/B191 detector separately caps the grade (F-154) - already
  reflected in the Grade card above, not something you compute yourself.
- **"Second opinion (advisory)"**: the mandatory judge panel's own verdicts from Step 2 -
  per-item annotations, explicitly advisory, never changing the Grade card above.
- **Section 3 - Coverage of OpenClaw surfaces** (details below).
- **Section 4 - "Worth a glance"** (details below).
- **Section 5 - "What you can do next"** - a short, finding-derived list of the capabilities
  worth running next (monitoring, the live injection test, trend, badge), each with its exact
  command. It is **rendered by the tool, not composed by you** (B-604): every item is gated on
  a finding, so a config where the advice is already done does not get offered it, and the
  wording adapts to whether this run earned a grade. Paste it with the rest of the card.
  Under `--compact` it condenses to a one-line pointer (`run --next for the ranked list`) -
  the compact card exists to fit a message-capped channel and has no room for the full block.
  If this audit was pointed at a non-default `--home` and/or `--data-dir`, the commands that
  actually read or write that state carry the same flags, so running one verbatim targets the
  setup this audit just looked at, not `~/.openclaw`/`~/.clawseccheck`.

Skills/Plugins/MCP/RISK Chains are each independently **omitted** only when there is
genuinely nothing to show (no skills/plugins/MCP servers installed, no RISK chain
detected) - Behavioural and Second opinion are shown once computed, even to report
"nothing fired" / "nothing in the borderline band," per the same never-guess-a-PASS rule
the rest of the audit follows. The one exception is the compact card (`--compact`): if it has to be
cut to its 4096-character budget a section can be dropped, and the cut is marked with a
`...(dropped: ...; truncated to fit budget)` line naming the sections it removed where it can.

Do **not** re-draw the frame, swap it for markdown bold, drop the rule lines, or re-order -
paste exactly what the command prints. Your own prose around the paste follows the
plain-language rule.

(`--dashboard-findings` still prints Section 2 alone, if you ever need just the findings block.)

**Plain `--dashboard` (no `--full`) is the chat-sized card (C-373).** It is a different
shape from the full render above, built for a single chat message: the grade card, an
**Inventory by subject** overview (one line per subject with its rolled-up verdict), the
**most urgent** findings by name only (no `why:`, no evidence), a disclosure of how many
findings it did not name, and a pointer to where the rest is. It is hard-capped under
~4096 characters on any input, so it always fits.

Pair it with `--pdf` - `--dashboard --pdf <path>` - and one run produces both: the card
(the message you paste) and a complete PDF report (every finding with its why and
evidence). The card then names that file. **Attach the PDF file itself; never paste its
path at the user and never present it as a link** - ClawSecCheck is local-only, so there
is no URL, and a path is not a deliverable. Without `--pdf`, the card says how to get one.

**Section 2 - what the pasted findings block contains**

The pasted card's findings block holds the FAIL/WARN findings already grouped by their
8 Inventory subjects, each under an **open 3-sided frame**
(<code>&#x250C;&#x2500; / &#x2502; {icon} {subject} &#x2014; {N} issue(s) / &#x2514;&#x2500;</code>, no right border), most-severe-first within
a subject, a <code>&#x1F534;/&#x1F7E0;/&#x1F7E1;/&#x26AA;</code> severity dot on every issue line, and the `why:` explanation on
every finding. **ClawSecCheck reports; it never changes anything (F-074).** The `why:`
text and a finding's `fix:` line may name the corrective action - that is description, not
action - so paste them as they are. What the tool never does, and what you must not do on
its behalf, is *apply* a change: no edits to the config, no commands run to "fix" a finding.

The renderer already guarantees the findings contract, so **you filter nothing yourself**:
- **PASS/UNKNOWN are dropped** - coverage is Section 3's job, not here;
- **`MEDIUM`/`ATTESTED`-confidence findings are dropped** - they surface in Section 4 ("Worth a glance");
- subjects with nothing to fix are **omitted** (no empty "- clear" headers);
- the Lethal Trifecta (A1) is folded into **Agents** as one finding (no standalone
  headline, F-044), with its active legs named in the finding's own `why:` line.

The 8 subjects, in the fixed order the command renders them:

| Icon | Subject | Surfaces |
|------|---------|---------|
| &#x2699;&#xFE0F; | OpenClaw core | gateway · tools · secrets · monitoring · hooks · update · sessions |
| &#x1F5A5;&#xFE0F; | Host machine | host |
| &#x1F916; | Agents | agents · bootstrap (**+ A1, the Lethal Trifecta**) |
| &#x1F9E9; | Skills | skills |
| &#x1F50C; | MCP servers | mcp |
| &#x1F4E6; | Plugins | installed plugins (populated by the `--full` sweep) |
| &#x1F4E1; | Channels | channels |
| &#x1F4DD; | Logs & trajectories | logs |

Plain-language still governs **your own prose** around the pasted block (any framing
sentence) - never raw codes like "B2 FAIL". The block's `why:` lines are the tool's own
plain-language text: leave them exactly as printed. If the user asks **how to fix** a
finding: remediation is out of ClawSecCheck's scope - it is a reports-only audit. Do not
invent fix commands on its behalf; point the user at the finding's `why:` facts and the
relevant OpenClaw docs instead.

A full worked example of the Grade card + findings block (real box-drawing, real
severity dots) lives in [`docs/USAGE.md`](../USAGE.md) next to the `--dashboard --full`
reference - read it there if you want to see the exact shape before your first paste.
**Always paste the real output, not a remembered sample** - and remember the real paste
continues past the Grade card + Findings with Skills/Plugins/MCP/RISK
Chains/Behavioural/Second opinion/Coverage/Worth a glance, in that order.

**Section 3 - Coverage of OpenClaw surfaces**

Already part of the SAME pasted stdout above - nothing to build from a separate JSON call.
It looks like this (names/counts vary; the `not-checkable`/`roadmap` lines appear only when
that bucket is non-empty):

<pre><code>&#x2014; Coverage of OpenClaw surfaces &#x2014;
&#x2705; checked {checked} · &#x25D1; partial/unknown {partial}  (of {checked+partial} config surfaces)
&#x2298; not-checkable {N} (no OpenClaw config control): {name, name, ...}
&#x25CB; roadmap {M} (no check yet): {name, name, ...}</code></pre>

Since the pasted Section 2 no longer tallies UNKNOWN, this coverage line is the single place
unassessed surfaces are surfaced.

For each partial surface (all findings returned UNKNOWN): if it's OpenClaw core (B43/B44)
and item 1 already ran the capability self-report in Step 2, it's likely already resolved - don't
tell the user to run something that just ran. For any other still-partial surface, note that
answering `--ask` then `--attest` ([`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md) ->
`Choice: deeper / capability check`) may resolve it. For each
entry in `coverage.gaps.not_checkable`: note it is out of static scope - OpenClaw has no config
control to audit there.

**Section 4 - Worth a glance**

Already part of the SAME pasted stdout above (a <code>&#x2014; &#x1F440; Worth a glance &#x2014;</code> block, omitted
entirely when nothing qualifies) - the pasted card already excludes `MEDIUM`/`ATTESTED`
findings from Section 2's findings block, so this is their only home; you don't pull them
out yourself. It reuses the SAME per-finding line format Section 2 uses (severity dot,
title, `why:` line) - it is not a separately-worded narrative, so paste it exactly like the
rest of the card rather than composing your own bullets.

**Your own surrounding prose is where the "confirm before acting" framing lives:** introduce
this block as heuristics, not definitive findings - say **what was seen and why it could
matter**, and suggest one concrete way the user could confirm or dismiss each item, rather
than acting on it outright. Don't rewrite the pasted lines themselves to do this - add the
framing before/after the paste, the same discipline the rest of the card already follows.
