<!-- markdownlint-disable MD040 MD032 -->

# Playbook: delivering the dashboard card

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it before you send the reply on every item 1 run.

**This step produces the ONLY chat-visible deliverable in this guided flow.** For item 1,
Step 2's `--judge-packet` pull is never shown to the user - it exists solely to source the
mandatory judge panel (see Step 2); it does not substitute for the paste below.

For item 1, run ONE command - the merged Step 2+3 render (F-153, C-297). It re-consumes the
SAME attestation Step 2 assembled (so B43/B44 come back assessed in THIS render too, not just
in Step 2's internal pull - each invocation is its own fresh process, so `--attest` has to be
passed again) and folds in the mandatory judge panel's verdicts:

```
python3 {baseDir}/audit.py --dashboard --full --attest <path-or- -> --judged-bundle <verdicts-path-or- -> --pdf
```

**`--pdf` is what makes this fit a chat message (C-374).** With it, the run writes a
complete PDF - every finding with its why and evidence, *plus* the Skills/Plugins/MCP,
RISK-chain, Behavioural, Second-opinion and Coverage blocks - and the card collapses to a
chat-sized overview that points at that file. Without `--pdf` the same command pastes the
whole pipeline inline (~11.5 KB), which a channel like Telegram will truncate or reject.
Given with no PATH, as above, it picks the destination itself: if the OpenClaw home's own
managed attachment directory (`<home>/media/outbound`) exists and is writable it writes
there, else `~/.clawseccheck/report.pdf` as before (`<DIR>/report.pdf` under `--data-dir DIR`)
- the check is existence and writability only, never a version.

`--pdf` writes a file. When the user asked for a read-only or no-files run, omit `--pdf` and add
`--no-history`, and say the full detail is available on request.

**Send it, don't describe it (B-606).** The stderr note this command prints hands you a
literal directive line - `MEDIA:<the real path>`. Reproduce that exact line, alone, on
its own line, outside any code fence, in your reply: OpenClaw parses `MEDIA:<path>` out of
assistant replies and turns it into a real file attachment on its own, in both the Control
UI and Telegram - this is a documented mechanism, not something to paraphrase. It can only
reach a path its read tool is allowed to open, which is why the auto-resolved location
above matters: `<home>/media/outbound` is always allowed, so writing there gives the
directive its best chance of actually attaching; anywhere else may be silently dropped by
the host with no error shown here. That is why the path is still worth saying in words
too - free to include, and the only thing left if the attachment never arrives. Never
present it as a link - ClawSecCheck is local-only, so no URL exists - and any link you
write will simply be broken. **Markdown link syntax counts**: `[report.pdf](path)` is a
link, and a chat client strips the href off a local path and leaves a dead one the user
can click forever (measured: 3 of 7 live runs did exactly this - B-606). Write the path as
plain text or inline code. If your channel cannot attach files, say so plainly, **name the
path so the user can open it themselves**, and offer `--dashboard --full` (everything
inline, split across messages) instead - the card names the most urgent findings either
way, so the user is
never left with only a grade.

**Plain-language rule:** Never use internal codes like "B2 FAIL". Describe the actual risk in one
sentence. Examples:

- "B2 FAIL" -> "Anyone on your network can send commands to your agent right now."
- "A1 FAIL (trifecta 3/3)" -> "Your agent has three risky things active at once: it accepts outside
  input, holds sensitive data, and can take actions online. That combination is the most dangerous setup."
- **"trifecta ?/3"** -> "I could not tell how many of the three are active" - never "zero of three".
  `?/3` means at least one leg could not be determined from the config (runtime tools granted at
  session start are not written there), so A1's own advice is to treat it as *possibly* 3/3. Offer
  `--ask` -> `--attest` to resolve it; on a run that found no config, point `--home` at one instead.
- **"A1 WARN naming a resolved default"** -> "One of your channels never says who is allowed to
  message the agent, and leaving that blank does not mean nobody - OpenClaw falls back to letting
  anyone it has approved once keep messaging." Do NOT report this as a third active leg; the tool
  deliberately does not count it as one, and the finding says so. If the user asks how to close it,
  read the `fix` text back rather than inventing a value - the only setting that closes DM ingress
  is `dmPolicy: "disabled"`, and Feishu and Lark have no closed setting at all.
- "B1 FAIL" -> "Your agent's config file is readable by anyone on this computer."
- "B13 FAIL" -> "One of your installed skills has code patterns used by malware."

Present the pasted card, then the two prose sections below it, **in one message**. Render
Sections 5-6 as ordinary text - do NOT wrap them in a code block or monospace fence; that
rule does not apply to the pasted card itself, which must be pasted exactly as the tool
prints it (see below) because its frame relies on monospace alignment.

**Channel-aware delivery:** the combined card can exceed a chat channel's message limit (e.g.
Telegram's ~4096-character cap - Sections 1-2 alone can already run to ~6,482 characters,
before the pipeline blocks listed in CARD_ANATOMY.md add more). You do not have to estimate this: when the rendered
card is too large to relay whole, the CLI says so on stderr with the measured character count
and names both remedies (B-605). Relaying part of an oversized card as if it were the whole is
the one response that is never right. If the destination channel truncates long
messages, drop `--pdf` and add `--compact` instead - the truncation remedy is
`--dashboard --full --compact`. It condenses Plugins/MCP/RISK Chains to headline
counts, trims each Findings/"Worth a glance" finding's "why" text and drops its
evidence bullets entirely (Findings is what actually scales with a bad config's
FAIL/WARN count, so it is what needs trimming), and appends a `--save`/`--html`
pointer for the full detail - or fall back to `--card` (grade + score + trifecta only)
and offer to save the full report via `--save <path>` / `--html <path>`.

**Do not compose the card - paste it, inside a fenced code block.**

Live testing showed that when the model composes the grade card / findings sections
itself, the &#x1F99E; header and the per-subject frames silently vanish. Measured across five live
sessions (2026-08-20): four of five hosts rebuilt the card as their own bullet list, and three
of those four dropped even the tool's name from the reply. The one host that relayed it intact
wrapped it in a fenced block - which is what preserves the header, the score-bar and the
per-subject frames, since the frame relies on monospace alignment. So the WHOLE card above is
one deterministic render - paste its **entire stdout here, verbatim, inside a fenced code
block** (language tag `text`). The CLI repeats this on stderr right next to the card (B-605),
because a rule that lives only here is one you have already summarised away by the time you
need it.

This is the one place a fence belongs: the menu (Step 1) and Sections 5-6 stay ordinary text.

**Section 5 - Scope + history**

<pre><code>&#x2139;&#xFE0F; Grades how your OpenClaw is configured, not live-attack resistance.
   A static audit bounds what your agent *can* do, not how it *behaves* at runtime &#x2014;
   OpenClaw core has no runtime egress/taint gate, so a clean Lethal Trifecta here isn't
   a runtime guarantee; a high grade means "not statically lethal-capable", not "runtime-proof".
   Three exceptions, all cap-only (never raise the grade): (1) a corroborated runtime
   signal (a trajaudit indicator match); (2) a VULNERABLE verdict from the live
   injection test below (menu item a) &#x2014; RESISTANT never raises anything (self-grading
   is never trusted upward); with nothing submitted this layer counts as not-run, so
   the whole result stays ungraded until it is;
   (3) a fired --behavioral detector (T1/T2/T3/B191) when --full ran WITHOUT --fast
   (F-154) &#x2014; that's the only path that computes this cap: a --full --fast run and a
   standalone --behavioral run never wire it into a score at all, and a --full run
   that ran the analysis but never fired one changes nothing. Every OTHER
   runtime-observed signal (every B164 signal including
   exfil_evidence) still cannot move it either way.
   History: ~/.clawseccheck/ (--no-history to skip; a live-test verdict only reaches
   history/trend when the test was run with a fixed --seed &#x2014; an unseeded verdict still
   caps THIS grade but is never recorded, so a fresh random token can't manufacture drift).</code></pre>

If grade is C or worse, add one sentence: "To see if your agent actually *resists* an injection
attack, choose the live test from the menu below."

**Section 6 - Next menu (inline, same message)**

Append immediately at the end of the Dashboard (see Step 4 for routing detail). No "deeper scan"
item - the capability self-report already ran automatically in Step 2 (F-043) - and no "second
opinion" item either - the mandatory judge panel already ran in Step 2 and its verdicts are
already in the Dashboard above, inline or in its PDF (C-297) - so there's nothing left to offer as a separate
follow-up for either (C-132). Render menus as ordinary text - do NOT wrap them
in a code block or monospace fence:

> Next - &#x2705; read-only · &#x26A1; touches live agent (asks)
>   a &#x26A1; Live injection test   b &#x2705; Turn on monitoring
>   c &#x2705; Save full report      d &#x2705; Menu   Start with a?

Item a is not a duplicate of anything in Step 2/3: nothing so far actually ran an injection
against you - the Behavioural block of the pasted card is a post-hoc replay of past activity, and the
mandatory judge panel only reviewed borderline findings, not tested the agent live - so this
is the first real behavioral test (VULNERABLE vs RESISTANT) in the flow.
