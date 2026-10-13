<!-- markdownlint-disable MD040 MD032 -->

## Playbook: judge panel for --judge-packet items

> **Note for the agent:** symbols in this file are written as HTML entities (for example `&#x1F99E;` is the lobster emoji). When you show them to the user, output the actual character, never the entity.

This is part of the ClawSecCheck skill, moved out of `SKILL.md` unchanged so the always-loaded
manifest stays small. `SKILL.md` says when to read it. A reference here to a numbered step or a named section of the skill (for example "Step 2") points to that section of `SKILL.md`; other playbook files are named. Read it before you spawn a judge or build a verdicts file on an item 1 run.

### Judge-panel fan-out for `--judge-packet` items (advisory second opinion)

`--judge-packet` (see `docs/OUTPUT_SCHEMA.md` §12) emits a JSON array of borderline
findings the deterministic engine could not resolve on its own - every item is already
stripped of raw skill source (only a redacted evidence location and a fixed
plain-language question survive). This section generalizes the isolator pattern in
[`docs/ISOLATION.md`](../ISOLATION.md)
from "one verdict per target" to "one **panel** of distinct-lens verdicts per packet
item," so the second opinion draws on more than one way of reading the same evidence.

**When to run it:** as a MANDATORY part of the SAME guided-flow turn as Step 2's audit,
whenever item 1 ("Check everything") was chosen - the same posture the capability
self-report/`--attest` step already has (F-043): run it every time, never wait for the
user to ask (Dave, 2026-07-30 - this reverses the prior "opt-in, only when asked"
policy; see Step 2). Step 2's own `--judge-packet --attest` pull already hands you the
`judgePacket` array in the same step - fan out the panel below over every item in it
immediately, BEFORE presenting Step 3's Dashboard, so the pasted card's "Second opinion
(advisory)" block already carries real per-item verdicts rather than a bare pending
count. **Outside item 1's flow** - the user explicitly asks for "a second opinion" /
"review the borderline findings" without having just run the full audit (Step 5's
`judge packet` branch) - this panel stays exactly what it always was: run only when
asked, per [`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md)'s `Choice: judge packet`
section.

1. Run `python3 {baseDir}/audit.py --judge-packet --attest <path-or- ->` (the same
   attestation file/stdin Step 2 just assembled) and parse its `judgePacket` array.
   This pull is cheap and own-config-only - it never runs `--full`'s heavier sweep/
   behavioral phases, so it costs nothing extra on top of Step 3's own
   `--dashboard --full` render in SKILL.md. (Outside item 1's flow, drop `--attest` if there
   is no attestation for this turn.)
2. For each item, spawn **3 judge subagents**, each given a distinct lens on the **same**
   packet item (input is the item's `redacted_evidence`/`question` fields, plus its
   engine-authored `safe_facts` (C-284 - e.g. a validated destination hostname) and
   `corroboration` (C-285 - how many other checks fired on the same target) fields when
   present - never raw skill source, so the context-firewall holds for the whole panel,
   not just one judge). **`corroboration` is context for the judge to weigh, never a
   rule to apply mechanically** - do not treat `count >= N` as itself meaning DANGEROUS;
   that would smuggle a threshold into an advisory layer and duplicate a severity
   decision this engine already owns deterministically. A high count is a reason to look
   closer, not a verdict already reached.
   - **Intent** - "does the skill's declared purpose justify this finding?"
   - **Exfil-destination** - "is the network/data sink first-party/trusted, or
     attacker-controlled?"
   - **Obfuscation** - "does the evidence suggest deliberate encoding/indirection to
     hide behavior, or an ordinary implementation detail?"

   Each judge returns **only** a typed verdict - no other output form is permitted:

   ```json
   {
     "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
     "confidence": 0.0,
     "reason": "<one sentence>",
     "risk_ids": ["B65"]
   }
   ```

   A judge that finds nothing in the item to decide from answers `"verdict": "ABSTAIN"`
   instead of guessing (each item's own `verdict_schema.abstain` says so). `ABSTAIN` is not
   a fourth severity: it means "I could not assess this", and it is never to be replaced
   by `SAFE` to look finished.
3. **Majority vote** per item across its 3 lens verdicts. A tie (no single verdict has
   at least 2 of the 3 votes - e.g. one SAFE, one SUSPICIOUS, one DANGEROUS) escalates
   to the **worst** of the three rather than picking arbitrarily - the same fail-safe
   principle as the rest of this skill. An `ABSTAIN` lens is not a vote: decide among the
   lenses that did answer. When only one lens answered, submit its answer if it is
   `SUSPICIOUS` or `DANGEROUS` (a concern is never discarded) and submit `ABSTAIN` if it
   is `SAFE` - one `SAFE` is not a majority. When no lens answered, submit `ABSTAIN`.
   An `ABSTAIN` entry is treated exactly like no entry for that item: the card shows it
   as abstained, not reviewed, and it never raises or lowers anything.
4. Spawn in the same locked-down form as the isolator subagent in
   [`docs/ISOLATION.md`](../ISOLATION.md) - **no tools**,
   `maxSpawnDepth: 1`, **ephemeral** - and bound concurrency the same way
   (`maxChildrenPerAgent` / `agents.subagents.maxConcurrent`); fan out across packet
   items, not unboundedly across items × 3 lenses at once.
5. **Mandatory, with graceful fallback**: run this panel every time item 1's audit
   completes - never skip it and never wait to be asked, the same posture Step 2's
   attestation already has. If subagents are unavailable, fall back to reasoning
   through all 3 lenses yourself in one inline turn per item, with the SECURITY rule as
   the active guard - never claim a panel ran when it did not, and never claim 3
   distinct subagents ran when you reasoned through it inline instead.
6. Build the verdicts JSON from the collected per-item majority votes and feed it back
   as Step 3's `--judged-bundle <file-or- ->`'s `judged` bucket (see Step 3), so the
   ONE pasted Dashboard card already shows the resulting **"Second opinion (advisory)"**
   block, explicitly labeled and **separate from the scored Dashboard** - never a
   follow-up message. (Outside item 1's flow, the standalone `--judge-packet` this
   panel answered is instead fed back with `--judged <file>`, which renders just the
   audit's grade/findings plus this same advisory panel - see
   [`docs/FLOW_CHOICES.md`](../FLOW_CHOICES.md).) This extends the "Verdicts are
   advisory narration only" rule in [`docs/ISOLATION.md`](../ISOLATION.md): a judge
   panel can re-rank or annotate a finding the engine already reported, but it can
   never raise or lower the A-F grade.
7. **Optional, only on the user's OWN config, only if they ask to reduce noise:** the
   same verdicts JSON can instead be fed to `--propose-ignore` (C-253), which prints
   PROPOSED `.clawseccheckignore` entries for items the panel verdicted SAFE - never
   applied by that command itself. Only suggest this when the user explicitly wants
   fewer findings to review, never as a default step. Applying a proposal is a
   **separate, human-confirmed** command (`--apply-ignore-proposals`, or `--yes` for
   scripted use) - always show the exact entries before running it, the same way
   `--purge` is presented. This gains no new authority over what `.clawseccheckignore`
   already does: a score-capping CRITICAL/HIGH FAIL (or a sensitive id) still appears
   in the report even if suppressed, and every applied entry changes
   `.clawseccheckignore`, which `--monitor` already flags as drift. **Residual, stated
   plainly:** if the host agent running this panel is itself compromised or
   prompt-injected, it could rubber-stamp a real finding as SAFE - the mitigations
   above bound the damage (the capping FAIL still surfaces, the change is still
   visible to `--monitor`) but do not eliminate the risk; this is not presented as a
   solved problem.
