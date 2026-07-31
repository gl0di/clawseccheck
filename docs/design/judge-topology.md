# Judge topology: why the LLM lives in the host agent, never inside the scanner

Design analysis and decision record. No code change is made by this document.

Origin: 2026-07-24, Dave asked how Cisco's Skill Scanner's approach compares to ours. A
local copy of their scanner was read from source at `eval/competitors/tools/skill-scanner/`
(pulled in for the E-055 benchmark run) during the grounding pass that produced the
judge-layer-hardening epic this document closes out. **That `eval/` checkout is a dev-only,
unshipped directory** — present on the machine that ran the benchmark, not guaranteed to
exist in every environment this doc is read from. The file:line citations below are
carried verbatim from that grounding pass, not re-derived in the session that wrote this
file (its own working copy had no `eval/` directory to check against). Nothing here is
inferred from Cisco's README or marketing copy — every claim traces to a specific file the
grounding pass actually opened; anything it could not confirm from source is marked
**unverified** rather than assumed.

## 1. The two topologies, factually

**Cisco Skill Scanner** is static by default, with four opt-in analyzer layers
(`skill_scanner/cli/cli.py:923-952`):

| flag | mechanism | network |
|---|---|---|
| *(default)* | `core/analyzers/static.py` (2,493 lines) | no |
| `--use-behavioral` | dataflow analysis | no |
| `--use-llm` | full skill content → LiteLLM (OpenAI/Anthropic/Bedrock/Gemini/Ollama) | **yes** |
| `--enable-meta` | a second LLM pass that **filters false positives** — i.e. can delete a finding the static pass already made | **yes** |
| `--use-aidefense` / `--use-virustotal` | vendor cloud lookups | **yes** |

With `--use-llm` enabled, the prompt builder sends the **raw** skill body and scripts —
15,000 chars per file, 100,000 chars total (`core/analyzers/llm_prompt_builder.py:100-190`)
— to whichever LLM provider is configured. Injection defence at that point is
**prompt-level**: a `secrets.token_hex(16)`-randomized delimiter pair around the untrusted
content, a fixed protection preamble (`skill_scanner/data/prompts/boilerplate_protection_rule_prompt.md`),
and detection of an attempt to forge the delimiter. This is the same *shape* of protocol
B-317 added to our own one intentionally-open read (§16 of `docs/OUTPUT_SCHEMA.md`) — the
difference is where it sits: theirs guards every `--use-llm` request to a third-party
model; ours guards one specific, narrow, human-in-the-loop read.

**ClawSecCheck** never puts an LLM inside the tool. The engine (stdlib-only, zero network)
emits a `--judge-packet`/`--vet-judge-packet` — an already-redacted, structured artifact
(§12/§15 of `docs/OUTPUT_SCHEMA.md`) — and the **user's own host agent**, running locally
under whatever model and policy the user already trusts, is the one that reads it and
judges. No API key, no per-scan network call, no raw skill content leaves the machine
through this engine. The context firewall is **structural**: content-ring evidence is
reduced to an engine-authored `(relpath:lineno)` location — or, when no location suffix
exists, a `dig()`-style config field path (`config_field_paths`, C-361) — before it ever
reaches a judge (F-113), with three narrow, validated exceptions this same epic added: a
length-capped LDH-only hostname (`safe_facts.destination_host`, C-284), bare check-id
corroboration counts (C-285), and that config field path itself
(`safe_facts.config_field_paths`, C-361) — none of which can carry attacker-authored free
text. Authority is scoped by content
**provenance**, not by a single global rule: a judge reviewing the user's own config may
only suppress noise (`--propose-ignore`, C-253); a judge reviewing an untrusted `--vet`
target may only escalate (C-254) — a successful injection against either path can only
ever move the verdict in the direction that costs the attacker nothing to fail at.

## 2. The rule that decides it

Golden Rule #1 (`CLAUDE.md` §2 of the project laws, this skill's binding doctrine):
**local-only, forever — no network calls, no telemetry, no analytics upload, no
phone-home. If a feature could exfiltrate, it must not exist.** A scanner whose job is to
audit `~/.openclaw/` for agents that might leak the user's own data to a third party would
be the exact thing it exists to catch if it routed the contents of that same directory to
an LLM vendor to do the auditing. This is a **product boundary**, decided once, not a
performance knob to be re-litigated per release — no child of the E-061 epic that produced
C-284/B-317/C-285 was permitted to introduce a network call, an API key, or a new runtime
dependency, and none did.

## 3. What the choice costs, stated honestly

We are not a standalone scanner in a CI pipeline with no host agent attached — Cisco's
`--use-llm` mode works unattended; ours structurally cannot, by design. And the actual
recall numbers must be quoted correctly, including the part that argues against us
(E-055, `docs/design/severity-separability.md`, SkillTrustBench 5,520 cases):

| operating point | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| ours, WARN+FAIL | 0.8136 | 0.8381 | 0.7906 | 0.3603 |
| ours, **FAIL only** | 0.5341 | 0.9121 | **0.3776** | 0.0858 |
| static peer, HIGH+ (peer's own `is_safe`) | 0.7803 | 0.9278 | **0.6732** | 0.1236 |

**At matched precision (~0.92)**, static Cisco recalls 0.673 against our FAIL-only 0.378 —
1.78x more of the real malware at the same false-alarm cost, with no LLM involved on
either side of that specific comparison. The headline "our 0.8136 beats their 0.7803" only
appears when our loosest setting (WARN+FAIL, judge-eligible) is compared against their
strictest — that comparison was published internally once already and was wrong to make;
it must never be repeated as a lead. The honest framing is that a static-only comparison
already favors the peer, before either side's LLM path is even in play.

## 4. What the choice buys

No API key to provision or rotate, no per-scan network round-trip or cost, no third party
added to the trust path for a tool whose whole purpose is auditing what already has access
to that path, and no raw `~/.openclaw/` content leaving the machine through this engine
under any flag. The injection defence for the one place we do hand untrusted prose to an
LLM (C-255) is enforced by a **structural firewall** for almost everything else, with a
documented, test-pinned protocol (B-317) for the one place that firewall is intentionally
open — rather than being a prompt asking a model nicely not to comply, which is the whole
of Cisco's defence for every `--use-llm` request.

## 5. The open frontier

C-252 (`docs/design/severity-separability.md`) measured that of the malicious cases this
engine catches only at WARN, **97.32% had zero FAIL-capable signal at all** — the attack
was described in the skill's prose, not shipped as code a regex can read intent out of.
Loosening the down-rank gates that keep WARN-only findings from a spurious FAIL is the
wrong lever: they already fire on benign content at 5.32%, roughly twice the malicious
rate, so widening them trades false negatives for false positives rather than closing the
gap. The strongest *sound* lever found — evidence accumulation (C-285's corroboration
count, C-252 §5.1) — narrows the precision-matched recall gap from 1.78x to 1.52x. It does
not close it.

**This is why the prose-reading judge path (C-255, and the packet it now hands the judge
via C-284/B-317/C-285) is not a side branch of this epic — it is the main remaining lever
on recall.** A regex-based engine cannot read intent out of prose; a host agent already
can. The quality of what we hand that judge, and the safety of the one read where the
context firewall opens for it, are first-order concerns for exactly this reason — which is
what the other three children of E-061 addressed.
