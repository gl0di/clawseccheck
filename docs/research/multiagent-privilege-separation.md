# Multi-agent privilege separation — schema recon & design (v1.4.0)

> Grounding doc for checks **B45** (per-agent trifecta decomposition) and **B46**
> (multi-agent trifecta exposure). Records what the real OpenClaw schema does and does
> **not** express about multi-agent topology, so the checks never fabricate a field
> (§4) and never emit a false PASS (§5).

## The gap this addresses

The headline trifecta check **A1** (`check_trifecta`) and **RISK-02** flatten the whole
setup into one capability surface: `_enabled_tools(cfg)` reads only global `tools.*` and
asks "is `input × sensitive × outbound` present *anywhere* in the setup?", not "does any
*single* agent hold all three legs?". So a setup that correctly splits capabilities across
agents (privilege separation — the canonical trifecta mitigation) still fails A1: the
engine cannot see the separation. B45 closes that blind spot; B46 sharpens the config-only
signal.

## Grounded schema facts (`agents.*`)

What the config **does** express (verified against existing checks/fixtures):

| Path | Used by | Note |
|------|---------|------|
| `agents.list[]` | B18, B31 | array of agent dicts |
| `agents.subagents`, `agents.defaults.subagents` | B18 (`_has_subagents`) | delegation present |
| `agents.list[N].tools.toolsBySender.<key>.deny` | B31 | per-agent **deny** only |
| `agents.defaults.sandbox.*` | B4 | global sandbox defaults |
| `agents.defaults.model`, `agents.{defaults,list[N]}.heartbeat` | B12, B17 | — |

What the config **does NOT** express — and therefore must stay UNKNOWN / be supplied by
attestation, never invented:

- **Delegation graph.** No field encodes "agent A spawns/calls agent B"
  (`agents.list[N].parent`/`spawns`/`id` do not exist). Multi-agent topology is only
  *inferred* from `agents.list` length > 1 / `agents.subagents` presence.
- **Per-agent capability allowlist.** Only per-agent *deny* lists exist
  (`toolsBySender.<key>.deny`); there is no `agents.list[N].tools.allow`, no per-agent
  `exec.mode`/`sandbox` override grounded in the schema.
- **Inter-agent data-handling controls.** No field for a structured/typed return schema,
  an output sanitizer, a content filter, or a quarantine boundary between agents.

## Design consequences

1. **B45 is attestation-driven (ATTESTED, advisory, `scored=False`).** Per-agent capability
   attribution is not in config, so the agent self-reports its roster via `--attest`
   (`agents: [{name, tools}]`); the engine classifies each agent's legs **itself**
   (reusing A1's `INPUT/SENSITIVE/OUTBOUND` hints — it never trusts a self-graded "safe").
   The config cannot corroborate the declaration, so findings carry ATTESTED confidence
   (like B43/B44) and do not move the grade. Without `--attest`, B45 is UNKNOWN →
   **zero new FAIL on real configs by construction.**
   - WARN — some single agent holds all three legs (separation absent).
   - PASS — no single agent does (necessary condition met) — explicitly **not** a safety
     guarantee: runtime data-flow and the delegation graph are not checked.
   - UNKNOWN — no roster attested.

2. **B46 is config-only and scored, capped at WARN.** The grounded multi-agent *fact*
   (`_has_subagents`) + the global trifecta (A1's legs) + no approval gate is a real,
   gradeable necessary condition for cross-agent reassembly. Capped at WARN so it can never
   introduce a new FAIL (§5); it is a deliberate light nudge layered on A1, not a duplicate.

## Why the runtime part stays out of scope

Even with a perfect roster, a static read-only audit cannot verify the *semantic* property
that makes separation actually safe: whether a privileged agent re-interprets untrusted
data at runtime, or whether the trifecta reassembles across the delegation graph (the
**confused-deputy** problem). Those are runtime behaviours the config does not encode and
that a self-report cannot soundly attest (the claim is exactly what an injection subverts).
The honest ceiling: check the **necessary** structural conditions; report the **sufficient**
runtime condition as UNKNOWN.

## Delivered in 1.5.0 — delegation-graph reassembly (B47 + RISK-11)

A new attestation block `delegation: [{from, to, returns}]` declares the call graph (config
can't express it). `returns` is the caller's data-handling tier for the callee's output:
`schema` (typed/structured = a **wall** that blocks the injected instruction/data channel),
`filtered` (sanitized text = a **sieve**), `raw` (passthrough), or `unknown`.

`checks._reassembly(ctx)` walks the graph from each untrusted-input agent and asks whether the
**full trifecta becomes reachable across agents** (confused deputy), tracking the weakest tier
the untrusted agent can traverse. Verdicts:
- **B47** (ATTESTED, advisory): UNKNOWN without a `delegation` block; PASS when no untrusted
  agent reaches the full trifecta, **or** when every edge it can traverse is a `schema` wall
  (with an explicit *not-runtime-verified* caveat — the wall blocks the channel, but whether a
  privileged agent re-interprets returned data at runtime is out of static scope); WARN when an
  untrusted agent reassembles the trifecta via a non-wall edge (raw/filtered/unknown).
- **RISK-11** narrative fires on the same WARN condition (`<entry> → <secrets> → <outbound>`).

The model is conservative on purpose (a necessary-condition reachability + weakest-tier heuristic,
not a precise per-edge data-flow proof). The runtime trust property stays UNKNOWN — checking the
*declared* graph, not the *execution*.

## Still out of scope

- Precise per-edge data-flow proof (we take the conservative reachability + weakest-tier signal).
- Runtime verification of how a privileged agent treats returned data (stays UNKNOWN by design).
- Localization of RISK narratives (`render_risk_paths` is English-only across all RISK rules).

## Threat references (real, current)

Lethal Trifecta (Simon Willison); confused-deputy / cross-agent reassembly; the dual-LLM
pattern (Willison) and CaMeL ("Defeating Prompt Injections by Design", Google DeepMind,
2025) as the grounded model for *what real separation looks like* — a privileged planner
that never sees untrusted content, a quarantined agent whose output is treated as inert data.
