# B76 — High-Blast MCP Tool-Inheritance Bypass (Attestation-Based)

**Date:** 2026-06-29  
**Version target:** v2.4.0  
**Check ID:** B76  
**Pulse task:** CLAWSECCHECK-I-010  
**Grounding:** OpenClaw issue #63399 (MCP tools bypass per-agent tools filter)

---

## Problem

OpenClaw issue #63399 confirms that globally-registered `mcp.servers` tools are
auto-injected into ALL agents, bypassing per-agent `tools.allow/deny/alsoAllow/profile`.

B75 (scored=False) flags this broadly: any agent with any MCP tools is advisory-warned.
B76 (scored=True) focuses on the risk that actually affects grade: agents that hold
**high-blast** MCP tools (EXEC, EGRESS, DESTRUCTIVE, MAILBOX_CONFIG verb classes).
These are the tools that enable code execution, external exfiltration, irreversible
deletion, or persistent mailbox takeover — the primitives attackers seek.

Note: OpenClaw config has **no** per-agent `tools.allow` field. The only per-agent
restriction is `agents.list[N].tools.toolsBySender.*.deny`. B75/B76 cannot compare
"intended" vs "actual" at the config level — they observe what the running agent
actually holds via attestation, and flag the dangerous subset.

---

## Check Design

**ID:** B76  
**Name:** `check_mcp_bypass_highblast`  
**Surface:** `multiagent`  
**scored:** `True` (affects grade when attestation is available)  
**Max verdict:** WARN (never FAIL — §5 zero false-positive FAILs)  
**confidence:** `ATTESTED`

### Trigger

For each attested agent:
1. Agent holds MCP tools (tool name contains `__` — the `<server>__<verb>` pattern)
2. At least one of those MCP tools has `classify_verb(tool)` in `HIGH_BLAST_CLASSES`
   (`"EXEC"`, `"MAILBOX_CONFIG"`, `"DESTRUCTIVE"`, `"EGRESS"`)
3. `mcp.servers` (or `mcpServers`) is configured in global config

→ WARN scored=True with agent name + high-blast tools cited

`classify_verb()` strips the MCP namespace (`mcp__server__verb` → `verb`) before
classifying, so provider names never pollute the verdict (§§ grounding §2.4 ZKDS).

### Verdict table

| Condition | Verdict |
|-----------|---------|
| No attestation | UNKNOWN |
| No `mcp.servers` configured | PASS |
| ≥1 agent holds high-blast MCP tools | WARN (scored) |
| All attested agents hold only low-blast MCP tools | PASS |

---

## Implementation

### Logic

```python
def check_mcp_bypass_highblast(ctx: Context) -> Finding:
    agents = _attest.attested_agents(ctx.attestation)
    if not agents:
        return _finding("B76", UNKNOWN, ...)

    mcp_servers = _mcp_servers(ctx.config)
    if not mcp_servers:
        return _finding("B76", PASS, ...)   # no MCP → not applicable

    blast_ev = []
    for agent in agents:
        mcp_tools = [t for t in agent["tools"] if "__" in t]
        high_blast = [t for t in mcp_tools
                      if _attest.classify_verb(t) in _attest.HIGH_BLAST_CLASSES]
        if high_blast:
            # build evidence line: "agent 'X' holds N high-blast MCP tool(s): ..."
            blast_ev.append(...)

    if blast_ev:
        return _finding("B76", WARN, ..., blast_ev)
    return _finding("B76", PASS, ...)
```

---

## Fixtures

### `tests/fixtures/clean_b76/`
- Config with `mcp.servers` configured
- Attest: agents hold only low-blast MCP tools (e.g. `mcp__slack__list_channels`,
  `mcp__drive__get`, `mcp__files__read`)
- Expected: PASS

### `tests/fixtures/bad_b76/`
- Config with `mcp.servers` configured
- Attest: agent holds high-blast MCP tools (e.g. `mcp__slack__send_message`,
  `mcp__files__bash`, `mcp__github__delete_forever`)
- Expected: WARN, agent name + tools cited in evidence

### No attestation
- `ctx.attestation = None`
- Expected: UNKNOWN

---

## Tests (`tests/test_b076_mcp_bypass_highblast.py`)

1. `test_b76_unknown_no_attestation` — no attestation → UNKNOWN
2. `test_b76_unknown_empty_attestation` — empty attestation → UNKNOWN
3. `test_b76_pass_no_mcp_servers` — attestation with MCP tools but no `mcp.servers` → PASS
4. `test_b76_pass_low_blast_only` — agents hold only search/read/draft MCP tools → PASS
5. `test_b76_warn_egress_mcp` — agent holds `mcp__slack__send_message` (EGRESS) → WARN
6. `test_b76_warn_exec_mcp` — agent holds `mcp__tools__bash` (EXEC) → WARN
7. `test_b76_warn_multiple_agents` — multiple agents with high-blast tools → WARN, all cited
8. `test_b76_warn_evidence_has_tool_names` — WARN evidence lists the specific tools
9. `test_b76_is_scored` — meta.scored is True
10. `test_b76_confidence_is_attested` — meta.confidence == "ATTESTED"

---

## Catalog entry

```python
CheckMeta(
    "B76",
    "High-blast MCP tool-inheritance bypass (attested)",
    HIGH,
    "hardening",
    "Least Privilege / MCP Tool Inheritance",
    scored=True,
    confidence=ATTESTED,
    surface="multiagent",
)
```

---

## Release checklist

- [ ] B76 check function in `checks.py` (after B75)
- [ ] CheckMeta in `catalog.py` (after B75 entry)
- [ ] CHECKS list registration (after `check_mcp_tool_inheritance`)
- [ ] `tests/test_b076_mcp_bypass_highblast.py` (10 tests)
- [ ] `ruff check .` clean
- [ ] Full suite 100% pass
- [ ] Zero false-positive FAILs on real home config
- [ ] Version bump to v2.4.0
