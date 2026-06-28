# Attestation Guide

## What attestation is

ClawSecCheck reads your OpenClaw config and bootstrap files.  That read-only
scan has a structural limit: it can see what the config says but not what the
agent actually does at runtime.

Attestation is the agent's own self-report that fills those gaps.  You produce
it once with `--ask` and feed it back to the audit with `--attest <file>`.

Without attestation the runtime-dependent checks return `UNKNOWN` and are
excluded from the score — the grade stays conservative but honest.  With
attestation four checks produce real verdicts:

| Check | What it needs | Without attestation |
|---|---|---|
| B43 — capability blast-radius | `tools`, `approval_gates`, `approval_bypass_actors`, `untrusted_to_action` | UNKNOWN |
| B44 — config/attest mismatch | `tools` | UNKNOWN |
| B45 — per-agent privilege separation | `agents` | UNKNOWN |
| B47 — cross-agent trifecta reassembly | `agents`, `delegation` | UNKNOWN |

Two more checks are assisted (not blocked) by attestation:

- **B50–B54** (host monitors): declaring a monitor the file scan cannot see
  upgrades UNKNOWN to PASS (ATTESTED confidence).
- **B20** (bootstrap write protection) and **C5** (OpenClaw binary safety):
  `paths` fields point the engine at non-standard locations it then stat()s
  itself — the verdict stays HIGH confidence, not ATTESTED.

---

## Round-trip

```text
# 1 — emit a filled-default template
clawseccheck --ask > answers.json

# 2 — fill in the fields (see below), then run:
clawseccheck --attest answers.json

# or combine with a config path:
clawseccheck --home ~/.openclaw --attest answers.json
```

The `_questions` block the template contains is documentation; the engine
ignores it.  Leave it or remove it — either works.

---

## Schema: clawseccheck-attest/1

The file must be valid JSON with `"schema": "clawseccheck-attest/1"` at the top.

### tools

```json
"tools": ["search_email", "create_draft", "send_email", "create_filter"]
```

The exact verb names you can invoke — same strings you would pass to a
tool-call API.  Include MCP-server verbs and built-ins.  The engine strips
provider namespacing before classifying, so `mcp__Gmail__send_email` and
`send_email` both resolve to `send_email`.

The engine classifies each verb into a blast-radius class:

| Class | Hints matched | Risk |
|---|---|---|
| EXEC | `bash`, `shell`, `exec`, `run_command`, `run_code`, `terminal` | Arbitrary code — broadest blast |
| MAILBOX_CONFIG | `create_filter`, `auto_forward`, `delegate`, `set_signature`, `vacation` | Persistent silent channel |
| DESTRUCTIVE | `delete_forever`, `permanently_delete`, `empty_trash`, `purge`, `expunge` | Irreversible data loss |
| EGRESS | `send`, `reply`, `forward`, `post`, `publish`, `upload`, `export` | Outbound data |
| REVERSIBLE | `search`, `list`, `get`, `read`, `fetch`, `create_draft`, `archive` | Low blast |

A verb not matching any hint is classified UNKNOWN (treated as low-blast).

### approval_gates

```json
"approval_gates": {"exec": "required", "send": "required", "write": "auto"}
```

For each action class: `"required"` (human confirms first), `"auto"` (agent
acts without asking), or `"unknown"` (the default; treated as worst-case).
Keys are fixed: `exec`, `send`, `write`.

B43 uses this to distinguish WARN (high-blast verb + gate reported) from FAIL
(high-blast verb + no gate or bypass actor).

### approval_bypass_actors

```json
"approval_bypass_actors": ["heartbeat", "cron"]
```

Actors that can fire tool calls without human confirmation based on runtime
logs or execution traces.  Common values: `heartbeat`, `cron`, `scheduled`,
`sleeper`.  Leave as `[]` if none.

B43 raises to FAIL when a bypass actor is present alongside a high-blast verb
even if `approval_gates` says `"required"`.

### untrusted_to_action

```json
"untrusted_to_action": "gated"
```

When the agent acts on untrusted content (incoming email, fetched web page,
tool result), can a side-effect fire without human approval?

- `"gated"` — no: human must confirm.
- `"ungated"` — yes: side-effect can fire automatically.
- `"unknown"` — not sure (default; treated as worst-case by B43).

### host_monitors

```json
"host_monitors": ["CrowdStrike Falcon EDR", "Little Snitch firewall"]
```

Defensive monitors running on the agent's host that the read-only file scan
cannot detect.  Use plain descriptive names; the engine keyword-matches them
to the five host-watch categories (network IDS, host audit, file integrity,
EDR/AV, firewall) and upgrades the matching B50–B54 result from UNKNOWN to
PASS with ATTESTED confidence.  Leave as `[]` if unsure.

### paths

```json
"paths": {
  "bootstrap": ["/home/alice/.openclaw/workspace/SOUL.md"],
  "openclaw_install": ""
}
```

**`paths.bootstrap`** — absolute paths to identity and memory files
(SOUL.md, AGENTS.md, TOOLS.md, MEMORY.md, …) if they live outside the
default workspace locations the audit already scans.  The engine `stat()`s
each path itself — you are only pointing it at where to look.  Enables B20
to check permissions on non-standard bootstrap locations.

**`paths.openclaw_install`** — the directory OpenClaw is installed in when
the `openclaw` binary is not on `PATH`.  The engine stats the directory
itself.  Enables C5 to check binary-dir and ancestor permissions.

Leave both as their defaults (`[]` and `""`) when the standard discovery
already finds your files.

### agents

```json
"agents": [
  {"name": "researcher", "tools": ["web_fetch", "read_file"]},
  {"name": "main",       "tools": ["read_file", "send_email", "create_filter"]}
]
```

Declare only when you run **more than one agent**.  List each agent by name
and the exact verb names it holds.  The engine classifies each agent's
lethal-trifecta legs itself using the same blast-radius taxonomy.  B45 then
checks whether any single agent holds all three legs (untrusted input +
sensitive data + outbound/exec).

Leave as `[]` for a single-agent setup.

### delegation

```json
"delegation": [
  {"from": "researcher", "to": "main",     "returns": "schema"},
  {"from": "main",       "to": "executor", "returns": "raw"}
]
```

Delegation edges between agents.  Each edge carries:

- `"from"` / `"to"` — names matching entries in `agents`.
- `"returns"` — how the **caller** handles the callee's output:
  - `"schema"` — typed/structured value (a wall; blocks injected instructions).
  - `"filtered"` — sanitized text (sieve; better than raw, not a wall).
  - `"raw"` — verbatim passthrough (highest risk).
  - `"unknown"` — not sure.

B47 uses this graph to check whether an untrusted-input agent can reach the
full trifecta by driving other agents.  A `"raw"` edge on any path from an
untrusted-input agent to a high-blast agent produces WARN.

Leave as `[]` when there is no delegation.

### notes

Free-text field for context.  The engine ignores it.

---

## Minimal example

```json
{
  "schema": "clawseccheck-attest/1",
  "tools": ["search_email", "read_email", "create_draft", "send_email", "create_filter"],
  "approval_gates": {"exec": "required", "send": "required", "write": "required"},
  "approval_bypass_actors": [],
  "untrusted_to_action": "gated",
  "host_monitors": ["CrowdStrike Falcon EDR"],
  "paths": {"bootstrap": [], "openclaw_install": ""},
  "agents": [],
  "delegation": [],
  "notes": "Email assistant — approval required before any send or filter creation."
}
```

With this file the audit produces:

- **B43 WARN** — agent holds MAILBOX_CONFIG and EGRESS verbs; approval gate
  prevents escalation to FAIL.
- **B44 PASS or WARN** — depends on whether `tools.allow` in config lists a
  high-blast verb absent from the attest `tools` array.
- **B45 UNKNOWN** — no agent roster (single-agent setup).
- **B47 UNKNOWN** — no delegation edges.
- **B53 PASS (ATTESTED)** — CrowdStrike Falcon matches the EDR/AV category.

---

## Keeping attestation current

- Re-run `clawseccheck --ask` any time your tool grants change; the template
  always reflects the current schema version.
- Store the file outside the OpenClaw config directory so it does not ship
  with your config (e.g. `~/.clawseccheck/attest.json`).
- Never put secrets or PII in any attestation field, including `notes`.
