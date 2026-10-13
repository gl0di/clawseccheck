# Attestation Guide

> Looking for pre-install attestation of a THIRD-PARTY skill (not your own
> agent setup)? That's a separate, escalate-only mechanism - see
> `--vet-judge-packet`/`--vet-judged` in `docs/OUTPUT_SCHEMA.md` §15/§16 and
> SKILL.md's "Judge-panel fan-out for `--vet` targets" section. This guide
> covers `--attest`, the whole-agent self-report described below.

## What attestation is

ClawSecCheck reads your OpenClaw config and bootstrap files.  That read-only
scan has a structural limit: it can see what the config says but not what the
agent actually does at runtime.

Attestation is the agent's own self-report that fills those gaps.  You produce
it once with `--ask` and feed it back to the audit with `--attest <file>`.

Without attestation the runtime-dependent checks return `UNKNOWN` and are
excluded from the score - the grade stays conservative but honest.  With
attestation five checks produce real verdicts:

| Check | What it needs | Without attestation |
|---|---|---|
| B43 - capability blast-radius | `tools`, `approval_gates`, `approval_bypass_actors`, `untrusted_to_action` | UNKNOWN |
| B44 - config/attest mismatch | `tools` | UNKNOWN |
| B45 - per-agent privilege separation | `agents` | UNKNOWN |
| B47 - cross-agent trifecta reassembly | `agents`, `delegation` | UNKNOWN |
| B84 - declared vs. effective vs. proven tool use | `proven_tools` (prefers a trajectory-log source when available) | UNKNOWN |

More checks are assisted (not blocked) by attestation:

- **B50-B54** (host monitors): a `host_monitors` name that matches the check's
  category makes that check report PASS (ATTESTED confidence) in place of
  whatever it would have said without it - UNKNOWN, or WARN where the agent is
  high-privilege - unless the host scan itself already found such a monitor.
- **B16** (threat monitoring): any named entry under `host_monitors` turns
  B16 from WARN to PASS (ATTESTED confidence), whatever the monitor is called -
  unlike B50-B54 it does not match the name against a category.
- **B75** and **B76** (MCP tools reaching agents past their per-agent filters):
  they read the `agents` roster, and stay UNKNOWN without one.  The roster is
  also read by B3 and A1 (a declared roster lets an unseen capability leg count
  as answered) and shows up in the report's capability graph.
- **B20** (bootstrap write protection) and **C5** (OpenClaw binary safety):
  `paths` fields point the engine at non-standard locations it then stat()s
  itself - the verdict stays MEDIUM confidence, not ATTESTED.

---

## Round-trip

```text
# 1 - emit a filled-default template
clawseccheck --ask > answers.json

# 2 - fill in the fields (see below), then run:
clawseccheck --attest answers.json

# or combine with a config path:
clawseccheck --home ~/.openclaw --attest answers.json
```

The `_questions` block the template contains is documentation; the engine
ignores it.  Leave it or remove it - either works.

---

## Schema: clawseccheck-attest/1

The file must be valid JSON. `"schema": "clawseccheck-attest/1"` at the top is
recommended and future-proofs the file, but is not required - an absent `schema`
key is accepted as-is; only a *present but wrong* value is rejected.

### tools

```json
"tools": ["search_email", "create_draft", "send_email", "create_filter"]
```

The exact verb names you can invoke - same strings you would pass to a
tool-call API.  Include MCP-server verbs and built-ins.  The engine strips
provider namespacing before classifying, so `mcp__Gmail__send_email` and
`send_email` both resolve to `send_email`.

The engine classifies each verb into a blast-radius class:

| Class | Hints matched | Risk |
|---|---|---|
| EXEC | `bash`, `shell`, `exec`, `run_command`, `run_code`, `terminal` | Arbitrary code - broadest blast |
| MAILBOX_CONFIG | `create_filter`, `auto_forward`, `delegate`, `set_signature`, `vacation` | Persistent silent channel |
| DESTRUCTIVE | `delete_forever`, `permanently_delete`, `empty_trash`, `purge`, `expunge` | Irreversible data loss |
| EGRESS | `send`, `reply`, `forward`, `post`, `publish`, `upload`, `export` | Outbound data |
| REVERSIBLE | `search`, `list`, `get`, `read`, `fetch`, `create_draft`, `archive` | Low blast |

A verb not matching any hint is classified UNKNOWN (treated as low-blast).

### proven_tools

```json
"proven_tools": ["send_email"]
```

Verbs you have LOG or TRACE evidence you *actually invoked* - not just hold.
Stronger than `tools` (which is only what you *could* invoke): a proven
high-blast verb that fired with no approval gate is "the agent did, ungated,"
not just "the agent could." Leave as `[]` if you have no execution log to
cite. Feeds **B84** (declared vs. effective vs. proven tool use), which
prefers an OpenClaw trajectory-log source over this field when one is
present, and otherwise falls back to it - WARN only when a proven high-blast
verb fired AND the attested posture is ungated; UNKNOWN when there's no
proven-tool evidence at all (most setups, since this needs runtime/log
evidence).

### approval_gates

```json
"approval_gates": {"exec": "required", "send": "required", "write": "auto"}
```

For each action class: `"required"` (human confirms first), `"auto"` (agent
acts without asking), or `"unknown"` (the default). Only an explicit `"auto"`
value marks a class as ungated for B43's wording - `"unknown"` is treated the
same as `"required"` (not escalated), so leaving a class at its default reads
as gated, not worst-case. Keys are fixed: `exec`, `send`, `write`.

B43 uses this to distinguish a milder WARN (high-blast verb + gate reported) from a
stronger WARN (high-blast verb + no gate or bypass actor). B43 is `ATTESTED`
confidence and `scored=False` - the verdict is the audited agent's own self-report,
so it never escalates to FAIL (a grade cap the subject can talk itself into would be
unsound); WARN is its ceiling.

### approval_bypass_actors

```json
"approval_bypass_actors": ["heartbeat", "cron"]
```

Actors that can fire tool calls without human confirmation based on runtime
logs or execution traces.  Common values: `heartbeat`, `cron`, `scheduled`,
`sleeper`.  Leave as `[]` if none.

B43 escalates its WARN wording when a bypass actor is present alongside a high-blast
verb even if `approval_gates` says `"required"` - but it never reaches FAIL (see
above).

### untrusted_to_action

```json
"untrusted_to_action": "gated"
```

When the agent acts on untrusted content (incoming email, fetched web page,
tool result), can a side-effect fire without human approval?

- `"gated"` - no: human must confirm.
- `"ungated"` - yes: side-effect can fire automatically.
- `"unknown"` - not sure (default). B43 only escalates on the explicit,
  evidenced `"ungated"` value - a config shorthand or an unanswered/default
  field is not treated as worst-case, it reads the same as `"gated"`.

### host_monitors

```json
"host_monitors": ["CrowdStrike Falcon EDR", "Little Snitch firewall"]
```

Defensive monitors running on the agent's host that the read-only file scan
cannot detect.  Use plain descriptive names; the engine keyword-matches them
to the five host-watch categories (network IDS, host audit, file integrity,
EDR/AV, firewall) and turns the matching B50-B54 result into PASS with
ATTESTED confidence (see the list above).  B16 counts any named entry.  Leave
as `[]` if unsure.

### paths

```json
"paths": {
  "bootstrap": ["/home/alice/.openclaw/workspace/SOUL.md"],
  "openclaw_install": ""
}
```

**`paths.bootstrap`** - absolute paths to identity and memory files
(SOUL.md, AGENTS.md, TOOLS.md, MEMORY.md, ...) if they live outside the
default workspace locations the audit already scans.  The engine `stat()`s
each path itself - you are only pointing it at where to look.  Enables B20
to check permissions on non-standard bootstrap locations.

**`paths.openclaw_install`** - the directory OpenClaw is installed in when
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

An entry must be an object with a non-blank `name` and a `tools` list whose
members are all non-blank strings.  `"tools": []` is valid: an agent that
declares it holds no tools is a legitimate self-report.

The roster is all or nothing.  If `agents` is not a list, or any one entry
fails the rule above, the whole roster is ignored - exactly as if the key
were missing - and B45, B47, B75, B76, B3 and A1 read it that way.  Nothing
is repaired or trimmed: a nameless agent, or one whose `tools` is not a list
of names, would read as an agent that holds nothing, and dropping only the bad
entry could drop the one that declared the risk.  The rest of the attestation
is read as written.  The run prints one warning on stderr with the count and
the reason (never the entry itself).

A name is blank when nothing is left after removing whitespace and the Unicode
control, format and separator characters (categories Cc, Cf, Zs, Zl, Zp), so a
name made only of a zero-width space, a byte-order mark or a control byte is
blank too.

The same all-or-nothing rule applies to the name lists `tools`, `proven_tools`
and `host_monitors`: a list with any member that is not a non-blank string is
ignored whole, with the same kind of warning, as if the key were absent.  A
valid list means what it always did - for example any named `host_monitors`
entry still counts for B16.

An attestation that cannot be parsed at all (not JSON, not an object, an
unknown `schema`, or nested deeper than 200 levels) is ignored whole, with its
own warning.

### delegation

```json
"delegation": [
  {"from": "researcher", "to": "main",     "returns": "schema"},
  {"from": "main",       "to": "executor", "returns": "raw"}
]
```

Delegation edges between agents.  Each edge carries:

- `"from"` / `"to"` - names matching entries in `agents`.
- `"returns"` - how the **caller** handles the callee's output:
  - `"schema"` - typed/structured value (a wall; blocks injected instructions).
  - `"filtered"` - sanitized text (sieve; better than raw, not a wall).
  - `"raw"` - verbatim passthrough (highest risk).
  - `"unknown"` - not sure.

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
  "notes": "Email assistant - approval required before any send or filter creation."
}
```

With this file the audit produces:

- **B43 WARN** - agent holds MAILBOX_CONFIG and EGRESS verbs; approval gate
  prevents escalation to FAIL.
- **B44 PASS or WARN** - depends on whether `tools.allow` in config lists a
  high-blast verb absent from the attest `tools` array.
- **B45 UNKNOWN** - no agent roster (single-agent setup).
- **B47 UNKNOWN** - no delegation edges.
- **B53 PASS (ATTESTED)** - CrowdStrike Falcon matches the EDR/AV category.

---

## Keeping attestation current

- Re-run `clawseccheck --ask` any time your tool grants change; the template
  always reflects the current schema version.
- Store the file outside the OpenClaw config directory so it does not ship
  with your config (e.g. `~/.clawseccheck/attest.json`).
- Never put secrets or PII in any attestation field, including `notes`.
