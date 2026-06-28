# ClawSecCheck — Output Schema (Public API Contract)

This document is the frozen public API contract for the machine-readable outputs
produced by `--json` and `--sarif`. Integrators (CI pipelines, dashboards, SIEM
connectors) may rely on the field names, types, and envelope shapes described here.

**Contract baseline:** v2.0.0 (2026-06-28). Breaking changes vs v1.x:

- `--lang` / `--lang he` CLI flag removed; output is English-only.
- No `lang` field in any JSON or SARIF output.

**Stability rule:** field names and top-level envelope shapes are frozen. New
**optional** top-level fields may be added in any minor release. Fields will not
be removed or renamed without a major version bump (see `CHANGELOG.md` and
versioning §6 in `CLAUDE.md`).

---

## 1. `--json` — Full Audit Output

### Top-level envelope

| Field | Type | Always present | Description |
|---|---|---|---|
| `score` | `int` | yes | Overall security score, 0–100. |
| `grade` | `str` | yes | Letter grade: `"A"`, `"B"`, `"C"`, `"D"`, `"E"`, or `"F"`. |
| `capped` | `bool` | yes | `true` if the score was capped below `raw_score` (e.g. Lethal Trifecta triggered). |
| `raw_score` | `int` | yes | Score before any cap is applied. Equals `score` when `capped` is `false`. |
| `trifecta` | `str` | yes | Lethal Trifecta sub-score expressed as `"<n>/3"` (e.g. `"2/3"`). `"?/3"` means check A1 did not run. |
| `findings` | `array[Finding]` | yes | All check results. See §2. |
| `next_actions` | `array[NextAction]` | yes | Prioritised remediation suggestions. See §3. |
| `risk_paths` | `array[RiskPath]` | only with `--risk` | Combinational attack chains. See §4. |
| `capability_graph` | `object` | yes | Static capability map of the inspected agent. See §5. |
| `secret_reachability` | `array[SecretClass]` | yes | Per-class secret-exposure analysis. See §6. |
| `intentAttestationRequests` | `array[SAR]` | yes | Structured Attestation Requests for B62 capability-intent mismatches. See §7. |
| `coverage` | `object` | yes | Surface/family coverage map for the Dashboard. See §8. |
| `projection` | `object` | yes | What-if score projections for the Dashboard. See §9. |

### Skeleton

```json
{
  "score": 74,
  "grade": "C",
  "capped": false,
  "raw_score": 74,
  "trifecta": "1/3",
  "findings": [ ... ],
  "next_actions": [ ... ],
  "capability_graph": { "nodes": [], "edges": [] },
  "secret_reachability": [ ... ],
  "intentAttestationRequests": [],
  "coverage": { "surfaces": {}, "families": {}, "gaps": {}, "summary": {} },
  "projection": { "current": {}, "top1": null, "cumulative": {} }
}
```

---

## 2. Finding Object

Shared by `--json`, `--json` with `--risk`, and `--vet` mode.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Check identifier, e.g. `"B21"`, `"B67"`, `"A1"`. |
| `title` | `str` | Human-readable check title (sanitised; no raw secrets). |
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `status` | `str` | `"PASS"`, `"FAIL"`, `"WARN"`, or `"UNKNOWN"`. |
| `detail` | `str` | Explanation of the finding (sanitised). |
| `fix` | `str` | Short remediation hint (sanitised). |
| `framework` | `str` | Threat-framework reference, e.g. `"OWASP LLM01"`. |
| `confidence` | `str` | `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `pass_confidence` | `str \| null` | For PASS findings only: `"verified"` (evidence-based pass), `"no_signal"` (check found nothing but couldn't confirm safety), or `null` (FAIL/WARN/UNKNOWN — not applicable). |
| `suppressed` | `bool` | `true` if the finding was suppressed by the user's baseline. |
| `owasp` | `array[str]` | OWASP LLM Top 10 codes that apply, e.g. `["LLM01", "LLM02"]`. May be empty. |
| `ast` | `array[str]` | OWASP Agentic Skills Top 10 (2026) codes that apply, e.g. `["AST03", "AST05"]`. May be empty. Additive metadata only — no scoring or verdict impact. |
| `remediation` | `object` | Paste-ready remediation. Keys: `commands` (`array[str]`) and `config` (`array[object]`). |
| `evidence` | `array[str]` | Supporting evidence strings (sanitised; no raw secrets). May be empty. |
| `surface` | `str` | OpenClaw surface slug this check belongs to (e.g. `"gateway"`, `"tools"`, `"bootstrap"`). `""` for findings not in the CATALOG (e.g. MCP-vet diagnostics). One of the 14 slugs in `catalog.SURFACES` or `""`. |

### `remediation` object

```json
{
  "commands": ["openclaw config set tool.sandboxed true"],
  "config": [
    {"path": "tools.sandboxed", "set": true, "note": "Restrict tool execution"}
  ]
}
```

Each `config` item has `path` (str, the config key), optionally `set` (the target
value), and optionally `note` (str, explanatory text). When `set` is absent the
item describes a manual configuration step.

### Finding skeleton

```json
{
  "id": "B21",
  "title": "Tool-output trust boundary",
  "severity": "HIGH",
  "status": "FAIL",
  "detail": "Retrieved content is injected into the prompt without sanitisation.",
  "fix": "Enable output sandboxing.",
  "framework": "OWASP LLM02",
  "confidence": "HIGH",
  "suppressed": false,
  "owasp": ["LLM02"],
  "ast": [],
  "remediation": {
    "commands": [],
    "config": []
  },
  "evidence": ["tools.output.sanitize = false"],
  "surface": "bootstrap"
}
```

---

## 3. NextAction Object

Items in `next_actions` are ordered by ascending `priority` (lower = more urgent).

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Action identifier, e.g. `"NA-B21"`. |
| `title` | `str` | Short action label (sanitised). |
| `command` | `str` | Paste-ready shell command or empty string if not applicable. |
| `why` | `str` | One-sentence rationale. |
| `priority` | `int` | Urgency rank; lower integers are higher priority. |

---

## 4. `--json` with `--risk` — Attack Chain Extension

When `--risk` is passed, `risk_paths` is added to the top-level envelope.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Risk chain identifier, e.g. `"RISK-03"`. |
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `title` | `str` | Attack chain name. |
| `chain` | `array[str]` | Ordered list of check IDs that form the chain, e.g. `["B07", "B21", "B33"]`. |
| `why` | `str` | Narrative explanation of the attack path. |
| `fix` | `str` | Recommended mitigation. |

`risk_paths` is absent (not `null`, not `[]`) when `--risk` was not passed.

---

## 5. `capability_graph` Object

Always present. Describes the static capability topology of the inspected agent
(inputs, main agent, sub-agents, MCP servers). Both arrays are empty when context
is unavailable.

```json
{
  "nodes": [
    {
      "id": "input",
      "label": "input",
      "kind": "ingress",
      "tools": ["web_search"],
      "secrets_visible": false,
      "can_write_memory": false,
      "can_egress": true
    },
    {
      "id": "main",
      "label": "main",
      "kind": "agent",
      "tools": ["fs_read", "web_search"],
      "secrets_visible": true,
      "can_write_memory": false,
      "can_egress": true
    },
    {
      "id": "mcp:brave-search",
      "label": "brave-search",
      "kind": "mcp",
      "tools": ["brave_web_search"],
      "secrets_visible": true,
      "can_write_memory": false,
      "can_egress": true
    }
  ],
  "edges": [
    {"from": "input", "to": "main"},
    {"from": "main", "to": "mcp:brave-search"}
  ]
}
```

### Node fields

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique node identifier. `"input"`, `"main"`, `"subagent:<name>"`, or `"mcp:<name>"`. |
| `label` | `str` | Display name. |
| `kind` | `str` | `"ingress"`, `"agent"`, `"subagent"`, or `"mcp"`. |
| `tools` | `array[str]` | Tool names visible to this node. |
| `secrets_visible` | `bool` | `true` if the node can read secret-bearing configuration or env vars. |
| `can_write_memory` | `bool` | `true` if the node has write access to memory / workspace. |
| `can_egress` | `bool` | `true` if the node can make outbound network calls. |

### Edge fields

| Field | Type | Description |
|---|---|---|
| `from` | `str` | Source node `id`. |
| `to` | `str` | Destination node `id`. |

---

## 6. `secret_reachability` Array

Always present. Each entry represents one class of potential secret exposure.
The array is not empty even when no secrets are found; it always contains all
defined classes with `reachable: false` and an empty `evidence` array.

| Field | Type | Description |
|---|---|---|
| `class` | `str` | Secret class: `"env"`, `"mcp-passthrough"`, `".env"`, `"keychain"`, `"cookies"`, `"ssh"`, or `"cloud"`. |
| `reachable` | `bool` | `true` if at least one signal in this class was detected. |
| `evidence` | `array[str]` | Supporting signals (sanitised; no raw secret values). |

---

## 7. `intentAttestationRequests` Array (F-020)

Always present. Empty list when no B62 capability-intent mismatches were found.
One entry per skill flagged by check B62.

| Field | Type | Description |
|---|---|---|
| `skill` | `str` | Skill name (redacted if secret-shaped). |
| `declared_purpose` | `str` | Declared purpose extracted from the skill manifest. |
| `capability_set` | `array[str]` | All capability families detected in the skill's code. |
| `mismatches` | `array[MismatchItem]` | Capabilities that are surprising for the declared category. |
| `computed_risk` | `str` | Risk level computed from the mismatch set: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `question` | `str` | Natural-language attestation question for the host operator. |

### MismatchItem fields

| Field | Type | Description |
|---|---|---|
| `capability` | `str` | Capability family name, e.g. `"network_egress"`. |
| `declared` | `bool` | Always `false` (the capability was not declared). |
| `evidence` | `str` | Explanation of where the capability was detected (redacted). |

---

## 8. `coverage` Object (F-031)

Always present in `--json` output. Describes check coverage across the 13 OpenClaw
bucket surfaces and the 7 security families they roll up to. Used by the Dashboard
to render the coverage heat-map.

```json
{
  "surfaces": {
    "gateway": { "state": "checked", "counts": {"pass": 2, "warn": 1, "fail": 0, "unknown": 0} },
    "tools":   { "state": "partial", "counts": {"pass": 0, "warn": 0, "fail": 0, "unknown": 3} }
  },
  "families": {
    "exposure":  { "surfaces": ["gateway", "channels", "sessions"],
                   "counts":   {"pass": 2, "warn": 1, "fail": 0, "unknown": 0},
                   "worst":    "warn" },
    "privilege": { "surfaces": ["tools", "agents"],
                   "counts":   {"pass": 0, "warn": 0, "fail": 0, "unknown": 5},
                   "worst":    "unknown" }
  },
  "gaps": {
    "not_checkable": ["outbound egress allowlist"],
    "roadmap": []
  },
  "summary": {
    "checked": 8,
    "partial": 5,
    "not_checkable": 1,
    "roadmap": 0
  }
}
```

### `surfaces` map

Each key is a surface slug (one of the 13 bucket surfaces; `"trifecta"` is excluded — it
is a cross-cutting headline chip, not a coverage bucket). Value fields:

| Field | Type | Description |
|---|---|---|
| `state` | `str` | `"checked"` if ≥1 finding returned PASS/FAIL/WARN; `"partial"` if all findings were UNKNOWN or none ran. |
| `counts` | `object` | `{"pass": N, "warn": N, "fail": N, "unknown": N}` — finding totals for this surface. |

### `families` map

Keys are the 7 security family slugs: `"exposure"`, `"privilege"`, `"supply_chain"`,
`"content_integrity"`, `"secrets"`, `"detection"`, `"automation"`. Value fields:

| Field | Type | Description |
|---|---|---|
| `surfaces` | `array[str]` | Member surface slugs in canonical order. |
| `counts` | `object` | Aggregated `{"pass", "warn", "fail", "unknown"}` across all member surfaces. |
| `worst` | `str` | Worst status across the family: `"fail"`, `"warn"`, `"pass"`, or `"unknown"`. |

### `gaps` object

| Field | Type | Description |
|---|---|---|
| `not_checkable` | `array[str]` | Static list of OpenClaw surfaces with no auditable config control. |
| `roadmap` | `array[str]` | Surfaces not yet covered by ClawSecCheck (extensible; currently empty). |

### `summary` object

| Field | Type | Description |
|---|---|---|
| `checked` | `int` | Surfaces with ≥1 non-UNKNOWN finding. |
| `partial` | `int` | Surfaces where all findings are UNKNOWN. |
| `not_checkable` | `int` | Count of `gaps.not_checkable` entries. |
| `roadmap` | `int` | Count of `gaps.roadmap` entries. |

---

## 9. `projection` Object (F-031)

Always present in `--json` output. Estimates the score impact of fixing FAIL findings.
Used by the Dashboard to render the "fix this one thing" call-to-action.

```json
{
  "current":    {"score": 52, "grade": "D"},
  "top1":       {"finding_id": "B1", "projected_score": 72, "projected_grade": "C", "delta": 20},
  "cumulative": {"projected_score": 81, "projected_grade": "B", "delta": 29}
}
```

| Field | Type | Description |
|---|---|---|
| `current` | `object` | `{"score": int, "grade": str}` — current audit score (mirrors top-level `score`/`grade`). |
| `top1` | `object \| null` | The single highest-leverage fix. `null` when there are no fixable (scored, non-suppressed) FAIL findings. |
| `cumulative` | `object` | Projected score after fixing all CRITICAL + HIGH FAILs simultaneously. `delta` is 0 when none exist. |

### `top1` fields

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` | Check ID of the recommended fix (e.g. `"B1"`). |
| `projected_score` | `int` | Estimated score if this finding were resolved. |
| `projected_grade` | `str` | Corresponding letter grade. |
| `delta` | `int` | `projected_score − current.score`. |

### `cumulative` fields

| Field | Type | Description |
|---|---|---|
| `projected_score` | `int` | Score after all CRITICAL + HIGH FAILs are fixed. |
| `projected_grade` | `str` | Corresponding letter grade. |
| `delta` | `int` | `projected_score − current.score`. 0 when no CRITICAL/HIGH FAILs exist. |

> **Projection is estimated**, not guaranteed. It assumes each fixing finding flips
> cleanly to PASS; actual hardening may unlock or reveal new findings.

---

## 10. SARIF 2.1.0 Output (`--sarif`)

Schema: `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`

Only `FAIL` and `WARN` findings that are not suppressed appear as `results` entries.
`PASS`, `UNKNOWN`, and suppressed findings are omitted from `results` but their
corresponding checks always appear in `rules`.

### Top-level structure

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { ... } },
      "results": [ ... ]
    }
  ]
}
```

### `runs[0].tool.driver` fields

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Always `"ClawSecCheck"`. |
| `version` | `str` | Tool version string, e.g. `"1.2.0"`. |
| `informationUri` | `str` | Always `"https://github.com/gl0di/clawseccheck"`. |
| `rules` | `array[Rule]` | One entry per check in the CATALOG, in catalog order. |

### Rule object

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Check identifier, e.g. `"B21"`. |
| `name` | `str` | Check title. |
| `shortDescription.text` | `str` | Same as `name`. |
| `defaultConfiguration.level` | `str` | Severity mapping: `CRITICAL`/`HIGH` → `"error"`, `MEDIUM` → `"warning"`, `LOW` → `"note"`. |

### Result object

| Field | Type | Always present | Description |
|---|---|---|---|
| `ruleId` | `str` | yes | Check identifier. |
| `level` | `str` | yes | `"error"` for `FAIL`, `"warning"` for `WARN`. |
| `message.text` | `str` | yes | Finding detail text (sanitised). |
| `properties.confidence` | `str` | yes | `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `properties.evidence` | `array[str]` | yes | Supporting evidence (may be empty array). |
| `fixes` | `array[Fix]` | only when remediation exists | Paste-ready remediation steps. |

### Fix object

```json
{"description": {"text": "openclaw config set tool.sandboxed true"}}
```

`fixes` is omitted (not `null`, not `[]`) when the check has no paste-ready remediation.
Each entry carries only `description.text`; ClawSecCheck never emits `artifactChanges`
because it is read-only by design.

### `runs[0].properties.analysis_completeness` (when context is available)

Present only when a full context object was passed to the renderer (i.e. when invoked
as a full audit, not in unit/library mode).

| Field | Type | Description |
|---|---|---|
| `total_files_inspected` | `int` | Number of files read during the audit. |
| `excluded_binary_files_count` | `int` | Binary files skipped. |
| `archives_unpacked` | `int` | Archives extracted and inspected. |
| `limit_hits` | `array` | Signals where an inspection limit was reached. |
| `path_traversal_violations` | `array` | Paths rejected by the traversal guard. |
| `file_manifest` | `object` | Map of relative path → file metadata. |
| `simulated_effects` | `array` | Effect-profile entries derived from static analysis of skill Python files. |

### `runs[0].properties.effectProfile` (when non-empty)

Present only when at least one installed skill has a non-empty effect profile (F-018).
Keys are skill names; values are arrays of effect-profile entry objects.

---

## 11. `--vet` Mode Output

Produced by `--vet` and `--vet-mcp`. Simpler than the full audit — no score, no
`next_actions`, no `capability_graph`.

### Fields

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Always `"clawseccheck"`. |
| `version` | `str` | Tool version string. |
| `mode` | `str` | `"vet"` or `"vet-mcp"`. |
| `target` | `str` | Path or name of the vetted skill/MCP server. |
| `verdict` | `str` | `"SAFE"`, `"SUSPICIOUS"`, `"DANGEROUS"`, or `"UNKNOWN"`. |
| `findings` | `array[Finding]` | All check results. Same Finding shape as §2. |

`verdict` is derived from the worst finding status:

- `FAIL` → `"DANGEROUS"`
- `WARN` → `"SUSPICIOUS"`
- `UNKNOWN` → `"UNKNOWN"`
- `PASS` (all) → `"SAFE"`
- Empty findings list → `"UNKNOWN"` (nothing to assess).

### Skeleton

```json
{
  "tool": "clawseccheck",
  "version": "1.2.0",
  "mode": "vet",
  "target": "/path/to/skill.zip",
  "verdict": "SAFE",
  "findings": []
}
```

---

## 12. Stability Policy

### Frozen (breaking change requires major version bump)

- Top-level field names in all three output modes.
- `Finding` object field names and their enumerated values (`severity`, `status`, `confidence`).
- SARIF `$schema` URI, `version`, and the `runs[0].tool.driver` shape.
- `verdict` enumeration in `--vet` mode.
- `capability_graph` node `kind` enumeration (`ingress`, `agent`, `subagent`, `mcp`).
- `secret_reachability` class enumeration.

### Stable additions (permitted in any minor release without breakage)

- New optional top-level fields in the `--json` envelope.
- New entries in `next_actions` or `secret_reachability`.
- New check IDs in `findings` or SARIF `rules`.
- New fields inside `capability_graph` nodes or edges.
- New fields in `intentAttestationRequests` items.

### Not part of the public contract

- Text content of `title`, `detail`, `fix`, `why`, `question`, and `message.text`
  fields — these may change to improve accuracy without a version bump.
- `runs[0].properties.*` SARIF extension fields — present only when context is
  available and may gain or lose sub-fields in minor releases.
- The `--text` (human-readable) and `--prompts` output formats — not machine-parseable
  and not versioned.
