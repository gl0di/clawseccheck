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
| `grade` | `str` | yes | Letter grade: `"A"`, `"B"`, `"C"`, `"D"`, or `"F"`. |
| `capped` | `bool` | yes | `true` if the score was capped below `raw_score` (e.g. Lethal Trifecta triggered). |
| `raw_score` | `int` | yes | Score before any cap is applied. Equals `score` when `capped` is `false`. |
| `cap_severity` | `str \| null` | yes | Severity that drove the score cap (`"CRITICAL"`, `"HIGH"`, …), or `null` when no *scored* FAIL capped the score. `null` alongside `capped: true` means a runtime signal (see `runtime_capped`) drove the cap instead, not a scored FAIL. |
| `runtime_capped` | `bool` | yes | `true` when a corroborated *runtime* signal — never a config-static finding — capped the score (I-025). The one eligible signal is a trajaudit-style skill/bootstrap indicator match (`--analyze-trajectory`). It never earns or costs an ordinary scored point — this is a hard cap only, applied after any severity-driven cap above. Every runtime-consuming check (`B83`, `B84`, `B85`, `B164`, `B180`, and the `--behavioral`-only `T1`/`T2`/`T3`) can never move the grade any other way, and this stays `false` for all of them. (`B164`'s `exfil_evidence` class was briefly cap-eligible on its same-line arm under an earlier ruling; retracted after four independent adversarial reviews found no sound host/verb gate exists for this tool's own audience — `exfil_evidence` is WARN-only, permanently, same-line or cross-line.) Same "`true` alongside `capped: false`" nuance as `config_blind_capped` applies when nothing else was scorable this run either — see that row. |
| `runtime_cap_reason` | `str \| null` | yes | Stable label for the eligible runtime signal that fired, e.g. `"trajaudit indicator match"`. `null` when `runtime_capped` is `false`. |
| `config_blind_capped` | `bool` | yes | `true` when `openclaw.json` was present but unparseable/unreadable this run (see `config_parse_error` below) and that alone hard-capped the score at the same ceiling a proven CRITICAL FAIL gets (B-306). Without this cap, a config-derived check correctly degrading FAIL/WARN to UNKNOWN (because it could no longer read the config) could otherwise let the grade rise even though the audit saw strictly less evidence, not more. Composes with `cap_severity`/`runtime_capped` — whichever cap is tightest wins; this one takes reporting priority when it is the binding one. **Can be `true` alongside `capped: false`**: when nothing else was scorable this run either (`score`/`raw_score` both `0`), there is nothing for the cap to numerically reduce, but a blind config is still real signal — B-306's follow-up fix (C-135, 2026-07-21) forces `grade: "F"`/`assessable: true` here instead of silently falling back to the neutral `"N/A"` this combination used to produce. |
| `assessable` | `bool` | yes | `false` for the distinct "N/A / nothing scorable" state (empty / all-UNKNOWN / all-advisory config, and neither `config_blind_capped` nor `runtime_capped` fired) — lets a consumer tell a real `F` apart from a not-assessable `"N/A"` config. `true` for every normal audit, **and also** when nothing else was scorable but `config_parse_error`/a corroborated runtime signal fired: B-306 forces a real `grade: "F"` (`score: 0`) in that case rather than falling back to the neutral `"N/A"` — a blind config or corroborated runtime evidence is real, alarming signal, never "nothing known". |
| `trifecta` | `str` | yes | Lethal Trifecta sub-score expressed as `"<n>/3"` (e.g. `"2/3"`). `"?/3"` means check A1 did not run. |
| `findings` | `array[Finding]` | yes | All check results. See §2. |
| `next_actions` | `array[NextAction]` | yes | Prioritised remediation suggestions. See §3. |
| `risk_paths` | `array[RiskPath]` | yes | Combinational attack chains. See §4. May be an empty array. |
| `capability_graph` | `object` | yes | Static capability map of the inspected agent. See §5. |
| `secret_reachability` | `array[SecretClass]` | yes | Per-class secret-exposure analysis. See §6. |
| `intentAttestationRequests` | `array[SAR]` | yes | Structured Attestation Requests for B62 capability-intent mismatches. See §7. |
| `coverage` | `object` | yes | Surface/family coverage map for the Dashboard. See §8. |
| `projection` | `object` | yes | What-if score projections for the Dashboard. See §9. |
| `config_found` | `bool` | yes | `true` when an `openclaw.json` was present at the scanned home (vs a non-OpenClaw setup). |
| `audited_config_path` | `string \| null` | yes | Absolute path of the config file this run actually read — every finding in the payload describes this file and only this file. May be a legacy `clawdbot.json`, which OpenClaw's resolver prefers when it exists. When `config_found` is `false` this still names the canonical path that was looked for. Compare it against check `B183`, which reports whether OpenClaw's own resolver (`OPENCLAW_CONFIG_PATH` / `OPENCLAW_HOME` / `OPENCLAW_STATE_DIR`) selects a different file. `null` only when no context was supplied to the renderer. |
| `config_parse_error` | `bool` | yes | `true` when `openclaw.json` was present but could not be parsed into a config object (syntax error, size-cap truncation, or a non-object top level). A gating consumer should treat `true` as "scan incomplete", not a clean result — the run is UNKNOWN-heavy. A valid empty `{}` config is `false`. |
| `config_symlink_escapes_home` | `bool` | yes | `true` when `openclaw.json` is a symlink whose target leaves its config directory AND that target is a readable regular file owned by the auditing user — a benign dotfiles layout (stow/chezmoi/yadm/bare-git). The collector follows it and audits the real bytes, so this is NOT a blind config: `config_parse_error` stays `false` and the run is never `config_blind_capped` for this reason. Lets a consumer distinguish a safely-relocated config from a genuinely dark one. `false` on every normal (non-symlinked, or in-directory-symlinked) run. |
| `config_parse_reason` | `string \| null` | yes | Short diagnostic for why `config_parse_error` is `true` (the raw loader message), OR a note that a dotfiles-style symlink was safely followed when `config_symlink_escapes_home` is `true`. `null` when the config parsed cleanly with no relocation. Never contains a secret or file-content value. |
| `errors` | `array[str]` | yes | Human-readable collection/parse messages (e.g. the `openclaw.json` parse error). Empty array on a clean run. |
| `inventory` | `object` | yes | Owner-facing "Inventory by subject" regrouping (System/Agents/Skills/MCP/Channels) of the SAME `findings` above. Purely additive/presentation — never affects `score`/`grade`. See §16. |
| `scan_receipt` | `str` | yes | Deterministic content-integrity hash over all findings, formatted `"sha256:<64-hex-chars>"`. Same findings set (any order) always yields the same receipt; a changed finding set changes it. Not a security signature — a drift/tamper-evidence checksum for the scan output itself. |

### Skeleton

```json
{
  "score": 74,
  "grade": "C",
  "capped": false,
  "raw_score": 74,
  "cap_severity": null,
  "runtime_capped": false,
  "runtime_cap_reason": null,
  "config_blind_capped": false,
  "assessable": true,
  "trifecta": "1/3",
  "findings": [ ... ],
  "next_actions": [ ... ],
  "risk_paths": [ ... ],
  "capability_graph": { "nodes": [], "edges": [] },
  "secret_reachability": [ ... ],
  "intentAttestationRequests": [],
  "coverage": { "surfaces": {}, "families": {}, "gaps": {}, "summary": {} },
  "projection": { "current": {}, "top1": null, "cumulative": {} },
  "config_found": true,
  "audited_config_path": "/home/you/.openclaw/openclaw.json",
  "config_parse_error": false,
  "config_symlink_escapes_home": false,
  "config_parse_reason": null,
  "errors": [],
  "inventory": {
    "system": { "status": "FAIL", "findings": ["B2"] },
    "agents": { "status": "PASS", "findings": [], "roster": ["(default)"], "attested": false },
    "skills": [ { "name": "pdf", "verdict": "NO KNOWN ISSUE", "status": "PASS", "reasons": [] } ],
    "mcp": [ { "name": "slack", "verdict": "ok", "reasons": [] } ],
    "channels": { "status": "WARN", "findings": ["B26"], "roster": ["telegram"] }
  },
  "scan_receipt": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

---

## 2. Finding Object

Shared by `--json` and `--vet` mode.

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
| `scored` | `bool` | `false` for advisory findings excluded from the weighted score (they still appear in the report but don't move the grade); `true` for findings that count toward the score. Lets a JSON consumer reproduce the human report's "N to fix vs M warn" arithmetic, which excludes advisory items. |
| `suppressed` | `bool` | `true` if the finding was suppressed by the user's baseline. |
| `owasp` | `array[str]` | OWASP LLM Top 10 codes that apply, e.g. `["LLM01", "LLM02"]`. May be empty. |
| `ast` | `array[str]` | OWASP Agentic Skills Top 10 (2026) codes that apply, e.g. `["AST03", "AST05"]`. May be empty. Additive metadata only — no scoring or verdict impact. |
| `remediation` | `object` | Paste-ready remediation. Keys: `commands` (`array[str]`) and `config` (`array[object]`). |
| `evidence` | `array[str]` | Supporting evidence strings (sanitised; no raw secrets). May be empty. |
| `surface` | `str` | OpenClaw surface slug this check belongs to (e.g. `"gateway"`, `"tools"`, `"bootstrap"`). `""` for findings not in the CATALOG (e.g. MCP-vet diagnostics). One of the 14 slugs in `catalog.SURFACES` or `""`. |
| `blast_radius` | `object` | **Only present when `status` is `"FAIL"` and a config context is available** (always true for the real `clawseccheck --json` CLI path; absent in library calls to `render_json()` made without `ctx`). Estimated attacker gain if this finding is exploited. See below. |

### `blast_radius` object (FAIL findings only)

```json
{
  "open_channels": 1,
  "has_exec": true,
  "has_write": false,
  "secret_paths": 3
}
```

| Field | Type | Description |
|---|---|---|
| `open_channels` | `int` | Count of messaging channels with `dmPolicy` or `groupPolicy` set to `"open"`. |
| `has_exec` | `bool` | `true` if `tools.exec.mode` is configured. |
| `has_write` | `bool` | `true` if `fs_write` or `apply_patch` appears in the tool allowlist. |
| `secret_paths` | `int` | Count of dotted config paths holding a secret-bearing value. |

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
  "surface": "bootstrap",
  "blast_radius": {
    "open_channels": 1,
    "has_exec": true,
    "has_write": false,
    "secret_paths": 3
  }
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

## 4. `risk_paths` — Attack Chain Array

`risk_paths` is always present in the real `clawseccheck --json` CLI output (combinational
attack chains are computed unconditionally per audit; there is no `--risk` gate — that was
true of an older CLI shape and is corrected here). It may be an empty array when no chain
condition matches. Library callers of `render_json()` directly can omit the `risk` keyword
(or pass `risk=None`) to suppress the key entirely — that path is for unit/library use, not
the shipped CLI.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Risk chain identifier, e.g. `"RISK-03"`. |
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"LOW"`. |
| `title` | `str` | Attack chain name. |
| `chain` | `array[str]` | Ordered list of check IDs that form the chain, e.g. `["B07", "B21", "B33"]`. |
| `why` | `str` | Narrative explanation of the attack path. |
| `fix` | `str` | Recommended mitigation. |

`risk_paths` is absent (not `null`, not `[]`) only when `render_json()` is called as a
library function without a `risk` argument.

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
| `version` | `str` | Tool version string, e.g. `"3.33.0"`. |
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
because ClawSecCheck never rewrites the artifacts it audits.

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

## 11. `--vet` Mode Output — Risk Dossier

Produced by `--vet` / `--vet-skill` / `--vet-plugin`, `--vet-mcp`, and `--vet-source`.
**Since v3.8.0** the vet output is a **risk dossier**: the same per-finding results (§2 shape)
plus a five-axis roll-up and an overall grade. No full-audit `next_actions` / `capability_graph`.

### Fields

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Always `"clawseccheck"`. |
| `version` | `str` | Tool version string. |
| `mode` | `str` | `"vet"` (skill), `"vet-plugin"`, `"vet-mcp"`, or `"vet-source"`. |
| `target` | `str` | Path, name, slug, or URL of the vetted artifact. |
| `target_type` | `str` | `"skill"`, `"plugin"`, `"mcp"`, or `"source"`. |
| `verdict` | `str` | `"NO KNOWN ISSUE"`, `"SUSPICIOUS"`, `"DANGEROUS"`, or `"UNKNOWN"` (derived from the overall status). |
| `grade` | `str` | Overall letter grade `A`–`F`, or `"N/A"` when nothing is assessable. |
| `score` | `int` | 0–100 axis pass-rate behind the grade (0 when not assessable). |
| `axes` | `array[Axis]` | The five risk axes, in fixed order (below). |
| `findings` | `array[Finding]` | All check results. Same Finding shape as §2. |
| `unmapped` | `array[str]` | Finding ids that resolved to no axis (coverage diagnostic; normally empty). |

### Axis object

| Field | Type | Description |
|---|---|---|
| `axis` | `str` | One of `danger`, `build`, `behavior`, `persistence`, `connections`. |
| `status` | `str` | `"PASS"`, `"WARN"`, `"FAIL"`, `"UNKNOWN"`, or `"N/A"`. |
| `reason` | `str` | One-line explanation (untrusted text; sanitized). |
| `fix` | `str` | One-line remediation, or `""`. |
| `finding_ids` | `array[str]` | Ids of the findings bucketed to this axis. |

The five axes answer, together, "how risky is this to install?": **danger** (active malice
/ known-bad — a FAIL here floors the grade to F), **build** (least-privilege, pinning,
authoring hygiene), **behavior** (override / jailbreak / forged provenance / tool-poisoning),
**persistence** (dormant / staged code, install hooks), **connections** (outbound surface,
exfil channels, secret env passthrough).

An axis a target type structurally cannot produce is `"N/A"` (excluded from the grade
denominator) — never a fabricated PASS/FAIL. Examples: an MCP server spec has no on-disk
code, so `persistence` is `"N/A"`; `--vet-source` never fetches the artifact, so every axis
but `danger` is `"N/A"`. An axis with a producer but no measurable input (e.g. a skill with
no executable code) is `"UNKNOWN"`, distinct from PASS. `verdict` maps the overall status:
`FAIL`→DANGEROUS, `WARN`→SUSPICIOUS, `PASS`→NO KNOWN ISSUE, else UNKNOWN.

`grade` derivation: `danger == FAIL` → `F`; otherwise a weighted pass-rate over the
assessable axes (PASS=1, WARN=0.5, FAIL=0; N/A and UNKNOWN excluded), with any WARN capping
below A and any non-danger FAIL capping at C. All-N/A/UNKNOWN → `"N/A"`.

`--vet-plugin` decomposes into its dispatched sub-findings (bundled-skill B13/ring,
embedded-MCP `MCP-VET`), which bucket onto the axes; the `PLUGIN-VET` container id is not
itself an axis. `--vet-source` returns a single `SOURCE-VET` finding on the `danger` axis
(never `PASS` — an identity check cannot prove unseen code safe).

### Skeleton

```json
{
  "tool": "clawseccheck",
  "version": "3.33.0",
  "mode": "vet",
  "target": "/path/to/skill",
  "target_type": "skill",
  "verdict": "DANGEROUS",
  "grade": "F",
  "score": 0,
  "axes": [
    {"axis": "danger", "status": "FAIL", "reason": "...", "fix": "...", "finding_ids": ["B13"]},
    {"axis": "persistence", "status": "PASS", "reason": "...", "fix": "", "finding_ids": []}
  ],
  "findings": [],
  "unmapped": []
}
```

SARIF: the vetting modes additionally carry the dossier roll-up on
`runs[0].properties.vetProfile` and tag each result with `properties.axis` — both additive
(the per-finding `results` stay finding-oriented).

---

## 12. `--judge-packet` Output (F-113)

Produced by the standalone `--judge-packet` flag. A separate JSON artifact — not part
of the `--json` envelope — that assembles the audit's borderline-band results (findings
whose status the engine could not determine, or that are deliberately WARN-only /
dual-use by design) into a machine-readable list of questions for the user's OWN host
agent to review and answer. **Read-only and purely additive**: it never re-runs a check,
never changes any Finding's status/severity/score, and never contacts an LLM or the
network itself.

Sources folded into the packet:

- every unsuppressed `UNKNOWN` finding from the audit;
- unsuppressed `WARN` findings whose id has a documented false-negative-prone history
  (dual-use signals deliberately down-ranked from FAIL so a legitimate skill is never
  hard-failed): `B13`, `B65`, `B66`, `B90`, `B99`, `B100`, `B102`, `B154`, `B156`;
- one item per B62 capability-intent mismatch (see §7);
- taint signals (`TT4_FILE_NET`, `TT_SSRF`, `TT5_ARG_INJECTION`, `DANGEROUS_SINK`) the
  skill AST/taint layer computes but the installed-skill check does not surface on its
  own when no independent credential/exfil signal is present elsewhere in the skill;
- `ENV_AUTH_KWARG_EXFIL`: an environment-variable or agent-config secret placed in an
  auth-shaped keyword (`headers=`/`auth=`/`cert=`) of a network call — the normal way a
  skill authenticates to its own API, so it is deliberately excluded from the engine's
  own `ENV_EXFIL_FLOW` taint rule and never independently reviewed. A separate AST walk
  scoped to exactly that excluded case surfaces it here.

### Envelope fields

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Always `"clawseccheck"`. |
| `version` | `str` | Tool version string. |
| `judgePacket` | `array[JudgePacketItem]` | The packet items. May be an empty array. |

### JudgePacketItem fields

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` | Check id (e.g. `"B13"`, `"B62"`) or recovered AST rule name (e.g. `"TT4_FILE_NET"`). |
| `target` | `str` | Skill/file name the item concerns (redacted if secret-shaped), or the `finding_id` when no target could be derived. |
| `redacted_evidence` | `str` | Human-readable evidence summary (fully redacted — no raw secrets or skill source). |
| `engine_disposition` | `str` | The underlying status: `"WARN"` or `"UNKNOWN"` (this artifact never carries `PASS`/`FAIL` items). |
| `question` | `str` | Plain-language yes/no attestation question for the host agent. |
| `verdict_schema` | `object` | Fixed answer contract: `{"answer": ["yes", "no"], "reason": "free text"}`. |

### Skeleton

```json
{
  "tool": "clawseccheck",
  "version": "3.37.0",
  "judgePacket": [
    {
      "finding_id": "TT4_FILE_NET",
      "target": "report_uploader",
      "redacted_evidence": "report_uploader: file-read contents flow into requests.post (indirect flow) — data exfiltration risk (uploader.py:8)",
      "engine_disposition": "UNKNOWN",
      "question": "This skill reads a file and the contents appear to flow into a network call, with no independent credential signal nearby (so the engine did not escalate it). Is this an intended upload/sync to a trusted destination? [yes/no + reason]",
      "verdict_schema": {"answer": ["yes", "no"], "reason": "free text"}
    }
  ]
}
```

---

## 13. `--judged` Output (F-115)

Consumes a host-agent judge panel's verdicts JSON for a prior `--judge-packet` run (see
§12) and renders the combined report. Takes the verdicts JSON via `--judged PATH`, or
`--judged -` to read it from stdin.

**Hard invariant:** the `score`, `grade`, `capped`, `raw_score`, `cap_severity`,
`assessable`, `trifecta`, and `findings` fields are **byte-identical** to a plain
`--json` run on the same inputs. A judge panel can only annotate an existing finding —
it can never raise, lower, or otherwise touch the deterministic grade. This is
mechanically enforced by `tests/test_adjudication.py`'s adversarial all-`DANGEROUS`
verdict test.

The only addition on top of the standard `--json` payload (§4) is one new key:

| Field | Type | Description |
|---|---|---|
| `secondOpinion` | `array[SecondOpinionItem]` | One row per current `--judge-packet` item — including ones nobody has judged yet. |

### SecondOpinionItem fields

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` | Same as the originating `judgePacket` item's `finding_id`. |
| `target` | `str` | Same as the originating item's `target`. |
| `engine_disposition` | `str` | The underlying status (`"WARN"` or `"UNKNOWN"`). |
| `judge_verdict` | `str \| null` | `"SAFE"` / `"SUSPICIOUS"` / `"DANGEROUS"` if a verdict was submitted for this item, else `null`. |
| `annotation` | `str` | Plain-language re-rank line, e.g. `"engine: WARN · judges: 3/3 DANGEROUS → treat as high priority"`, or `"not yet reviewed by a judge"`. |

### Input contract (the verdicts JSON `--judged` consumes)

Matched against `judgePacket` items by the `(finding_id, target)` pair. Parsing is
bounded and defensive (untrusted input from a host agent, possibly reflecting
attacker-influenced skill content): a payload over 2 MB, malformed JSON, a
non-object root, a non-array `verdicts` field, a non-object entry, or an entry whose
`finding_id`/`target` isn't a string or whose `verdict` isn't one of `SAFE` /
`SUSPICIOUS` / `DANGEROUS` is each simply dropped (that entry, or the whole parse) —
`--judged` never raises or crashes on bad input; the affected item(s) just render as
not-yet-reviewed.

```json
{
  "verdicts": [
    {
      "finding_id": "B13",
      "target": "skillx",
      "verdict": "DANGEROUS",
      "votes": {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 3}
    }
  ]
}
```

`votes` is optional — when present and its values sum to something greater than
zero, the annotation renders a vote breakdown (`"judges: 3/3 DANGEROUS"`); when
absent, it renders `"judge: DANGEROUS"`.

---

## 14. `--propose-ignore` / `--apply-ignore-proposals` Output (C-253)

`--propose-ignore` consumes the same host-agent judge panel verdicts JSON as
`--judged` (§13, same `(finding_id, target)` matching, same 2 MB bound and defensive
parsing) for a prior `--judge-packet` run (§12), but instead of annotating a finding
it proposes suppressing it: items the panel verdicted `"SAFE"` become PROPOSED
`.clawseccheckignore` entries. **Read-only** — this command never writes to disk.
Takes the verdicts JSON via `--propose-ignore PATH`, or `--propose-ignore -` to read
it from stdin.

**Structural guarantee:** only findings already offered to the judge via
`--judge-packet` (unsuppressed `UNKNOWN`, or `WARN` in the documented
false-negative-prone set) are ever candidates — a `FAIL`-status finding (the only
kind that can cap the score) can never be selected here, regardless of what a
verdicts file claims for it. A finding aggregating more than one target (e.g. a
`WARN` that names several skills in one `Finding`) is also never proposed: a
`SAFE` verdict scoped to one target cannot safely suppress the whole aggregate
without silently hiding the OTHER, unreviewed targets bundled into the same
fingerprint (C-135, 2026-07-22).

`--apply-ignore-proposals` only ever writes an `entry` shaped like a genuine
`fingerprint()` output (`<id>:<8 lowercase hex chars>`) — a bare check id (e.g.
`"B1"`, `"B20"`) in a proposals file that did not genuinely come from
`--propose-ignore` is refused and named on stderr/stdout, never silently applied
(C-135, 2026-07-22): this command's whole premise is "only ever what
`--propose-ignore` already offered," and a bare id would instead suppress that
check file-wide via `.clawseccheckignore`'s separate bare-id form.

### Envelope fields

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Always `"clawseccheck"`. |
| `version` | `str` | Tool version string. |
| `proposedIgnoreEntries` | `array[IgnoreProposalItem]` | The proposals. May be an empty array. |
| `note` | `str` | Plain-language reminder that nothing was written and how to apply. |

### IgnoreProposalItem fields

| Field | Type | Description |
|---|---|---|
| `entry` | `str` | The exact `.clawseccheckignore` line (`<id>:<fingerprint>`) — the same fingerprint `baseline.py` matches against. |
| `finding_id` | `str` | Check id (e.g. `"B13"`). |
| `target` | `str` | Same as the originating `judgePacket` item's `target`. |
| `votes` | `object \| null` | Vote breakdown if the verdicts file supplied one, else `null`. |

```json
{
  "tool": "clawseccheck",
  "version": "3.55.0",
  "proposedIgnoreEntries": [
    {"entry": "B13:ab12cd34", "finding_id": "B13", "target": "skillx", "votes": {"SAFE": 3}}
  ],
  "note": "PROPOSED ONLY -- nothing was written by this command. ..."
}
```

`--apply-ignore-proposals PATH` reads exactly that JSON and appends each `entry` to
`<home>/.clawseccheckignore`, creating the file if absent. It is **opt-in and
confirmation-gated** the same way `--purge` is: it prints the exact lines and asks
for `[y/N]` unless `--yes` is also given; an unanswerable prompt (no tty / EOF)
aborts loudly (exit 1), never silently proceeds. It never invents an entry beyond
what the proposals file already listed, and already-present entries are skipped
(repeated applies do not grow the file with duplicates).

**This gains no new suppression authority.** A suppressed score-capping
`CRITICAL`/`HIGH` `FAIL`, or a sensitive check id (`B1`, `B2`, `B13`, `B20`), still
surfaces regardless of how the suppressing line got into `.clawseccheckignore` (see
`surfaced_despite_suppression`, §2), and any change to that file — including one made
this way — is still flagged by `--monitor` as drift (`ignore_hash`, §1).

**Residual, stated plainly (not solved away):** if the host agent generating the
verdicts JSON is itself compromised or prompt-injected, it could propose (and, if
also given `--yes` or talked past the confirmation prompt, apply) a suppression for
a real finding. The mitigations above bound the damage — a capping FAIL still
surfaces, the file change is still visible to `--monitor` — but do not eliminate the
risk. This is an accepted, disclosed limitation, not a claim that the risk is gone.

---

## 15. Stability Policy

### Frozen (breaking change requires major version bump)

- Top-level field names in all three output modes.
- `Finding` object field names and their enumerated values (`severity`, `status`, `confidence`).
- SARIF `$schema` URI, `version`, and the `runs[0].tool.driver` shape.
- `verdict` enumeration in `--vet` mode.
- `capability_graph` node `kind` enumeration (`ingress`, `agent`, `subagent`, `mcp`).
- `secret_reachability` class enumeration.

> **Extended in v3.8.0 (additive):** the `--vet` envelope gained the risk-dossier fields
> (§11) — `target_type`, `grade`, `score`, `axes`, `unmapped` — as additive top-level fields
> (permitted in a minor release). `verdict` keeps its frozen enumeration but now derives from
> the overall dossier status; the per-finding `findings[]` shape (§2) is unchanged.

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
- The default human-readable text output (printed when neither `--json` nor `--sarif`
  is given) — not machine-parseable and not versioned.

---

## 16. `inventory` Object (F-131 — Inventory by Subject, Phase 1)

Owner-facing regrouping of the SAME `findings` (§2) above by the entities an owner
actually owns — System, Agents, Skills, MCP servers, Channels — instead of the 7
analyst-facing security families the text report groups by underneath it. Purely
additive and presentation-only: it never changes `score`, `grade`, or any `Finding`;
every finding id it lists also appears, unchanged, in the top-level `findings` array.

Skills and MCP servers get a **per-instance** verdict (one entry per installed skill /
configured MCP server, reusing the same scoring paths `--vet <skill>` / `--vet-mcp` use).
System, Agents, and Channels stay **bucket-level** in Phase 1 — one rolled-up status plus
the ids of the surface's own FAIL/WARN findings — because no `Finding` carries a
precise per-instance (e.g. "which channel") attribution yet; that is deferred to a
possible Phase 2.

| Field | Type | Description |
|---|---|---|
| `system` | `object` | Bucket: `{"status": str, "findings": array[str]}`. `status` is the worst status (`FAIL` > `WARN` > `UNKNOWN` > `PASS`) among findings on the system surfaces (gateway, tools, secrets, monitoring, hooks, host, update, sessions); `findings` lists the ids of that bucket's own FAIL/WARN findings. |
| `agents` | `object` | Bucket, same shape as `system`, plus: `roster` (`array[str]`) — agent names, preferring an attested roster (`--attest`) over the static `agents.list` config, falling back to `["(default)"]`; `attested` (`bool`) — `true` when the roster came from an attestation self-report. |
| `skills` | `array[object]` | One entry per installed skill: `{"name": str, "verdict": str, "status": str, "reasons": array[str]}`. `verdict` reuses the same word set `--vet` uses (`"NO KNOWN ISSUE"`, `"SUSPICIOUS"`, `"DANGEROUS"`, `"UNKNOWN"`); `status` is the underlying `PASS`/`WARN`/`FAIL`/`UNKNOWN`; `reasons` holds up to 3 sanitised detail strings. Empty array when no skills are installed. A skill the per-skill scan budget could not reach reports `status: "UNKNOWN"` with a reason explaining why — never a false `"NO KNOWN ISSUE"`. |
| `mcp` | `array[object]` | One entry per configured MCP server (both `mcp.servers` nesting and legacy `mcpServers`/`mcp_servers`): `{"name": str, "verdict": str, "reasons": array[str]}`. `verdict` is `"ok"` (no supply-chain/trust signal), or `"WARN"`/`"FAIL"`/`"UNKNOWN"`. Empty array when no MCP servers are configured. |
| `channels` | `object` | Bucket, same shape as `system`, plus: `roster` (`array[str]`) — configured channel provider names (the `defaults` pseudo-provider excluded). |

### Notes

- `inventory` is always present (an empty/all-`PASS` shape when nothing is configured or
  `ctx` is unavailable), matching every other always-present top-level field.
- The exact wording of `reasons[]` entries is **not** part of the frozen contract (same
  rule as `detail`/`fix` text elsewhere in this doc) — only the field names/types are.
