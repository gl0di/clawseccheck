"""I-022 R1 — module-layout / anti-bloat guard.

Mechanized structure enforcement so the package can't silently re-bloat and the
public import surface of `clawseccheck.checks` can't silently shrink. Stdlib-only,
offline, deterministic — same spirit as tests/test_public_boundary.py.

Three guards:
  (a) per-file line budget (<= _MAX_LINES) with an explicit, reasoned _EXEMPT dict —
      blocks a NEW file from growing into another 14k-line monolith;
  (b) export-contract: tests/checks_public_api.txt MUST be a subset of
      dir(clawseccheck.checks), so every name tests/siblings import stays importable
      no matter how the engine is internally split (see CLAUDE.md §3.1-a);
  (c) placement lint: a checks/_shared.py leaf (created by the I-022 R2 split) may
      hold only shared helpers/constants — no check_*/vet_* entry point.

The line budget deliberately records the over-budget checks/ topic modules (today:
_content, _vet, _mcp, _config, _lifecycle, _egress, _shared, _capability, _agents,
_host and the __init__ aggregator) in _EXEMPT as *tracked debt*, not a free pass —
each carries a reason and two companion tests keep it honest: one fails when an
exemption goes stale (the file dropped under budget or vanished), so the guard tightens
on its own as any finer split lands; the other fails when the reason's stated size stops
describing the file, which is how every count in here silently rotted by up to 400%
before C-417 measured them.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

import clawseccheck.checks as checks_mod

pytestmark = pytest.mark.mechanical

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG = REPO_ROOT / "clawseccheck"
MANIFEST = REPO_ROOT / "tests" / "checks_public_api.txt"

_MAX_LINES = 1200

# Files intentionally over budget. Every entry MUST carry a reason. An entry here is
# tracked debt, not a free pass — trim it as the I-022 modularization lands (the
# companion staleness test fails if an exemption no longer applies).
_EXEMPT = {
    # CLAWSECCHECK-B-887 (2026-09-23): 1,102 -> 1,263 lines (net +161). Closes the
    # case-fold gap that let three prior rounds each break the invariant that a
    # re.I-compiled pattern's confusable fold must commute with case: capital
    # Cyrillic/Greek lookalikes added to _CONFUSABLES (14 code points, mirroring
    # existing lowercase entries), the I1 upper-closure assert that keeps the table
    # honest, the derived _PATTERN_CASE_CLOSURE map for capital-only lookalikes, and
    # `fold_pattern()` — the single function every B63-family regex now compiles
    # through instead of `normalize_for_scan`. Over budget by 56 lines; not trimmed
    # because the added comments are the proof-of-invariant documentation the design
    # review asked for (three retracted prior attempts are exactly what this module's
    # own docstrings warn the next editor away from repeating) — shortening them to
    # slip under the cap would remove the reasoning, not the risk. Split candidate:
    # none identified — this is one cohesive de-obfuscation table plus its two
    # derived closure structures, and splitting the invariant assert from the table
    # it guards would just relocate the coupling, not remove it.
    "textnorm.py": "~1,263 lines — the confusable-fold table (_CONFUSABLES), its "
                   "case-closure invariant and derived pattern-closure map, and "
                   "fold_pattern(). Over budget by 63 lines since CLAWSECCHECK-B-887. "
                   "Tracked debt, not a design statement.",
    # B-917 (2026-09-23): 1,200 -> 1,461 lines. `_FileFacts` gained `locate()`/`Loc`/
    # `loc_eq` -- a SECOND path resolver alongside `resolve()`/`_Path` (the B-638 proof,
    # which stays byte-identical and untouched), because a loader-sink/staged-import
    # correlation needs to know WHERE a path is anchored (FILE/CWD/ABS/TEMP/HOME/SYM),
    # not just whether it resolves inside the artifact. `ShippedArtifact.classify()` and
    # the `PathFacts` single-file convenience wrapper are the other two public additions.
    # Kept in this one module rather than split out: `locate()` shares `sole()`/`dotted()`/
    # `literal()`/the import table with `resolve()` on the same `_FileFacts` instance, and
    # a caller (skillast.py's new pass) needs both together.
    # Restated 2026-09-23, B-917 fix round 1 -- was ~1,461; +59 lines for the two review
    # gaps: `locate()`'s Name branch gained the LEGB fallback b917-design.md 2.1 itself
    # specifies (`_legb_lookup`), guarded by `_legb_blocked` (an attribute store or a
    # `_tampers()` spelling anywhere in the file refuses the fallback rather than risk an
    # unsound resolution) -- `resolve()` is untouched, so B-638's proof is unaffected.
    # Restated 2026-09-23, B-917 fix round 2 -- was ~1,520; +29 lines for a single
    # C-135 review finding (BLOCKER, introduced by fix round 1 above): the LEGB fallback
    # gated itself on `sole() is None`, which is also true of a scope that DOES bind the
    # name via a non-assign form (a parameter, a for/with/comprehension target, an
    # except-as name, a nested def/class, an import) -- that binding makes the name local
    # to the WHOLE scope in real Python, so the fallback must stop there, never walk past
    # it into an enclosing/module scope. Both the `locate()` call site and each step of
    # `_legb_lookup()`'s own walk now gate on "does this scope have any record for the
    # name at all" (`records(scope).get(name)`) instead. No new helper; both sites grew a
    # few lines of guard plus documentation of why sole()-is-None was the wrong condition.
    "shippedexec.py": "~1,549 lines — B-638's shipped-exec containment proof "
                       "(`resolve()`/`_Path`, untouched) plus B-917's location resolver "
                       "(`locate()`/`Loc`/`loc_eq`, `ShippedArtifact.classify()`, "
                       "`PathFacts`) for the loader-sink/staged-import correlation, plus "
                       "the fix-round-1 LEGB fallback (`_legb_lookup`/`_legb_blocked`), "
                       "plus fix-round-2's any-record scope gate on that same fallback. "
                       "Over budget by 349 lines since B-917. Split candidate: the two "
                       "resolvers do not share state beyond `_FileFacts` itself and could "
                       "separate into a `locations.py` leaf; not attempted here because "
                       "`locate()` reuses `resolve()`'s exact `sole()`/`dotted()`/"
                       "`literal()`/import-table machinery, and the B-917 Pulse task's "
                       "own consistency pin (locate() vs resolve() over the same sources) "
                       "reads clearer with both on one instance.",
    # B-816 (2026-09-15): 1,158 -> 1,208 lines (net +50: +58/-8, git diff --stat).
    # SQLite-trajectory-container corroboration (trajectorystore.corroborate()) wired
    # into self_test_corroboration()/render_self_test_corroboration()/
    # render_trajectory_analysis() so --analyze-trajectory and the self-test-corroboration
    # lines stop asserting "no trajectory sidecar was found" on a SQLite-era install with
    # real evidence elsewhere — same disclosure pattern B85/B189/B164 already carry.
    # 8 lines over budget, recorded rather than trimmed for the same reason scoring.py's
    # entry below gives: shortening the new guard clauses' own documentation to slip back
    # under would measure the comment, not the module. Split candidate, not attempted
    # here: the canary/multi-turn self-test
    # machinery (_SELFTEST_SOURCES, self_test_corroboration,
    # render_self_test_corroboration, ~180 lines) is B-300's own concern and reads/writes
    # nothing the rest of this file's trajectory-analysis code touches — a `selftest.py`
    # leaf this module imports would leave ~1,030 here with no cycle.
    "trajaudit.py": "~1,208 lines — the --analyze-trajectory engine (analyze/render_trajectory_"
                    "analysis) plus B-300's canary/multi-turn self-test corroboration. Over "
                    "budget by 8 lines since B-816. Split candidate named above; tracked "
                    "debt, not a design statement.",
    # The first NON-checks/ entry, and the only one that is not a topic module. It is here
    # because the module was already at 1,194 of 1,200 before B-558's fifth ledger-derived
    # field — six lines of headroom is not a stable state, and the next field of any kind
    # would have re-tripped it. Recorded rather than absorbed: shortening the field's own
    # documentation to slip back under would have made the guard measure the comment
    # instead of the module.
    #
    # The split, when someone takes it: the five cap-signal helpers (_degraded_signal,
    # _config_blind_signal, _runtime_cap_signal, _live_injection_cap_signal,
    # _behavioral_cap_signal, ~165 lines together) read Findings and answer one question
    # each, and nothing else in the module reads their internals. Moving them to a leaf
    # `scorecaps.py` that `scoring` imports leaves ~1,050 here and adds no cycle. NOT done
    # in the change that added this entry: it lands mid-release, beside a second session
    # working in the same tree, and it moves code whose outputs many tests pin.
    "scoring.py": "~1,217 lines — score computation, the six cap signals, `project()` and "
                  "`assessment_coverage()`. Over budget by 17 lines since B-558 added "
                  "`layer_coverage`. Split candidate named above; tracked debt, not a "
                  "design statement.",
    # Restated 2026-09-23 for the task/b-852 -> integration/4.3.0 merge: two independent
    # per-branch entries had each gone stale in isolation, neither seeing the other's
    # growth. B-852's own lineage (rounds 3, 7-11) reached ~1,970 lines (over budget by
    # 718) via a total cross-database byte budget for read_compiled_tool_descriptions(),
    # the sequential SQLite content-drain phase, and that drain's own
    # ordering/fairness fixes (cum_bytes-descending, EARNED-bytes keying, a per-pass
    # equal-share cap replacing a fixed-fraction one, then a two-sweep
    # equal-share-then-smallest-first pass) — see git history for that lineage's own
    # entry text before this restatement. CLAWSECCHECK-B-845's own lineage (round 3)
    # reached ~1,251 lines (over budget by 51) via the FIFO/sidecar stat-guard
    # (`_refuse_non_regular_sqlite_paths`, wired into `_open_readonly`) closing a hang
    # in the same per-agent auth-profile-store code path its own VIEW-refusal fix
    # closed. Merging both branches' code into one file lands at the actual combined
    # total below — restating the count, not excusing new debt.
    "trajectorystore.py": "~2,168 lines — SQLite-trajectory-container corroboration "
                          "(corroborate()), the B-811/B-852 event_json content readers "
                          "(read_compiled_tool_descriptions() and its streaming/drain "
                          "core), and the shared schema-verification/hardened-open "
                          "layer (`_open_readonly`/`_table_kind`/"
                          "`_open_and_verify_table`) a second table "
                          "(`auth_profile_store`) now reuses. Over budget by 968 lines. "
                          "Split candidates, neither attempted here (mid-merge is not "
                          "the moment to also restructure the module): a "
                          "`trajectorycontent.py` leaf for the event_json content "
                          "readers (~950 lines would remain, per B-852's own analysis), "
                          "or a `trajectoryschema.py` leaf for just the "
                          "schema-verification layer (~900 lines would remain, per "
                          "B-845's own analysis) — either narrows this file with no "
                          "import cycle.",
    "checks/_config.py": "~6,986 lines (restated 2026-09-21 for the 4.3.0 wave build — "
                         "was ~6,302, +11% stale; earlier 2026-09-18, B382 — ~5,743) — the config-hardening topic (29 checks + helpers); "
                         "topic-faithful and over budget by design. A finer split is a "
                         "later cycle (I-022 secondary target).",
    # Restated 2026-09-04 (B-727): 5,662 -> 6,172. The tolerance is min(25%, 500 LINES),
    # so on a file this size it is the 500-line cap that binds, and the claim had already
    # drifted ~490 before this change added ~20 — i.e. the number is being corrected, not
    # the debt excused. The guard's own instruction is not to just bump it, so: the split
    # this file has owed since I-022 is still owed, and a measurement taken while restating
    # says it is not alone — `checks/_mcp.py` sits at 97% of its own tolerance, and five
    # more modules are past 70%. That whole table needs a restate-and-reconsider pass, not
    # one entry at a time as each next commit trips it.
    "checks/_lifecycle.py": "~7,329 lines (restated 2026-09-17 — was ~6,779) — the "
                            "approval / update-pinning / self-modification / supply-chain "
                            "topic (17 checks + helpers); topic-faithful and over budget "
                            "by design. A finer split is a later cycle.",
    "checks/_content.py": "~16,589 lines (restated 2026-09-23, B-886 fence leg — was ~16,459) — the "
                          "content-security ring: 51 check functions, 178 "
                          "private helpers and 241 module regexes. Restated 2026-09-06 "
                          "(C-432), and the previous reason is RETRACTED rather than "
                          "reworded. It read: kept as one unit because SKILL_CONTENT_RING "
                          "is the single source consumed by both the full audit and --vet, "
                          "do not split. Measured, that argues for nothing: the ring is a "
                          "TUPLE OF FUNCTION REFERENCES and it is not even defined here — "
                          "it lives in checks/_vet.py — and it ALREADY spans two modules "
                          "today, 49 of its 50 members from this file and one from "
                          "checks/_lifecycle.py, with nothing broken by that. Module "
                          "boundaries are invisible to a tuple of references. So the ring "
                          "was never a reason to keep this file whole; keeping the RING "
                          "single is a different claim, it is true, and a split does not "
                          "touch it. "
                          "The honest position is therefore that the split is warranted and "
                          "has simply not been done. The seam the structure shows: the "
                          "per-check detectors are largely independent of each other — the "
                          "section banners run one check per section — while a small set of "
                          "SHARED machinery (the fence/segment classifier, the F-096 "
                          "defensive-context guard, the F-097 capability-not-malice reclass "
                          "helpers, the C-135 addressee gate) is what many of them call. "
                          "That is the same shape checks/_shared.py already has for "
                          "cross-topic helpers, so the cut is along a line this package "
                          "already uses rather than a new invention. Performing it is its "
                          "own change with its own verification (byte-identical audit "
                          "output at every step, as I-022-R2 did); this entry's job is to "
                          "stop recording a non-reason as a decision.",
    "checks/_vet.py": "~8,461 lines (restated 2026-09-23, CLAWSECCHECK-B-895 — was "
                      "~7,922, see the B-895 restatement below; and before that "
                      "restated 2026-09-23, CLAWSECCHECK-B-649 port to "
                      "integration/4.3.0 — was ~7,638) — the --vet entry engine "
                      "(vet_skill/vet_source/"
                      "detect_vet_type/check_installed_skills + SKILL_CONTENT_RING + the "
                      "shared effect/sink analysis); consumes the content ring. Crossed "
                      "the tolerance with B395 (check_installed_skill_content_coverage; "
                      "ported from task/b-649's B383, re-IDed because B383 was already "
                      "taken on this base), "
                      "placed next to check_installed_skills because it reads the exact "
                      "same ctx.skill_coverage_gaps collector state B13 does — a genuine "
                      "second check, not padding — the module now holds TWO check "
                      "functions, not one. Restated "
                      "2026-09-07 with the shape measured rather than described: "
                      "(at the time) ONE check function, TWO vet entry points, 62 private "
                      "helpers. For a "
                      "file in checks/, that ratio is the finding — this is not a place "
                      "where checks live, it is the machinery one entry point needs, and "
                      "the earlier reading of it as an over-budget check module was the "
                      "wrong frame. "
                      "Where it grew, measured over the last twelve commits (~784 lines): "
                      "almost none of it is new detection. It is verdict HONESTY (a vet "
                      "that declined to read the bundle no longer recommends installing "
                      "it; an unread config no longer reported as unconfigured; exit 2 "
                      "when a target cannot be assessed; the paste-host disclosure) and "
                      "FENCE visibility (four separate commits letting a real signal be "
                      "seen through a code fence). Both families are about what may "
                      "truthfully be said, and they land here because this is where the "
                      "saying happens — the same pull report.py's own entry already "
                      "records for itself. "
                      "So the split argument stands and is now specific: the honesty and "
                      "fence layers are what to lift out, not an arbitrary halving. Same "
                      "sequencing as checks/_content.py — that one is twice this size and "
                      "has the simpler seam, so it goes first. "
                      "Restated 2026-09-22 (B-857): 7,080 -> 7,638. The module had already "
                      "drifted to 7,578 (unrestated since the count above) before this task; "
                      "it added the ~60 lines closing a B-745 review gap — "
                      "_B13_WINNER_ONLY_BUCKETS and its per-site pointer comments, "
                      "explicitly declaring three late-registered B13 buckets as "
                      "winner-only rather than leaving that undeclared. Verdict text and a "
                      "named contract, not new detection; the split argument above is "
                      "unchanged. "
                      "Restated 2026-09-23 (CLAWSECCHECK-B-895): 7,922 -> 8,461. Split "
                      "the paste/exfiltration-host reach check into an anchor-provenance "
                      "form (_exfil_host_reach_anchors, the _exfil_host_hits crit_anchors "
                      "sink, exfil_crit_anchors_by_skill in check_installed_skills) plus a "
                      "same-sized residual comment recording three retracted carve-outs and "
                      "a reproduced evasion. No verdict moved — every existing FAIL/WARN is "
                      "byte-identical — only which disclosure sentence, if any, a paste-host "
                      "CRITICAL's `fix` text carries. Same HONESTY family as the rest of "
                      "this entry, not new detection; the split argument above is "
                      "unchanged.",
    "checks/_host.py": "~1,779 lines — the host-monitor / incident-readiness topic "
                       "(B10/B16/B50-B54 + the attestation helpers). Sat at EXACTLY 1,200 "
                       "for a while, i.e. one line under a tripwire, and crossed it with "
                       "B-514: check_audit_log went from a 2-branch stub that returned "
                       "UNKNOWN on the false premise that audit.enabled does not exist, to "
                       "the four verdicts the real field actually supports (explicit "
                       "false / redaction off / explicit true / unset-with-no-schema-"
                       "default). The extra lines are user-facing verdict text, not "
                       "machinery; squeezing them to hold a line count would trade the "
                       "report's clarity for a number. Restated 2026-09-16 (F-178, "
                       "CLAWSECCHECK-B-379): 1,324 -> 1,779 with check_host_scheduled_"
                       "persistence, this module's own next entry in the same "
                       "host-monitor family (systemd timer / system cron, sibling of "
                       "B150 one function up) — same reasoning, a real new check's "
                       "verdict text, not padding. A finer split is a later cycle.",
    # Restated 2026-09-05 (B-742): 7,597 -> 8,111. B-727 restated `_lifecycle.py` one day
    # earlier and, while measuring, wrote down that THIS file "sits at 97% of its own
    # tolerance" and that the table "needs a restate-and-reconsider pass, not one entry at
    # a time as each next commit trips it". That prediction landed: B-742 added 27 lines
    # and they were the 27 that crossed the 500-line cap. 487 of the 514 predate it.
    #
    # So, reconsidering rather than bumping, and measured today with the guard's own
    # counter: the queue behind this file is real and close. risk.py 82% of tolerance,
    # report.py 77%, skillast.py 74%, collector.py 70% — four more entries that the next
    # commit touching each will trip, individually, exactly as B-727 said. The split
    # `_mcp.py` has owed since I-022 is still owed and is now the second-largest piece of
    # structural debt in the tree after `_content.py`; vet_plugin alone (the dispatcher,
    # its tree sweep and the plugin sweep) is a coherent unit that could leave.
    "checks/_mcp.py": "~9,356 lines — the MCP / plugin checks + vet_mcp / vet_plugin; "
                      "topic-faithful and over budget by design. Restated 2026-09-23 "
                      "(B-831 added a second, appServer-level detection branch to B353 "
                      "plus its grounding helpers, +517 lines, and its round-1 fix ported "
                      "the vendor's exec-policy layering, +214) — previously restated "
                      "2026-09-16 "
                      "(B-661 added a config-found guard to three checks, +510 lines) — "
                      "originally restated 2026-09-06 "
                      "(C-432) with the measurement the old 'a finer split is a later "
                      "cycle' never carried: 20 check functions, 2 vet entry points, 64 "
                      "private helpers, 59 regexes. Unlike checks/_content.py this file "
                      "holds TWO surfaces, not one — the audit checks, and the --vet entry "
                      "points with sweep_plugins — and the section banners put the vet "
                      "surface in roughly the first 4,900 lines with the B-checks after it. "
                      "So a seam exists here too, and it is even cleaner than _content's "
                      "because it is a boundary between two ENTRY POINTS rather than "
                      "between helpers and their callers. "
                      "The argument for waiting is real and worth stating rather than "
                      "implying: both surfaces share one domain model (the plugin/MCP "
                      "config shapes, the trust-record readers), so cutting between them "
                      "duplicates that model or forces a third module for it — and this "
                      "file is HALF the size of _content.py, which has the same problem "
                      "without the shared-model complication. Order matters: split "
                      "_content.py first, learn what the shared-machinery module wants to "
                      "look like, then decide here. That is a sequencing decision, not a "
                      "deferral for its own sake.",
    "checks/_egress.py": "~5,267 lines (restated 2026-09-21 for the 4.3.0 wave build — "
                         "was ~4,736) — the "
                         "egress-hardening topic (proxy/TLS/SSRF/data-at-rest + "
                         "web-fetch/log checks). Crossed the budget with B178's "
                         "check_provider_baseurl (models.providers.<id>.baseUrl "
                         "cleartext http:// leak) — kept adjacent to B155's "
                         "check_outbound_proxy, its sibling check on the SAME provider "
                         "object, rather than splitting one config object's security "
                         "posture across two topic files. A finer split is a later cycle.",
    "checks/_shared.py": "~5,014 lines (restated 2026-09-21 for the 4.3.0 wave build — "
                         "was ~4,458) — "
                         "the leaf every checks/_<topic> module (and "
                         "risk.py) imports from: tool-hint constants, MCP-server helpers, "
                         "and _trifecta_legs, the single shared leg definition A1 and B46 "
                         "both read. Crossed the exact 1,200-line ceiling with B-247's MCP "
                         "intake-leg contributor (_MCP_INTAKE_CAP_RE / _mcp_intake_reason) "
                         "— it must sit next to _mcp_leg_contributions, which only "
                         "_shared.py can host without a checks/_<topic> -> _shared import "
                         "cycle (CLAUDE.md §3 dependency flow). Grew +19% with B-619's "
                         "_declared_dm_policy and its three grounding tables "
                         "(_DM_POLICY_NESTED_ONLY_CHANNELS / _DM_POLICY_FLAT_PRIMARY_"
                         "CHANNELS / _DM_POLICY_ENABLED_GATE_CHANNELS): most of the added "
                         "bulk is the per-channel dist grounding comment (schema+"
                         "normalizer+consumer-gate citations for 4 channels), not new "
                         "control flow — it sits here rather than in checks/_config.py "
                         "because _untrusted_input_channels and "
                         "_resolved_default_input_channels, its only two callers, already "
                         "live in this leaf and are themselves imported by checks/_config.py "
                         "and risk.py, the same cross-topic-leaf shape B-247 already "
                         "established. A finer split (the grounding prose into a doc, the "
                         "tables kept here) is a later cycle, not this one.",
    "checks/_capability.py": "~2,977 lines (restated 2026-09-20, F-199 — was ~2,460) — "
                             "the declared-vs-effective capability / "
                             "manifest topic (B44/B55/B68/B84/B326 + helpers). Crossed the "
                             "budget with CLAWSECCHECK-B-376/B-369's B55 WARN->FAIL "
                             "escalation: an independent C-135 adversarial pass found and "
                             "fixed 2 real false-positive root causes (tools.elevated."
                             "allowFrom's real dict-per-provider shape; B68's own "
                             "fs-confinement predicate) that the fix needed in place, in the "
                             "same function, to be sound. Grew further with "
                             "CLAWSECCHECK-B-423/B-411: the shared _tool_policy_view "
                             "resolver (+2 independent C-135 rounds' worth of grounding "
                             "comments) that B44/B55/B68/B84 now delegate to, replacing four "
                             "independent accumulators that used to disagree with each "
                             "other and with OpenClaw's real tool-grant resolution. Grew "
                             "again with CLAWSECCHECK-B-409 Slice B: _agent_profile_widenings "
                             "(the one per-agent policy layer that WIDENS rather than "
                             "narrows, `??`-coalesced against the global tools.profile) "
                             "wired into _b68_fs_tools_granted plus grounding comments on "
                             "why it's WARN-only and correcting a prior false "
                             "\"per-agent layers can only narrow\" claim in two docstrings. "
                             "Grew again with CLAWSECCHECK-F-199: check_node_"
                             "allowskills_default_on (B386), the sibling of B71's "
                             "gateway.nodes.commands dual-shape read for the "
                             "gateway.nodes.allowSkills / legacy skills.enabled rename. "
                             "A finer split is a later cycle.",
    "checks/_agents.py": "~2,239 lines (restated 2026-09-19, B-833 — was ~1,798 on 2026-09-11, ~1,358 before C-411) — "
                        "the multi-agent / subagent-exposure topic "
                        "(check_agent_separation, check_untrusted_context, "
                        "check_subagents_allow_agents, etc.). Crossed the budget with "
                        "E-060's check_embedded_agent_project_settings_policy (B327) — "
                        "kept in this module rather than _capability.py because the threat "
                        "(an embedded sub-agent trusting untrusted WORKSPACE content) "
                        "matches this module's existing threat model, not a capability/"
                        "blast-radius one. A finer split is a later cycle.",
    "checks/__init__.py": "~1,490 lines — the aggregator (every check import + the CHECKS "
                          "list + run_all). Its length is driven directly by the NUMBER OF "
                          "CHECKS (one import line per check, by design — see §3.1-a: no "
                          "narrow __all__, every name must stay importable), so it grows by "
                          "~1-2 lines with every new check the catalog gains. Crossed the "
                          "budget with C-207's check_self_privesc_directive (B159); there is "
                          "no topic to split imports/registration into without breaking the "
                          "aggregator pattern itself. A finer split is a later cycle.",
    "monitor.py": "~1,355 lines — the drift/monitor comparison layer, after C-433 split it "
                  "PER DIMENSION. What is left is the orchestration: snapshot() (which calls "
                  "each dimension's signature builder), diff_with_notes()' preamble and its "
                  "list of arm calls, WATCHED_DIMENSIONS, and _degrade_snapshot. Every "
                  "dimension's signature builder AND its diff arm now live together in "
                  "monitordims/<dimension>.py — the shape the task asked for and the one three "
                  "earlier attempts got wrong by splitting BY FUNCTION, which separates the two "
                  "halves that must always change together. 4,916 -> 1,355 across the whole "
                  "task; diff_with_notes 1,635 -> 638; 28 diff arms extracted, each verified "
                  "individually by disabling it and requiring the equivalence matrix to move. "
                  "Output proven identical to the pre-split code over 77 constructed snapshot "
                  "pairs plus byte-identical snapshots on home_safe and home_vuln. Still over "
                  "budget by ~155 lines, and the remaining excess is the preamble — the "
                  "blind-run / scope / config-usable computation the arms depend on, which is "
                  "where the genuinely shared locals live and the one place a mistake "
                  "FABRICATES alerts rather than losing them. That is a data-flow question, not "
                  "a file move, and it is deliberately not bundled with this one.",
    "risk.py": "~2,937 lines (restated 2026-09-17 — was ~2,421) — the combinational "
               "attack-chain engine (one _rule_* per chain "
               "plus the shared leg predicates they compose). Crossed the 1,200-line ceiling "
               "with B-283 (c), which taught _channels_with_visibility_all the account -> "
               "channel -> default precedence the dist resolver uses; that helper MUST stay "
               "here rather than move to checks/_shared.py, because risk.py imports only via "
               "the checks aggregator (CLAUDE.md §3.1-a) and RISK-18 calls it directly. Grew "
               "again with F-135's RISK-21, the first chain to join config posture with the "
               "trajectory log: most of its bulk is the in-source record of WHY the coarse "
               "join (open channel + high-blast proven anywhere) is a Golden-Rule-#5 blocker "
               "and the per-session-origin one is not — reasoning a later reader must not "
               "have to rediscover before widening it. Grew again with B-288's RISK-20, "
               "which fills what was a deliberate numbering hole between RISK-19 and "
               "RISK-21: it joins the root-`hooks` session-key/agent-routing posture with "
               "gateway remote exposure. Its field-reading half correctly lives in "
               "checks/_shared.py (B179 reads the same family), so what is here is only "
               "the chain plus the in-source record of the two judgement calls a later "
               "reader must not have to re-derive — why an arm that is true in the DEFAULT "
               "state can only ever escalate inside a chain, and why this rule is HIGH "
               "where the vendor's own audit says critical. Splitting the rules from the "
               "predicates they share would separate a chain from its own evidence. A finer "
               "split (one module per severity tier, or rules/ + predicates.py) is a later "
               "cycle.",
    "skillast.py": "~12,316 lines (restated 2026-09-24, B-894 -- was ~11,796; the addition "
                   "is the shell for-loop credential-taint engine for SHELL_CRED_EXFIL "
                   "(~520 lines: continuation-join/heredoc-blank/code-mask lexical prep, "
                   "the do/done-paired loop-region finder, and the three-role direct/hop/"
                   "pipe consumer that unrolls a loop onto the EXISTING literal cred-read "
                   "rules rather than adding a second taint model, plus a round-4 fix "
                   "splitting the in-cluster/TLS exemption's position-only TLS-flag arm "
                   "from its content-dependent in-cluster-token arm, since the flag arm "
                   "alone is safe to check with one representative word per line but the "
                   "token arm is not) -- the shell family, not python/js, and no new "
                   "parser). Restated 2026-09-23, merging three concurrent growth lines "
                   "from a common ~7,267-line B-643 baseline (2026-09-16): B-830 round 2, "
                   "B-850 rounds 3-5, and B-917's build plus its two fix rounds. B-830 round 2 (+538) added a RecursionError guard around the two B-830 fold call "
                   "sites (analyze_python's credential-taint pass, capability_families) so a pathological path-join/arithmetic chain falls back to "
                   "ctx=None instead of crashing --vet-skill with no verdict, plus threading the fold context into the in-cluster credential classifier so a folded "
                   "extension of the in-cluster token literal cannot misclassify as exempt — the same taint layer this note already tracks, not a new parser "
                   "family. B-850 rounds 3-5 (+1,711 combined) replaced the old B-752 token-presence proxy with the artifact-containment ALLOWLIST recognizer: "
                   "round 4 (9fc20cc9) added the ambiguous-fires provenance walker backing the fail-closed guard's mutation-target check (~395 lines), and round 5 "
                   "wired the .__dict__/subscript-store gates onto that same combinator plus traced the Call branch's function-return/class-constructor "
                   "provenance (~120 lines) — both inside the same self-contained abstract-interpretation engine, not a new parser family. B-917 (its build plus fix "
                   "rounds 1-2, combined) added the loader-sink / staged-import correlation pass (runpy/importlib/zipimport modelled as code-execution sinks, "
                   "plus a write-then-import location correlation reusing shippedexec's `locate()`/`loc_eq()` resolver rather than a spelling-keyed "
                   "predicate), the artifact-wide staged-write cache (`_b917_artifact_staged_writes`, a `weakref.WeakKeyDictionary` keyed on the "
                   "`ShippedArtifact` instance so a write in one file of an artifact correlates with an import in another without leaking across artifacts "
                   "or re-parsing every sibling file per pass), the LEGB fallback for `locate()`'s Name branch (`_legb_lookup`, guarded by `_legb_blocked`), and "
                   "the any-record scope gate that round 2's own C-135 review required (`records(scope).get(name)` replacing the sole()-is-None test, since a "
                   "non-assign binding — a parameter, a for/with/comprehension target, an except-as name, a nested def/class, an import — makes a name local to "
                   "the whole scope and must stop the fallback there). None of this adds a new "
                   "parser family — the file's split is still along the existing "
                   "python/shell/js parser families; its own split is "
                   "deferred to a later cycle (I-022 secondary target). Restated "
                   "2026-09-16 (B-643), and the guard's own instruction is to reconsider "
                   "the split rather than bump the number: the B-850 engine (constants "
                   "through the classify_* predicates, ~700 lines) is itself a candidate "
                   "extraction — it depends on nothing else in this module and nothing "
                   "else in this module depends on it except the four small wrapper "
                   "functions that call into it — deferred here for the same reason the "
                   "python-taint layer was: this change is already large enough to review "
                   "on its own without also moving it to a new file in the same commit.",
    # Restated 2026-09-08: 5,641 -> 6,178. The claim had already drifted ~467 lines before
    # this touch; two commits adding ~70 (a mark swap, an ungraded-state block, and the
    # credential-surface env fix — most of it the comment explaining each) crossed the
    # 500-line cap that binds a file this size. That is the SECOND time this one entry has
    # been restated at the same threshold: its own text below already narrates a "+10% that
    # tripped the staleness guard". `checks/_lifecycle.py`'s restate note says what that
    # means — the table needs one restate-and-reconsider pass, not an entry bumped each
    # time the next commit trips it — and this bump is exactly the pattern it warned about.
    # Recorded rather than quietly corrected: the split below is now owed twice over.
    "report.py": "~6,699 lines — the output renderers; grew further with F-131's "
                 "Inventory-by-subject block (its own additive presentation layer, not "
                 "branching check logic), then with the B-617 inert-disclosure channel "
                 "and the B-547 scope-note rewiring, then with B-758's three report "
                 "self-contradiction fixes (_urgent_headline gained risk-chain awareness; "
                 "the skills/MCP inventory rows were reordered) — each landed here because "
                 "each is a claim this file phrases. The split (renderers vs the "
                 "disclosure/scope layer they share) is still deferred, but it is no "
                 "longer only an I-022 secondary target — it is the second-largest "
                 "structural debt after checks/_content.py.",
    "catalog.py": "~3,916 lines (restated 2026-09-12, C-526/C-527 — was ~3,404) — the "
                  "CheckMeta CATALOG (one entry per check) + BY_ID + "
                  "the additive FAMILY_OF/SUBJECT_OF roll-up metadata; reference data / a "
                  "manifest, not branching logic.",
    "collector.py": "~8,254 lines (restated 2026-09-23 — was ~7,542) — the read-only "
                    "collection layer (config / bootstrap / skill "
                    "collection + the Context dataclass + byte-format classify_bytes); a "
                    "cohesive foundational module. Crossed the budget with F-116 (.ipynb->AST "
                    "+ .pyc/.wasm sniffing), grew again with B-610 (deriving the workspace "
                    "directories OpenClaw builds from an agent id, instead of hardcoding three "
                    "names), and again with B-537 (a validating legacy-multibyte rung in the "
                    "decode ladder, +116). That third growth is what tripped this staleness "
                    "guard, which is the guard working: the byte-format half is now roughly a "
                    "module's worth on its own and every encoding fix lands in it. Splitting "
                    "byte-format sniffing + the decode ladder out to a leaf (the "
                    "workspace/agent-id resolution to another) has moved from 'a later cycle' "
                    "to the next structural task on this file. FOURTH growth (+386): making "
                    "three state-SQLite readers dual-shape after OpenClaw's state schema "
                    "consolidated columns into JSON blobs and renamed a table. That growth is "
                    "structural, not incidental — every one of those readers now carries a "
                    "legacy branch AND a modern branch, and a fourth reader "
                    "(_collect_plugin_trust) still has to follow. The state-DB readers are "
                    "therefore a THIRD candidate seam alongside the two named above, and the "
                    "one with the clearest boundary: they share a database handle, a "
                    "read-only discipline, and nothing else with the file around them. "
                    "Read the +386 with this in mind, because it applies to every threshold "
                    "guard here and not just this entry: the claim was ALREADY stale at "
                    "~5,907 against a real 6,034 before that change. A threshold bills the "
                    "growth to whoever crosses the line, not to whoever accumulated it, so "
                    "the commit a staleness guard fires on is rarely the commit that caused "
                    "most of the drift. FIFTH growth (+263, B-612): `read_skill_declared` — "
                    "a file only a skill's SKILL.md names with an interpreter, collected for "
                    "B13's danger pass alone, kept out of the three coverage lists on purpose "
                    "(the seven-round retraction history is why). That is a fourth candidate "
                    "seam, and the leaf-most one of the four: it depends on nothing else this "
                    "file collects and nothing else depends on it, unlike the byte-format and "
                    "state-DB seams above.",
    "cli.py": "~7,009 lines — the Layer-4 shell (all flags + the dispatch cascade); every new "
              "primary mode adds a few lines here by design. Crossed the budget with F-113 "
              "(--judge-packet). Grew ~520 lines over B-584/B-586/B-598/B-601, all of it in "
              "the dispatch cascade: each `_mode` branch that returns early has to repeat "
              "what the shared tail does, which is precisely the shape those four bugs were. "
              "Then another ~550 over B-502/B-566/B-578/B-583 — and the shape repeated "
              "exactly: B-583 was a mode branch not telling an absent journal from an empty "
              "one, and B-578 was a mode branch that could not reach its own output at all. "
              "Both are the early-return cascade failing to carry what the shared tail knows. "
              "That is the argument for the split (flag registration -> its own module, and "
              "the mode branches -> a dispatch table) rather than a reason to defer it again; "
              "the entry has now been restated twice for the same cause. Restated a third "
              "time after a batch of small dispatch-cascade additions (C-448's --all window "
              "opt-out, C-519's --show-suppressed attribution/expiry, C-524's --save-run/"
              "--diff) — each individually a few lines by design, same as every other primary "
              "mode this entry already names; not a new argument, the same one landing again. "
              "Restated a fourth time after C-517's --watch/--watch-status: two new primary "
              "modes plus their argparse registration and CLI-side helpers (the loop itself "
              "lives in the new watch.py, not here) — same shape, same cause. Restated a "
              "fifth time after B-888: SkillSweep.counts()/not_scanned() gained a bucket for "
              "a skill whose own vet_skill() scan raised, plus the matching disclosure in "
              "both tally renderers — this is the coverage-accounting side of the shell, not "
              "the dispatch cascade, but it lives in the same exempted file.",
    "pipeline.py": "~1,961 lines — the --full P7-P10 orchestration. Crossed the budget with "
                   "C-425's PipelineResult.to_ledger(), which projects the run's phases onto "
                   "the five-layer ledger (layers.py). It belongs here and nowhere else: it "
                   "reads PhaseResult state, and layers.py must stay a leaf that scoring.py "
                   "can import, so the projection cannot live down there. Restated after an "
                   "E-087 incident-response batch (B-799's ctx-aware to_ledger honesty and "
                   "F-193's live-test scenario-id validation, B-800's behavioral-incompleteness "
                   "wording, B-804's verdictsSubmitted gating, B-758's runState reprojection) — "
                   "five fixes landing in the same module in one pass, not scope creep in any "
                   "one of them. A finer split (phase runners vs. roll-up) is a later cycle.",
    "behavioral.py": "~1,263 lines — the --behavioral replay ring: the trajectory reader's "
                     "consumers, the four detectors (T1/T2/T3/B191), the F-154 cap reducer "
                     "and the renderer. Sat three lines under the budget until B-559, which "
                     "made T1/T2 answer UNKNOWN instead of a vacuous PASS when the log was "
                     "not read in full; the predicate that decides that "
                     "(analysis_incompleteness) has to live beside the flags it reads, or a "
                     "new incompleteness signal would silently not reach it. Splitting the "
                     "detectors from the renderer would separate each verdict from the text "
                     "that discloses its own limits, which is the pairing B-245 and B-559 "
                     "both exist to keep. A finer split is a later cycle.",
    # CLAWSECCHECK-C-455: adjudication.py (2,478 lines; the _EXEMPT reason had been
    # restated three times since 2026-08-24 — ~1,247 -> ~1,570 -> ~1,920 -> ~2,433,
    # each restatement filing the split rather than doing it, and the file grew again
    # to 2,478 before this task landed) is now the `adjudication/` package below.
    # `_verdicts.py` (804 lines) and `__init__.py` (163 lines, the aggregator) both came
    # out under the 1,200-line budget and need no exemption; only the builder half does.
    "adjudication/_builder.py": "~1,736 lines — the judge-packet BUILDER half of the "
                                "C-455 split: the evidence sources (recovered taint, "
                                "env-auth-kwarg exfil, the B-452 keyword-gated-trigger "
                                "detector, B62 mismatches), evidence/target/host "
                                "redaction, corroboration, and "
                                "build_judge_packet/render_judge_packet_json. Checked "
                                "mechanically before the split: nothing here calls into "
                                "_verdicts.py (the dependency runs one way, verdicts -> "
                                "builder), so the two are a leaf and a consumer, not an "
                                "arbitrary halving. A finer split (the B-452 keyword-"
                                "gated-trigger detector is a self-contained chunk near "
                                "the end of this file) is a later cycle, not attempted "
                                "here.",
}


def _line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def _package_py_files() -> list[Path]:
    """Top-level package modules + the checks/ and adjudication/ subpackages."""
    files = sorted(PKG.glob("*.py"))
    files += sorted((PKG / "checks").glob("*.py"))
    files += sorted((PKG / "adjudication").glob("*.py"))
    return files


def _exempt_key(path: Path) -> str | None:
    """Return the _EXEMPT key matching this file (basename or pkg-relative), or None."""
    rel = str(path.relative_to(PKG))
    if path.name in _EXEMPT:
        return path.name
    if rel in _EXEMPT:
        return rel
    return None


def test_no_module_exceeds_line_budget() -> None:
    offenders = []
    for f in _package_py_files():
        n = _line_count(f)
        if n <= _MAX_LINES or _exempt_key(f) is not None:
            continue
        offenders.append(f"{f.relative_to(PKG)}: {n} lines (> {_MAX_LINES})")
    assert not offenders, (
        f"Module(s) over the {_MAX_LINES}-line budget with no exemption:\n"
        + "\n".join(offenders)
        + "\n\nSplit the file into a topic module (see CLAUDE.md §3.1 'Where new code "
        "goes'); or, if the size is genuinely justified, add it to _EXEMPT here WITH a "
        "reason AND update the §3 module map in the same change (rule §3.1-b)."
    )


def test_exempt_entries_are_not_stale() -> None:
    """Keep _EXEMPT honest: an entry that vanished or dropped under budget is stale —
    remove it so the guard tightens automatically (that is the whole point)."""
    present = {}
    for f in _package_py_files():
        key = _exempt_key(f)
        if key is not None:
            present.setdefault(key, []).append(f)
    stale = []
    for key in _EXEMPT:
        matches = present.get(key)
        if not matches:
            stale.append(f"{key}: exempt but no such file exists — remove the exemption")
            continue
        if all(_line_count(f) <= _MAX_LINES for f in matches):
            n = max(_line_count(f) for f in matches)
            stale.append(f"{key}: now {n} lines (<= {_MAX_LINES}) — drop the exemption")
    assert not stale, "Stale _EXEMPT entries (tighten the guard):\n" + "\n".join(stale)


_CLAIM_RE = re.compile(r"~([\d,]+) lines")
# How far a stated size may lag reality before it must be restated. Not equality: that
# would redden CI on any commit that adds a line to an exempt module, which is most of
# them. Not open-ended either — that is precisely what rotted. Same reasoning as the
# doc-facts test-count band (CLAUDE.md §6.2), a slack wide enough to absorb ordinary
# growth and narrow enough that a number cannot become fiction.
#
# Proportional AND absolute, because a purely proportional band lets the largest debts rot
# fastest: 25% of checks/_content.py's 14,300 lines is 3,575 lines of undetected growth —
# longer than 16 of the 20 exempt files are in total. The absolute arm makes the guard
# tighten as a file gets worse, which is the direction that matters.
_CLAIM_SLACK = 0.25
_CLAIM_SLACK_MAX_LINES = 500


def test_exempt_line_claims_match_reality() -> None:
    """Every _EXEMPT reason states a size. Until this guard existed, nothing checked it.

    The result, measured when the guard was written: 13 of 20 claims were stale, and
    ``checks/_content.py`` — whose reason argues it is a coherent unit worth keeping
    whole — claimed ~4,800 lines while holding 14,300. The budget test above passed green
    throughout, because it only asks whether a file is over 1,200 lines, never whether the
    exemption still describes the file it excuses. An exemption is a debt record; a debt
    record that understates the debt by 200% is worse than none, because it is read and
    believed.
    """
    # Resolve keys exactly the way the budget and staleness tests do. `_exempt_key`
    # deliberately accepts a BARE BASENAME as well as a package-relative path, so a naive
    # `PKG / key` misses every basename-keyed entry — and skipping it there meant a
    # `"_content.py": "~1 lines"` entry passed this guard silently while passing the
    # staleness guard too. Both guards green over a claim understating the file by 14,299
    # lines.
    present: dict = {}
    for f in _package_py_files():
        key = _exempt_key(f)
        if key is not None:
            present.setdefault(key, []).append(f)

    wrong = []
    for key, reason in _EXEMPT.items():
        matches = present.get(key)
        if not matches:
            continue  # the staleness test above owns "exempt but no such file"
        m = _CLAIM_RE.match(reason)
        if m is None:
            wrong.append(f"{key}: reason must open with '~N lines — ', got: {reason[:40]!r}")
            continue
        claimed = int(m.group(1).replace(",", ""))
        if claimed <= 0:
            # Would divide by zero building the message below; fail with a sentence.
            wrong.append(f"{key}: reason claims ~{claimed} lines, which cannot be a size")
            continue
        actual = max(_line_count(f) for f in matches)
        tolerance = min(claimed * _CLAIM_SLACK, _CLAIM_SLACK_MAX_LINES)
        if abs(actual - claimed) > tolerance:
            wrong.append(
                f"{key}: reason claims ~{claimed:,} lines, file is {actual:,} "
                f"({(actual - claimed) / claimed:+.0%}) — restate it"
            )
    assert not wrong, (
        "_EXEMPT reasons no longer describe their files:\n" + "\n".join(wrong)
        + "\n\nUpdate the stated count. If a module grew this much, that is the signal "
        "the exemption was tracking — reconsider the split, do not just bump the number."
    )


def _load_manifest() -> list[str]:
    names = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def test_public_api_manifest_is_subset_of_live_surface() -> None:
    """The export contract: every name tests/siblings import from clawseccheck.checks
    stays importable. One-directional (subset) so adding new public names never fails
    — only losing one that callers still use does."""
    manifest = _load_manifest()
    assert manifest, "checks_public_api.txt parsed empty — the export-contract guard is inert."
    assert manifest == sorted(set(manifest)), (
        "checks_public_api.txt must be sorted and duplicate-free."
    )
    live = set(dir(checks_mod))
    missing = [n for n in manifest if n not in live]
    assert not missing, (
        "Names in the export contract are no longer importable from clawseccheck.checks:\n"
        + "\n".join(missing)
        + "\n\nA rename/move dropped a re-export and shrank the public surface. The "
        "aggregator must keep every manifest name importable (CLAUDE.md §3.1-a). If a "
        "name was intentionally removed and no caller uses it, delete it from the "
        "manifest in the same change."
    )


def test_shared_leaf_holds_no_check_definitions() -> None:
    """Placement lint (active once I-022 R2 creates checks/_shared.py): the shared leaf
    is helpers + constants only; check_*/vet_* entry points belong in a topic module."""
    shared = PKG / "checks" / "_shared.py"
    if not shared.exists():
        return  # pre-R2: nothing to lint yet
    tree = ast.parse(shared.read_text(encoding="utf-8"))
    misplaced = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (node.name.startswith("check_") or node.name.startswith("vet_"))
    ]
    assert not misplaced, (
        "checks/_shared.py must hold only shared helpers/constants, but it defines "
        "check/vet entry points: " + ", ".join(misplaced)
        + " — move them to the owning topic module (CLAUDE.md §3.1)."
    )
