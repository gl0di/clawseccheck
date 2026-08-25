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

import clawseccheck.checks as checks_mod

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG = REPO_ROOT / "clawseccheck"
MANIFEST = REPO_ROOT / "tests" / "checks_public_api.txt"

_MAX_LINES = 1200

# Files intentionally over budget. Every entry MUST carry a reason. An entry here is
# tracked debt, not a free pass — trim it as the I-022 modularization lands (the
# companion staleness test fails if an exemption no longer applies).
_EXEMPT = {
    "checks/_config.py": "~3,995 lines — the config-hardening topic (15 checks + helpers); "
                         "topic-faithful and over budget by design. A finer split is a "
                         "later cycle (I-022 secondary target).",
    "checks/_lifecycle.py": "~5,662 lines — the approval / update-pinning / self-modification "
                            "/ supply-chain topic (17 checks + helpers); topic-faithful and "
                            "over budget by design. A finer split is a later cycle.",
    "checks/_content.py": "~14,300 lines — the content-security ring (30 skill-malware / "
                          "prompt-injection checks + the fence/decode/typosquat machinery). "
                          "Kept as ONE unit on purpose (SKILL_CONTENT_RING is the single "
                          "source consumed by both the full audit and --vet); do not split.",
    "checks/_vet.py": "~5,890 lines — the --vet entry engine (vet_skill/vet_source/"
                      "detect_vet_type/check_installed_skills + SKILL_CONTENT_RING + the "
                      "shared effect/sink analysis); consumes the content ring. Over budget "
                      "by design; a finer split is a later cycle.",
    "checks/_host.py": "~1,324 lines — the host-monitor / incident-readiness topic "
                       "(B10/B16/B50-B54 + the attestation helpers). Sat at EXACTLY 1,200 "
                       "for a while, i.e. one line under a tripwire, and crossed it with "
                       "B-514: check_audit_log went from a 2-branch stub that returned "
                       "UNKNOWN on the false premise that audit.enabled does not exist, to "
                       "the four verdicts the real field actually supports (explicit "
                       "false / redaction off / explicit true / unset-with-no-schema-"
                       "default). The extra lines are user-facing verdict text, not "
                       "machinery; squeezing them to hold a line count would trade the "
                       "report's clarity for a number. A finer split is a later cycle.",
    "checks/_mcp.py": "~7,049 lines — the MCP / plugin checks + vet_mcp / vet_plugin (40 "
                      "symbols); topic-faithful and over budget by design. A finer split is "
                      "a later cycle.",
    "checks/_egress.py": "~4,077 lines — the egress-hardening topic (proxy/TLS/SSRF/"
                         "data-at-rest + web-fetch/log checks). Crossed the budget with "
                         "B178's check_provider_baseurl (models.providers.<id>.baseUrl "
                         "cleartext http:// leak) — kept adjacent to B155's "
                         "check_outbound_proxy, its sibling check on the SAME provider "
                         "object, rather than splitting one config object's security "
                         "posture across two topic files. A finer split is a later cycle.",
    "checks/_shared.py": "~3,216 lines — the leaf every checks/_<topic> module (and "
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
    "checks/_capability.py": "~1,960 lines — the declared-vs-effective capability / "
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
                             "A finer split is a later cycle.",
    "checks/_agents.py": "~1,358 lines — the multi-agent / subagent-exposure topic "
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
    "monitor.py": "~3,798 lines — the drift-snapshot/diff engine (snapshot() builds every "
                  "dimension, diff() compares them, plus the hash-chained journal). Crossed "
                  "the budget with B-267/B-268: the skill signature gained a full-directory "
                  "fingerprint independent of the malware-scan budget, and every capped "
                  "collection (skills, memory files) gained a persisted truncation frontier "
                  "so a cap-evicted entry is no longer diffed as a deletion. Grew again with "
                  "B-272/B-273/B-279/B-280, four independent dimension repairs (memory-hash "
                  "backstop + presence guard + shared injection patterns, the uncapped "
                  "raw_score backstop + status-regression arm, RP2's non-flag package key, "
                  "and the catalog severity on 'Now FAILING'); most of the added bulk is the "
                  "in-source reasoning each upgrade-safety guard has to carry. All are "
                  "cross-cutting corrections to snapshot()/diff() themselves, not a new "
                  "topic that could live elsewhere — splitting them out would separate a "
                  "dimension's snapshot half from its diff half. A finer split (per-dimension "
                  "snapshot/diff pairs) is a later cycle. Grew again with B-274 (+ the "
                  "deferred B-283 monitor hunk): the channel signature went from one opaque "
                  "hash to a dict of named sub-signatures (allowlist MEMBERSHIP, credential "
                  "digests, requireMention gating, contextVisibility, the Feishu allowall "
                  "alias), which is what lets diff() compare only the sub-keys present on "
                  "BOTH sides and so widen the signature without mass-firing on every user's "
                  "first post-upgrade run. Same shape as the guards above: most of the bulk "
                  "is the grounding each field read has to carry (dist file:line for every "
                  "schema key) plus the reasoning for the upgrade-safety gate. Grew by ~600 "
                  "lines again with the E-076 monitor epic (C-418 coverage notes, B-500's "
                  "check-transition matrix, F-170's three config-journal arms). The epic "
                  "deliberately pushed the JOURNAL PARSER out to its own leaf module "
                  "(configjournal.py) rather than adding it here; what remains is "
                  "snapshot()/diff() logic, which cannot move without separating a "
                  "dimension's snapshot half from its diff half. A per-dimension split is "
                  "now the largest single piece of debt in this file. Grew ~535 lines more "
                  "with F-173/F-174/F-175 (the behavioural arm, the two supply-chain "
                  "dimensions and their diff arms, the baseline reference, changed_skills). "
                  "Both new READERS went to their own leaf modules (openclawdist.py, "
                  "skillprovenance.py) — this file gained only the comparisons. Restating "
                  "the number here is not the answer and this guard says so: the split is "
                  "tracked as its own task, because doing it inside a feature change would "
                  "bury a 3,800-line refactor in a diff nobody could review.",
    "risk.py": "~2,421 lines — the combinational attack-chain engine (one _rule_* per chain "
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
    "skillast.py": "~6,628 lines — the python/shell/js parser families; its own split is "
                   "deferred to a later cycle (I-022 secondary target).",
    "report.py": "~5,641 lines — the output renderers; grew further with F-131's "
                 "Inventory-by-subject block (its own additive presentation layer, not "
                 "branching check logic), then with the B-617 inert-disclosure channel "
                 "and the B-547 scope-note rewiring. The +10% that tripped the staleness "
                 "guard is mostly explanatory comment, not new branching — but the "
                 "pattern is worth naming: this file now hosts the scope note, the "
                 "disclosure block, the inventory, the coverage page's text half and "
                 "every renderer, and each honesty fix lands here because it is where "
                 "claims are phrased. The split (renderers vs the disclosure/scope "
                 "layer they share) is still deferred, but it is no longer only an "
                 "I-022 secondary target — it is the second-largest structural debt "
                 "after checks/_content.py.",
    "catalog.py": "~3,404 lines — the CheckMeta CATALOG (one entry per check) + BY_ID + "
                  "the additive FAMILY_OF/SUBJECT_OF roll-up metadata; reference data / a "
                  "manifest, not branching logic.",
    "collector.py": "~5,549 lines — the read-only collection layer (config / bootstrap / skill "
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
                    "to the next structural task on this file.",
    "cli.py": "~4,329 lines — the Layer-4 shell (all flags + the dispatch cascade); every new "
              "primary mode adds a few lines here by design. Crossed the budget with F-113 "
              "(--judge-packet). Grew ~520 lines over B-584/B-586/B-598/B-601, all of it in "
              "the dispatch cascade: each `_mode` branch that returns early has to repeat "
              "what the shared tail does, which is precisely the shape those four bugs were. "
              "That is the argument for the split (flag registration -> its own module, and "
              "the mode branches -> a dispatch table) rather than a reason to defer it again.",
    "pipeline.py": "~1,314 lines — the --full P7-P10 orchestration. Crossed the budget with "
                   "C-425's PipelineResult.to_ledger(), which projects the run's phases onto "
                   "the five-layer ledger (layers.py). It belongs here and nowhere else: it "
                   "reads PhaseResult state, and layers.py must stay a leaf that scoring.py "
                   "can import, so the projection cannot live down there. A finer split "
                   "(phase runners vs. roll-up) is a later cycle.",
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
    "adjudication.py": "~1,570 lines — the judge-packet builder. Crossed the budget with the "
                       "ESET H1 2026 gap-closure pass (C-361: config field-path extraction so "
                       "the audit-path majority of findings, which cite a dig() path rather "
                       "than a file:line, stop always hitting the contentless evidence "
                       "fallback) and grew again with B-406 (duplicate (finding_id, target) "
                       "verdict-entry resolution, order-independent by severity rank). "
                       "Restated from ~1,247 on 2026-08-24: it had drifted to 1,543 unnoticed "
                       "(+24%, one point under this guard's tripwire) and B-618's cross-skill "
                       "host attribution took it over. The guard fired for the right reason and "
                       "the split is filed rather than waved off — restating the number without "
                       "recording that would be the exact evasion this test exists to catch.",
}


def _line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def _package_py_files() -> list[Path]:
    """Top-level package modules + the checks/ subpackage (empty until I-022 R2)."""
    files = sorted(PKG.glob("*.py"))
    files += sorted((PKG / "checks").glob("*.py"))
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
