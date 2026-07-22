"""Judge-packet builder (F-113): generalizes sar.py's single-check SAR into a full
borderline-band packet for an external host-agent adjudicator.

ClawSecCheck never calls an LLM or the network. This module only assembles a
machine-readable list of borderline findings for the user's OWN host agent to
review and answer — it does NOT change any check's verdict or score, and it
does NOT re-run the audit. It covers five sources, read-only, over data an
audit() pass already collected:

  (a) every unsuppressed UNKNOWN finding — "could not determine from config",
      worth a second look by something that can read more context;
  (b) unsuppressed WARN findings whose id has a documented false-negative-prone
      history (dual-use signals deliberately down-ranked from FAIL to WARN so a
      legitimate skill is never hard-failed);
  (c) one item per B62 capability-intent mismatch (a thin adapter over
      sar.build_sars, which already re-derives the same mismatches B62 itself
      computes);
  (d) taint signals check_installed_skills (checks/_vet.py) computes via
      skillast.analyze_python but then silently drops — its crit/warn cascade
      has no ``else`` branch for an "info"-severity ASTFinding when no
      independent credential/exfil signal exists elsewhere in the skill. This
      module re-runs analyze_python (read-only, the same call checks/_vet.py
      already makes) and surfaces exactly those otherwise-invisible findings as
      UNKNOWN, so a host agent can decide instead of never seeing them;
  (e) env/agent-config secrets placed in an auth-shaped kwarg (headers=/auth=/
      cert=) of a network call (B-190). This case is excluded from
      ENV_EXFIL_FLOW inside analyze_python itself (skillast._ENV_AUTH_KWARGS,
      the normal way a skill authenticates to its own API), so unlike (d) it is
      never computed at all — re-running analyze_python can't find it either.
      A second, independent AST walk (skillast.analyze_env_auth_kwarg_exfil)
      scoped to exactly that excluded case surfaces it as UNKNOWN.

Every string field is routed through logsafe.redact() before it reaches the
packet — no raw skill source or secret value ever appears in the output.

Stdlib only. No network, no subprocess, no writes.
"""
from __future__ import annotations

import json
import re
from dataclasses import replace as dc_replace

from .baseline import fingerprint
from .catalog import FAIL, UNKNOWN, WARN
from .logsafe import redact
from .sar import build_sars
from .skillast import analyze_env_auth_kwarg_exfil, analyze_python

# --------------------------------------------------------------------------- constants

# The schema every packet item's "verdict_schema" field carries — a fixed
# contract the host agent's answer must conform to.
_VERDICT_SCHEMA = {"answer": ["yes", "no"], "reason": "free text"}

# WARN-grade check ids with a documented false-negative-prone history: each is a
# dual-use signal deliberately down-ranked from FAIL to WARN so a legitimate skill
# is never hard-failed on it alone — exactly the band where a second, independent
# read is most valuable. B62 is intentionally absent: its mismatches are handled
# per-skill by _b62_items (a thin adapter over sar.build_sars), not aggregated
# here as a single Finding.
_FN_PRONE_WARN_IDS = frozenset({
    "B100", "B65", "B66", "B99", "B90", "B102", "B154", "B13", "B156",
})

# ASTFinding rules that check_installed_skills (checks/_vet.py) computes via
# skillast.analyze_python but silently drops: each is "info"-severity, and that
# cascade only promotes an "info" finding when a cred/exfil signal already fired
# elsewhere in the same skill -- there is no `else` branch, so an "info" finding
# with no such co-signal is never surfaced anywhere. See _recover_dropped_taint.
_RECOVERED_TAINT_RULES = frozenset({
    "TT4_FILE_NET", "TT_SSRF", "TT5_ARG_INJECTION", "DANGEROUS_SINK",
})

# Plain-language attestation questions, keyed by check id.
_ID_QUESTIONS = {
    "B13": "The installed-skill scan flagged a WARN-level pattern in this skill "
           "(a possible secret/env value reaching a network call, a time-bomb / "
           "environment-gated sink, a soft content signal, or a bare notify-host "
           "post). Did you configure this skill to behave this way, and do you "
           "trust the destination? [yes/no + reason]",
    "B100": "A setup/install section instructs pasting a remote-fetch command "
            "into a terminal (ClickFix pattern). Did you write or vet this "
            "installer yourself? [yes/no + reason]",
    "B65": "A conditional 'if the user asks for X, then do Y' sleeper-trigger "
           "pattern was found. Is this hidden conditional behavior something "
           "you intended? [yes/no + reason]",
    "B66": "A persona/role-override instruction (e.g. 'pretend you are ...') "
           "was found. Is this deliberate, and could it weaken the assistant's "
           "policy hierarchy? [yes/no + reason]",
    "B99": "A shipped .pth file or sitecustomize/usercustomize module auto-runs "
           "on every Python interpreter start, not just on import. Is this "
           "auto-execution genuinely required? [yes/no + reason]",
    "B90": "A base64 payload only reassembles into a runnable command when "
           "string fragments split across this skill's files are joined. Is "
           "this a legitimate embedded asset, not a scanner-evasion payload? "
           "[yes/no + reason]",
    "B102": "A base64 payload only reassembles into a runnable command when "
            "two file sections are joined at their boundary. Is this a "
            "legitimate embedded asset, not a scanner-evasion payload? "
            "[yes/no + reason]",
    "B154": "A plaintext (non-base64) command reassembles from string literals "
            "split across this skill's files. Is this a legitimate pattern, "
            "not a scanner-evasion payload? [yes/no + reason]",
    "B156": "A secret (token / credential / api_key) appears to be sent to an "
            "external or second-party destination with no secrecy, override, "
            "or trigger framing. Is that destination one you trust with this "
            "secret? [yes/no + reason]",
}

# Plain-language attestation questions, keyed by the recovered ASTFinding rule.
_RULE_QUESTIONS = {
    "TT4_FILE_NET": "This skill reads a file and the contents appear to flow "
                    "into a network call, with no independent credential "
                    "signal nearby (so the engine did not escalate it). Is "
                    "this an intended upload/sync to a trusted destination? "
                    "[yes/no + reason]",
    "TT_SSRF": "An externally-controlled value appears to flow into a "
               "network-fetch URL in this skill. Is the destination bounded "
               "to a trusted host, or could this reach an unexpected / "
               "internal endpoint? [yes/no + reason]",
    "TT5_ARG_INJECTION": "External input appears to flow into a subprocess "
                         "call as a non-program argument (argument, not "
                         "command, injection). Are the arguments safely "
                         "bounded? [yes/no + reason]",
    "DANGEROUS_SINK": "This skill calls a shell/exec-family sink directly, "
                      "with no independent credential/exfil signal nearby. Is "
                      "this expected of the skill's declared purpose? "
                      "[yes/no + reason]",
    "ENV_AUTH_KWARG_EXFIL": "An environment-variable or agent-config secret is placed "
                            "in an auth-shaped keyword (headers/auth/cert) of a network "
                            "call — the normal way a skill authenticates to its own API, "
                            "but this destination was never independently reviewed. Do "
                            "you recognize and trust this destination? [yes/no + reason]",
}


# --------------------------------------------------------------------------- helpers

def _question_for(finding_id: str) -> str:
    """Plain-language attestation question for a finding id or ASTFinding rule.

    Falls back to a generic, finding-id-only question for anything not in the
    curated maps above. Deliberately never interpolates a Finding's raw
    detail/evidence text: several content-ring checks (B65/B66/B90/B99/B100/
    B102/B154/B156) quote the actual matched skill prose in their evidence for
    a human reader, and that prose can itself be adversarial (a persona-
    jailbreak or prompt-injection directive) -- logsafe.redact() only masks
    known secret shapes, not arbitrary injection text, so it must never be the
    only thing standing between skill-authored prose and this packet.
    """
    q = _ID_QUESTIONS.get(finding_id) or _RULE_QUESTIONS.get(finding_id)
    if q is None:
        q = (
            f"Check {finding_id} could not be automatically resolved. Review "
            "this item in the full report and confirm whether it is expected "
            "and trusted. [yes/no + reason]"
        )
    return redact(q)


def _target_from_evidence(f) -> str:
    """Best-effort skill/file name off the first evidence entry's ``name: ...``
    prefix (the convention every check's evidence list follows); falls back to
    the finding id when there is no evidence to draw a target from.
    """
    for entry in getattr(f, "evidence", None) or []:
        name, sep, _rest = entry.partition(": ")
        if sep and name.strip():
            return redact(name.strip())
    return f.id


# Trailing "(relpath:lineno)" location suffix every check's evidence line
# conventionally ends with (checks/_vet.py, checks/_content.py). Matched so a
# packet item can cite WHERE a finding fired without ever carrying the free-text
# match itself -- see _evidence_locations.
_LOC_SUFFIX_RE = re.compile(r"\(([^()\s][^()]*:\d+)\)\s*$")


def _evidence_locations(f) -> str:
    """Skill-relative file:line locations pulled from a Finding's evidence,
    with the matched free text itself dropped.

    Several content-ring checks (persona-jailbreak, sleeper-trigger, secret-
    exfil, ...) quote the actual matched skill prose in their evidence so a
    human reading the full report can see exactly what fired. That prose is
    attacker-influenceable and logsafe.redact() only masks known secret
    shapes -- it does not neutralize arbitrary injection/persona-override
    text. Since this packet is meant for an external host-agent judge to
    read, only the location is surfaced here; the matched text itself never
    reaches this module's output.
    """
    locs = [m.group(1) for e in (f.evidence or []) if (m := _LOC_SUFFIX_RE.search(e))]
    if locs:
        return redact("; ".join(locs))
    n = len(f.evidence) if f.evidence else (1 if f.detail else 0)
    if n == 0:
        return ""
    return f"{n} evidence entr{'y' if n == 1 else 'ies'} in the full report (not reproduced here)"


def _item_from_finding(f) -> dict:
    return {
        "finding_id": f.id,
        "target": _target_from_evidence(f),
        "redacted_evidence": _evidence_locations(f),
        "engine_disposition": f.status,
        "question": _question_for(f.id),
        "verdict_schema": _VERDICT_SCHEMA,
    }


def _recover_dropped_taint(ctx) -> list[dict]:
    """Re-run analyze_python over every installed skill's Python source and
    surface the info-severity taint rules check_installed_skills silently
    drops when no independent credential/exfil signal exists elsewhere in the
    skill. Read-only, additive: never touches ctx or any check's own verdict —
    a second, independent pass over data check_installed_skills already read.
    """
    installed_py = getattr(ctx, "installed_skill_py", None) or {}
    items: list[dict] = []
    for skill_name, sources in installed_py.items():
        for relpath, src in sources:
            for af in analyze_python(src, relpath):
                if af.rule not in _RECOVERED_TAINT_RULES:
                    continue
                loc = f"{relpath}:{af.lineno}"
                items.append({
                    "finding_id": af.rule,
                    "target": redact(skill_name),
                    "redacted_evidence": redact(f"{skill_name}: {af.reason} ({loc})"),
                    "engine_disposition": UNKNOWN,
                    "question": _question_for(af.rule),
                    "verdict_schema": _VERDICT_SCHEMA,
                })
    return items


def _env_auth_kwarg_items(ctx) -> list[dict]:
    """B-190: surface env/agent-config secrets placed in an auth-shaped kwarg
    (headers=/auth=/cert=) of a network call. Excluded from ENV_EXFIL_FLOW by design
    (skillast._ENV_AUTH_KWARGS) because that's the normal way a skill authenticates to
    its own API — so analyze_python never computes it, and _recover_dropped_taint's
    re-run of analyze_python can never find it either. This is a second, independent
    AST walk (analyze_env_auth_kwarg_exfil) scoped to exactly that excluded case.
    Read-only, additive: never touches ctx or any check's own verdict.
    """
    installed_py = getattr(ctx, "installed_skill_py", None) or {}
    items: list[dict] = []
    for skill_name, sources in installed_py.items():
        for relpath, src in sources:
            for af in analyze_env_auth_kwarg_exfil(src, relpath):
                loc = f"{relpath}:{af.lineno}"
                items.append({
                    "finding_id": af.rule,
                    "target": redact(skill_name),
                    "redacted_evidence": redact(f"{skill_name}: {af.reason} ({loc})"),
                    "engine_disposition": UNKNOWN,
                    "question": _question_for(af.rule),
                    "verdict_schema": _VERDICT_SCHEMA,
                })
    return items


def _b62_items(ctx) -> list[dict]:
    """Thin adapter over sar.build_sars(ctx): one packet item per B62
    capability-intent mismatch. build_sars already redacts every string field.
    """
    items: list[dict] = []
    for sar in build_sars(ctx):
        mismatch_evidence = "; ".join(m["evidence"] for m in sar["mismatches"])
        items.append({
            "finding_id": "B62",
            "target": sar["skill"],
            "redacted_evidence": redact(mismatch_evidence) if mismatch_evidence else sar["question"],
            "engine_disposition": WARN,
            "question": sar["question"],
            "verdict_schema": _VERDICT_SCHEMA,
        })
    return items


# --------------------------------------------------------------------------- public API

def _is_borderline(f) -> bool:
    """True for an unsuppressed finding the judge packet offers to the host agent:
    every UNKNOWN, plus WARN results with a documented false-negative-prone history
    (_FN_PRONE_WARN_IDS). Factored out so build_ignore_proposals (C-253) can only
    ever consider exactly the same population build_judge_packet already showed the
    judge — it must never propose suppressing a finding the judge never saw, and by
    construction (UNKNOWN/WARN only) it can never even reach a FAIL-status finding.
    """
    return not getattr(f, "suppressed", False) and (
        f.status == UNKNOWN or (f.status == WARN and f.id in _FN_PRONE_WARN_IDS)
    )


def build_judge_packet(ctx, findings) -> list[dict]:
    """Assemble the judge packet from a completed audit() pass.

    Reads ctx.installed_skill_py (for the recovered-taint and env-auth-kwarg passes),
    re-derives B62 mismatches via sar.build_sars(ctx), and scans the already-computed
    ``findings`` list for unsuppressed UNKNOWN results and unsuppressed WARN
    results in _FN_PRONE_WARN_IDS. Does not re-run any check and never alters a
    Finding's status/severity/score. Deterministic: same inputs always sort to
    the same output order, regardless of dict-iteration order upstream.
    """
    items: list[dict] = [_item_from_finding(f) for f in (findings or []) if _is_borderline(f)]

    items.extend(_b62_items(ctx))
    items.extend(_recover_dropped_taint(ctx))
    items.extend(_env_auth_kwarg_items(ctx))

    items.sort(key=lambda d: (d["finding_id"], d["target"], d["redacted_evidence"]))
    return items


def render_judge_packet_json(ctx, findings, *, version: str) -> str:
    """Return the standalone ``--judge-packet`` JSON artifact as a string."""
    payload = {
        "tool": "clawseccheck",
        "version": version,
        "judgePacket": build_judge_packet(ctx, findings),
    }
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- --judged consumer (F-115)

# A --judged payload larger than this is refused outright (bounded/defensive
# parsing of untrusted input -- see CLAUDE.md 2). Well past any real judge
# panel's output for one audit's borderline band.
_MAX_VERDICTS_BYTES = 2_000_000

_VALID_VERDICTS = frozenset({"SAFE", "SUSPICIOUS", "DANGEROUS"})

_PRIORITY_BY_VERDICT = {
    "DANGEROUS": "treat as high priority",
    "SUSPICIOUS": "worth a closer look",
    "SAFE": "likely benign",
}


def _parse_verdicts(raw: str) -> dict:
    """Defensively parse ``--judged``'s untrusted input JSON into a
    ``{(finding_id, target): {"verdict": ..., "votes": ...}}`` map.

    Bounded and never raises: an oversized payload, malformed JSON, the wrong
    shape, or an unrecognized verdict value each just drop that entry (or the
    whole parse) rather than error -- this data is advisory-only and must
    never be able to crash or otherwise perturb the audit itself.
    """
    if not isinstance(raw, str) or len(raw.encode("utf-8", "surrogatepass")) > _MAX_VERDICTS_BYTES:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    entries = data.get("verdicts")
    if not isinstance(entries, list):
        return {}
    out: dict = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        fid, target = entry.get("finding_id"), entry.get("target")
        verdict = entry.get("verdict")
        if not (isinstance(fid, str) and isinstance(target, str) and verdict in _VALID_VERDICTS):
            continue
        votes = entry.get("votes")
        out[(fid, target)] = {"verdict": verdict, "votes": votes if isinstance(votes, dict) else None}
    return out


def _annotate(engine_disposition: str, entry: dict | None) -> str:
    """Plain-language re-rank line for one packet item, e.g. "engine: WARN
    ... judges: 3/3 DANGEROUS -> treat as high priority". ``entry`` is None
    when no verdict was submitted for this item.
    """
    if entry is None:
        return "not yet reviewed by a judge"
    verdict = entry["verdict"]
    votes = entry.get("votes")
    judges_desc = f"judge: {verdict}"
    if isinstance(votes, dict):
        try:
            total = sum(int(v) for v in votes.values())
            hit = int(votes.get(verdict, 0))
        except (TypeError, ValueError):
            total = 0
        if total > 0:
            judges_desc = f"judges: {hit}/{total} {verdict}"
    priority = _PRIORITY_BY_VERDICT.get(verdict, "worth a closer look")
    return f"engine: {engine_disposition} · {judges_desc} → {priority}"


def _second_opinion(ctx, findings, verdicts_map: dict) -> list[dict]:
    """One row per current judge-packet item, annotated with any submitted
    verdict. Items nobody judged yet still appear, marked unreviewed -- the
    panel shows the whole borderline band, not just what came back judged.
    """
    items = []
    for item in build_judge_packet(ctx, findings):
        entry = verdicts_map.get((item["finding_id"], item["target"]))
        items.append({
            "finding_id": item["finding_id"],
            "target": item["target"],
            "engine_disposition": item["engine_disposition"],
            "judge_verdict": entry["verdict"] if entry else None,
            "annotation": _annotate(item["engine_disposition"], entry),
        })
    return items


def render_judged_json(ctx, findings, score, *, verdicts_raw: str, risk=None) -> str:
    """``--judged``: render the standard ``--json`` payload UNCHANGED (its
    score/grade/findings are byte-identical to a plain --json run on the same
    inputs -- tests/test_adjudication.py enforces this against an adversarial
    all-DANGEROUS verdict set) plus one added key, ``secondOpinion``: an
    advisory panel built from the host's already-majority-voted judge-panel
    verdicts (SKILL.md's "Judge-panel fan-out" section). A verdict can only
    annotate an existing finding; it can never alter score, grade, or the
    findings list itself.
    """
    from .report import render_json  # noqa: PLC0415 -- lazy import mirrors sar.py's precedent

    base = json.loads(render_json(findings, score, risk=risk, ctx=ctx))
    base["secondOpinion"] = _second_opinion(ctx, findings, _parse_verdicts(verdicts_raw))
    return json.dumps(base, ensure_ascii=True, indent=2)


# --------------------------------------------------------------------------- --propose-ignore (C-253)

# C-253 -- "judge as noise-remover on the user's OWN config." This does NOT gain any
# new suppression authority: it only ever proposes entries for findings that were
# already offered to the judge via build_judge_packet (_is_borderline), i.e. UNKNOWN
# or FN-prone-WARN only -- a FAIL-status finding (the only kind that can cap the
# score) can never be selected here, structurally, regardless of what a verdicts
# file claims. And even for a proposal that IS applied, baseline.py's existing
# suppression + report.surfaced_despite_suppression split already guarantees a
# score-capping CRITICAL/HIGH FAIL or a SENSITIVE_SUPPRESSED_IDS id (e.g. WARN-status
# B13) is still surfaced -- this module adds no new bypass of that rule. Nothing is
# EVER written here: --propose-ignore only renders JSON; the separate, confirmation-
# gated --apply-ignore-proposals (cli.py) is the only path that writes, and even that
# can only write exactly what was already proposed.


def build_ignore_proposals(findings, verdicts_map: dict) -> list[dict]:
    """One entry per borderline finding the judge panel verdicted SAFE.

    *verdicts_map* is the same ``{(finding_id, target): {"verdict": ..., "votes":
    ...}}`` shape ``_parse_verdicts`` returns for ``--judged`` -- this is the same
    verdicts file, read the same way; a SAFE verdict here is treated as "this
    finding is benign in context, propose suppressing it" rather than merely
    annotated. Only ``_is_borderline`` findings are ever considered (see module
    note above). Deterministic ordering, same convention as build_judge_packet.

    C-135 (2026-07-22): several _FN_PRONE_WARN_IDS checks (B100, B65, B66, B99,
    B90, B102, B154, B156, ...) emit ONE Finding aggregating a hit per installed
    skill -- one evidence entry per skill, but a SINGLE fingerprint over the whole
    Finding.detail. _target_from_evidence only ever surfaces the FIRST evidence
    entry's name, so a judge reviewing "target A" cannot see, and cannot scope its
    verdict to exclude, skills B/C/... bundled into the same Finding. Proposing a
    suppression there would suppress the WHOLE aggregate -- every bundled skill,
    not just the one reviewed -- on a verdict that only ever covered one of them.
    A finding with more than one evidence entry is therefore never proposed here;
    baseline.py's suppression granularity (one fingerprint per Finding) cannot
    safely represent "safe for this target only" in that shape, and offering an
    entry anyway would silently widen what a "SAFE" verdict actually covers.
    """
    proposals: list[dict] = []
    for f in findings or []:
        if not _is_borderline(f):
            continue
        if len(f.evidence or []) > 1:
            continue
        target = _target_from_evidence(f)
        entry = verdicts_map.get((f.id, target))
        if entry is None or entry.get("verdict") != "SAFE":
            continue
        proposals.append({
            "entry": fingerprint(f),
            "finding_id": f.id,
            "target": target,
            "votes": entry.get("votes"),
        })
    proposals.sort(key=lambda d: (d["finding_id"], d["target"]))
    return proposals


def render_ignore_proposals_json(findings, *, verdicts_raw: str, version: str) -> str:
    """Return the standalone ``--propose-ignore`` JSON artifact as a string.

    Read-only: this function never touches disk. Applying a proposal is a
    separate, confirmation-gated step (``--apply-ignore-proposals``, cli.py).
    """
    proposals = build_ignore_proposals(findings, _parse_verdicts(verdicts_raw))
    payload = {
        "tool": "clawseccheck",
        "version": version,
        "proposedIgnoreEntries": proposals,
        "note": (
            "PROPOSED ONLY -- nothing was written by this command. A score-capping "
            "CRITICAL/HIGH FAIL or a sensitive check id is never hidden by these "
            "entries even once applied (see report.surfaced_despite_suppression), "
            "and any applied entry changes .clawseccheckignore, which --monitor "
            "already flags as drift. Review each line, then either add it to "
            ".clawseccheckignore yourself or re-run with --apply-ignore-proposals "
            "against this output saved to a file."
        ),
    }
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- --vet-judge-packet / --vet-judged (C-254)

# C-254 -- "escalate-only on untrusted third-party content (--vet)." Authority here
# is scoped by CONTENT PROVENANCE, not direction (the organising principle behind
# both C-253 and this module): a --vet target is untrusted third-party content, so
# a judge reviewing it may only ESCALATE a finding's status, never lower it. This
# is the OPPOSITE rule from C-253's noise-remover above, which may only suppress --
# deliberately: the two are not the same mechanism with a direction flag toggled.
# On untrusted content the attacker's goal is "say it's clean," so a judge that is
# structurally incapable of downgrading buys a successful prompt injection against
# it nothing -- the worst it can achieve is a verdict at least as severe as the
# deterministic engine already produced.
#
# Escalation is monotonic BY CONSTRUCTION (_escalated_status), not by convention:
# the only two possible transitions are UNKNOWN -> WARN (a "SUSPICIOUS" verdict)
# and {UNKNOWN, WARN} -> FAIL (a "DANGEROUS" verdict) -- there is no code path that
# ever returns a status ranked below the finding's current one, for ANY verdict
# value including a malformed/adversarial one (which falls through to "no change").

_ESCALATION_TARGET = {"SUSPICIOUS": WARN, "DANGEROUS": FAIL}


def _escalated_status(current_status: str, verdict: str | None) -> str | None:
    """None when nothing should change; otherwise the new status, which is
    always higher-or-equal to *current_status*. *current_status* is always
    UNKNOWN or WARN here (the _is_borderline population this is only ever
    called against): a "SUSPICIOUS" verdict escalates an UNKNOWN to WARN but is
    a no-op on an already-WARN finding (WARN is already that rank -- nothing to
    raise); a "DANGEROUS" verdict always escalates to FAIL, the ceiling. "SAFE",
    an unrecognized verdict, or no submitted verdict at all changes nothing.
    """
    target = _ESCALATION_TARGET.get(verdict)
    if target is None:
        return None
    if target == WARN and current_status != UNKNOWN:
        return None
    return target


def _vet_pool(engine_output) -> list:
    """Flatten a vet engine's return into a single finding pool, the same way
    dossier._normalize_pool does (kept independent rather than importing
    dossier's private helper -- see module note): vet_mcp returns a list
    already; vet_skill/vet_plugin return one primary Finding carrying
    ``.ring_findings`` -- crucially, for a single-signal vet the ENTIRE result
    often rides on the primary alone (``.ring_findings`` empty), so a judge
    packet built from ``.ring_findings`` alone would miss it. Both must be
    considered.
    """
    if isinstance(engine_output, list):
        return list(engine_output)
    return [engine_output, *getattr(engine_output, "ring_findings", [])]


def build_vet_judge_packet(engine_output) -> list[dict]:
    """--vet-judge-packet: the borderline band of a SINGLE vet target's own
    findings (``vet_skill``/``vet_plugin``'s primary Finding plus its
    ``.ring_findings``) -- same shape and ``_is_borderline`` predicate as
    build_judge_packet, but scoped to one target's own findings rather than the
    user's full audit. Does not include the B62/recovered-taint/env-auth-kwarg
    sources build_judge_packet adds for the full-audit case -- those read
    ``ctx.installed_skill_py`` across every installed skill, not one vet target.
    """
    return [_item_from_finding(f) for f in _vet_pool(engine_output) if _is_borderline(f)]


def render_vet_judge_packet_json(engine_output, *, target: str, version: str) -> str:
    """Return the standalone ``--vet-judge-packet`` JSON artifact as a string."""
    payload = {
        "tool": "clawseccheck",
        "version": version,
        "target": target,
        "judgePacket": build_vet_judge_packet(engine_output),
    }
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)


def _escalate_finding(f, verdicts_map: dict):
    """Return *f* unchanged, or a NEW copy (``dataclasses.replace``) with its
    status escalated per ``_escalated_status``. Nothing is mutated in place.
    The escalation is attributed in ``detail`` so a reader can tell a judge,
    not the deterministic engine, raised it.
    """
    if not _is_borderline(f):
        return f
    entry = verdicts_map.get((f.id, _target_from_evidence(f)))
    verdict = entry.get("verdict") if entry else None
    new_status = _escalated_status(f.status, verdict)
    if new_status is None:
        return f
    return dc_replace(
        f, status=new_status,
        detail=f"[escalated by host-agent judge: {verdict}] {f.detail}",
    )


def escalate_vet_output(engine_output, verdicts_raw: str):
    """``--vet-judged``: return a NEW engine_output, same shape as *engine_output*
    (one primary Finding with ``.ring_findings``, or a list), with every
    ``_is_borderline`` entry -- primary INCLUDED, not just ring_findings, since a
    single-signal vet's entire result is often the primary alone -- escalated per
    ``_escalate_finding``. ``build_profile`` is then re-run UNCHANGED on this
    output; it re-derives ``overall_status``/``score``/``grade`` from the pool the
    NORMAL way. This function invents no new axis-rollup logic of its own; it
    only ever hands ``build_profile`` a pool where a finding can rank higher,
    never lower, than the deterministic engine already ranked it.

    ``verdicts_raw`` is parsed exactly like ``--judged``'s (2 MB bound, defensive
    against malformed/wrong-shaped/garbage input -- see ``_parse_verdicts``).
    """
    verdicts_map = _parse_verdicts(verdicts_raw)
    if isinstance(engine_output, list):
        return [_escalate_finding(f, verdicts_map) for f in engine_output]
    escalated_primary = _escalate_finding(engine_output, verdicts_map)
    escalated_ring = [
        _escalate_finding(f, verdicts_map)
        for f in getattr(engine_output, "ring_findings", [])
    ]
    return dc_replace(escalated_primary, ring_findings=escalated_ring)
