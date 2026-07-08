"""Behavioral trajectory audit — post-hoc sequence detectors over observed tool-call
order (E-032 v1, `--behavioral`). Layer 3, same "post-hoc/self-test" shelf as
`trajaudit.py`/`redteam.py`/`dryrun.py`.

Everything else in ClawSecCheck answers "what could the agent do" (static config +
skill-source audit). This module answers the complementary question: "what did the
agent actually DO" — reconstructed from OpenClaw's trajectory sidecar
(`agents/*/sessions/*.trajectory.jsonl`, schema grounded in
`docs/research/openclaw-schema-recon.md` §9.1), proven by the log rather than inferred
from declared capability.

§8 privacy boundary: reads ONLY `trajectory.read_events()`'s metadata — `type`, `name`,
`ts`, `seq`, `sessionId`, `turnId`, `threadId`, `outcome`. NEVER reads
`arguments`/`output`/`result`/`contentItems` (the sensitive call/return payloads).

Findings are WARN-only, `scored=False` (Golden Rule #5) — a heuristic on observed VERB
NAMES classified by role (ingress/sensitive/egress), not on the untouched payload
content, so confidence stays MEDIUM even though "this verb ran" itself is log-observed
HIGH-confidence fact. T1/T2 never run as part of the main `audit()`/CHECKS list or the
A-F score — only through `--behavioral`, mirroring `--analyze-trajectory`'s own
`trajaudit.py` scope.
"""
from __future__ import annotations

from . import attest
from .catalog import PASS, WARN
from .checks import INPUT_TOOL_HINTS, _finding
from .trajectory import read_events

# C-170 adversarial pass found the naive "reuse A1's three hint tuples verbatim"
# design (still used for `INPUT_TOOL_HINTS` below) has two real bugs when applied
# per-VERB instead of per-CONFIG (A1's coarse "is any such tool present anywhere"
# check tolerates broad hints; a per-call sequence claim does not):
#
# 1. FALSE NEGATIVE (the canonical exfil path, invisible): `INPUT_TOOL_HINTS`
#    contains "email"/"gmail" for the ingress leg, and was checked FIRST — so an
#    EGRESS verb like "gmail_send"/"send_email" matched "gmail"/"email" and got
#    swallowed into "ingress", never reaching the egress check at all. Fixed by
#    classifying egress via `attest.classify_verb()` (B43's own action-verb-
#    anchored blast-radius taxonomy — "send"/"forward"/"post"/"webhook"/... —
#    already grounded and battle-tested) FIRST, before the ingress hints get a
#    chance to shadow it.
# 2. FALSE POSITIVE (routine workflows): the shared `SENSITIVE_TOOL_HINTS`
#    includes bare "files"/"fs_read", broad enough to match ANY filesystem verb
#    ("list_files", "read_files") — so "web_search -> list_files -> slack_send"
#    (an entirely mundane combo) read as a proven lethal-trifecta WARN. Fixed with
#    `_T_SENSITIVE_HINTS` below: a stricter LOCAL subset for T1/T2's per-verb
#    precision need — genuinely sensitive stores/credentials only, dropping the
#    bare filesystem terms. Deliberately NOT edited in `checks/_shared.py` itself
#    (that tuple's broader recall is correct at A1's coarse, whole-config grain;
#    narrowing it there would weaken A1, a change out of this check's scope).
_T_SENSITIVE_HINTS = ("db", "sql", "postgres", "supabase", "secret", "credential", "vault")


def _classify_verb_role(name: str | None) -> str | None:
    """Classify one tool verb as "ingress" / "sensitive" / "egress" / None.

    Order matters (see the C-170 note above): egress is checked FIRST via
    `attest.classify_verb()` so an egress action verb is never shadowed by an
    ingress product-name hint; only then ingress (`INPUT_TOOL_HINTS`, shared with
    A1); only then the tightened local sensitive-data hint set.
    """
    if not name:
        return None
    n = name.lower()
    if attest.classify_verb(n) in ("EGRESS", "EXEC"):
        return "egress"
    if any(h in n for h in INPUT_TOOL_HINTS):
        return "ingress"
    if any(h in n for h in _T_SENSITIVE_HINTS):
        return "sensitive"
    return None


def _sort_key(event: dict):
    """Deterministic (seq, ts) ordering key — events with a missing/non-int seq sort
    after those with one (so partial data never silently reorders known-good events)."""
    seq = event.get("seq")
    has_seq = isinstance(seq, int)
    return (0 if has_seq else 1, seq if has_seq else 0, str(event.get("ts") or ""))


def group_events_by_thread(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by `(sessionId, threadId-or-turnId)`, each group sorted by (seq, ts).

    C-170 adversarial finding: `seq` is a per-SESSION counter (§9.1 recon), not
    globally unique — pooling events across multiple trajectory files/sessions
    keyed by bare `threadId`/`turnId` risked merging unrelated sessions that
    happen to share a thread/turn id (or both lack one) into a manufactured
    sequence. Scoping the key by `sessionId` first closes that: two events only
    group together if they're both the same session AND the same thread/turn.
    (If OpenClaw ever legitimately reuses one threadId across session restarts,
    this fails toward a missed detection, never a false one — the safe direction
    per Golden Rule #5.) The label shown in a finding uses the thread/turn id
    alone (`_group_label`) since that's what a reviewer greps the sidecar for.
    """
    groups: dict[str, list[dict]] = {}
    for ev in events:
        thread_or_turn = str(ev.get("threadId") or ev.get("turnId") or "")
        key = f"{ev.get('sessionId')}\x1f{thread_or_turn}"
        groups.setdefault(key, []).append(ev)
    for key in groups:
        groups[key].sort(key=_sort_key)
    return groups


def _group_label(group_key: str) -> str:
    """Human-facing label for a group key — the thread/turn id half only."""
    thread_or_turn = group_key.split("\x1f", 1)[-1]
    return thread_or_turn or "(no thread/turn id)"


def _disambiguated_labels(firing_keys: list[str]) -> list[str]:
    """Label each firing group_key, appending its session id ONLY where two
    different sessions collide on the same bare thread/turn label.

    C-180: OpenClaw's own default threadId ("th1") makes this collision
    realistic — two unrelated sessions both flagged the same "th1" rendered
    as two identical, indistinguishable labels with no way to tell which
    session's sidecar to actually go inspect. The common single-session case
    (the overwhelming majority) keeps the plain thread/turn-id-only label
    _group_label's own docstring says a reviewer greps for.
    """
    labels = [_group_label(k) for k in firing_keys]
    dupes = {lbl for lbl in labels if labels.count(lbl) > 1}
    out = []
    for key, lbl in zip(firing_keys, labels):
        if lbl in dupes:
            session_id = key.split("\x1f", 1)[0]
            out.append(f"{lbl} (session {session_id})")
        else:
            out.append(lbl)
    return out


# ---------------------------------------------------------------------------
# T1 — behavioral trifecta: ingress-verb -> sensitive-verb -> egress-verb, in that
# order (by seq/ts), within one thread.
# ---------------------------------------------------------------------------

def _t1_thread_trifecta(thread_events: list[dict]) -> bool:
    """True when this thread's events show ingress before sensitive before egress."""
    seen_ingress = False
    seen_sensitive_after_ingress = False
    for ev in thread_events:
        role = _classify_verb_role(ev.get("name"))
        if role == "ingress":
            seen_ingress = True
        elif role == "sensitive" and seen_ingress:
            seen_sensitive_after_ingress = True
        elif role == "egress" and seen_sensitive_after_ingress:
            return True
    return False


def check_behavioral_trifecta(groups: dict[str, list[dict]]) -> object:
    """T1 — behavioral trifecta, proven by the trajectory log (not declared capability).

    WARN — at least one thread shows an ingress-verb, then a sensitive-verb, then an
           egress-verb, in that order.
    PASS — threads present, no thread shows the ordered sequence.
    """
    firing_keys: list[str] = []
    for group_key, thread_events in groups.items():
        if _t1_thread_trifecta(thread_events):
            firing_keys.append(group_key)
    firing = _disambiguated_labels(firing_keys)

    if firing:
        detail = "; ".join(firing[:6]) + (f" (+{len(firing) - 6} more)" if len(firing) > 6 else "")
        return _finding(
            "T1",
            WARN,
            "Behavioral trifecta observed — an ingress verb, then a sensitive-data "
            f"verb, then an egress verb, ran in this order within a thread: {detail}.",
            "Review the trajectory sidecar for the named thread(s) manually. This is "
            "proof-by-log of the same pattern A1 flags by capability — untrusted input "
            "reached sensitive data and then left the agent, in one observed sequence.",
            firing[:6],
        )
    return _finding(
        "T1",
        PASS,
        "No thread shows an ingress -> sensitive -> egress verb sequence in the "
        "trajectory log.",
        "No action needed.",
    )


# ---------------------------------------------------------------------------
# T2 — outcome anomaly: fail -> fail -> success series on a sensitive verb, within one
# thread (from tool.result status/isError/success).
# ---------------------------------------------------------------------------

_T2_MIN_FAILURES = 2  # at least this many consecutive failures before the success


def _t2_thread_anomaly(thread_events: list[dict]) -> bool:
    """True when a sensitive-verb tool.result shows >=2 consecutive failures then a
    success, for the SAME verb, within this thread — conservative on purpose: an
    isolated failure (the overwhelming common case) never counts."""
    # Track a running fail-streak per verb name so an unrelated verb's success doesn't
    # reset a different verb's fail streak.
    streaks: dict[str, int] = {}
    for ev in thread_events:
        if ev.get("type") != "tool.result":
            continue
        name = ev.get("name")
        if _classify_verb_role(name) != "sensitive":
            continue
        outcome = ev.get("outcome")
        if outcome == "failed":
            streaks[name] = streaks.get(name, 0) + 1
        elif outcome == "success":
            if streaks.get(name, 0) >= _T2_MIN_FAILURES:
                return True
            streaks[name] = 0
        # outcome is None (ambiguous) — leave the streak untouched, never guessed.
    return False


def check_outcome_anomaly(groups: dict[str, list[dict]]) -> object:
    """T2 — outcome anomaly: repeated failure then success on a sensitive verb.

    WARN — a sensitive verb failed at least twice in a row, then succeeded, within one
           thread. Ambiguous by design (§8 — no error-class/message is read, only
           status/isError/success): this can mean persistence past an initial denial
           (e.g. permission/path probing), OR ordinary retry/backoff on a transient
           failure (rate limit, timeout) — the finding text says so explicitly rather
           than asserting the more alarming reading (C-170 adversarial finding).
    PASS — threads present, no such series found.
    """
    firing_keys: list[str] = []
    for group_key, thread_events in groups.items():
        if _t2_thread_anomaly(thread_events):
            firing_keys.append(group_key)
    firing = _disambiguated_labels(firing_keys)

    if firing:
        detail = "; ".join(firing[:6]) + (f" (+{len(firing) - 6} more)" if len(firing) > 6 else "")
        return _finding(
            "T2",
            WARN,
            "Outcome anomaly observed — a sensitive-data tool call failed at least "
            f"{_T2_MIN_FAILURES} times in a row and then succeeded, within a thread: "
            f"{detail}.",
            "Review the trajectory sidecar for the named thread(s) manually. This can "
            "mean persistence past an initial denial (e.g. permission/path probing) — "
            "or an ordinary retry/backoff on a transient failure (rate limit, timeout); "
            "the log's status/isError/success alone can't distinguish the two.",
            firing[:6],
        )
    return _finding(
        "T2",
        PASS,
        "No fail->fail->success series on a sensitive verb found in the trajectory log.",
        "No action needed.",
    )


def analyze(ctx, *, explicit_path: str | None = None) -> dict:
    """Run the v1 behavioral detectors (T1, T2) and return a result dict."""
    home = getattr(ctx, "home", None)
    events, meta = read_events(home, explicit_path=explicit_path)
    result = {
        "present": meta["present"],
        "files_scanned": meta["files_scanned"],
        "unknown_version": meta["unknown_version"],
        "truncated": meta["truncated"],
        "event_count": len(events),
        "thread_count": 0,
        "findings": [],
    }
    if not meta["present"]:
        return result

    groups = group_events_by_thread(events)
    result["thread_count"] = len(groups)
    result["findings"] = [
        check_behavioral_trifecta(groups),
        check_outcome_anomaly(groups),
    ]
    return result


def render_behavioral_analysis(ctx, *, explicit_path: str | None = None, ascii_only: bool = False) -> str:
    """Human-readable, §8-safe behavioral report for --behavioral."""
    r = analyze(ctx, explicit_path=explicit_path)
    warn = "[!]" if ascii_only else "⚠"
    ok = "[ok]" if ascii_only else "✓"
    q = "[?]" if ascii_only else "?"
    lines = ["Behavioral trajectory audit (post-hoc, read-only, metadata-only)"]

    if not r["present"]:
        lines.append(f"  {q} No trajectory sidecars found "
                     "(agents/*/sessions/*.trajectory.jsonl). Nothing to analyze — run on a "
                     "host where an OpenClaw agent has produced session trajectories.")
        return "\n".join(lines)

    lines.append(
        f"  scanned {r['files_scanned']} trajectory file(s), {r['event_count']} event(s) "
        f"across {r['thread_count']} thread(s)/turn(s)."
    )
    if r["unknown_version"]:
        lines.append(f"  {q} Some records used an unrecognised trajectory schema version — "
                     "results are INCOMPLETE (treat as UNKNOWN, not authoritative).")
    if r["truncated"]:
        lines.append(f"  {q} A trajectory file exceeded the per-file scan cap — the "
                     "unscanned remainder was never analyzed. Results are INCOMPLETE "
                     "(treat as UNKNOWN, not authoritative).")

    any_warn = False
    for f in r["findings"]:
        if f.status == WARN:
            any_warn = True
            lines.append(f"  {warn} {f.id} — {f.detail}")
            lines.append(f"      fix: {f.fix}")
        else:
            lines.append(f"  {ok} {f.id} — {f.detail}")

    if not any_warn:
        lines.append(f"  {ok} No behavioral anomalies found.")
    return "\n".join(lines)
