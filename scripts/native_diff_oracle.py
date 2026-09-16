#!/usr/bin/env python3
"""C-415 — differential-vs-native recall oracle.

Recall (false negatives), not false positives, is this project's repeatedly-confirmed
weak axis. `clawseccheck/native.py` already runs the user's own `openclaw security
audit --json` and folds its findings into a normal report (`run_native_audit`) — but
nothing ever DIFFS the two sides. This script does exactly that, offline:

    python3 scripts/native_diff_oracle.py [--home PATH] [--json]

  * native fires, we don't  -> a candidate FALSE NEGATIVE (the point of this tool)
  * we fire, native doesn't -> our differentiator (evidence for positioning claims)
  * both fire               -> agreement, no action

DEV-TIME TOOL, NOT A SHIPPED CHECK. It shells the vendor `openclaw` binary, which is
fine for an offline dev harness and forbidden for the runtime audit (Golden Rule:
stdlib-only, local, read-only) — this lives in `scripts/`, is never imported by
`clawseccheck/`, and is never added to `CHECKS`.

REUSES, DOES NOT BYPASS, `native.py`'s own guard: `_untrusted_exec_reason` (B-014 —
refuses to exec an `openclaw` binary whose install path is group/world-writable,
since a local user could have swapped it) gates the subprocess call here exactly as
it gates `run_native_audit`'s own. `_parse`/`_extract` (the JSON-shape tolerant
reader) are reused too, rather than re-implemented, so this script cannot silently
read the vendor's output differently than the shipped fold-in does.

WHY THIS DOES NOT CALL `run_native_audit` DIRECTLY. It was tried first, and it does
not work for a diff: `native._to_finding`'s id extraction is
`_pick(d, "id", "check", "rule", ..., default="native")`, but the real `--json`
output's per-finding key is `checkId` — verified against a live run on this machine,
2026-09-16, openclaw 2026.9.4. None of `_pick`'s three keys match `checkId`, so EVERY
finding `run_native_audit` folds in collapses to the same synthetic id `N:native`,
indistinguishable from every other native finding. That makes `NativeResult.findings`
useless as a native-side IDENTITY for a diff. This script therefore re-parses the raw
JSON itself (via the same `_parse`/`_extract` helpers) and reads `checkId` directly,
rather than going through `_to_finding`'s lossy conversion. The `_pick` gap is a real,
separately-fixable one-line bug in shipped code (changes runtime behavior, which this
task's own DoD says not to do here) — filed as CLAWSECCHECK-B-818, not fixed in this
change.

MATCHING IS A HAND-CURATED REGISTRY, NOT FUZZY TEXT MATCHING — per this task's own
"a mapping table will be needed; start coarse ... refine later." `NATIVE_CHECKID_NOTES`
below classifies every native `checkId` this script has actually been run against and
a human has actually read:
  * "informational"    — a descriptive summary block, not an actionable finding
  * "covered"          — grounded: cite the ClawSecCheck id(s) that already cover it
  * "gap_confirmed"    — grounded: our own audit was run against the SAME config and
                          genuinely produces no equivalent finding (a real FN)
  * "related_not_same" — a nearby check exists but covers a materially different
                          condition; not resolved, needs a human decision
An UNREGISTERED checkId is always reported as `needs_triage` — never silently treated
as covered. A coarse automatic hint (token overlap between the native checkId/title and
our own findings' title+detail) is computed and shown alongside every unregistered
checkId, to speed up triage — but it is a HINT, never a verdict; nothing here promotes
a text-overlap hit to "covered" without a human adding it to the registry.

CAVEATS THIS SCRIPT RESPECTS (per the task description):
  * a missing/timed-out/unparseable native side is reported as UNKNOWN coverage, never
    read as "we're complete" — see `--json`'s `native_status`.
  * cross-version: `checkId`s are OpenClaw's own vocabulary and can rename across
    releases; re-run this after an OpenClaw upgrade (the openclaw-upgrade protocol is
    the natural place to add that step — not done here, flagged in the Pulse task).

Offline except for the one guarded, read-only, --json, no-shell `openclaw security
audit` invocation. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from clawseccheck import audit  # noqa: E402
from clawseccheck.native import _extract, _parse, _untrusted_exec_reason  # noqa: E402

EXIT_OK = 0
EXIT_FN_FOUND = 1
EXIT_CANNOT_RUN = 2

# ---------------------------------------------------------------------- registry
#
# Grounded by hand against a real `openclaw security audit --json` run on this
# machine (2026-09-16, openclaw 2026.9.4) and this project's own catalog. See the
# module docstring for what each classification means and the non-negotiable rule:
# an unregistered checkId is ALWAYS `needs_triage`, never silently `covered`.

INFORMATIONAL = "informational"
COVERED = "covered"
GAP_CONFIRMED = "gap_confirmed"
RELATED_NOT_SAME = "related_not_same"
NEEDS_TRIAGE = "needs_triage"

NATIVE_CHECKID_NOTES = {
    "summary.attack_surface": (
        INFORMATIONAL, (),
        "a descriptive block (groups/tools/hooks posture), always present, not a "
        "pass/fail finding — nothing to cover.",
    ),
    "gateway.trusted_proxies_missing": (
        GAP_CONFIRMED, (),
        "native warns whenever gateway.bind is loopback AND gateway.trustedProxies is "
        "empty — a forward-looking nudge, independent of whether "
        "gateway.allowRealIpFallback is enabled. Our only trustedProxies-empty check, "
        "C032, is GATED on allowRealIpFallback being enabled first (checks/_config.py "
        "check_proxy_header_forging) — verified live: on a real config with "
        "allowRealIpFallback unset, C032 reports PASS ('Real-IP fallback is not "
        "enabled...') while native still WARNs. A genuine recall gap: nothing nudges "
        "the user to set trustedProxies BEFORE they put the gateway behind a reverse "
        "proxy, only after allowRealIpFallback is already on.",
    ),
    "security.trust_model.multi_user_heuristic": (
        RELATED_NOT_SAME, ("B26",),
        "native's heuristic combines a channel groupPolicy=allowlist-with-targets "
        "signal with non-fully-sandboxed exec/process tool exposure, to warn that the "
        "personal-assistant trust model may not hold. B26 (Untrusted-context "
        "exposure) fires on a related but DIFFERENT condition (contextVisibility "
        "injecting untrusted quoted history into the model) — real overlap in subject "
        "(channel trust) but not in the specific claim. Not resolved here; needs a "
        "deliberate decision on whether to extend an existing check or add a new one.",
    ),
}

_STOPWORDS = frozenset({
    "the", "and", "for", "are", "not", "with", "this", "that", "your", "you", "its",
    "security", "audit", "check", "checks", "finding", "findings", "config", "openclaw",
    "gateway", "default", "enabled", "disabled", "set", "value", "when", "into",
})


def _tokenize(text: str) -> "set[str]":
    return {
        w for w in re.split(r"[^a-z0-9]+", (text or "").lower())
        if len(w) > 2 and w not in _STOPWORDS
    }


def _coarse_hint(native_checkid: str, native_title: str, our_findings) -> list:
    """`[(our_id, our_status, shared_tokens), ...]`, sorted by overlap size — a HINT
    for human triage, never a verdict (see module docstring)."""
    native_tokens = _tokenize(native_checkid.replace(".", " ").replace("_", " ")
                              + " " + native_title)
    hits = []
    for f in our_findings:
        our_tokens = _tokenize((f.title or "") + " " + (f.detail or ""))
        overlap = native_tokens & our_tokens
        if overlap:
            hits.append((f.id, f.status, sorted(overlap)))
    hits.sort(key=lambda h: -len(h[2]))
    return hits


# ---------------------------------------------------------------------- native side

def run_native_raw(openclaw_bin: str = "openclaw", timeout: int = 60):
    """`(status, raw_finding_dicts, note)`. Mirrors `native.run_native_audit`'s own
    guard/invocation exactly (same argv, same B-014 guard, same timeout) but keeps the
    RAW per-finding dict — `checkId` intact — instead of native's lossy `_to_finding`
    conversion (see module docstring for why that conversion cannot be reused here)."""
    exe = shutil.which(openclaw_bin)
    if not exe:
        return "not_found", [], (
            "openclaw CLI not on PATH — this oracle needs a real install to diff "
            "against."
        )
    unsafe = _untrusted_exec_reason(exe)
    if unsafe:
        return "skipped", [], (
            f"openclaw at {os.path.realpath(exe)} not run: {unsafe}."
        )
    try:
        proc = subprocess.run(
            [exe, "security", "audit", "--json"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout", [], f"openclaw security audit timed out after {timeout}s"
    except OSError as exc:
        return "error", [], f"could not run openclaw: {exc}"

    data = _parse(proc.stdout)
    if data is None:
        if proc.returncode != 0:
            note = f"openclaw security audit exited {proc.returncode}"
            if proc.stderr:
                note += f": {proc.stderr.strip()[:300]}"
            return "error", [], note
        return "error", [], "could not parse openclaw security audit JSON output"
    return "ok", _extract(data), f"{len(_extract(data))} raw native finding(s)"


# ---------------------------------------------------------------------- diff

def diff_against_native(home: str, openclaw_bin: str = "openclaw", timeout: int = 60):
    """The full three-way diff for one config. Returns a plain dict, JSON-serializable."""
    native_status, native_raw, native_note = run_native_raw(openclaw_bin, timeout)

    _ctx, our_findings, _score = audit(home, include_native=False)

    native_only = []
    matched = []
    for d in native_raw:
        checkid = str(d.get("checkId") or d.get("id") or d.get("check") or "unknown")
        title = str(d.get("title") or "")
        severity = str(d.get("severity") or "")
        registered = NATIVE_CHECKID_NOTES.get(checkid)
        if registered:
            cls, our_ids, reason = registered
            row = {
                "checkId": checkid, "title": title, "severity": severity,
                "classification": cls, "our_ids": list(our_ids), "reason": reason,
            }
            (matched if cls in (INFORMATIONAL, COVERED, RELATED_NOT_SAME) else native_only).append(row)
        else:
            hint = _coarse_hint(checkid, title, our_findings)
            native_only.append({
                "checkId": checkid, "title": title, "severity": severity,
                "classification": NEEDS_TRIAGE,
                "coarse_hint": [{"id": i, "status": s, "shared_tokens": t}
                               for i, s, t in hint[:5]],
                "reason": "unregistered checkId — add it to NATIVE_CHECKID_NOTES after "
                          "a human reads the finding and this project's coverage.",
            })

    ours_only = sorted(
        f.id for f in our_findings
        if f.status not in ("PASS",) and not getattr(f, "suppressed", False)
    )

    return {
        "home": str(Path(home).expanduser()),
        "native_status": native_status,
        "native_note": native_note,
        "native_raw_count": len(native_raw),
        "native_only_or_needs_triage": native_only,
        "matched_or_classified": matched,
        # Coarse, per this task's own DoD ("by config path / subject, refine later"):
        # every fired (non-PASS, unsuppressed) id on our side, for a human to eyeball
        # against native_only — not a per-finding cross-match.
        "ours_fired": ours_only,
    }


# ---------------------------------------------------------------------- rendering

def render(result: dict) -> str:
    lines = [
        f"config: {result['home']}",
        f"native: {result['native_status']} — {result['native_note']}",
    ]
    if result["native_status"] != "ok":
        lines.append(
            "\nUNKNOWN coverage: the native side did not run, so this is NOT a "
            "recall-complete comparison — never read a missing native side as "
            "'no gaps found'."
        )
        return "\n".join(lines)

    lines.append(f"our findings fired (non-PASS, unsuppressed): {len(result['ours_fired'])}")
    lines.append("")
    for row in result["matched_or_classified"]:
        lines.append(
            f"  {row['classification']:16} {row['checkId']:42} "
            f"{('-> ' + ','.join(row['our_ids'])) if row['our_ids'] else ''}"
        )
    for row in result["native_only_or_needs_triage"]:
        marker = "GAP" if row["classification"] == GAP_CONFIRMED else row["classification"]
        lines.append(f"  {marker:16} {row['checkId']:42} [{row['severity']}] {row['title']}")
        if row.get("coarse_hint"):
            for h in row["coarse_hint"][:3]:
                lines.append(f"      hint: {h['id']} ({h['status']}) shares {h['shared_tokens']}")
    gaps = [r for r in result["native_only_or_needs_triage"]
            if r["classification"] in (GAP_CONFIRMED, NEEDS_TRIAGE)]
    if gaps:
        lines.append(
            f"\n{len(gaps)} native finding(s) with no confirmed ClawSecCheck coverage "
            "(gap_confirmed + needs_triage) — see above."
        )
    else:
        lines.append("\nNo uncovered native findings on this config.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="native_diff_oracle.py",
        description="C-415: diff ClawSecCheck's findings against openclaw's own "
                    "`security audit --json`, offline, to surface recall gaps.",
    )
    ap.add_argument("--home", default="~/.openclaw")
    ap.add_argument("--openclaw-bin", default="openclaw")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    result = diff_against_native(args.home, args.openclaw_bin, args.timeout)
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else render(result))

    if result["native_status"] != "ok":
        return EXIT_CANNOT_RUN
    gaps = [r for r in result["native_only_or_needs_triage"]
            if r["classification"] in (GAP_CONFIRMED, NEEDS_TRIAGE)]
    return EXIT_FN_FOUND if gaps else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
