#!/usr/bin/env python3
"""Real-fleet false-positive gate: the counterweight to a benchmark-motivated change.

Golden Rule #5 forbids a false-positive FAIL on the user's real configs. A corpus
metric is the loud signal; the real fleet is the quiet one, and a detection change
justified by a corpus number is exactly the shape that overfits to the corpus and
regresses on real skills. This script makes the quiet signal cheap to check:

    python3 scripts/fleet_fp_gate.py snapshot        # 1) produce the real-fleet FAIL set
    python3 scripts/fleet_fp_gate.py compare         # 2) diff it against the baseline

`compare` exits non-zero on any FAIL (scope, target, check id) that is present now and
was absent from the recorded baseline. That is a hard blocker until diagnosed --
independent of what any corpus number did. A FAIL that DISAPPEARED is reported but
never blocks: this gate exists to catch new false positives, not to freeze coverage.

What it compares, and what it deliberately does not:

  * FAIL SETS, never scores. Adding a passing check raises the score without changing
    correctness, and a baseline's score is only meaningful for the commit that produced
    it. `score`/`grade` are recorded as context and can never affect the exit code.
  * Unsuppressed FAILs only -- what the user actually sees. The count of suppressed
    FAILs is recorded alongside, so a change that silently widens suppression is at
    least visible to a reader.
  * Only a snapshot where every check actually RAN. A check that crashes or overruns
    its wall-clock budget (C-159) degrades to an `ERR:<check>` UNKNOWN, which means a
    real FAIL can silently go missing -- observed live on this machine under parallel
    load, where a loaded run dropped a FAIL a quiet run reported. A snapshot carrying
    any degraded check is refused for comparison rather than compared anyway: a
    baseline recorded on a loaded machine would later report the recovered FAIL as
    "new" and block on a false alarm.
  * The DETERMINISTIC engine only. The host-agent judge path (--vet-judge-packet /
    --vet-judged) is out of scope here because its input is a host agent's verdict,
    which is not reproducible run-to-run; it has its own measured result (the judge
    can only ADD a WARN-capped prose finding on a real fleet with no borderline
    deterministic findings, and cannot reach FAIL without one).

Storage: the baseline lives in local state (~/.clawseccheck/), NOT in the repo. The
real fleet is one machine's installed software; a repo-committed baseline of it would
be wrong for every other checkout and would publish the machine's skill inventory.
Snapshot output carries no absolute paths -- skill directory NAMES and check ids only.

Local, read-only, offline: no network, no subprocess, nothing in the audited setup is
written. Native fold-in (`openclaw security audit`) is deliberately OFF -- it is the
one part of a normal CLI run that shells out, and a gate must not launch the audited
software. Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from clawseccheck import __version__, audit, vet_plugin, vet_skill  # noqa: E402
from clawseccheck.collector import skill_load_roots  # noqa: E402
from clawseccheck.safeio import secure_dir, secure_write_text  # noqa: E402

SCHEMA = 1

DEFAULT_HOME = "~/.openclaw"
DEFAULT_BASELINE = "~/.clawseccheck/fleet-fp-baseline.json"

# Exit codes. 2 (not 1) for a usage/plumbing failure so a caller can tell "the gate ran
# and found a new FAIL" apart from "the gate could not run" -- a missing baseline must
# never read as a pass.
EXIT_OK = 0
EXIT_NEW_FAIL = 1
EXIT_CANNOT_RUN = 2

# Directory names that live under a skill root but are not skills.
_SKIP_DIR_NAMES = frozenset({"node_modules", "__pycache__"})

# run_all gives a check that crashed (B-101 isolation) or overran its wall-clock budget
# (C-159) a synthetic UNKNOWN finding under this id prefix. Both mean the same thing for
# a gate: that check produced no verdict, so this snapshot is incomplete.
_DEGRADED_ID_PREFIX = "ERR:"


# --------------------------------------------------------------------------- discovery

def discover_targets(home):
    """Every real installed-skill directory the audit itself can see, as sorted
    ``(name, path)`` pairs.

    Uses ``collector.skill_load_roots`` -- the SAME root list the engine uses -- rather
    than a hand-written path list, so a root the tool learns about later is covered here
    without editing this script. Resolved-path de-duped (one physical dir vetted once,
    even when two roots alias it); dot-directories and build/vendor dirs are skipped.
    """
    home = Path(home).expanduser()
    found = {}
    seen_resolved = set()
    for root, _tier in skill_load_roots(home, {}, user_home=Path.home()):
        if not root.is_dir():
            continue
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            if child.name.startswith(".") or child.name in _SKIP_DIR_NAMES:
                continue
            try:
                key = child.resolve()
            except (OSError, ValueError, RuntimeError):
                key = child
            if key in seen_resolved:
                continue
            seen_resolved.add(key)
            found.setdefault(child.name, child)
    return sorted(found.items())


# --------------------------------------------------------------------------- FAIL set

def _is_unsuppressed_fail(f):
    return getattr(f, "status", None) == "FAIL" and not getattr(f, "suppressed", False)


def fail_rows(findings, *, scope, target=""):
    """Normalized FAIL rows for one finding pool.

    Deliberately narrow: scope, target NAME, check id, severity. No detail, no evidence,
    no path. Detail text is not stable run-to-run (it can embed live counts read off a
    growing log), and evidence can quote skill prose -- neither belongs in an artifact
    whose whole job is to be comparable across commits.
    """
    rows = [
        {"scope": scope, "target": target, "id": f.id, "severity": f.severity}
        for f in (findings or [])
        if _is_unsuppressed_fail(f)
    ]
    rows.sort(key=fail_key)
    return rows


def fail_key(row):
    """Identity of a FAIL for diffing. Severity is context, not identity: a severity
    re-grade is a deliberate catalog change, not a new false positive."""
    return (row["scope"], row["target"], row["id"])


def degraded_checks(findings):
    """Sorted ids of every check that produced no verdict in this pool -- a crash or a
    wall-clock-budget timeout. Non-empty means the snapshot is incomplete, not clean."""
    return sorted({
        f.id for f in (findings or [])
        if isinstance(getattr(f, "id", None), str) and f.id.startswith(_DEGRADED_ID_PREFIX)
    })


def _vet_pool(engine_output):
    """Flatten a vet engine's return the way every vet consumer does: a list is already
    a pool; a single primary Finding carries the rest on ``.ring_findings``, and for a
    single-signal vet the entire result often rides on the primary alone."""
    if isinstance(engine_output, list):
        return list(engine_output)
    return [engine_output, *getattr(engine_output, "ring_findings", [])]


def _home_label(home):
    """Stable, non-identifying label for the machine's fleet root. A snapshot must be
    comparable across commits on the same machine without carrying an absolute path."""
    try:
        resolved = str(Path(home).expanduser().resolve())
    except OSError:
        resolved = str(home)
    return hashlib.sha256(resolved.encode("utf-8", "replace")).hexdigest()[:12]


def build_snapshot(home=DEFAULT_HOME, *, vet_kind="skill"):
    """Run the audit over the real config and ``--vet`` over every discovered installed
    skill; return the snapshot dict.

    The rule is: gate exactly what a plain CLI run scores, minus only the one step a
    gate may not take.

    ``include_native=False``: the native fold-in is the one part of a normal CLI run
    that launches the audited software, and a gate must stay subprocess-free -- the
    sole deviation from "what the user sees".
    ``include_host=True``, ``include_sockets=True``, ``include_deptree=True``: each is
    on by default in the CLI (``cli.py`` passes ``include_deptree=not args.no_deptree``
    and ``include_sockets=not args.no_sockets``), so each is part of the real posture a
    user is graded on. ``include_deptree`` in particular runs B349 (CRITICAL) against the
    installed npm tree; leaving it off here left the fleet-FP gate structurally blind to
    the newest FAIL-capable check -- exactly the surface C-303 exists to guard. All three
    are read-only and subprocess-free, so a gate may take them.
    """
    home_path = Path(home).expanduser()
    _ctx, findings, score = audit(
        home_path, include_native=False, include_host=True,
        include_sockets=True, include_deptree=True,
    )

    rows = fail_rows(findings, scope="audit")
    suppressed = sum(
        1 for f in findings
        if getattr(f, "status", None) == "FAIL" and getattr(f, "suppressed", False)
    )
    degraded = list(degraded_checks(findings))

    targets = []
    for name, path in discover_targets(home_path):
        engine_output = vet_plugin(str(path)) if vet_kind == "plugin" else vet_skill(str(path))
        pool = _vet_pool(engine_output)
        rows.extend(fail_rows(pool, scope="vet", target=name))
        degraded.extend(degraded_checks(pool))
        targets.append(name)

    rows.sort(key=fail_key)
    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "home_label": _home_label(home_path),
        "targets": targets,
        # Any entry here means a check produced no verdict, so this snapshot cannot be
        # compared (see compare()). Not context -- a validity precondition.
        "degraded_checks": sorted(set(degraded)),
        # Context only -- never compared, never able to block. See the module note.
        "context": {
            "score": score.score,
            "grade": score.grade,
            "suppressed_fail_count": suppressed,
        },
        "fails": rows,
    }


# --------------------------------------------------------------------------- compare

def compare(snapshot, baseline):
    """Diff two snapshots' FAIL sets.

    ``new`` is the blocking set: a FAIL live now that the baseline did not carry. That
    includes every FAIL on a target the baseline never saw -- a newly installed skill
    is exactly where an overfitted regex shows up first, so it must not get a free pass.
    ``resolved`` is reported and never blocks.

    ``comparable`` is False when either side carries a degraded check. The diff is still
    computed (a reader may want to see it) but the caller must treat the run as "could
    not be measured", never as a pass -- a missing FAIL on one side is indistinguishable
    from a fixed one, and a recovered FAIL on the other is indistinguishable from a new
    one. Honest UNKNOWN over a confident guess.
    """
    now = {fail_key(r): r for r in snapshot.get("fails", [])}
    then = {fail_key(r): r for r in baseline.get("fails", [])}
    new = [now[k] for k in sorted(now.keys() - then.keys())]
    resolved = [then[k] for k in sorted(then.keys() - now.keys())]
    degraded = sorted(set(snapshot.get("degraded_checks") or [])
                      | set(baseline.get("degraded_checks") or []))
    return {
        "new_fails": new,
        "resolved_fails": resolved,
        "blocked": bool(new),
        "comparable": not degraded,
        "degraded_checks": degraded,
        "baseline_version": baseline.get("tool_version"),
        "snapshot_version": snapshot.get("tool_version"),
        "baseline_home_label": baseline.get("home_label"),
        "snapshot_home_label": snapshot.get("home_label"),
        "new_targets": sorted(set(snapshot.get("targets", [])) - set(baseline.get("targets", []))),
    }


def _load_baseline(path):
    """Read a recorded baseline, or exit ``EXIT_CANNOT_RUN``. Fails CLOSED: a missing,
    unreadable, or wrong-shaped baseline is never treated as an empty one -- that would
    silently turn every real FAIL into "expected"."""
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        print(
            f"error: no recorded baseline at {path} -- run "
            "`python3 scripts/fleet_fp_gate.py record` first, on a machine with the "
            "real fleet installed.",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_CANNOT_RUN) from None
    except ValueError:
        print(f"error: baseline at {path} is not valid JSON.", file=sys.stderr)
        raise SystemExit(EXIT_CANNOT_RUN) from None
    if not isinstance(data, dict) or not isinstance(data.get("fails"), list):
        print(f"error: baseline at {path} has no 'fails' array.", file=sys.stderr)
        raise SystemExit(EXIT_CANNOT_RUN)
    return data


def _write_json(path, payload):
    p = Path(path).expanduser()
    secure_dir(p.parent)
    secure_write_text(p, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return p


# --------------------------------------------------------------------------- rendering

def render_compare(result):
    lines = []
    if not result["comparable"]:
        lines.append(
            "CANNOT COMPARE: a check produced no verdict (crash or wall-clock budget) in "
            "the snapshot or the baseline: " + ", ".join(result["degraded_checks"])
            + "\nRe-run on a quieter machine. A degraded run hides FAILs, so neither a "
            "pass nor a block from it means anything."
        )
    if result["baseline_home_label"] != result["snapshot_home_label"]:
        lines.append(
            "WARNING: this baseline was recorded on a different fleet root -- the "
            "comparison below is not meaningful."
        )
    if result["baseline_version"] != result["snapshot_version"]:
        lines.append(
            f"note: baseline recorded for v{result['baseline_version']}, "
            f"current v{result['snapshot_version']}."
        )
    if result["new_targets"]:
        lines.append("note: target(s) not in the baseline: " + ", ".join(result["new_targets"]))
    for row in result["resolved_fails"]:
        lines.append(f"  resolved  {row['scope']:5} {row['target'] or '-':22} {row['id']}")
    for row in result["new_fails"]:
        lines.append(f"  NEW FAIL  {row['scope']:5} {row['target'] or '-':22} {row['id']}")
    if result["blocked"]:
        lines.append(
            f"\nBLOCKED: {len(result['new_fails'])} new real-fleet FAIL(s). Golden Rule #5: "
            "diagnose each one before shipping. A corpus metric improving does not "
            "excuse a new FAIL here."
        )
    else:
        lines.append("\nOK: no new real-fleet FAIL against the recorded baseline.")
    return "\n".join(lines)


def render_snapshot(snap):
    lines = [
        f"clawseccheck v{snap['tool_version']} -- real-fleet FAIL set ({snap['generated']})",
        f"targets: {', '.join(snap['targets']) or '(none found)'}",
        f"context: score={snap['context']['score']} grade={snap['context']['grade']} "
        f"suppressed_fails={snap['context']['suppressed_fail_count']} (never compared)",
        f"unsuppressed FAILs: {len(snap['fails'])}",
    ]
    if snap.get("degraded_checks"):
        lines.append(
            "DEGRADED (no verdict -- snapshot is incomplete): "
            + ", ".join(snap["degraded_checks"])
        )
    for row in snap["fails"]:
        lines.append(f"  {row['scope']:5} {row['target'] or '-':22} {row['id']:6} {row['severity']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- cli

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fleet_fp_gate.py",
        description="Real-fleet false-positive gate (Golden Rule #5 counterweight).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_snap = sub.add_parser("snapshot", help="produce the real-fleet FAIL set")
    p_snap.add_argument("--home", default=DEFAULT_HOME)
    p_snap.add_argument("--out", default=None, help="also write the snapshot JSON here")
    p_snap.add_argument("--json", action="store_true", help="print JSON instead of a table")

    p_cmp = sub.add_parser("compare", help="diff the FAIL set against the recorded baseline")
    p_cmp.add_argument("--home", default=DEFAULT_HOME)
    p_cmp.add_argument("--baseline", default=DEFAULT_BASELINE)
    p_cmp.add_argument("--snapshot", default=None,
                       help="reuse a snapshot JSON instead of running a fresh scan")
    p_cmp.add_argument("--json", action="store_true", help="print JSON instead of a table")

    p_rec = sub.add_parser("record", help="record the current FAIL set as the baseline")
    p_rec.add_argument("--home", default=DEFAULT_HOME)
    p_rec.add_argument("--baseline", default=DEFAULT_BASELINE)

    args = ap.parse_args(argv)

    if args.cmd == "snapshot":
        snap = build_snapshot(args.home)
        if args.out:
            _write_json(args.out, snap)
        print(json.dumps(snap, indent=2, sort_keys=True) if args.json else render_snapshot(snap))
        return EXIT_CANNOT_RUN if snap["degraded_checks"] else EXIT_OK

    if args.cmd == "record":
        snap = build_snapshot(args.home)
        if snap["degraded_checks"]:
            # A degraded baseline is worse than none: it silently omits a real FAIL, so
            # every later comparison reports that FAIL as "new" and blocks on a false
            # alarm. Refuse rather than write it.
            print(render_snapshot(snap))
            print(
                "\nrefusing to record: a check produced no verdict, so this FAIL set is "
                "incomplete. Re-run on a quieter machine.",
                file=sys.stderr,
            )
            return EXIT_CANNOT_RUN
        written = _write_json(args.baseline, snap)
        print(render_snapshot(snap))
        print(f"\nbaseline recorded: {written}")
        return EXIT_OK

    baseline = _load_baseline(args.baseline)
    if args.snapshot:
        try:
            snap = json.loads(Path(args.snapshot).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print(f"error: could not read snapshot {args.snapshot}.", file=sys.stderr)
            return EXIT_CANNOT_RUN
    else:
        snap = build_snapshot(args.home)
    result = compare(snap, baseline)
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else render_compare(result))
    if not result["comparable"]:
        return EXIT_CANNOT_RUN
    return EXIT_NEW_FAIL if result["blocked"] else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
