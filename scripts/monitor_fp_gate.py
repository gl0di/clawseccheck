#!/usr/bin/env python3
"""Monitor false-positive gate: two snapshots of an unchanged home must diff to nothing.

`scripts/fleet_fp_gate.py` guards check FAILs against the real fleet. Nothing guarded
monitor ALERTS, so every dimension the watch epic adds landed with no mechanical
regression net -- only a per-task C-135 pass, which is a human act and does not re-run on
the next commit.

    python3 scripts/monitor_fp_gate.py check          # the real home, twice, nothing changed

Exit 0 when the second run reports no alert. Exit 1 on any alert -- each one is a false
positive by construction, because nothing changed between the two snapshots. Exit 2 when
the run was too degraded to judge.

Two false-positive classes found by hand during the epic's design are exactly what this
would have caught for free:

  * `meta.lastTouchedVersion` / `meta.lastTouchedAt` / `wizard.lastRun*` -- written by
    OpenClaw itself, so a naive whole-config hash fires on every upgrade carrying zero
    security content.
  * B191 divergence -- on a host that has rotated its 60-file trajectory cap,
    `behavioral.py`'s own note calls bare divergence "expected, near-certain-benign
    background noise". Routed raw into `diff()` it would fire every run, forever.

## Three decisions worth stating

**It writes nothing at all.** The task that specified this asked for the harness to
redirect state, events and history away from `~/.clawseccheck/`. Going through the
library instead of the CLI -- collect, run the checks, `snapshot()`, `diff_with_notes()`
-- means there is no file to redirect: a snapshot is a dict, and the diff compares two of
them in memory. Not writing is strictly safer than redirecting correctly.

**It builds the snapshot the way `cli.py` does, dimension for dimension.** The behavioural
layer, the OpenClaw install and the skill provenance are resolved here with the same
containment the shell uses, because a gate that skips them is blind to precisely the
dimensions this epic keeps adding -- which is the one thing it exists to prevent. Each is
contained the same way: a subject that cannot be read leaves its key ABSENT, so the diff
says "not examined" instead of treating an empty view as fact.

**It asserts on alerts only.** Notes (C-418) are expected to be non-empty on a healthy
run -- a note records a comparison the run declined to make, which is information, not
drift. Counting them as false positives would make the gate red on a correct machine.

The second snapshot is built with `prev=` the first, because that is what a real second
run does (B-269: `snapshot()` needs the previous state to repair a blind run). Comparing
two independently-built snapshots would be a different, easier question than the one the
watch actually answers.

Two full audit passes, not one audit rendered twice -- nondeterminism inside the checks
is the interesting kind, and a single pass cannot see it.

Local, read-only, offline. Nothing in the audited setup is written; native fold-in stays
off for the same reason the fleet gate keeps it off -- a gate must not launch the audited
software. Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# The package, and this script's own directory so the sibling gate imports whether this
# is run as `python3 scripts/monitor_fp_gate.py` from anywhere or loaded by the test twin
# through spec_from_file_location, which puts neither on the path for us.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from clawseccheck import __version__  # noqa: E402
from clawseccheck.behavioral import analyze as _analyze  # noqa: E402
from clawseccheck.behavioral import grade_cap_signal as _grade_cap_signal  # noqa: E402
from clawseccheck.catalog import UNKNOWN  # noqa: E402
from clawseccheck.checks import run_all  # noqa: E402
from clawseccheck.collector import collect  # noqa: E402
from clawseccheck.monitor import diff_with_notes, snapshot  # noqa: E402
from clawseccheck.openclawdist import describe_install  # noqa: E402
from clawseccheck.scoring import compute  # noqa: E402
from clawseccheck.skillprovenance import read_provenance  # noqa: E402

from fleet_fp_gate import degraded_checks  # noqa: E402  -- reuse, do not reimplement

DEFAULT_HOME = "~/.openclaw"


def _behavioral_dimension(ctx):
    """The reduced behavioural verdict `cli.py` hands to snapshot(), same containment.

    Never the raw findings: a bare B191 divergence under a rotated trajectory cap is
    documented benign background noise, and routing it in would put a permanent entry in
    the drift stream -- one of the two false positives this gate exists to catch.
    """
    try:
        result = _analyze(ctx)
    except Exception:  # noqa: BLE001 -- the watch must survive the layer it just gained
        return None
    return {
        "fired": sorted(_grade_cap_signal(result)),
        "undetermined": sorted(f.id for f in result.get("findings", ())
                               if f.status == UNKNOWN),
        "capped": bool(result.get("files_capped")),
    }


def _install_dimension():
    try:
        found = describe_install("openclaw")
    except Exception:  # noqa: BLE001 -- a supply-chain reader must not kill the watch
        return None
    return found.as_dimension() if found is not None else None


def _provenance_dimension(ctx):
    try:
        scan = read_provenance(ctx.home, ctx.config)
    except Exception:  # noqa: BLE001 -- same containment
        return None
    # Gated on `present`, not on the scan succeeding: `{}` means "established, empty",
    # absent means "not established". Recording the first for the second would report
    # every skill as newly installed on the next run that did find the file.
    return scan.as_dimension() if scan.present else None


def build_one(home, prev=None):
    """One complete monitor pass: collect, check, score, snapshot. Writes nothing."""
    ctx = collect(home)
    findings = run_all(ctx)
    score = compute(findings, ctx)
    snap = snapshot(ctx, findings, score, prev=prev,
                    behavioral=_behavioral_dimension(ctx),
                    install=_install_dimension(),
                    provenance=_provenance_dimension(ctx))
    return snap, findings


def check(home=DEFAULT_HOME):
    """Two passes over an unchanged home; report every alert the second one raises."""
    first, first_findings = build_one(home)
    second, second_findings = build_one(home, prev=first)
    alerts, notes = diff_with_notes(first, second)
    degraded = sorted(set(degraded_checks(first_findings))
                      | set(degraded_checks(second_findings)))
    return {
        "version": __version__,
        "alerts": [{"level": lvl, "message": msg} for lvl, msg in alerts],
        "note_count": len(notes),
        "degraded_checks": degraded,
        "comparable": not degraded,
    }


def render(result):
    """Human-readable verdict. Returns (text, exit_code)."""
    if not result["comparable"]:
        return (
            "REFUSED: checks degraded during one of the two runs -- "
            + ", ".join(result["degraded_checks"])
            + "\nA degraded run can lose a signal, so neither an alert nor its absence "
              "means anything here. Re-run on a quieter machine.",
            2,
        )
    notes = result["note_count"]
    if not result["alerts"]:
        return (f"OK: two runs over an unchanged home produced no alert "
                f"({notes} note{'' if notes == 1 else 's'}, which is expected).", 0)
    lines = [f"FALSE POSITIVES: {len(result['alerts'])} alert(s) on an unchanged home.",
             "Nothing changed between the two snapshots, so every line below is a false "
             "positive by construction.", ""]
    lines += [f"  [{a['level']}] {a['message']}" for a in result["alerts"]]
    return "\n".join(lines), 1


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="monitor_fp_gate",
        description="Two monitor snapshots of an unchanged home must diff to nothing.")
    p.add_argument("command", choices=["check"], help="run the gate")
    p.add_argument("--home", default=DEFAULT_HOME,
                   help=f"OpenClaw home to audit (default: {DEFAULT_HOME})")
    args = p.parse_args(argv)
    text, code = render(check(args.home))
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
