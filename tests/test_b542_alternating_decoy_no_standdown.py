"""B-542 — re-measured against the sibling fix (B-541, commit 42a44b4) before building
anything, per the task's own instruction: "If option 2 lands for the sibling, re-measure
this before building option 1; it may be moot."

**Finding: it is moot.** The filed defect was that `_prov_comparable`'s stand-down keyed
on `winner_root` (commit 01e2f36), and a decoy `lock.json` planted-and-removed under the
SAME skill name in an earlier-sorting workspace flips `winner_root` every run, so the
comparison stood down every run, permanently and silently.

B-541 (42a44b4, landed after 01e2f36 and already on this branch) removed the election from
the verdict path: `read_provenance` now records EVERY `(root, skill)` pair, and
`monitor._prov_compare_records` compares each one with ITSELF across runs, keyed by root —
not by "the winner". `diff_with_notes`'s legacy `winner_root`-keyed loop (`_prov_comparable`
/ `_prov_not_compared`) still exists, but is gated by `if _per_root: break` and never runs
once BOTH sides carry per-root records — which `read_provenance` populates for every root
holding a lock file, unconditionally, so it is true on every ordinary run with skills
installed. The legacy path is reachable only on the one-time schema-transition run (an old
baseline predating 42a44b4), which is the same one-run cost every prior C-417/F-170/F-174
field addition already carries and already discloses via `watched`.

Measured directly (see the module docstring's own numbers for the shape this replaces):
across 6 runs alternating a same-name decoy in ``workspace-home`` (which sorts before the
real ``workspace``), `winner_root` still flips every run — but `diff_with_notes` now fires a
real alert on every run from run 2 onward (MEDIUM on the decoy's arrival, INFO on its
departure), never silence. This file pins that measured behaviour as a regression guard,
rather than building the "escalate after N runs" machinery the task offered as a fallback —
there is nothing left standing down to escalate.

Offline, read-only, stdlib only; writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit, snapshot
from clawseccheck.monitor import WATCHED_DIMENSIONS, diff_with_notes
from clawseccheck.skillprovenance import read_provenance

_ART_A, _ART_B, _ART_DECOY = "a" * 64, "b" * 64, "c" * 64
_SKF = "s" * 64


def _lock(root: Path, *, name="clawseccheck", version="2.0.0", artifact=_ART_A) -> None:
    (root / ".clawhub").mkdir(parents=True, exist_ok=True)
    (root / ".clawhub" / "lock.json").write_text(json.dumps({
        "version": 1, "skills": {name: {
            "version": version, "installedAt": 1, "registry": "https://clawhub.ai",
            "artifact": {"sha256": artifact}, "skillFile": {"sha256": _SKF}}}}),
        encoding="utf-8")


def _snap(dim: dict) -> dict:
    return {
        "version": 8, "watched": list(WATCHED_DIMENSIONS),
        "score": 90, "raw_score": 90, "raw_score_scope": "abc", "grade": "A",
        "graded": True, "checks": {"B1": "PASS"}, "checks_not_applicable": [],
        "checks_degraded": [], "behavioral_fired": [], "behavioral_undetermined": [],
        "behavioral_capped": False, "skill_provenance": dim,
    }


def test_alternating_same_name_decoy_alerts_on_every_run_not_silent(tmp_path):
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)  # the real record, stable
    decoy_dir = home / "workspace-home"  # sorts before "workspace"

    prev = _snap(read_provenance(home).as_dimension())
    winners = []
    silent_runs = []
    for run in range(2, 8):  # 6 comparisons, matching the task's "alternating, >= 6 runs"
        if run % 2 == 0:
            _lock(decoy_dir, version="9.9.9", artifact=_ART_DECOY)
        else:
            for f in (decoy_dir / ".clawhub" / "lock.json",):
                f.unlink(missing_ok=True)
        dim = read_provenance(home).as_dimension()
        winners.append(dim["clawseccheck"]["winner_root"])
        curr = _snap(dim)
        alerts, _notes = diff_with_notes(prev, curr)
        if not alerts:
            silent_runs.append(run)
        prev = curr

    # The bug's own precondition: winner_root really does flip every run.
    assert winners[0] != winners[1] and winners[1] != winners[2], winners
    # The bug's own symptom, now absent: no run in the alternating sequence is silent.
    assert silent_runs == [], (
        f"run(s) {silent_runs} produced no alert at all — the stand-down is back"
    )


def test_real_tamper_is_still_caught_while_a_decoy_churns_end_to_end(tmp_path):
    """End-to-end through the real audit pipeline, not just the synthetic-snapshot helper
    the sibling B-541 tests use — a genuine content tamper must surface even while an
    unrelated decoy is simultaneously planted in the winning-by-sort-order workspace."""
    home = tmp_path
    (home / "openclaw.json").write_text("{}")
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    ctx1, f1, s1 = audit(home)
    before = snapshot(ctx1, f1, s1,
                      provenance=read_provenance(ctx1.home, ctx1.config).as_dimension())

    _lock(home / "workspace-home", version="9.9.9", artifact=_ART_DECOY)  # decoy plant
    _lock(home / "workspace", version="1.0.0", artifact=_ART_B)  # real downgrade + swap
    ctx2, f2, s2 = audit(home)
    after = snapshot(ctx2, f2, s2,
                     provenance=read_provenance(ctx2.home, ctx2.config).as_dimension())

    alerts, _notes = diff_with_notes(before, after)
    msgs = [m for _, m in alerts]
    assert any("from 2.0.0 to 1.0.0" in m for m in msgs), msgs


def test_a_workspace_that_comes_and_goes_gets_the_same_escalation_once_known(tmp_path):
    """The genuinely-benign case (B-542's test plan item 2): a workspace directory that is
    intermittently absent (a removable mount) rather than a planted decoy. Once a root has
    been searched once, `roots_searched` records it as searched on every later run
    regardless of whether the directory currently exists — so its record reappearing is
    always "appeared", never a quiet, indefinitely-repeatable "somewhere new" note. Same
    mechanism, so the same escalation applies without needing to know intent."""
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    mount_dir = home / "workspace-work"  # a second fixed WORKSPACE_DIRS root

    run1 = read_provenance(home).as_dimension()  # mount absent this run
    _lock(mount_dir, name="clawseccheck", version="2.0.0", artifact=_ART_A)
    run2 = read_provenance(home).as_dimension()  # mount appears
    for f in (mount_dir / ".clawhub" / "lock.json",):
        f.unlink()
    run3 = read_provenance(home).as_dimension()  # mount disappears again

    alerts_2, _ = diff_with_notes(_snap(run1), _snap(run2))
    alerts_3, _ = diff_with_notes(_snap(run2), _snap(run3))
    assert alerts_2, "the mount's first reappearance produced no alert at all"
    assert alerts_3, "the mount's disappearance produced no alert at all"
