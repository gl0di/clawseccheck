"""The `bootstrap` dimension — your agent's startup instruction files.

Content that is read into the model's context before anything else, so a change here is a
change to the agent's standing instructions. The arm tracks files that MOVED as moves
rather than as a deletion plus an unrelated addition — otherwise renaming a bootstrap file
reports a loss the user never suffered.
"""

from __future__ import annotations
from ._shared import NOTE_UNDETERMINED  # noqa: F401


def _diff_bootstrap_removed(_boot_moved_from, _boot_removed, alerts, trust_removals) -> None:
    """A bootstrap file that is gone, once removals can be trusted at all.

    Gated on `trust_removals` in the caller: after a blind run, "absent" and "we could not
    look" are the same observation, and reporting the first is a fabrication.
    """
    # B-275: the removal branch the bootstrap dimension never had — deleting SOUL.md /
    # IDENTITY.md / USER.md / HEARTBEAT.md / BOOTSTRAP.md used to be completely silent,
    # while *modifying* the same file alerted HIGH. That asymmetry manufactured confidence:
    # the cheapest way to drop the agent's standing guardrails was also the only way that
    # produced no alert at all.
    #
    # MEDIUM, not the HIGH used for a content change: removal is also ordinary
    # housekeeping — a user retiring a HEARTBEAT.md they never used is not an attack — and
    # unlike a content change there is no poisoning signal in the event itself, only lost
    # coverage. The wording states what was OBSERVED and asks for confirmation, and
    # deliberately covers both causes of a disappearance: the file was deleted/moved, or it
    # is still there but no longer readable (a chmod 000 on USER.md alone drops it from
    # ctx.bootstrap).
    #
    # C-135 FIX3: it deliberately stops at the observation and does NOT go on to assert
    # "so its standing instructions no longer reach the agent" — a key disappearing from
    # this scan-order-dependent map is not proof the agent stopped reading the underlying
    # file (the FIX1 move case immediately above is exactly that: the key changed, the
    # file did not). An unsupported claim about a consequence this tool cannot observe is
    # treated as a defect in its own right, independent of whether the underlying WARN/FAIL
    # verdict is correct.
    if trust_removals:
        for name in sorted(_boot_removed - _boot_moved_from):
            alerts.append(("MEDIUM",
                           f"Bootstrap file no longer being read: {name} (deleted, moved, "
                           "or no longer readable). Confirm you intended this."))


def _diff_bootstrap_added(_boot_added, _boot_moved_to, alerts) -> None:
    """A bootstrap file that appeared and is not the far side of a rename."""
    for name in sorted(_boot_added - _boot_moved_to):
        alerts.append(("INFO", f"New bootstrap file appeared: {name}."))


def _diff_bootstrap_moved(
        _boot_added,
        _boot_moved_from,
        _boot_moved_to,
        _boot_removed,
        cb,
        pb,
) -> None:
    """Pair a removal with an addition of identical content, so a RENAME reads as a rename.

    Mutates the two sets in place; they are the caller's, and the arms that follow read
    them. That is why they are parameters rather than return values — the ordering the
    inline code had is preserved exactly.
    """
    for _r in sorted(_boot_removed):
        for _a in sorted(_boot_added - _boot_moved_to):
            if pb[_r] == cb[_a]:
                _boot_moved_from.add(_r)
                _boot_moved_to.add(_a)
                break


def _diff_bootstrap_changed(alerts, cb, pb) -> None:
    """A bootstrap file whose content moved while its name did not."""
    for name in sorted(pb.keys() & cb.keys()):
        if pb[name] != cb[name]:
            alerts.append(("HIGH", f"{name} changed since last check — possible prompt / memory "
                                   "poisoning (drift)."))
