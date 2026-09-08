"""The `native_count` dimension — how many findings OpenClaw's OWN audit reported.

A second opinion this tool does not produce and cannot verify, so the arm compares two
recorded counts and nothing else. A count that becomes unavailable is UNDETERMINED, never
a drop to zero: "their audit stopped answering" and "their audit found nothing" are
different facts and only one of them is good news.
"""

from __future__ import annotations
from ._shared import NOTE_NO_PRIOR_RECORD, NOTE_UNDETERMINED  # noqa: F401


def _diff_native_findings(
        _both_native,
        _c_native,
        _p_native,
        _same_scope_flags,
        alerts,
        note,
) -> None:
    """C-433: the diff arm for the native-tool finding count.

    The statement is moved **verbatim, condition included**. The previous batch rebuilt an
    `if compare_config and _pair is not None:` as `if pair is None: return`, kept one clause
    and dropped the blind-run interlock, and reintroduced a B-269 fabrication. Moving the
    whole `if` removes that class of error entirely.

    Parameter names keep their original underscore-prefixed spelling for the same reason:
    a rename is an edit, and the contract for this move is that the body is unchanged.
    """
    if not _both_native:
        # Absent on either side is not silence: C-418's contract is that a comparison this
        # run did not make is counted and, under --verbose, named. Self-healing — the next
        # run has the key on both sides.
        note(NOTE_NO_PRIOR_RECORD,
             "The built-in `openclaw security audit` issue count was not compared: one of "
             "these two runs did not record one.")
    elif not _same_scope_flags:
        note(NOTE_UNDETERMINED,
             "The built-in `openclaw security audit` issue count was not compared: this "
             "run and the last were taken with different options, so a change in the "
             "number would be the option changing rather than the machine.")
    elif _c_native > _p_native:
        delta = _c_native - _p_native
        alerts.append(("INFO",
                       f"openclaw security audit reports {delta} more issue(s) than last time."))
