"""The `host_persist` dimension — the HOST's own persistence surface.

F-179. `hostpersist.py` is the reader; this is the comparison. The family labels and the
INFRASTRUCTURE classification are sourced from the leaf's own tables rather than retyped:
B-483 found seven copies of one table in this tree and three of them had drifted.
"""

from __future__ import annotations
from ..hostpersist import FAMILY_LABELS as _hp_FAMILY_LABELS  # noqa: F401
from ..hostpersist import FAMILY_SYSTEM_CRON as _hp_FAMILY_SYSTEM_CRON  # noqa: F401
from ..hostpersist import FAMILY_SYSTEMD as _hp_FAMILY_SYSTEMD  # noqa: F401
from ._shared import (  # noqa: F401
    NOTE_INSPECTION_CAPPED,
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    _DIMENSION_NAME_CAP,
)


# F-179: the human-facing family names, and which families count as INFRASTRUCTURE for
# severity purposes. Sourced from `hostpersist.FAMILY_LABELS` rather than retyped, so a
# family renamed in the leaf cannot silently stop matching here — B-483 found seven copies
# of one table in this tree and three of them had drifted.
_HOST_PERSIST_LABELS = dict(_hp_FAMILY_LABELS)


# systemd units and system cron are edited rarely and every line in them can start a
# process, so a MODIFICATION is as meaningful as an addition. Shell startup files and
# Python auto-execution hooks are routinely rewritten by package managers and by the user,
# so a modification there stays advisory. Membership is asserted against the leaf's own
# family list by a test, so a new family cannot land here unclassified.
_HOST_PERSIST_INFRA = frozenset({_hp_FAMILY_SYSTEMD, _hp_FAMILY_SYSTEM_CRON})


def _diff_host_persist(_hp_pair, alerts, curr, note, prev) -> None:
    """C-433: the diff arm for the machine's own startup and scheduling files.

    The statement is moved **verbatim, condition included**. The previous batch rebuilt an
    `if compare_config and _pair is not None:` as `if pair is None: return`, kept one clause
    and dropped the blind-run interlock, and reintroduced a B-269 fabrication. Moving the
    whole `if` removes that class of error entirely.

    Parameter names keep their original underscore-prefixed spelling for the same reason:
    a rename is an edit, and the contract for this move is that the body is unchanged.
    """
    if _hp_pair is None:
        if "host_persist" in prev and "host_persist" not in curr:
            note(NOTE_UNDETERMINED,
                 "This machine's own startup and scheduling files were not compared: this "
                 "run did not examine them. Your saved record for them is kept as it was.")
        elif "host_persist" not in prev and "host_persist" in curr:
            note(NOTE_NO_PRIOR_RECORD,
                 "This machine's own startup and scheduling files had nothing to compare "
                 "against — your saved record predates this check. It will cover them from "
                 "the next run onwards.")
        elif "host_persist" in prev or "host_persist" in curr:
            note(NOTE_RECORD_DAMAGED,
                 "The record of this machine's startup and scheduling files is not in the "
                 "expected form, so it was not compared. It will rebuild on the next run.")
    else:
        _php, _chp = _hp_pair
        _pe = _php.get("entries") if isinstance(_php.get("entries"), dict) else None
        _ce = _chp.get("entries") if isinstance(_chp.get("entries"), dict) else None
        if _pe is None or _ce is None:
            note(NOTE_RECORD_DAMAGED,
                 "The record of this machine's startup and scheduling files is not in the "
                 "expected form, so it was not compared. It will rebuild on the next run.")
        else:
            def _fam(entry: object) -> str:
                return entry.get("family", "") if isinstance(entry, dict) else ""

            def _dig(entry: object) -> str:
                return entry.get("digest", "") if isinstance(entry, dict) else ""

            def _label(path: str, entry: object) -> str:
                fam = _HOST_PERSIST_LABELS.get(_fam(entry))
                return "{0} ({1})".format(path, fam) if fam else path

            def _say(level: str, verb: str, items: "list[str]") -> None:
                if not items:
                    return
                shown = sorted(items)[:_DIMENSION_NAME_CAP]
                more = len(items) - len(shown)
                tail = ", and {0} more".format(more) if more > 0 else ""
                alerts.append((level, "Startup/scheduling file(s) {0} on this machine: "
                                      "{1}{2}. These run code without your agent's "
                                      "involvement, so a change here is outside anything "
                                      "your OpenClaw settings control."
                               .format(verb, ", ".join(shown), tail)))

            _added = [p for p in _ce if p not in _pe]
            _removed = [p for p in _pe if p not in _ce]
            _changed = [p for p in (set(_pe) & set(_ce)) if _dig(_pe[p]) != _dig(_ce[p])]

            _say("MEDIUM", "appeared", [_label(p, _ce[p]) for p in _added])
            _say("INFO", "were removed", [_label(p, _pe[p]) for p in _removed])
            _say("MEDIUM", "changed",
                 [_label(p, _ce[p]) for p in _changed
                  if _fam(_ce[p]) in _HOST_PERSIST_INFRA])
            _say("INFO", "changed",
                 [_label(p, _ce[p]) for p in _changed
                  if _fam(_ce[p]) not in _HOST_PERSIST_INFRA])

        # A path that EXISTS but this process may not read. On a normal Linux box the
        # user's own crontab spool is here every single run, and that is the point: the
        # closest on-disk analogue of the published attack is one we structurally cannot
        # see, and saying so every run beats a silence that reads as "nothing scheduled".
        _unread = _chp.get("unreadable")
        if isinstance(_unread, list) and _unread:
            note(NOTE_UNDETERMINED,
                 "{0} startup/scheduling location(s) on this machine exist but could not "
                 "be read, so this run cannot tell you whether anything in them changed: "
                 "{1}. Reading a per-user crontab needs privileges this tool does not "
                 "take; check it yourself with 'crontab -l'."
                 .format(len(_unread), ", ".join(sorted(_unread)[:_DIMENSION_NAME_CAP])))
        if _chp.get("capped"):
            note(NOTE_INSPECTION_CAPPED,
                 "There are more startup and scheduling files on this machine than can be "
                 "recorded in one run, so only part of that surface was compared.")
