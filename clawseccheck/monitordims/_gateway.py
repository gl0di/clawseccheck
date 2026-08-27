"""The `gateway_bind` dimension — which interface the gateway listens on.

One string, and the difference between `127.0.0.1` and `0.0.0.0` is the difference between
a local service and one the network can reach. The arm refuses to compare two values it
cannot both read as strings rather than treating an unreadable side as unchanged.
"""

from __future__ import annotations
from ._shared import (  # noqa: F401
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
)


def _diff_gateway_bind_moved(_cgb, _pgb, alerts, compare_config) -> None:
    """The gateway moved from a local bind to one the network can reach."""
    if (compare_config and isinstance(_pgb, str) and isinstance(_cgb, str)
            and _pgb != _cgb):
        from ..checks import EXPOSED_BINDS  # noqa: PLC0415
        cb = _cgb
        exposed = cb in EXPOSED_BINDS
        alerts.append(("CRITICAL" if exposed else "HIGH",
                       f"Gateway bind changed: '{_pgb}' -> '{cb}'"
                       + (" (now exposed to the network!)" if exposed else "")))


def _note_gateway_bind_unreadable(_cgb, _pgb, compare_config, note, prev) -> None:
    """Say so when the bind could not be read as a string on both sides.

    B-270: both sides must be STRINGS, not merely present, or the membership test raises
    on a hand-edited baseline — and an unreadable side must not pass as unchanged.
    """
    # C-418: the gateway address is the single highest-consequence field this tool watches —
    # 127.0.0.1 to 0.0.0.0 is the difference between a local agent and one on the network —
    # so a run that could not compare it must say so rather than let the all-clear imply it
    # did. Only when the config WAS readable: when it was not, the blind-config note above
    # already covers the gateway and a second sentence would be noise.
    if compare_config and not (isinstance(_pgb, str) and isinstance(_cgb, str)):
        note(NOTE_NO_PRIOR_RECORD if "gateway_bind" not in prev else NOTE_RECORD_DAMAGED,
             "The gateway's network address was not compared with last time — it is "
             "missing or unreadable in one of the two records.")


def _gateway_bind(ctx) -> str:
    from ..checks import parse_bind_host  # noqa: PLC0415
    from ..collector import dig  # noqa: PLC0415
    return parse_bind_host(dig(ctx.config, "gateway.bind")
                           or dig(ctx.config, "gateway.host") or "")
