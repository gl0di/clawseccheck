"""The `gateway_bind` dimension - which interface the gateway listens on.

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
    """The gateway moved from a local bind to one the network can reach.

    C-681: a whole-value templated bind (``${VAR}`` / ``${VAR:-default}``) used to be stored
    as ``parse_bind_host`` of the template text - lowercased and cut at a colon, e.g.
    ``${gw_bind`` - and is now stored as written (`_gateway_bind`). Against an older baseline
    that is a re-spelling and must not alert once, so a previous value equal to the old
    function's output for THIS template is skipped. That old record is lossy: it cannot tell
    two templates apart when they differ only in what the old function dropped (the
    ``:-default`` after the variable name), so such a change is not reported on that one
    run; every run after it compares the full text. A different variable, a template that
    became a literal and a literal that became a template still alert.
    """
    if (compare_config and isinstance(_pgb, str) and isinstance(_cgb, str)
            and _pgb != _cgb):
        from ..checks import EXPOSED_BINDS, parse_bind_host  # noqa: PLC0415
        from ..checks._shared import _BIND_TEMPLATE_RE, _js_trim  # noqa: PLC0415
        if _BIND_TEMPLATE_RE.fullmatch(_js_trim(_cgb)) and parse_bind_host(_cgb) == _pgb:
            return
        cb = _cgb
        exposed = cb in EXPOSED_BINDS
        alerts.append(("CRITICAL" if exposed else "HIGH",
                       f"Gateway bind changed: '{_pgb}' -> '{cb}'"
                       + (" (now exposed to the network!)" if exposed else "")))


def _note_gateway_bind_unreadable(_cgb, _pgb, compare_config, note, prev) -> None:
    """Say so when the bind could not be read as a string on both sides.

    B-270: both sides must be STRINGS, not merely present, or the membership test raises
    on a hand-edited baseline - and an unreadable side must not pass as unchanged.
    """
    # C-418: the gateway address is the single highest-consequence field this tool watches -
    # 127.0.0.1 to 0.0.0.0 is the difference between a local agent and one on the network -
    # so a run that could not compare it must say so rather than let the all-clear imply it
    # did. Only when the config WAS readable: when it was not, the blind-config note above
    # already covers the gateway and a second sentence would be noise.
    if compare_config and not (isinstance(_pgb, str) and isinstance(_cgb, str)):
        note(NOTE_NO_PRIOR_RECORD if "gateway_bind" not in prev else NOTE_RECORD_DAMAGED,
             "The gateway's network address was not compared with last time \u2014 it is "
             "missing or unreadable in one of the two records.")


def _gateway_bind(ctx) -> str:
    """The bind the snapshot records: the host of a literal bind, lowercased as always.

    C-681: a WHOLE-VALUE ``${VAR}`` / ``${VAR:-default}`` bind is recorded as WRITTEN
    (trimmed, original case, whole value), never through ``parse_bind_host`` - which
    lowercased it and cut it at a colon (``${gw_bind``), so the monitor compared garbled
    text. The value the variable stands for is deliberately NOT resolved here
    (``_effective_gateway_bind``): that answer depends on which unit and dotenv files this
    particular run could read, so a baseline taken on one run would differ from the next for
    reasons that are not a change of the config. The template text is stable. A template
    EMBEDDED in a literal host (``0.0.0.0:${GW_PORT}``) is recorded exactly as before: its
    visible host part (``0.0.0.0``) is what `_diff_gateway_bind_moved` tests for exposure,
    and recording the whole text would turn a CRITICAL "now exposed" into a plain change.
    """
    from ..checks import parse_bind_host  # noqa: PLC0415
    from ..checks._shared import _BIND_TEMPLATE_RE, _js_trim  # noqa: PLC0415
    from ..collector import dig  # noqa: PLC0415
    raw = dig(ctx.config, "gateway.bind") or dig(ctx.config, "gateway.host") or ""
    if isinstance(raw, str) and _BIND_TEMPLATE_RE.fullmatch(_js_trim(raw)):
        return _js_trim(raw)
    return parse_bind_host(raw)
