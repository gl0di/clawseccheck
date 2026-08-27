"""The `host` dimension — security tools detected running on this machine.

Only a `present -> absent` transition alerts. A watcher whose earlier state was `unknown`
can stop without a word, which is a real limit rather than an oversight, so the arm says
so in a note instead of letting the silence read as "nothing changed".
"""

from __future__ import annotations
from ._shared import NOTE_UNDETERMINED  # noqa: F401


def _diff_host_monitors(pair, alerts, note) -> None:
    """C-433: the `host` dimension's diff arm, lifted out of `diff_with_notes`.

    **The first per-dimension extraction, and it is the shape the task asks for** rather
    than the by-function shape it rejected three times: this arm travels with its own
    dimension, not with "all the diff code".

    It was chosen because it is the cleanest, measured rather than guessed. Its entire free
    variable set inside `diff_with_notes` was `_host_pair`, `alerts`, `note` plus module
    constants — three parameters. The blocking analysis on the task said a per-dimension cut
    meant threading 61 shared locals; that figure is an aggregate over the whole function
    and does not describe the arms, which read three or four names each. The 61 live in the
    blind-run preamble, which is why the preamble moves last, not first.

    `alerts` and `note` are passed in because they are the two accumulators every arm
    shares. `note` is still a closure over `diff_with_notes`' own state, so it is handed
    over rather than reconstructed — reconstructing it is what an earlier verification pass
    correctly said cannot be lifted to a `_shared` module.

    Returns nothing: it appends. That is deliberate and matches how the arm behaved inline,
    so the extraction cannot change ordering — the contract for this move is an identical
    alert and note sequence, verified across six snapshot pairs including both directions
    and a blind run.
    """
    if pair is None:
        return
    ph, ch = pair
    for cls in sorted(set(ph) & set(ch)):
        if ph[cls] == "present" and ch[cls] != "present":
            alerts.append(("HIGH", f"Host monitor '{cls}' is no longer detected — "
                           "a watcher on this machine was removed or disabled."))
    # C-418: only a present -> absent transition alerts, so a watcher whose earlier
    # state was `unknown` can stop without a word. Measured on a real machine: five of
    # seven classes are `unknown`, i.e. most of this dimension is not in fact being
    # watched for disappearance.
    #
    # `unknown` ONLY — not "anything other than present". The first version tested
    # `!= "present"`, which swept in `absent -> absent`: a confident verdict on both
    # sides, fully compared, with nothing that could have stopped. That is a false
    # note, and a permanent one — a machine that simply has no EDR would report it on
    # every run forever, which would put the tick this change introduced permanently
    # out of reach there. A note that can never be cleared trains the reader to ignore
    # the whole block.
    _undetermined = sum(1 for cls in set(ph) & set(ch) if ph[cls] == "unknown")
    if _undetermined:
        note(NOTE_UNDETERMINED,
             f"{_undetermined} security tool(s) on this machine could not be confirmed "
             f"as running last time, so this run cannot tell you if they stopped.")
