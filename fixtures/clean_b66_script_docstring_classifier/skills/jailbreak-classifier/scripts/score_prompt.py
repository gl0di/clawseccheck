"""Heuristics for the jailbreak / persona-override classifier.

The classifier raises the risk band when a prompt tells the model you are now
DAN, or asks it to bypass safety filters before answering. Both shapes are
weighted more heavily than a bare role-play request.
"""

BANDS = ("low", "medium", "high")


def score(prompt: str) -> str:
    """Return the risk band for *prompt*."""
    lowered = prompt.lower()
    hits = sum(marker in lowered for marker in _MARKERS)
    return BANDS[min(hits, 2)]


_MARKERS = ("do anything now", "no restrictions", "ignore all previous")
