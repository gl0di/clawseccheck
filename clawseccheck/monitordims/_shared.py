"""C-433 — the vocabulary every dimension module reuses.

The LEAF of the `monitordims` package: it imports nothing from `clawseccheck`, so a
dimension module can import it without any question of ordering. Same arrangement as
`monitorstore.py`, and for the same reason — the supporting names move DOWN so the new
modules are true leaves and `monitor` imports one way.

Only names with more than one consumer live here. A helper or constant used by exactly
one dimension belongs in that dimension's own module, next to the arm that reads it —
the `checks/_shared.py` rule, applied to this package.
"""

from __future__ import annotations
import hashlib


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


# C-441: what to CALL a watched dimension when the user is told one could not be compared.
#
# The note that reports a baseline predating a comparison used to say only "this run cannot
# say which comparisons it was able to make", which tells the reader nothing they can act on
# and — on the very upgrade path it exists for — was the least informative sentence the
# monitor emitted. The names are derivable; only the vocabulary was missing.
#
# Deliberately partial. Roughly half of WATCHED_DIMENSIONS is internal bookkeeping
# (`graded`, `raw_score_scope`, `config_baseline`, the `*_capped` frontiers) whose names
# would be jargon in a user-facing sentence, so those are COUNTED rather than named. A key
# absent from this map is not an error: it falls into the count. That is why the renderer
# below reports both halves instead of a single number — dropping the unnamed ones would
# understate what was skipped, and naming them would bury the ones that matter.
_DIMENSION_LABELS = {
    "behavioral_fired": "how your agent has been behaving",
    "bootstrap": "your bootstrap files",
    "channels": "chat channel access",
    "checks": "the individual check results",
    "config_file_sha256": "the settings file's contents",
    "config_journal_head": "OpenClaw's own record of settings changes",
    "config_resolved_sha256": "the settings file including any included fragments",
    "config_written_by": "who last wrote your settings",
    "gateway_bind": "the gateway address",
    "host": "the security tools on this machine",
    "host_persist": "the machine's own startup and scheduling files",
    "ignore_hash": "your suppression list",
    "mcp": "connected tool servers",
    "mcp_detail": "what each tool server exposes",
    "memory": "your agent's memory files",
    "native_count": "OpenClaw's own audit",
    "openclaw_install": "the OpenClaw installation itself",
    "plugins": "which plugins may load",
    "score": "the security score",
    "skill_provenance": "where each installed skill came from",
    "skills": "your installed skills",
}


# How many names to spell out before falling back to a count. Six fits a readable sentence;
# the rest are still counted, and the cap is stated in the output rather than applied
# silently — a truncation the reader cannot see reads as "that was all of them".
_DIMENSION_NAME_CAP = 6


def _name_dimensions(keys: "list[str]") -> str:
    """A readable clause naming *keys*, capped, with everything unnamed still counted.

    Returns the empty string for an empty list, so the caller can decide whether there is
    anything to say at all rather than emitting a sentence about nothing.
    """
    named = [_DIMENSION_LABELS[k] for k in keys if k in _DIMENSION_LABELS]
    unnamed = len(keys) - len(named)
    if not named:
        return (f"{unnamed} internal bookkeeping field(s)") if unnamed else ""
    shown, hidden = named[:_DIMENSION_NAME_CAP], len(named) - _DIMENSION_NAME_CAP
    clause = ", ".join(shown)
    if hidden > 0:
        clause += f" and {hidden} more"
    if unnamed:
        clause += f", plus {unnamed} internal bookkeeping field(s)"
    return clause


# C-418 — the four reasons a comparison is DECLINED, as opposed to made and found equal.
#
# `diff()` is full of deliberate silences: a blind config makes every disappearance
# untrustworthy, a truncated collection cannot tell "gone" from "never looked at", an older
# baseline simply lacks the key a newer comparison needs. Each is individually correct, and
# each used to fall through invisibly into an unconditional "No new threats since last
# check" — a sentence about the whole setup, printed over the parts of it that were never
# examined.
#
# Four categories rather than forty individual reasons, because the render collapses to a
# count by default: an eight-line "not compared" list on a healthy run reads as a
# malfunction, and teaching users to ignore the monitor is a worse outcome than the silence
# this replaces. They are ordered by how much they should worry the reader.
NOTE_CONFIG_BLIND = "config_blind"          # openclaw.json unreadable — the loudest
NOTE_RECORD_DAMAGED = "record_damaged"      # the saved baseline is corrupt in part
NOTE_INSPECTION_CAPPED = "inspection_capped"  # too much on disk to inspect it all
NOTE_UNDETERMINED = "undetermined"          # a real record on both sides, but it says "unknown"
NOTE_NO_PRIOR_RECORD = "no_prior_record"    # nothing to compare against yet — the quietest


NOTE_CATEGORY_ORDER = (
    NOTE_CONFIG_BLIND,
    NOTE_RECORD_DAMAGED,
    NOTE_INSPECTION_CAPPED,
    NOTE_UNDETERMINED,
    NOTE_NO_PRIOR_RECORD,
)


def _dim(snap: dict, key: str) -> dict:
    """B-270: a snapshot dimension as a dict — ``{}`` when absent OR the wrong type.

    ``read_baseline`` guarantees the snapshot itself is a non-empty dict, but says nothing
    about what is *inside* it: a hand-edited or partially-corrupted state file can hold
    ``{"skills": [1,2]}``, and every dimension loop below assumes ``.keys()``. Coercing to
    ``{}`` makes such a dimension a no-op for one run instead of an AttributeError that
    takes the whole monitor run down — the same self-healing, absent-key-is-a-no-op idiom
    the B-267 ``tree`` fallback and the RP2 ``args_pkg`` gate already use.
    """
    val = snap.get(key)
    return val if isinstance(val, dict) else {}


def _both_dims(prev: dict, curr: dict, key: str) -> "tuple[dict, dict] | None":
    """B-270: ``(prev[key], curr[key])`` when BOTH sides carry a dict there, else None.

    Preserves the deliberate *presence* guard the mcp / mcp_detail / channels / host blocks
    already carried ("guarded so an old snapshot without these keys never produces spurious
    'new X' alerts after upgrade") and extends it to *type*, so a corrupted dimension is
    skipped rather than crashing. Skipping is the conservative direction here: comparing a
    real side against a coerced ``{}`` would report every live entry as newly appeared.
    """
    p, c = prev.get(key), curr.get(key)
    if isinstance(p, dict) and isinstance(c, dict):
        return p, c
    return None


def _frontier(snap: dict, key: str) -> set:
    """B-270: a truncation-frontier dimension (``*_capped``) as a set of strings.

    Same reasoning as ``_dim``: the frontier keys are consumed with ``set(... or ())``,
    which raises TypeError on an int and silently yields dict KEYS on a dict. An
    unusable frontier must degrade to "nothing known to be capped", which is the same
    value a pre-frontier snapshot supplies — already a handled, self-healing case.
    """
    val = snap.get(key)
    if isinstance(val, (list, tuple, set, frozenset)):
        return {v for v in val if isinstance(v, str)}
    return set()


def _num(snap: dict, key: str, default: int = 0) -> "int | float":
    """B-270: a numeric snapshot field, or *default* when absent or non-numeric.

    ``curr["score"] < prev["score"]`` raises TypeError when a hand-edited snapshot holds a
    string there; bool is excluded because ``True < 2`` compares as 1 and would silently
    fabricate a score-drop alert out of a corrupted field.
    """
    val = snap.get(key)
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return val
    return default
