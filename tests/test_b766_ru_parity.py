"""B-766: `INJECTION_PATTERNS` (the canonical English blanket-obedience/injection list)
and `_ML_OVERRIDE_TABLE["ru"]` (the Russian override table) are two unrelated,
non-communicating surfaces that can silently drift apart.

Measured, not assumed: of the four categories `INJECTION_PATTERNS` encodes, exactly one
("ignore previous instructions") has a Russian counterpart anywhere in the tree (the
`override` family), and even that one is reachable ONLY from B64's
`check_instruction_hierarchy_override` — B6 (`check_bootstrap_injection`), B58, B59 and
logscan.py, every consumer of `INJECTION_PATTERNS` itself, never call `_ml_override_scan`
at all. So "covered" and "reachable from the same check" are different claims, and this
guard keeps them separate rather than letting a table entry stand in for real coverage.

This is a structural/consumer-reachability guard, not a translation-correctness one: it
cannot verify a Cyrillic stem-tuple means the same thing as its English category, only
that every category has an EXPLICIT, NAMED decision recorded here — covered-and-where, or
not-yet-covered-and-why. The failure mode this closes is silent: a fifth English category
added to `INJECTION_PATTERNS` with no corresponding decision here goes unnoticed forever,
which is exactly how the current three-category gap accumulated.

Same shape as `tests/test_schema_grounding.py`'s `_NOT_IN_CURRENT_SCHEMA` register — an
absence is fine when it is disclosed and reasoned about; it is a defect only when nobody
looked. Regenerate nothing here by hand; a new INJECTION_PATTERNS entry must add a ledger
row in the SAME change, or `test_every_pattern_has_a_ledger_entry` below fails the build.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.checks._content import _ML_OVERRIDE_TABLE
from clawseccheck.checks._shared import INJECTION_PATTERNS

# Index into INJECTION_PATTERNS -> a short, stable name for the category that pattern
# encodes. Positional, not derived from the regex text, because two categories could
# legitimately share vocabulary (a #: comment is not a machine-checkable source of truth).
_INJECTION_PATTERN_CATEGORIES = {
    0: "ignore_previous",        # "ignore (all|any|previous|prior) (instructions|messages)"
    1: "obey_blanket",           # "obey (all|any|every|whatever)"
    2: "follow_whatever",        # "follow (all|any|every|whatever) (instruction|command|request)"
    3: "do_whatever_user_says",  # "do (whatever|anything) (the )?(user|...) (says|asks|wants)"
}

# category name -> a disclosure, ALWAYS present, whether covered or not. Two shapes:
#   ("covered", ru_family, reachable_from)  -- a real _ML_OVERRIDE_TABLE["ru"] family
#       exists; reachable_from names the check function that actually consumes it, or
#       None if nothing English-list-adjacent reaches it yet (the honest B-766 finding:
#       today this is None even for the one covered category).
#   ("not_covered", reason)  -- no Russian equivalent exists anywhere in the tree.
_RUSSIAN_PARITY_LEDGER = {
    "ignore_previous": (
        "covered", "override", None,
        "B-360's 'override' family (checks/_content.py::_ML_OVERRIDE_TABLE['ru']) covers "
        "the same ignore/forget/cancel+previous+instructions shape. NOT reachable from "
        "check_bootstrap_injection (B6) or any other INJECTION_PATTERNS consumer -- only "
        "check_instruction_hierarchy_override (B64) calls _ml_override_scan. Wiring it "
        "into B6/B58/B59/logscan is real, separate work (its own C-135 pass, since it "
        "changes those checks' verdicts on real Russian bootstrap content), not done here.",
    ),
    "obey_blanket": (
        "not_covered",
        "no Russian equivalent exists anywhere in the tree (B-766, measured 2026-09-09) "
        "-- not yet authored.",
    ),
    "follow_whatever": (
        "not_covered",
        "no Russian equivalent exists anywhere in the tree (B-766, measured 2026-09-09) "
        "-- not yet authored.",
    ),
    "do_whatever_user_says": (
        "not_covered",
        "no Russian equivalent exists anywhere in the tree (B-766, measured 2026-09-09) "
        "-- not yet authored.",
    ),
}


def test_every_pattern_has_a_named_category():
    """A pattern added to or removed from INJECTION_PATTERNS without updating the
    category map is exactly the silent-drift shape this file exists to catch."""
    assert set(range(len(INJECTION_PATTERNS))) == set(_INJECTION_PATTERN_CATEGORIES), (
        f"INJECTION_PATTERNS has {len(INJECTION_PATTERNS)} entries but "
        f"_INJECTION_PATTERN_CATEGORIES names {len(_INJECTION_PATTERN_CATEGORIES)} -- "
        "add or remove a category entry in the same change."
    )


def test_every_category_has_a_ledger_entry():
    named = set(_INJECTION_PATTERN_CATEGORIES.values())
    ledgered = set(_RUSSIAN_PARITY_LEDGER)
    assert named == ledgered, (
        f"categories with no parity decision: {named - ledgered}; "
        f"ledger entries for a category that no longer exists: {ledgered - named}"
    )


def test_covered_entries_name_a_real_ru_family():
    """A "covered" claim that names a family absent from the real table would be worse
    than no claim at all -- it would read as parity that was never built."""
    ru_families = {family for family, _ in _ML_OVERRIDE_TABLE["ru"]}
    for category, entry in _RUSSIAN_PARITY_LEDGER.items():
        if entry[0] == "covered":
            _, family, _reachable, _reason = entry
            assert family in ru_families, (
                f"{category!r} claims ru family {family!r}, which is not in "
                f"_ML_OVERRIDE_TABLE['ru'] ({sorted(ru_families)})"
            )


def test_not_covered_entries_carry_a_dated_reason():
    for category, entry in _RUSSIAN_PARITY_LEDGER.items():
        if entry[0] == "not_covered":
            _, reason = entry
            assert reason, f"{category!r} has an empty not_covered reason"


def test_the_ledger_is_not_all_one_shape():
    """A control on the ledger itself: three of four categories are "not_covered" today
    (measured). A ledger that is 100% one shape either in reality is fine, but a bug that
    always writes "covered" (or always "not_covered") regardless of the real table would
    also pass a schema-only check -- this asserts the actual, current, measured mix."""
    shapes = {entry[0] for entry in _RUSSIAN_PARITY_LEDGER.values()}
    assert shapes == {"covered", "not_covered"}, (
        f"expected both shapes present (measured reality as of B-766), got {shapes}"
    )


def test_the_one_covered_category_is_disclosed_as_unreached_from_b6():
    """The honest half of the B-766 finding: 'covered' is not 'protects your bootstrap
    files today'. A future session that wires _ml_override_scan into B6 should update
    this ledger entry's `reachable_from` field to name the real consumer -- this test
    pins that the entry does not silently start CLAIMING reachability it doesn't have."""
    entry = _RUSSIAN_PARITY_LEDGER["ignore_previous"]
    assert entry[0] == "covered"
    assert entry[2] is None, (
        "ignore_previous's ru coverage is now marked reachable from a real check -- "
        "if check_bootstrap_injection (B6) or another INJECTION_PATTERNS consumer "
        "really was wired to _ml_override_scan, update this test to match; if this "
        "flipped without that wiring landing, it is a false claim."
    )
