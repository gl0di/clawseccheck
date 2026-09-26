"""B-940 -- `toolpolicy._scope_rows` used to keep the LAST of two roster agents that
normalise to the same id, discarding the first entirely.

Two id-less ``agents.list`` entries both fold to ``main`` (``_normalize_agent_id`` maps a
missing id to the default agent id), so a roster of exactly two such entries is the minimal
config that reproduces a duplicate normalized id -- the same shape
``tests/test_b737_permissive_default_scope.py::test_resolved_scopes_duplicate_normalized_id_returns_none``
uses to prove ``toolgrant.resolved_scopes`` treats it as ambiguous and answers ``None``.

The real vendor's ``resolveAgentEntry`` takes the FIRST match on a duplicate id and silently
shadows the rest (documented in both ``toolpolicy._scope_rows`` and
``toolgrant.resolved_scopes``). ``_scope_rows`` built its per-name lookup with a dict
comprehension, which is LAST-wins by construction -- so the answer flipped depending on
which of the two entries happened to be declared last, rather than being pinned to the
first one the way the vendor and ``toolgrant`` agree it should be.

This file proves the fix with a security-relevant pair: one entry is workspace-confined
(``tools.fs.workspaceOnly: true``), the other is not and grants ``write`` via
``profile: coding``. Before the fix, declaring the PERMISSIVE entry first and the
RESTRICTIVE one second made ``unconfined_write_scopes`` silently miss the real,
vendor-honoured write exposure (measured: it returned ``[]`` where the fixed answer is
``["main"]``) -- the dangerous direction, a false negative on a scope the vendor actually
leaves open. Declaring them the other way round is the safe-direction mirror (a false
FAIL rather than a missed exposure) and is pinned here too, for completeness.
"""
from clawseccheck import toolgrant
from clawseccheck.toolpolicy import _scope_rows, confined_scopes, unconfined_write_scopes

_RESTRICTIVE = {"tools": {"fs": {"workspaceOnly": True}}}
_PERMISSIVE = {"tools": {"profile": "coding"}}


def _roster(first, second):
    return {"agents": {"list": [first, second]}}


def test_toolgrant_flags_the_duplicate_id_as_ambiguous():
    """Sanity check that both orderings really do produce the duplicate normalized id this
    file exercises -- `toolgrant.resolved_scopes` declines to answer either one."""
    assert toolgrant.resolved_scopes(_roster(_RESTRICTIVE, _PERMISSIVE)) is None
    assert toolgrant.resolved_scopes(_roster(_PERMISSIVE, _RESTRICTIVE)) is None


def test_scope_rows_keeps_the_first_declared_entry_not_the_last():
    cfg = _roster(_RESTRICTIVE, _PERMISSIVE)
    rows = _scope_rows(cfg)
    assert rows == [("main", _RESTRICTIVE, "")]

    cfg = _roster(_PERMISSIVE, _RESTRICTIVE)
    rows = _scope_rows(cfg)
    assert rows == [("main", _PERMISSIVE, "")]


def test_restrictive_first_stays_confined_and_write_reach_free():
    cfg = _roster(_RESTRICTIVE, _PERMISSIVE)
    assert confined_scopes(cfg) == [True]
    assert unconfined_write_scopes(cfg, ["write"]) == []


def test_permissive_first_is_the_dangerous_miss_this_bug_fixes():
    """Before the fix, this ordering silently lost the write exposure: the LAST-wins dict
    picked the restrictive second entry as `main`'s row, so `unconfined_write_scopes`
    returned `[]` for a scope the vendor's own first-match resolution leaves writable."""
    cfg = _roster(_PERMISSIVE, _RESTRICTIVE)
    assert confined_scopes(cfg) == [False]
    assert unconfined_write_scopes(cfg, ["write"]) == ["main"]


def test_three_agents_only_the_first_of_the_colliding_pair_survives():
    """A third, uniquely-named agent must not be affected by the collision between the
    other two, and the colliding pair must still resolve to exactly one row."""
    cfg = {"agents": {"list": [
        _RESTRICTIVE,
        {"id": "worker", "tools": {"profile": "coding"}},
        _PERMISSIVE,
    ]}}
    rows = _scope_rows(cfg)
    assert rows == [
        ("main", _RESTRICTIVE, ""),
        ("worker", {"id": "worker", "tools": {"profile": "coding"}}, "worker"),
    ]
    assert unconfined_write_scopes(cfg, ["write"]) == ["worker"]


def test_mutant_reintroducing_last_wins_is_killed():
    """Pins the exact regression: a last-wins `by_name` dict comprehension (the pre-fix
    shape: `{name: (entry, raw) for name, entry, raw in rows}` over the raw, non-deduped
    rows) answers `_PERMISSIVE` for this ordering; the fix must answer `_RESTRICTIVE`."""
    cfg = _roster(_RESTRICTIVE, _PERMISSIVE)
    entry = _scope_rows(cfg)[0][1]
    assert entry is _RESTRICTIVE
    assert entry is not _PERMISSIVE
