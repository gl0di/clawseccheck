"""C-679: the state-SQLite table baseline covers the satellite schema constants too.

`vendor_state_tables.txt` used to list only what `OPENCLAW_STATE_SCHEMA_SQL` declares, but
OpenClaw 2026.9.9 creates three more tables in the same state database from satellite
constants (`USER_PROFILES_SCHEMA_SQL`, `WORKER_ENVIRONMENT_SESSION_ATTACHMENTS_SCHEMA_SQL`).
The generator now reads an explicit allowlist, names its exclusions, and stops on any
`*_SCHEMA_SQL` constant it has not been told about. These tests drive that machinery on
synthetic dists; the live-database backstop at the bottom is local-only.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from _realhome import REAL_HOME
from test_state_schema_grounding import (
    OPENCLAW_DIST,
    _CREATE_TABLE_NAMED_RE,
    _STATE_DERIVED_CONSTANTS,
    _STATE_EXCLUDED_CONSTANTS,
    _STATE_REDECLARING_CONSTANTS,
    _STATE_SATELLITE_CONSTANTS,
    _read_vendor_table_baseline,
    _satellite_header_block,
    _satellite_state_tables,
    _table_set_delta,
    _vendor_state_table_surface,
    _write_dist,
)

_MAIN_TABLES = {"a_main", "b_main"}
_SAT = "FOO_SCHEMA_SQL"
_EXCLUDED = "BAR_SCHEMA_SQL"
_REDECL = "BAZ_SCHEMA_SQL"
_DERIVED = "QUX_SCHEMA_SQL"
_LISTS = {"satellites": {_SAT: "test"}, "excluded": {_EXCLUDED: "test"}, "redeclaring": {},
          "derived": {}}
_WITH_REDECL = {**_LISTS, "redeclaring": {_REDECL: "test"}}
_WITH_DERIVED = {**_LISTS, "derived": {_DERIVED: "test"}}


def _ddl(*names: str) -> str:
    """CREATE TABLE text built at RUNTIME. test_state_schema_grounding.py registers every
    plain string literal under tests/ that executes as state DDL; an f-string is not one, and
    these are inputs to the generator, not state DDLs of this tree."""
    return "\n".join(f"CREATE TABLE IF NOT EXISTS {n} (x TEXT) STRICT;" for n in names)


_SPLICE = "${extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, %s)}"


def _sat_template(body: str) -> str:
    return f"const {_SAT} = `{body}`;\n"


def _tables(dist, **lists):
    return _satellite_state_tables(dist, _MAIN_TABLES, **(lists or _LISTS))


def test_a_satellite_adds_its_tables_and_an_excluded_constant_is_ignored(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one", "sat_two")),
        "b.mjs": f"const {_EXCLUDED} = `{_ddl('excluded_tbl')}`;\n",
    })
    got = _tables(dist)
    assert got[_SAT]["tables"] == ["sat_one", "sat_two"]
    assert got[_SAT]["adds"] == ["sat_one", "sat_two"]
    assert "excluded_tbl" not in {t for p in got.values() for t in p["tables"]}


def test_a_redeclaring_constant_with_only_known_tables_passes_and_adds_nothing(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one")),
        "r.mjs": f"const {_REDECL} = `{_ddl('a_main', 'b_main')}`;\n",
    })
    got = _tables(dist, **_WITH_REDECL)
    assert set(got) == {_SAT}, "a redeclaring constant is checked, never returned as a source"
    assert got[_SAT]["tables"] == ["sat_one"]


def test_a_redeclaring_constant_that_declares_a_new_table_stops_the_generator(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one")),
        "r.mjs": f"const {_REDECL} = `{_ddl('a_main', 'brand_new')}`;\n",
    })
    with pytest.raises(AssertionError) as exc:
        _tables(dist, **_WITH_REDECL)
    assert _REDECL in str(exc.value) and "brand_new" in str(exc.value)
    assert "a_main" not in str(exc.value).split("declares")[-1], "only the NEW table is named"


def test_a_redeclaring_constant_the_dist_no_longer_defines_fails_loudly(tmp_path):
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(_ddl("sat_one"))})
    with pytest.raises(AssertionError, match="allowlisted"):
        _tables(dist, **_WITH_REDECL)


# ---- C-683: a constant derived from the main one (2026.10.1's CRON_RUNTIME_AUTHORITY) -----

_DERIVED_OK = ('const T = "a_main";\n'
               f"const {_DERIVED} = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, T);\n")


def _derived_dist(tmp_path, body):
    return _write_dist(tmp_path, {"a.mjs": _sat_template(_ddl("sat_one")), "d.mjs": body})


def test_a_derived_constant_over_a_main_table_passes_and_adds_nothing(tmp_path):
    got = _tables(_derived_dist(tmp_path, _DERIVED_OK), **_WITH_DERIVED)
    assert set(got) == {_SAT}, "a derived constant is checked, never returned as a source"


def test_a_derived_constant_with_an_inline_table_literal_passes(tmp_path):
    body = f'const {_DERIVED} = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, "b_main");\n'
    assert set(_tables(_derived_dist(tmp_path, body), **_WITH_DERIVED)) == {_SAT}


def test_a_derived_constant_for_a_table_the_main_constant_lacks_stops_the_generator(tmp_path):
    body = _DERIVED_OK.replace("a_main", "brand_new")
    with pytest.raises(AssertionError, match="brand_new"):
        _tables(_derived_dist(tmp_path, body), **_WITH_DERIVED)


@pytest.mark.parametrize("rhs", [
    f"`{_ddl('a_main')}`",                                              # a literal, not a derivation
    "extractSqliteTableSchema(OTHER_SOURCE_SQL, T)",                    # a different source constant
    "extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, T, { x: 1 })",  # an options argument
    "extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, tableFor(1))",  # a computed table
    "compose(OPENCLAW_STATE_SCHEMA_SQL)",
])
def test_an_unrecognised_derived_definition_shape_stops_the_generator(tmp_path, rhs):
    body = f'const T = "a_main";\nconst {_DERIVED} = {rhs};\n'
    with pytest.raises(AssertionError, match="not the one shape|re-ground"):
        _tables(_derived_dist(tmp_path, body), **_WITH_DERIVED)


def test_a_table_identifier_bound_twice_or_not_at_all_is_refused(tmp_path):
    for binding in ('const T = "a_main";\nconst T2 = "b_main";\nlet T = "b_main";\n', ""):
        body = binding + f"const {_DERIVED} = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, T);\n"
        with pytest.raises(AssertionError, match="not bound to exactly one"):
            _tables(_derived_dist(tmp_path, body), **_WITH_DERIVED)


def test_a_derived_constant_the_dist_no_longer_defines_fails_loudly(tmp_path):
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(_ddl("sat_one"))})
    with pytest.raises(AssertionError, match="no bundle under"):
        _tables(dist, **_WITH_DERIVED)


def test_a_derived_constant_is_not_a_literal_redeclarer(tmp_path):
    """The old classification demanded a literal definition; the derived one must not."""
    dist = _derived_dist(tmp_path, _DERIVED_OK)
    with pytest.raises(AssertionError, match="allowlisted"):
        _tables(dist, **{**_LISTS, "redeclaring": {_DERIVED: "test"}})


def test_an_unclassified_schema_constant_stops_the_generator(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one")),
        "c.mjs": f"const NEWTHING_SCHEMA_SQL = `{_ddl('sneaky')}`;\n",
    })
    with pytest.raises(AssertionError, match=r"unclassified \*_SCHEMA_SQL.*NEWTHING_SCHEMA_SQL"):
        _tables(dist)


def test_a_constant_that_is_only_referenced_still_has_to_be_classified(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one")),
        "c.mjs": "db.exec(IMPORTED_ELSEWHERE_SCHEMA_SQL);\n",
    })
    with pytest.raises(AssertionError, match="IMPORTED_ELSEWHERE_SCHEMA_SQL"):
        _tables(dist)


def test_a_template_interpolation_of_a_main_table_is_tolerated_not_counted(tmp_path):
    body = _ddl("sat_one") + "\n" + _SPLICE % '"a_main"' + "\n"
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(body)})
    got = _tables(dist)
    assert got[_SAT]["tables"] == ["sat_one"]
    assert got[_SAT]["adds"] == ["sat_one"]


@pytest.mark.parametrize("expr", ["someHelper()", "tableName"])
def test_an_unmodelled_interpolation_is_refused(tmp_path, expr):
    """Includes a computed table name (`CREATE TABLE IF NOT EXISTS ${tableName}`), which can
    only arrive through an interpolation and must never be dropped silently."""
    body = _ddl("sat_one") + "\nCREATE TABLE IF NOT EXISTS ${" + expr + "} (y TEXT);"
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(body)})
    with pytest.raises(AssertionError, match="interpolates"):
        _tables(dist)


def test_a_splice_of_a_table_the_main_constant_lacks_is_refused(tmp_path):
    body = _ddl("sat_one") + "\n" + _SPLICE % '"ghost"'
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(body)})
    with pytest.raises(AssertionError, match="ghost"):
        _tables(dist)


def test_a_table_name_that_is_not_a_bare_identifier_is_refused_not_dropped(tmp_path):
    body = _ddl("sat_one") + "\nCREATE TABLE IF NOT EXISTS " + '"quoted one"' + " (y TEXT);"
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(body)})
    with pytest.raises(AssertionError, match="not a bare identifier"):
        _tables(dist)


def test_a_nested_template_inside_an_interpolation_does_not_end_the_literal_early(tmp_path):
    body = _ddl("sat_one") + "\n" + _SPLICE % "`b_main`" + "\n" + _ddl("sat_two")
    dist = _write_dist(tmp_path, {"a.mjs": _sat_template(body)})
    assert _tables(dist)[_SAT]["tables"] == ["sat_one", "sat_two"]


def test_copies_in_different_spellings_that_agree_are_one_definition(tmp_path):
    readable = f"const {_SAT} = `{_ddl('sat_one')}\n" + _SPLICE % '"a_main"' + "\n`;\n"
    minified = f"x=1,{_SAT}=`{_ddl('sat_one')}\n" + (_SPLICE % "`a_main`").replace(", ", ",") + "\n`,y=2;\n"
    dist = _write_dist(tmp_path, {"a.mjs": readable, "worker/w.mjs": minified})
    got = _tables(dist)
    assert got[_SAT]["copies"] == 2 and got[_SAT]["bundle"] == "a.mjs"


def test_copies_that_disagree_fail_loudly(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": _sat_template(_ddl("sat_one")),
        "b.mjs": _sat_template(_ddl("sat_other")),
    })
    with pytest.raises(AssertionError, match="DIFFERENT schemas"):
        _tables(dist)


def test_an_allowlisted_constant_the_dist_no_longer_defines_fails_loudly(tmp_path):
    dist = _write_dist(tmp_path, {"a.mjs": "const unrelated = 1;\n"})
    with pytest.raises(AssertionError, match="allowlisted"):
        _tables(dist)


def test_a_double_quoted_satellite_is_read_too(tmp_path):
    dist = _write_dist(tmp_path, {
        "a.mjs": f'const {_SAT} = "{_ddl("sat_one")}\\n";\n'})
    assert _tables(dist)[_SAT]["tables"] == ["sat_one"]


def test_the_if_not_exists_keyword_is_never_read_as_a_table_name():
    assert _CREATE_TABLE_NAMED_RE.findall("CREATE TABLE IF NOT EXISTS ${name} (x)") == []
    both = f"CREATE TABLE IF NOT EXISTS {'t1'} (x); CREATE TABLE {'t2'} (y)"
    assert _CREATE_TABLE_NAMED_RE.findall(both) == ["t1", "t2"]


def test_the_header_block_carries_provenance_without_touching_the_data_lines():
    block = _satellite_header_block({"X_SCHEMA_SQL": {
        "tables": ["t1"], "adds": ["t1"], "bundle": "x-ABC.mjs", "copies": 2}})
    assert all(line.startswith("#") for line in block.splitlines())
    assert "X_SCHEMA_SQL" in block and "x-ABC.mjs" in block and "adds: t1" in block


def test_every_allowlisted_name_is_absent_from_the_exclusions():
    lists = (_STATE_SATELLITE_CONSTANTS, _STATE_REDECLARING_CONSTANTS, _STATE_DERIVED_CONSTANTS,
             _STATE_EXCLUDED_CONSTANTS)
    names = [n for lst in lists for n in lst]
    assert len(names) == len(set(names)), "a constant is classified twice"
    assert all(v for lst in lists for v in lst.values()), "every entry needs its evidence/reason"


def test_the_shipped_baseline_lists_the_satellite_only_tables():
    """Always-on: the three tables that motivated C-679 are in the shipped file."""
    _, names = _read_vendor_table_baseline()
    assert {"user_profiles", "user_profile_emails",
            "worker_environment_session_attachments"} <= set(names)


# --------------------------------------------------------------------------------------
# LOCAL-ONLY: the live state database against the generated set.
# --------------------------------------------------------------------------------------

_LIVE_STATE_DB = REAL_HOME / ".openclaw" / "state" / "openclaw.sqlite"


# Tables a database created by an OLDER build still holds although the installed build no
# longer declares them: the vendor stopped using them and nothing drops them. They are not a
# classification gap, so the backstop below must not read them as one. Each entry names the
# measurement that retired it; an entry that the installed dist declares again fails
# `test_a_lingering_table_is_really_not_declared`.
_LINGERING_RETIRED_TABLES = {
    "fleet_cells": "2026.10.5: no longer declared; its only readers (registry.worker) are gone "
                   "from dist (still present in 2026.10.4); the live database keeps the table",
}


def _live_state_tables() -> set:
    conn = sqlite3.connect(f"file:{_LIVE_STATE_DB}?mode=ro", uri=True)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
            if r[0] not in _LINGERING_RETIRED_TABLES}
    finally:
        conn.close()


def test_a_lingering_table_is_really_not_declared():
    """Control for the allowance above: a table listed as retired must be absent from the
    generated vendor set, or the allowance is hiding a live table."""
    _, names = _read_vendor_table_baseline()
    assert not (set(_LINGERING_RETIRED_TABLES) & set(names))


def _require_live_state_db() -> Path:
    if not OPENCLAW_DIST.is_dir() or not _LIVE_STATE_DB.is_file():
        pytest.skip("no installed OpenClaw dist / live state database -- this backstop is local-only")
    return _LIVE_STATE_DB


def test_the_live_state_database_has_no_table_the_baseline_lacks():
    """LOCAL-ONLY backstop. It only sees tables a feature has ALREADY created on this machine
    (25 declared tables do not exist here yet), so a clean run proves the generated set is not
    missing a table that exists, never that the set is complete. It would have named
    user_profiles, user_profile_emails and worker_environment_session_attachments."""
    _require_live_state_db()
    _, names = _read_vendor_table_baseline()
    unknown, _ = _table_set_delta(_live_state_tables(), names)
    assert not unknown, (
        f"live state tables missing from vendor_state_tables.txt: {unknown}. A satellite schema "
        "constant is probably unread -- classify it in test_state_schema_grounding.py "
        "(_STATE_SATELLITE_CONSTANTS / _STATE_EXCLUDED_CONSTANTS), then regenerate.")


def test_the_backstop_fails_when_a_satellite_table_is_removed_from_the_set():
    """Positive control: the same comparison, with a satellite table dropped, must report it."""
    _require_live_state_db()
    _, names = _read_vendor_table_baseline()
    live = _live_state_tables()
    victim = "user_profiles"
    assert victim in live, "the control needs a live satellite table to remove"
    missing, _ = _table_set_delta(live, [n for n in names if n != victim])
    assert missing == [victim]


def test_the_installed_dist_classifies_every_schema_constant_and_matches_the_baseline():
    """LOCAL-ONLY: an unclassified constant in the real dist raises here."""
    if not OPENCLAW_DIST.is_dir():
        pytest.skip("OpenClaw dist not installed -- local-only")
    surface, provenance, _ = _vendor_state_table_surface(OPENCLAW_DIST)
    _, names = _read_vendor_table_baseline()
    assert set(provenance) == set(_STATE_SATELLITE_CONSTANTS)
    assert _table_set_delta(surface, names) == ([], [])
