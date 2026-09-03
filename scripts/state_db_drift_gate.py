#!/usr/bin/env python3
"""State-DB drift gate: the fourth oracle for an OpenClaw upgrade.

The upgrade protocol's three oracles -- the generated JSON-Schema path diff, the
vendor's retired-path lists, and its migration log -- all read the CONFIG schema.
OpenClaw's state SQLite is a SECOND, INDEPENDENT schema, and nothing watched it.

That gap is not theoretical. On the 2026.8.1 -> 2026.8.2 upgrade the config schema
diff came back +0/-0 (5254 paths both sides, byte-identical but for the header
stamp), and the conclusion drawn from it -- "the config schema did not move, so
nothing else needed changing" -- was wider than the measurement supported. On that
same build four collector readers were broken: `cron_jobs` and `subagent_runs` had
folded columns into JSON blobs, and `cron_run_logs` and `installed_plugin_index`
were gone outright. Three enabled cron jobs sat unread while B168 reported UNKNOWN.

The general form, worth stating once: A GREEN ORACLE IS EVIDENCE ONLY ABOUT THE
SURFACE THAT ORACLE READS.

    python3 scripts/state_db_drift_gate.py            # audit the installed state DB
    python3 scripts/state_db_drift_gate.py --db PATH  # audit a specific database

Exit codes: 0 = no drift, 1 = drift found, 2 = could not run the comparison.

WHY THE EXPECTATIONS ARE DERIVED FROM SOURCE AND NOT LISTED HERE
----------------------------------------------------------------
A hand-maintained list of "tables we read" would rot exactly the way the test
fixtures did: `tests/test_b296_subagent_runs_disclosure.py` carries the comment
"Column list + types copied verbatim from the dist CREATE TABLE so the fixture
cannot drift", and it drifted, because copying once is not a guard. So this script
parses `clawseccheck/` and extracts the SELECT statements the code ACTUALLY issues.
Anchor a guard on the producer, never on a second hand-written copy of it.

The extraction walks the AST and takes ONLY strings passed to `.execute()`. Two
weaker versions were tried and both over-reported: a regex over the raw text found
eight phantom tables ("THE", "these") picked up from comments, and walking every
string constant still found two ("C", "well") from prose inside docstrings and
user-facing messages. Only a string actually handed to sqlite3 is a query. Python
concatenates adjacent literals at parse time, so a SELECT split across source lines
arrives as a single constant and needs no re-joining.

WHAT THIS CANNOT CATCH
----------------------
* A table we do not read at all -- a NEW surface. That is bucket C and needs the
  schema walk, not this gate. Its column-level twin IS reported: a column on a
  table we already read that no statement of ours selects is listed as `unread col`
  and routed to the same bucket. That half was silently missing until 2026-09-03,
  which made this gate an instance of the very thing it was built to expose --
  green about the surface it models, mute about the one it does not.
  Note what `unread col` does NOT claim: not that the column is NEW. This gate has
  no baseline of a previous build, so it cannot separate "appeared in this upgrade"
  from "never read since the reader was written". It reports present-tense coverage,
  and the operator supplies the time axis by diffing two runs.
* A column that still exists but changed MEANING or units.
* A query built by string interpolation at runtime rather than a literal.
* Drift on a machine whose state DB has not yet been migrated by the new build:
  the DB migrates on first run, so audit AFTER launching the upgraded OpenClaw.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sqlite3
import sys
from pathlib import Path

# SELECT ... FROM <table>. DOTALL because a literal may span lines.
_SELECT_RE = re.compile(r"SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_]*)", re.I | re.S)
# Bare identifiers inside the column list, minus SQL noise words.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SQL_NOISE = {
    "select", "from", "where", "count", "min", "max", "sum", "total", "distinct",
    "as", "and", "or", "not", "null", "is", "in", "like", "order", "by", "group",
    "limit", "offset", "asc", "desc", "case", "when", "then", "else", "end",
    "join", "left", "inner", "outer", "on", "union", "all", "coalesce", "cast",
}


def _static_str(node):
    """The statically-known text of a str literal or f-string, else None.

    An f-string contributes its literal segments only; a `{value}` placeholder
    becomes a space, so an interpolated table name can never be mistaken for a
    real one. `collector.py` builds one query this way.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
            else:
                parts.append(" ")
        return "".join(parts)
    return None


def _executed_sql(root: Path):
    """Yield (path, sql, enclosing_function) per `.execute()`/`.executemany()` literal.

    Anchoring on the CALL, not on every string in the file, is what makes this
    sound. An earlier version walked all string constants and reported tables
    named "C" and "well" -- prose inside docstrings and user-facing messages that
    happened to contain "select ... from ...". Only a string that is actually
    handed to sqlite3 is a query.
    """
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError:
            continue
        # Remember the enclosing def for every node, so a statement can be
        # attributed to the reader that issues it. See `expected_reads`.
        enclosing = {}
        for parent in ast.walk(tree):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(parent):
                    enclosing.setdefault(child, parent.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in ("execute", "executemany"):
                continue
            if not node.args:
                continue
            sql = _static_str(node.args[0])
            if sql:
                yield path, sql, enclosing.get(node, "<module>")


def expected_reads(pkg_root: Path) -> dict[str, list]:
    """reader -> list of {"table", "columns", "site"}, ONE ENTRY PER SELECT.

    The unit of grouping is the READER FUNCTION, not the table, and that choice
    is what makes the gate correct on both kinds of vendor move.

    Grouping by table handles a dual-shape reader whose branches name the SAME
    table (`cron_jobs` old columns vs new) but CANNOT handle a rename: when
    `cron_run_logs` became `task_runs`, a per-table view saw only "a table we
    read is absent" and reported drift forever, even though the same function
    reads the successor two lines further down. A gate that cries wolf about the
    fix it asked for teaches people to ignore it.

    Asking instead "can this reader still read anything?" answers both. A
    function with at least one satisfiable statement can see its surface, however
    many retired names it also mentions; a function with none is blind. That is
    the question the gate exists to answer, and it needs no hand-maintained map
    of old name -> new name, which would rot exactly like the fixtures did.
    """
    found: dict[str, list] = {}
    for path, text, reader in _executed_sql(pkg_root):
        if "SELECT" not in text.upper():
            continue
        for match in _SELECT_RE.finditer(text):
            collist, table = match.group(1), match.group(2)
            columns = set()
            if "*" not in collist:
                columns = {i for i in _IDENT_RE.findall(collist)
                           if i.lower() not in _SQL_NOISE}
            # `SELECT *` and `SELECT COUNT(*)` both yield an empty column set,
            # and they are OPPOSITES for the reverse difference: the first reads
            # every column, the second reads none. Collapsing them would make the
            # gate announce a `SELECT *` reader's whole table as unread -- a lie,
            # in the one script written to catch exactly that kind of lie. No
            # reader uses `SELECT *` today (measured: 0); this is here so that the
            # day one does, the gate stays honest instead of quietly inverting.
            found.setdefault(f"{path.name}:{reader}", []).append(
                {"table": table, "columns": columns, "site": path.name,
                 "reads_all": collist.strip() == "*"})
    return found


def live_schema(db_path: Path) -> dict[str, set]:
    """table -> set(columns), read strictly read-only."""
    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.execute("PRAGMA query_only = 1")
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        return {t: {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}
                for t in tables}
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", type=Path, default=None,
                    help="state database (default: ~/.openclaw/state/openclaw.sqlite)")
    ap.add_argument("--package", type=Path, default=None,
                    help="package root to scan (default: ./clawseccheck)")
    args = ap.parse_args()

    db_path = args.db or Path(
        os.environ.get("OPENCLAW_HOME", Path.home() / ".openclaw")
    ) / "state" / "openclaw.sqlite"
    pkg_root = args.package or Path(__file__).resolve().parent.parent / "clawseccheck"

    if not pkg_root.is_dir():
        print(f"cannot scan: {pkg_root} is not a directory", file=sys.stderr)
        return 2
    if not db_path.is_file():
        print(f"cannot compare: no state database at {db_path}", file=sys.stderr)
        print("Run this on a machine with OpenClaw installed and launched at least once.",
              file=sys.stderr)
        return 2

    expected = expected_reads(pkg_root)

    # Positive control. An extractor that silently matches nothing would otherwise
    # print a clean bill of health -- the failure mode this gate exists to prevent.
    if not expected:
        print("cannot compare: extracted ZERO SELECT statements from "
              f"{pkg_root} -- the extractor is broken, not the schema clean",
              file=sys.stderr)
        return 2

    live = live_schema(db_path)

    blind, dual_shape = [], []
    for reader in sorted(expected):
        statements = expected[reader]

        def _unsatisfied(stmt):
            """What stops this statement running here: a table, or columns."""
            table = stmt["table"]
            if table not in live:
                return f"table '{table}' does not exist"
            missing = sorted(c for c in stmt["columns"] if c not in live[table])
            if missing:
                return f"{table} is missing {', '.join(missing)}"
            return None

        reasons = [_unsatisfied(s) for s in statements]
        if any(r is None for r in reasons):
            # At least one statement runs, so this reader can see its surface.
            # The statements that cannot are its other-generation branches.
            if any(r for r in reasons):
                dual_shape.append((reader, [r for r in reasons if r]))
            continue
        blind.append((reader, sorted(set(reasons))))

    # The column half of bucket C. The docstring's first limit routes a table we do
    # not read AT ALL to the schema walk, so that gap has a home. A column we do not
    # read on a table we DO had none -- the one spec item this gate dropped, and the
    # same shape the gate exists to catch: green about the surface it models, silent
    # about the one it does not. Advisory, never fatal: a column we do not read has
    # not broken anything we do read, so it must not turn a clean build red. And it
    # is deliberately NOT called "new": with no baseline of the previous build, this
    # cannot tell an upgrade's addition from a column never read since day one.
    read_columns: dict = {}
    reads_all = set()
    for statements in expected.values():
        for stmt in statements:
            if stmt["table"] not in live:
                continue
            if stmt.get("reads_all"):
                reads_all.add(stmt["table"])
            read_columns.setdefault(stmt["table"], set()).update(stmt["columns"])
    grew = []
    for table in sorted(read_columns):
        if table in reads_all:
            continue
        added = sorted(live[table] - read_columns[table])
        if added:
            grew.append((table, added))

    print(f"state database : {db_path}")
    print(f"package        : {pkg_root}")
    print(f"state-DB readers: {len(expected)}   tables present: {len(live)}")
    print()

    for reader, reasons in dual_shape:
        print(f"dual-shape  {reader}")
        for reason in reasons:
            print(f"            other-generation branch: {reason}")
        print("            -> reads this build via another statement. Not drift.")
    for table, added in grew:
        print(f"unread col  {table}: {', '.join(added)}")
        print("            -> bucket C, on a table we already read. Nothing we read "
              "broke, so this is not drift -- but confirm none of these carries a "
              "signal we should be reading before closing the upgrade.")
    if grew or (dual_shape and not blind):
        print()

    if not blind:
        print(f"OK - each of the {len(expected)} state-DB readers has at least one "
              "statement this build can satisfy.")
        if grew:
            print(f"     Not silent about the rest: {len(grew)} table(s) we read "
                  "carry columns no statement of ours selects (above). Bucket C, "
                  "not drift.")
        return 0

    for reader, reasons in blind:
        print(f"BLIND       {reader}")
        for reason in reasons:
            print(f"            {reason}")
        print("            -> bucket B: find the successor in the dist before "
              "changing the reader. If the data moved into a JSON column on the "
              "same table, it is a re-map, not a loss.")
    print()
    print(f"DRIFT: {len(blind)} reader(s) cannot run a single statement on this build.")
    print("Each renders no verdict about a surface that may well be populated.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
