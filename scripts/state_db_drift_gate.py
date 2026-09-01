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
  schema walk, not this gate.
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
    """Yield (path, sql) for every literal passed to `.execute()`/`.executemany()`.

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
                yield path, sql


def expected_reads(pkg_root: Path) -> dict[str, list]:
    """table -> list of {"columns": set, "site": str}, ONE ENTRY PER SELECT.

    Grouping per statement rather than per table is what makes a dual-shape
    reader legible. A reader that supports both the modern and the legacy schema
    necessarily names the legacy columns in one of its branches; if the columns
    of every branch were merged into one set per table, that reader would report
    drift forever on both builds, and the gate would be crying wolf about the
    very fix it asked for. The real question is not "does every column we ever
    name still exist" but "is there a statement that can still read this table".
    """
    found: dict[str, list] = {}
    for path, text in _executed_sql(pkg_root):
        if "SELECT" not in text.upper():
            continue
        for match in _SELECT_RE.finditer(text):
            collist, table = match.group(1), match.group(2)
            columns = set()
            if "*" not in collist:
                columns = {i for i in _IDENT_RE.findall(collist)
                           if i.lower() not in _SQL_NOISE}
            found.setdefault(table, []).append(
                {"columns": columns, "site": path.name})
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

    absent_tables, absent_columns, dual_shape = [], [], []
    for table in sorted(expected):
        statements = expected[table]
        sites = ", ".join(sorted({s["site"] for s in statements}))
        if table not in live:
            absent_tables.append((table, sites))
            continue
        # Per statement: which of its named columns are gone on this build.
        gaps = [sorted(c for c in s["columns"] if c not in live[table])
                for s in statements]
        if any(not gap for gap in gaps):
            # At least one statement is fully satisfiable, so the table IS
            # readable here. If another statement is not, that is the legacy
            # branch of a dual-shape reader doing its job, not drift.
            if any(gap for gap in gaps):
                dual_shape.append((table, sites))
            continue
        # No statement can be satisfied -- the reader is blind on this build.
        widest = min(gaps, key=len)
        absent_columns.append((table, widest, sites))

    print(f"state database : {db_path}")
    print(f"package        : {pkg_root}")
    print(f"tables we read : {len(expected)}   tables present: {len(live)}")
    print()

    for table, sites in dual_shape:
        print(f"dual-shape     {table} ({sites}) - one branch reads this build, "
              "another names columns it does not have. Expected for a reader that "
              "supports more than one OpenClaw generation; not drift.")
    if dual_shape and not (absent_tables or absent_columns):
        print()

    if not absent_tables and not absent_columns:
        print(f"OK - every one of the {len(expected)} tables we SELECT from exists, "
              "and each has at least one statement this build can satisfy.")
        return 0

    for table, sites in absent_tables:
        print(f"TABLE ABSENT   {table}")
        print(f"               read from: {sites}")
        print("               -> bucket B: the table was renamed or retired. Find its "
              "successor in the dist before changing any reader.")
    for table, missing, sites in absent_columns:
        print(f"COLUMNS ABSENT {table}: {', '.join(missing)}")
        print(f"               read from: {sites}")
        print("               -> bucket B: check whether the data moved into a JSON "
              "column on the same table before assuming it is gone.")
    print()
    print(f"DRIFT: {len(absent_tables)} absent table(s), "
          f"{len(absent_columns)} table(s) with absent columns.")
    print("A reader hitting either case renders no verdict about a surface that may "
          "well be populated.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
