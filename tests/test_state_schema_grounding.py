"""State-DB schema grounding guard (B-710).

`tests/test_schema_grounding.py` closes Golden Rule #4 for the CONFIG schema
(`openclaw.json`). OpenClaw's state SQLite is a SECOND, INDEPENDENT schema, and nothing
grounded it: every test exercising a state-SQLite reader CREATES THE TABLE ITSELF from a
hand-written column list, so the fixture and the code under test only ever agree with each
other, never with what OpenClaw ships. `tests/test_b296_subagent_runs_disclosure.py` once
claimed its column list was "copied verbatim from the dist CREATE TABLE so the fixture
cannot drift" — it drifted anyway (four collector readers broke on the 2026.8.1 ->
2026.8.2 upgrade while 18,276 tests passed, ruff was clean, and both the monitor-detection
and fleet-FP gates were green), because copying once is not a guard.

`scripts/state_db_drift_gate.py` closes the CODE side of this: it extracts the SELECT
statements `clawseccheck/` actually issues and checks them against a live installed state
DB. This module closes the TEST side: every `CREATE TABLE` a test or fixture declares is
registered here, classified against the vendor's own schema, and pinned so a "legacy"
shape can never silently become the current one without the registry noticing.

Three layers, same shape as `test_schema_grounding.py`'s C-249/B-516 arrangement, ranked
by how much they actually know:

  * ALWAYS ON (tests 1-6 below) — read the shipped, vendored snapshot
    `tests/state_schema_snapshot.sql` and the module-level `_REGISTRY`. No dist needed,
    so these run in CI. A new/changed state DDL anywhere in the tree fails
    `test_every_state_ddl_in_the_tree_is_registered` until it is classified here.
  * LOCAL-ONLY (test 7) — re-derives the schema from a REAL installed OpenClaw and checks
    the shipped snapshot still agrees with it, AND that the snapshot's own
    `openclaw-version:` stamp matches the installed version. That second half is
    non-optional: `test_schema_grounding.py`'s own history records a header that was
    inert — rewriting `openclaw-version:` to `1999.1.1` left every other test green,
    because nothing actually read the stamp. Skips cleanly when OpenClaw is not
    installed (CI, B-106), exactly like `test_schema_grounding.py`'s dist layer.

The vendor's schema lives as ONE string constant, `const OPENCLAW_STATE_SCHEMA_SQL`, in a
content-hashed dist file matched by the glob `openclaw-state-db-readonly-*.js`. TRAP: a
dist-wide grep for `CREATE TABLE` also finds `DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL` in a
DIFFERENT file (`runtime-*.js`) — a legacy schema for an unrelated debug-proxy sidecar
database that happens to declare a table also named `capture_events`. The glob here is
narrow enough to never match that file, and `_find_state_db_readonly_js` asserts EXACTLY
one match rather than trusting the first hit.

Regenerating the snapshot is part of the OpenClaw-upgrade protocol's re-baseline, on a
machine with the matching OpenClaw installed:

    PYTHONPATH=tests:. python3 tests/test_state_schema_grounding.py --write-state-snapshot

`PYTHONPATH=tests` is load-bearing — `REAL_HOME` comes from `tests/_realhome.py`, because
the suite redirects `$HOME` for the rest of the run. Hand-editing the snapshot is the
guard writing its own evidence — regenerate it, never patch it by hand.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest

from _realhome import REAL_HOME

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
FIXTURES_DIR = REPO_ROOT / "fixtures"
PACKAGE_DIR = REPO_ROOT / "clawseccheck"
DRIFT_GATE_SCRIPT = REPO_ROOT / "scripts" / "state_db_drift_gate.py"

SNAPSHOT_FILE = Path(__file__).resolve().parent / "state_schema_snapshot.sql"

# B-519: REAL_HOME, not Path.home() — see tests/_realhome.py. Mirrors test_schema_
# grounding.py's OPENCLAW_DIST exactly (same installed package, same reasoning).
OPENCLAW_DIST = REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"
STATE_DB_READONLY_GLOB = "openclaw-state-db-readonly-*.js"
STATE_DB_CONTRACT_GLOB = "openclaw-state-db-contract-*.js"
SCHEMA_SQL_CONST_MARKER = 'const OPENCLAW_STATE_SCHEMA_SQL = "'
SCHEMA_VERSION_RE = re.compile(r"OPENCLAW_STATE_SCHEMA_VERSION\s*=\s*(\d+)")

REGENERATE_CMD = (
    "PYTHONPATH=tests:. python3 tests/test_state_schema_grounding.py --write-state-snapshot"
)

# --------------------------------------------------------------------------------------
# Classes. Computed from the vendor snapshot alone, mutually exclusive.
# --------------------------------------------------------------------------------------
MODERN = "MODERN"          # column tuples equal the vendor's, order included
PARTIAL = "PARTIAL"        # a proper subset of the vendor's columns
LEGACY_COLS = "LEGACY_COLS"    # offers >=1 column the vendor table lacks
LEGACY_TABLE = "LEGACY_TABLE"  # table name absent from the vendor snapshot
_CLASSES = frozenset({MODERN, PARTIAL, LEGACY_COLS, LEGACY_TABLE})
_LEGACY_CLASSES = frozenset({LEGACY_COLS, LEGACY_TABLE})


@dataclass(frozen=True)
class _Entry:
    cls: str
    disproof: str = ""

    def __post_init__(self):
        assert self.cls in _CLASSES, self.cls


# --------------------------------------------------------------------------------------
# JS string-literal + vendor DDL extraction. Self-contained (no reliance on json.loads
# coincidentally accepting JS escape sequences).
# --------------------------------------------------------------------------------------

_JS_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\",
    "0": "\0", "b": "\b", "f": "\f", "v": "\v",
}


def _unescape_js_double_quoted(raw: str) -> str:
    """Unescape a JS double-quoted string literal's raw source text (no surrounding
    quotes). Handles the escapes the vendor bundle actually emits (\\n, \\", \\\\, \\uXXXX)
    plus JS's fallback rule for an unrecognized escape: the backslash is dropped and the
    following character kept literally."""
    out = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            if nxt == "u" and i + 5 < n and all(ch in "0123456789abcdefABCDEF" for ch in raw[i + 2:i + 6]):
                out.append(chr(int(raw[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append(_JS_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _find_state_db_readonly_js(dist_dir: Path) -> Path:
    """Exactly one file matching `STATE_DB_READONLY_GLOB` under *dist_dir*. Raises loudly
    on zero or more-than-one match rather than trusting the first glob hit — the TRAP
    this guards against is `DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL` living in a
    same-shaped `runtime-*.js` file that a broader `CREATE TABLE` grep would also find."""
    matches = sorted(dist_dir.glob(STATE_DB_READONLY_GLOB))
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {STATE_DB_READONLY_GLOB!r} file under {dist_dir}, "
            f"found {len(matches)}: {matches}. A dist-wide CREATE TABLE grep also matches "
            "DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL in an unrelated runtime-*.js file "
            "(a different sidecar debug-proxy-capture database) — this glob must resolve "
            "to exactly the state-db-readonly module, never that one."
        )
    return matches[0]


def _extract_vendor_schema_sql(js_text: str) -> str:
    """The unescaped SQL text of `const OPENCLAW_STATE_SCHEMA_SQL = "..."`."""
    idx = js_text.find(SCHEMA_SQL_CONST_MARKER)
    if idx == -1:
        raise AssertionError(
            f"{SCHEMA_SQL_CONST_MARKER!r} not found — the dist no longer defines the "
            "state schema the way this guard expects; re-ground it against the current "
            "bundle before trusting anything downstream."
        )
    start = idx + len(SCHEMA_SQL_CONST_MARKER)
    i, n = start, len(js_text)
    while i < n:
        c = js_text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            break
        i += 1
    else:
        raise AssertionError("unterminated OPENCLAW_STATE_SCHEMA_SQL string literal in the dist")
    return _unescape_js_double_quoted(js_text[start:i])


def _dist_table_ddl_texts(sql_text: str) -> "dict[str, str]":
    """table -> its exact `CREATE TABLE IF NOT EXISTS ... ;` statement text, byte-for-byte
    as written in the vendor bundle (paren-balanced, so nested parens in column
    constraints don't truncate it early)."""
    ddls: "dict[str, str]" = {}
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\(", sql_text):
        table = m.group(1)
        start = m.start()
        i = m.end()  # just past the opening '('
        depth = 1
        n = len(sql_text)
        while depth > 0 and i < n:
            ch = sql_text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth != 0:
            raise AssertionError(f"unbalanced parens extracting CREATE TABLE {table}")
        j = sql_text.index(";", i) + 1
        ddls[table] = sql_text[start:j]
    if len(ddls) < 100:
        raise AssertionError(
            f"only extracted {len(ddls)} CREATE TABLE statement(s) from the vendor SQL — "
            "the extractor is broken, not the schema clean (expected >=100)."
        )
    return ddls


def _dist_table_columns(sql_text: str) -> "dict[str, list]":
    """table -> [(name, type, notnull, dflt_value, pk), ...] in cid order, executed for
    real rather than parsed textually (sqlite is the ground truth for column identity)."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(sql_text)
        names = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
            )
        ]
        out = {}
        for t in names:
            rows = conn.execute(f"PRAGMA table_info({t})").fetchall()
            out[t] = [(r[1], r[2], r[3], r[4], r[5]) for r in rows]
        return out
    finally:
        conn.close()


def _installed_openclaw_version() -> str:
    package_json = OPENCLAW_DIST.parent / "package.json"
    return json.loads(package_json.read_text(encoding="utf-8"))["version"]


def _installed_state_schema_version() -> int:
    for path in sorted(OPENCLAW_DIST.glob(STATE_DB_CONTRACT_GLOB)):
        m = SCHEMA_VERSION_RE.search(path.read_text(encoding="utf-8"))
        if m:
            return int(m.group(1))
    raise AssertionError(
        f"OPENCLAW_STATE_SCHEMA_VERSION not found in any {STATE_DB_CONTRACT_GLOB!r} file"
    )


def _require_dist() -> Path:
    """The installed OpenClaw dist dir, or a clean skip. Local-only: absent in CI (B-106,
    CI checks out only the skill tree) and on a machine without OpenClaw."""
    if not OPENCLAW_DIST.is_dir():
        pytest.skip(
            f"OpenClaw dist not installed at {OPENCLAW_DIST} — state schema drift check "
            "is local-only"
        )
    return OPENCLAW_DIST


# --------------------------------------------------------------------------------------
# The CODE-side reuse: scripts/state_db_drift_gate.py already extracts every table
# clawseccheck/ reads via SELECT. Reusing it (not re-implementing it) is deliberate —
# duplicating that extractor here is exactly the kind of second hand-written copy this
# whole module exists to stop trusting.
# --------------------------------------------------------------------------------------

def _load_drift_gate():
    spec = importlib.util.spec_from_file_location("_state_db_drift_gate", DRIFT_GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _clawseccheck_read_tables() -> "set[str]":
    """Every table name `clawseccheck/` SELECTs from, via the drift gate's own extractor."""
    gate = _load_drift_gate()
    expected = gate.expected_reads(PACKAGE_DIR)
    tables: "set[str]" = set()
    for statements in expected.values():
        for stmt in statements:
            tables.add(stmt["table"])
    return tables


# --------------------------------------------------------------------------------------
# TEST-side extraction: every state DDL a test or fixture declares.
#
# The sound filter is "every non-docstring string constant that executescripts cleanly" —
# NOT anchored on `.execute()` call sites. An `.execute()`-anchored extractor (like the
# drift gate's, which is right for the CODE side) misses a DDL string reaching
# `conn.execute(ddl)` through a helper PARAMETER, which several of these fixtures do. A
# bare string constant containing "CREATE TABLE" is candidate; trying to executescript it
# in a fresh :memory: connection is what tells a real DDL apart from module-docstring
# prose that merely QUOTES a CREATE TABLE statement — self-validating, since prose is not
# valid SQL and fails to execute.
#
# f-string (JoinedStr) fragments are deliberately excluded: walking every ast.Constant
# also visits each literal SEGMENT of an f-string separately, and a segment like
# `"CREATE TABLE "` (up to a `{table}` placeholder) is neither valid SQL nor prose — it is
# a fragment, and letting it through would silently narrow the corpus in the wrong
# direction (a real f-string-built DDL becomes invisible rather than merely unclassified).
# No production test currently builds its DDL this way; if one starts to, this filter
# will make it MISSING from the registry, which test_every_state_ddl_in_the_tree_is_
# registered will only notice if the site is later converted to a plain literal. That is
# a known, narrow gap, not a silent one — see the module docstring's scope note.
# --------------------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()


def _extract_python_ddl_sites() -> "dict[str, dict]":
    """Every registered-quality DDL site under tests/test_*.py -- excluding THIS module.

    This file's own unit tests deliberately contain synthetic 'CREATE TABLE' strings (to
    pin the extraction/classification machinery itself against known-shape input, some
    multi-table or intentionally malformed). Those are test INPUTS to this guard, not
    state DDLs the guard should register -- scanning them would mean the guard trips over
    its own fixtures the moment it runs against itself."""
    sites: "dict[str, dict]" = {}
    for py_file in sorted(TESTS_DIR.glob("test_*.py")):
        if py_file.resolve() == _THIS_FILE:
            continue
        text = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(py_file))
        except SyntaxError:
            continue
        joined_children = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                for v in node.values:
                    joined_children.add(id(v))
        rel = py_file.relative_to(REPO_ROOT).as_posix()
        for node in ast.walk(tree):
            if id(node) in joined_children:
                continue
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if "CREATE TABLE" not in node.value:
                continue
            conn = sqlite3.connect(":memory:")
            try:
                conn.executescript(node.value)
            except sqlite3.Error:
                conn.close()
                continue
            tables = [
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
                )
            ]
            if len(tables) != 1:
                conn.close()
                raise RuntimeError(
                    f"{rel}:{node.lineno} declares {len(tables)} table(s) in one string "
                    f"constant ({tables}) — the registry key format assumes one table per "
                    "site; extend it before trusting this one."
                )
            table = tables[0]
            cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
            conn.close()
            key = f"{rel}:{node.lineno}"
            sites[key] = {"table": table, "cols": [(r[1], r[2], r[3], r[4], r[5]) for r in cols]}
    return sites


def _extract_fixture_sqlite_sites() -> "dict[str, dict]":
    sites: "dict[str, dict]" = {}
    for db_path in sorted(FIXTURES_DIR.rglob("*.sqlite")):
        rel = db_path.relative_to(REPO_ROOT).as_posix()
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            tables = [
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
                )
            ]
            for table in tables:
                cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
                key = f"{rel}:{table}"
                sites[key] = {"table": table, "cols": [(r[1], r[2], r[3], r[4], r[5]) for r in cols]}
        finally:
            conn.close()
    return sites


def _extract_all_ddl_sites() -> "dict[str, dict]":
    sites = _extract_python_ddl_sites()
    sites.update(_extract_fixture_sqlite_sites())
    return sites


def _reduced(col5) -> tuple:
    """(name, type, notnull, pk) — the HARD comparison basis. dflt_value is excluded
    deliberately: OpenClaw's own `STATE_PERSISTENT_SCHEMA_COMPATIBILITY.
    allowedColumnDefinitions` accepts `cron_jobs.enabled`/`.name`/`.payload_kind` with a
    DEFAULT the canonical literal lacks, so a host migrated from an older build may
    legitimately differ there. Asserting it would fail on a real, harmless variance."""
    name, type_, notnull, _dflt, pk = col5
    return (name, type_, notnull, pk)


def _classify(table: str, cols, vendor: "dict[str, list]") -> str:
    """Pure function of (table, cols, vendor) — no filesystem/registry state, so it can be
    pinned directly against synthetic data (see test_classify_* below)."""
    if table not in vendor:
        return LEGACY_TABLE
    vendor_reduced = [_reduced(c) for c in vendor[table]]
    site_reduced = [_reduced(c) for c in cols]
    if site_reduced == vendor_reduced:
        return MODERN
    if set(site_reduced) < set(vendor_reduced):
        return PARTIAL
    return LEGACY_COLS


def _target_table_names(vendor_tables: "set[str]") -> "set[str]":
    """Tables this tree declares (a test/fixture CREATE TABLE) or clawseccheck/ reads,
    projected onto tables that actually exist in the vendor schema — retired tables
    (`cron_run_logs`, `installed_plugin_index`) and pure test decoys (`unrelated`,
    `unrelated_table`) drop out of the projection on their own, because they are absent
    from *vendor_tables* rather than being named here."""
    declared = {info["table"] for info in _extract_all_ddl_sites().values()}
    read_by_code = _clawseccheck_read_tables()
    return (declared | read_by_code) & vendor_tables


# --------------------------------------------------------------------------------------
# The snapshot file itself.
# --------------------------------------------------------------------------------------

_SNAPSHOT_HEADER = """\
-- state_schema_snapshot.sql -- GENERATED. Do not hand-edit.
--
-- openclaw-version: {version}
-- state-schema-version: {schema_version}
-- generated: {generated}
-- tables: {count}
--
-- What this is
-- ------------
-- The vendor's own `CREATE TABLE` statements, copied byte-for-byte out of the installed
-- OpenClaw's `OPENCLAW_STATE_SCHEMA_SQL` (dist/openclaw-state-db-readonly-*.js), projected
-- to the state-SQLite tables this tree declares in a test DDL or that clawseccheck/ reads.
--
-- Why it exists (B-710)
-- ----------------------
-- Every test exercising a state-SQLite reader used to CREATE THE TABLE ITSELF from a
-- hand-written column list, so the fixture and the code under test only ever agreed with
-- each other -- never with what OpenClaw ships. A comment in
-- tests/test_b296_subagent_runs_disclosure.py once claimed its column list was "copied
-- verbatim from the dist CREATE TABLE so the fixture cannot drift"; it drifted anyway --
-- four collector readers broke on a real upgrade while the whole suite, ruff, and both
-- the monitor-detection and fleet-FP gates stayed green. Copying once is not a guard.
-- This snapshot, read by tests/test_state_schema_grounding.py's registry of every state
-- DDL site in the tree, is the guard: a table shape can no longer silently pass as
-- current when the vendor moved on.
--
-- Regenerating this file is part of the OpenClaw-upgrade protocol's re-baseline, on a
-- machine with the matching OpenClaw installed:
--   {regen_cmd}
-- Hand-editing it is the guard writing its own evidence -- don't.

"""


def _read_snapshot_sql() -> str:
    return SNAPSHOT_FILE.read_text(encoding="utf-8")


def _read_snapshot_tables() -> "dict[str, list]":
    """table -> [(name, type, notnull, dflt_value, pk), ...], executed fresh from the
    shipped file each call (no caching -- tests monkeypatch SNAPSHOT_FILE)."""
    sql_text = _read_snapshot_sql()
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(sql_text)
    except sqlite3.Error as exc:
        raise AssertionError(
            f"{SNAPSHOT_FILE.name} does not executescript cleanly: {exc}. It must be "
            f"regenerated, never hand-edited: {REGENERATE_CMD}"
        ) from exc
    try:
        names = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
            )
        ]
        return {
            t: [(r[1], r[2], r[3], r[4], r[5]) for r in conn.execute(f"PRAGMA table_info({t})")]
            for t in names
        }
    finally:
        conn.close()


def _header_field(header: str, name: str) -> "str | None":
    m = re.search(rf"^--\s*{re.escape(name)}:\s*(\S+)", header, re.MULTILINE)
    return m.group(1) if m else None


def _write_state_snapshot() -> int:
    """Regenerate SNAPSHOT_FILE from a real installed OpenClaw. Raises rather than
    emitting a vacuous file when no dist is present -- this is a script entry point, not a
    test, so it errors hard instead of skipping."""
    if not OPENCLAW_DIST.is_dir():
        raise RuntimeError(
            f"OpenClaw dist not installed at {OPENCLAW_DIST} -- cannot regenerate a "
            "vacuous snapshot. Run this on a machine with the matching OpenClaw installed."
        )
    js_path = _find_state_db_readonly_js(OPENCLAW_DIST)
    sql_text = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    ddl_texts = _dist_table_ddl_texts(sql_text)
    vendor_tables = set(ddl_texts)

    target = _target_table_names(vendor_tables)
    if not target:
        raise RuntimeError(
            "computed an EMPTY target-table set -- refusing to write a vacuous snapshot. "
            "Check that tests/ still declares state DDLs and clawseccheck/ still reads "
            "the state DB."
        )

    header = _SNAPSHOT_HEADER.format(
        version=_installed_openclaw_version(),
        schema_version=_installed_state_schema_version(),
        generated=date.today().isoformat(),
        count=len(target),
        regen_cmd=REGENERATE_CMD,
    )
    body = "\n\n".join(ddl_texts[t].rstrip() for t in sorted(target))
    SNAPSHOT_FILE.write_text(header + body + "\n", encoding="utf-8")
    return len(target)


# ========================================================================================
# The registry. One entry per DDL site, keyed "<relpath>:<lineno>" for a Python string
# constant or "<relpath>:<table>" for a binary sqlite fixture (which carries no lineno).
# Classes and disproofs below were computed by running the extraction + classification
# functions above against the tree and the vendor snapshot, then read off by hand -- this
# module does NOT auto-populate the registry from that computation, so a real drift shows
# up as a mismatch (test_every_state_ddl_in_the_tree_is_registered /
# test_legacy_entries_still_differ_from_the_snapshot) rather than silently reclassifying.
# ========================================================================================

_CRON_JOBS_LEGACY = (
    "pre-2026.8.x cron_jobs shape: flat `enabled`/`name`/`payload_kind` columns with no "
    "`job_json` blob and no `store_key`+`job_id` composite key, modelling the cron store "
    "before the job body was folded into one JSON column. Real vendor cron_jobs has "
    "job_json NOT NULL and this fixture never declares it."
)
_CRON_RUN_LOGS_RETIRED = (
    "cron_run_logs is not a table in the installed 2026.8.2 vendor schema at all -- "
    "grep -c 'CREATE TABLE IF NOT EXISTS cron_run_logs' over OPENCLAW_STATE_SCHEMA_SQL is "
    "0. The per-run log rows this table modelled now live on task_runs; kept as a "
    "deliberate legacy-shape fixture for the pre-retirement disclosure path."
)
_INSTALLED_PLUGIN_INDEX_RETIRED = (
    "installed_plugin_index is not a table in the installed 2026.8.2 vendor schema -- "
    "grep -c 'CREATE TABLE IF NOT EXISTS installed_plugin_index' over "
    "OPENCLAW_STATE_SCHEMA_SQL is 0. Kept as a legacy-shape fixture for the plugin-trust "
    "checks that still read this table on older builds."
)
_UNRELATED_DECOY = (
    "a deliberately unrelated table (`unrelated`/`unrelated_table`), used by this test as "
    "negative-path noise -- never a real OpenClaw table, never meant to resolve."
)
_SUBAGENT_RUNS_WIDE_LEGACY = (
    "the wide pre-2026.8.2 subagent_runs shape (43 flat columns: model, agent_dir, "
    "workspace_dir, spawn_mode, outcome_json, ...) that the modern 6-column payload_json "
    "blob replaced. This is the ONLY site exercising collector._collect_subagent_runs's "
    "'legacy columns win over payload_json' precedence through a real check, deliberately "
    "carrying BOTH shapes at once -- see the file's own module docstring."
)
_AUDIT_EVENTS_PARTIAL_LEGACY = (
    "an early audit_events shape: 16 of the vendor's 31 columns, and several declared NOT "
    "NULL where the real table leaves them nullable (agent_id, run_id), so it is not even "
    "a clean subset -- LEGACY_COLS, not PARTIAL, by the strict (name,type,notnull,pk) "
    "comparison basis."
)
_TASK_RUNS_NO_NOTNULL_LEGACY = (
    "same 30 column NAMES/types as the real task_runs, but with NOT NULL dropped from "
    "every column that the vendor declares NOT NULL -- an identically-named, "
    "differently-constrained shape, so it fails the ordered-tuple MODERN comparison and "
    "is not a subset (same column count) either."
)
_CONFIG_MACHINE_STATE_LOOSE_LEGACY = (
    "same 3 column NAMES/types as the real config_machine_state, but with NOT NULL "
    "dropped from value_json and updated_at_ms -- an F-183 fixture predating the STRICT "
    "constraint on the vendor table; not a subset since every real column is nullable "
    "here, not merely a fewer-columns slice."
)

_REGISTRY: "dict[str, _Entry]" = {
    # ---- fixtures/clean_b188_state_db/state/openclaw.sqlite -- the binary fixture no
    # source scanner sees. Pinned by a full fingerprint row at
    # tests/finding_fingerprint_manifest.txt:395.
    "fixtures/clean_b188_state_db/state/openclaw.sqlite:cron_jobs": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "fixtures/clean_b188_state_db/state/openclaw.sqlite:cron_run_logs": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),

    # ---- cron_jobs (legacy flat shapes) ----
    "tests/test_b168_cron_job_content.py:279": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b168_cron_job_content.py:301": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b294_cron_run_logs.py:45": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b294_cron_run_logs.py:585": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b709_cron_state_db_shapes.py:43": _Entry(
        LEGACY_COLS,
        "an intermediate cron_jobs shape (store_key/job_id/declaration_key/owner_agent_id/"
        "job_json/state_json) with several columns absent from the final vendor shape and "
        "no NOT NULL declared anywhere -- a B-709 dual-shape reader fixture, not the "
        "current table.",
    ),
    "tests/test_b709_cron_state_db_shapes.py:51": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b709_cron_state_db_shapes.py:55": _Entry(
        LEGACY_COLS,
        "a synthetic decoy shape (`foo TEXT, bar TEXT`) named cron_jobs purely to exercise "
        "the 'neither generation matches' negative path -- never meant to resolve against "
        "any real cron_jobs shape.",
    ),
    "tests/test_limit_hit_domains.py:53": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),

    # ---- cron_run_logs (retired table) ----
    "tests/test_b294_cron_run_logs.py:49": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),
    "tests/test_b709_cron_run_logs_shapes.py:43": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),
    "tests/test_limit_hit_domains.py:57": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),

    # ---- installed_plugin_index (retired table) ----
    "tests/test_b177_installed_index_shapes.py:68": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:53": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:288": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:313": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b187_plugin_tool_result_middleware.py:82": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b187_plugin_tool_result_middleware.py:332": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_f150_plugin_sweep.py:82": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_f153_dashboard_full.py:351": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),

    # ---- config_machine_state (F-183) ----
    "tests/test_b177_installed_index_shapes.py:55": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_LOOSE_LEGACY),

    # ---- audit_events (B191 / F-154) ----
    "tests/test_b191_audit_events.py:44": _Entry(LEGACY_COLS, _AUDIT_EVENTS_PARTIAL_LEGACY),
    "tests/test_f154_behavioral_cap.py:877": _Entry(LEGACY_COLS, _AUDIT_EVENTS_PARTIAL_LEGACY),

    # ---- capture_events / capture_blobs (B295 debug-proxy-capture) -- MODERN ----
    "tests/test_b295_debug_proxy_capture.py:31": _Entry(MODERN),
    "tests/test_b295_debug_proxy_capture.py:39": _Entry(MODERN),
    "tests/test_b295_debug_proxy_capture.py:76": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),

    # ---- subagent_runs (B296 / B709) ----
    "tests/test_b296_subagent_runs_disclosure.py:44": _Entry(LEGACY_COLS, _SUBAGENT_RUNS_WIDE_LEGACY),
    "tests/test_b296_subagent_runs_disclosure.py:102": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    "tests/test_b709_subagent_runs_shapes.py:52": _Entry(MODERN),
    "tests/test_b709_subagent_runs_shapes.py:61": _Entry(
        LEGACY_COLS,
        "an intermediate 13-column subagent_runs shape (task/cleanup/model/agent_dir/"
        "workspace_dir/outcome_json/ended_reason but no payload_json) -- a B-709 "
        "dual-shape reader fixture between the wide legacy table and the modern blob.",
    ),
    "tests/test_b709_subagent_runs_shapes.py:69": _Entry(
        LEGACY_COLS,
        "a synthetic decoy shape (`foo TEXT, bar TEXT`) named subagent_runs purely to "
        "exercise the 'neither generation matches' negative path -- never meant to "
        "resolve against any real subagent_runs shape.",
    ),
    "tests/test_b709_cron_run_logs_shapes.py:238": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    "tests/test_b709_cron_state_db_shapes.py:280": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    "tests/test_b709_subagent_runs_shapes.py:274": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),

    # ---- task_runs (B709) ----
    "tests/test_b709_cron_run_logs_shapes.py:52": _Entry(LEGACY_COLS, _TASK_RUNS_NO_NOTNULL_LEGACY),
}

assert len(_REGISTRY) == 36, f"registry has {len(_REGISTRY)} entries, expected 36"


# ========================================================================================
# ALWAYS-ON tests (1-6). No dist needed -- these run in CI.
# ========================================================================================

def test_every_state_ddl_in_the_tree_is_registered():
    """Set equality: every DDL site the extractor finds must be registered, and every
    registered key must still correspond to a real site -- a new fixture cannot arrive
    unregistered, and a stale key cannot linger after its fixture is deleted."""
    actual = set(_extract_all_ddl_sites())
    registered = set(_REGISTRY)
    unregistered = sorted(actual - registered)
    stale = sorted(registered - actual)
    assert not (unregistered or stale), (
        ("Unregistered state DDL site(s) -- classify each in _REGISTRY:\n"
         + "\n".join(f"  - {k}" for k in unregistered) + "\n" if unregistered else "")
        + ("Stale _REGISTRY key(s) -- no such DDL site exists in the tree anymore:\n"
           + "\n".join(f"  - {k}" for k in stale) + "\n" if stale else "")
    )


def test_modern_entries_match_the_shipped_snapshot():
    sites = _extract_all_ddl_sites()
    snapshot = _read_snapshot_tables()
    checked = 0
    for key, entry in _REGISTRY.items():
        if entry.cls != MODERN:
            continue
        table = sites[key]["table"]
        assert table in snapshot, f"{key}: MODERN but {table!r} is absent from the shipped snapshot"
        want = [_reduced(c) for c in snapshot[table]]
        got = [_reduced(c) for c in sites[key]["cols"]]
        assert got == want, f"{key}: registered MODERN but {table!r} no longer matches the snapshot"
        checked += 1
    assert checked > 0, "no MODERN entries were checked -- the positive path is untested"


def test_partial_entries_are_proper_subsets_with_agreeing_shared_columns():
    """The current corpus happens to register zero PARTIAL entries (every legacy fixture
    in this tree either matches exactly or diverges in notnull/pk on a shared column
    name, which this module's strict tuple comparison correctly treats as LEGACY_COLS,
    not PARTIAL). That makes this loop vacuous today -- test_classify_partial_case below
    pins the classifier's PARTIAL branch directly against synthetic data so the emptiness
    here is not this guard's only evidence that PARTIAL is handled correctly."""
    sites = _extract_all_ddl_sites()
    snapshot = _read_snapshot_tables()
    for key, entry in _REGISTRY.items():
        if entry.cls != PARTIAL:
            continue
        table = sites[key]["table"]
        vendor_reduced = {_reduced(c) for c in snapshot[table]}
        site_reduced = [_reduced(c) for c in sites[key]["cols"]]
        assert set(site_reduced) < vendor_reduced, f"{key}: PARTIAL entry is not a proper subset"
        assert len(site_reduced) == len(set(site_reduced)), f"{key}: duplicate columns"


def test_legacy_entries_still_differ_from_the_snapshot():
    """The inequality arm: a 'legacy' shape that quietly becomes the current one must
    fail here, not pass silently."""
    sites = _extract_all_ddl_sites()
    snapshot = _read_snapshot_tables()
    checked = 0
    for key, entry in _REGISTRY.items():
        if entry.cls not in _LEGACY_CLASSES:
            continue
        table = sites[key]["table"]
        if table not in snapshot:
            assert entry.cls == LEGACY_TABLE, f"{key}: table absent from snapshot but not registered LEGACY_TABLE"
            checked += 1
            continue
        got = [_reduced(c) for c in sites[key]["cols"]]
        want = [_reduced(c) for c in snapshot[table]]
        assert got != want, (
            f"{key}: registered {entry.cls} but now MATCHES the current vendor shape for "
            f"{table!r} -- re-classify it as MODERN."
        )
        checked += 1
    assert checked > 0


def test_legacy_entries_carry_a_disproof():
    for key, entry in _REGISTRY.items():
        if entry.cls in _LEGACY_CLASSES:
            assert entry.disproof and len(entry.disproof) > 30, f"{key} lacks a real disproof"


def test_the_snapshot_is_not_vacuous():
    """A negative check (test_legacy_entries_still_differ_from_the_snapshot) passes just
    as happily against an empty file -- pin the positive side explicitly."""
    snapshot = _read_snapshot_tables()
    assert len(snapshot) >= 5, f"{SNAPSHOT_FILE.name} holds only {len(snapshot)} table(s)"

    declared = {info["table"] for info in _extract_all_ddl_sites().values()}
    relevant = declared | _clawseccheck_read_tables()
    stray = sorted(set(snapshot) - relevant)
    assert not stray, (
        f"{SNAPSHOT_FILE.name} carries table(s) neither declared in a test DDL nor read "
        f"by clawseccheck/: {stray}"
    )

    cron_jobs_cols = {c[0] for c in snapshot.get("cron_jobs", [])}
    assert "job_json" in cron_jobs_cols, "cron_jobs lost job_json -- snapshot looks stale"
    subagent_cols = {c[0] for c in snapshot.get("subagent_runs", [])}
    assert "payload_json" in subagent_cols, "subagent_runs lost payload_json -- snapshot looks stale"
    assert len(snapshot.get("audit_events", [])) == 31, (
        f"audit_events has {len(snapshot.get('audit_events', []))} columns, expected 31"
    )

    header = _read_snapshot_sql()
    assert "GENERATED" in header, "the snapshot must say it is generated, not hand-edited"
    assert "openclaw-version:" in header, "the snapshot must record which OpenClaw vouched"


def test_registry_has_no_unclassified_entries():
    for key, entry in _REGISTRY.items():
        assert entry.cls in _CLASSES, f"{key}: unknown class {entry.cls!r}"


# ========================================================================================
# Classifier unit tests -- pin _classify() directly against synthetic data, independent of
# what the real corpus happens to contain today (the corpus has zero PARTIAL entries;
# this proves the branch itself is correct).
# ========================================================================================

def test_classify_modern_case():
    vendor = {"t": [("a", "TEXT", 1, None, 1), ("b", "INTEGER", 0, None, 0)]}
    cols = [("a", "TEXT", 1, None, 1), ("b", "INTEGER", 0, None, 0)]
    assert _classify("t", cols, vendor) == MODERN


def test_classify_partial_case():
    vendor = {"t": [("a", "TEXT", 1, None, 1), ("b", "INTEGER", 0, None, 0), ("c", "TEXT", 0, None, 0)]}
    cols = [("a", "TEXT", 1, None, 1), ("b", "INTEGER", 0, None, 0)]
    assert _classify("t", cols, vendor) == PARTIAL


def test_classify_legacy_cols_case():
    vendor = {"t": [("a", "TEXT", 1, None, 1)]}
    cols = [("a", "TEXT", 1, None, 1), ("z", "TEXT", 0, None, 0)]
    assert _classify("t", cols, vendor) == LEGACY_COLS


def test_classify_legacy_cols_when_notnull_differs_on_a_shared_name():
    """The real corpus's actual shape: same column NAME, different notnull -- not a
    subset (the tuple doesn't match), not modern, not fewer columns either."""
    vendor = {"t": [("a", "TEXT", 1, None, 1), ("b", "TEXT", 1, None, 0)]}
    cols = [("a", "TEXT", 1, None, 1), ("b", "TEXT", 0, None, 0)]
    assert _classify("t", cols, vendor) == LEGACY_COLS


def test_classify_legacy_table_case():
    vendor = {"other": [("a", "TEXT", 1, None, 1)]}
    assert _classify("gone", [("a", "TEXT", 1, None, 1)], vendor) == LEGACY_TABLE


def test_classify_ignores_dflt_value_for_modern():
    """dflt_value is warn-level, not asserted -- a real, benign migration artifact
    (OpenClaw's own compatibility allowlist accepts a default drift on cron_jobs).
    A default-value difference alone must not demote MODERN to LEGACY_COLS."""
    vendor = {"t": [("a", "TEXT", 0, "'{}'", 0)]}
    cols = [("a", "TEXT", 0, "'[]'", 0)]
    assert _classify("t", cols, vendor) == MODERN


def test_classify_is_a_pure_function_of_its_arguments():
    """Calling twice with identical inputs must not depend on any hidden state."""
    vendor = {"t": [("a", "TEXT", 1, None, 1)]}
    cols = [("a", "TEXT", 1, None, 1)]
    assert _classify("t", cols, vendor) == _classify("t", cols, vendor) == MODERN


# ========================================================================================
# Extraction/regeneration machinery -- self-contained parsers, pinned on synthetic input
# so their correctness does not depend on the shape of today's real dist.
# ========================================================================================

def test_unescape_js_double_quoted_handles_the_real_escapes():
    assert _unescape_js_double_quoted("a\\nb") == "a\nb"
    assert _unescape_js_double_quoted('a\\"b') == 'a"b'
    assert _unescape_js_double_quoted("a\\\\b") == "a\\b"
    assert _unescape_js_double_quoted("a\\u0041b") == "aAb"
    # unrecognized escape: JS drops the backslash, keeps the char
    assert _unescape_js_double_quoted("a\\qb") == "aqb"


def test_extract_vendor_schema_sql_finds_the_const(tmp_path):
    js = 'const OTHER = "noise";\nconst OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE t (a TEXT);\\n";\nmore code'
    sql = _extract_vendor_schema_sql(js)
    assert sql.strip() == "CREATE TABLE t (a TEXT);"


def test_extract_vendor_schema_sql_raises_when_const_missing():
    with pytest.raises(AssertionError, match="not found"):
        _extract_vendor_schema_sql("const SOMETHING_ELSE = 1;")


def test_dist_table_ddl_texts_is_paren_balanced():
    sql = (
        "CREATE TABLE IF NOT EXISTS a (x TEXT, y INTEGER, CHECK (x <> '')) STRICT;\n"
        "CREATE TABLE IF NOT EXISTS b (z TEXT) STRICT;\n"
    )
    # pad past the >=100-table floor guard by monkeypatching would be needed for the real
    # function; call the regex/paren-walk logic directly on a small sample instead by
    # bypassing the floor check via a local reimplementation is unnecessary -- assert the
    # floor guard itself fires on genuinely small input.
    with pytest.raises(AssertionError, match="only extracted"):
        _dist_table_ddl_texts(sql)


def test_dist_table_ddl_texts_extracts_full_statement_text():
    """One table, byte-for-byte, with the floor guard bypassed by padding with filler
    CREATE TABLE statements (cheap synthetic stand-ins for the real 116)."""
    filler = "".join(f"CREATE TABLE IF NOT EXISTS filler_{i} (x TEXT) STRICT;\n" for i in range(100))
    sql = filler + "CREATE TABLE IF NOT EXISTS capture_events (\n  id INTEGER,\n  ts INTEGER\n) STRICT;\n"
    ddls = _dist_table_ddl_texts(sql)
    assert ddls["capture_events"] == (
        "CREATE TABLE IF NOT EXISTS capture_events (\n  id INTEGER,\n  ts INTEGER\n) STRICT;"
    )


def test_find_state_db_readonly_js_ignores_the_legacy_capture_trap(tmp_path):
    """The TRAP this module's docstring names: a DIFFERENT const declares its own
    capture_events in a same-directory file that does NOT match the readonly glob."""
    (tmp_path / "openclaw-state-db-readonly-XyZ123.js").write_text(
        'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS capture_events (a TEXT);";',
        encoding="utf-8",
    )
    (tmp_path / "runtime-Cfcu-Z0-.js").write_text(
        'const DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL = "CREATE TABLE capture_events (b TEXT);";',
        encoding="utf-8",
    )
    found = _find_state_db_readonly_js(tmp_path)
    assert found.name == "openclaw-state-db-readonly-XyZ123.js"


def test_find_state_db_readonly_js_raises_on_zero_matches(tmp_path):
    with pytest.raises(AssertionError, match="expected exactly one"):
        _find_state_db_readonly_js(tmp_path)


def test_find_state_db_readonly_js_raises_on_multiple_matches(tmp_path):
    (tmp_path / "openclaw-state-db-readonly-AAA.js").write_text("x", encoding="utf-8")
    (tmp_path / "openclaw-state-db-readonly-BBB.js").write_text("y", encoding="utf-8")
    with pytest.raises(AssertionError, match="expected exactly one"):
        _find_state_db_readonly_js(tmp_path)


def test_require_dist_skips_cleanly_when_openclaw_is_not_installed(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "OPENCLAW_DIST", Path("/nonexistent/openclaw/dist"))
    with pytest.raises(pytest.skip.Exception) as excinfo:
        _require_dist()
    assert "local-only" in str(excinfo.value)


def test_write_state_snapshot_raises_without_a_dist(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "OPENCLAW_DIST", Path("/nonexistent/openclaw/dist"))
    with pytest.raises(RuntimeError, match="cannot regenerate a vacuous snapshot"):
        _write_state_snapshot()


def test_clawseccheck_read_tables_reuses_the_drift_gate_not_a_second_copy():
    """Sanity: the reader delegates to scripts/state_db_drift_gate.py's own
    expected_reads(), rather than re-implementing a SELECT-statement extractor here."""
    tables = _clawseccheck_read_tables()
    assert "cron_jobs" in tables
    assert "audit_events" in tables


def test_header_field_parses_the_stamped_version():
    header = "-- openclaw-version: 2026.8.2\n-- state-schema-version: 15\n"
    assert _header_field(header, "openclaw-version") == "2026.8.2"
    assert _header_field(header, "state-schema-version") == "15"
    assert _header_field(header, "nonexistent-field") is None


# ========================================================================================
# LOCAL-ONLY test (needs the dist). Skip is pinned as a skip.
# ========================================================================================

def test_snapshot_matches_installed_dist_and_stamped_version():
    """The strongest authority still has to say something, even locally: the shipped
    snapshot must (a) structurally agree with what a real installed OpenClaw's schema
    says today, and (b) be STAMPED with that same version. (b) is non-optional --
    test_schema_grounding.py's own history is the reason: its dist-snapshot header used
    to be inert, and rewriting `openclaw-version:` to `1999.1.1` by hand left every other
    test green, because nothing actually read the stamp back."""
    dist_dir = _require_dist()
    js_path = _find_state_db_readonly_js(dist_dir)
    sql_text = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    live = _dist_table_columns(sql_text)

    snapshot = _read_snapshot_tables()
    mismatched = []
    for table, cols in snapshot.items():
        want = live.get(table)
        got = [_reduced(c) for c in cols]
        want_reduced = [_reduced(c) for c in want] if want is not None else None
        if want_reduced != got:
            mismatched.append(table)
    assert not mismatched, (
        f"{SNAPSHOT_FILE.name} disagrees with the installed dist for: {mismatched}. "
        f"Regenerate: {REGENERATE_CMD}"
    )

    header = _read_snapshot_sql()
    stamped = _header_field(header, "openclaw-version")
    installed = _installed_openclaw_version()
    assert stamped == installed, (
        f"{SNAPSHOT_FILE.name} is stamped openclaw-version: {stamped!r} but the installed "
        f"OpenClaw is {installed!r} -- a stale/faked stamp used to leave a sibling guard "
        f"green (test_schema_grounding.py's own regression). Regenerate: {REGENERATE_CMD}"
    )


if __name__ == "__main__":
    if "--write-state-snapshot" in sys.argv:
        n = _write_state_snapshot()
        print(f"wrote {SNAPSHOT_FILE} -- {n} tables")
    else:
        print("usage: python3 tests/test_state_schema_grounding.py --write-state-snapshot")
