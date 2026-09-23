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
content-hashed dist file. It is located by that CONSTANT, not by a filename glob.

That changed on 2026-09-03. The locator used to glob `openclaw-state-db-readonly-*.js`,
and openclaw 2026.9.1 moved the constant into `openclaw-state-db-cache-*.js` while
KEEPING a file the old glob still matched — so the glob resolved happily to a bundle that
no longer defines the schema, and the guard failed with "the dist no longer defines the
state schema the way this guard expects". It was right to fail; the anchor was wrong.
Bundle filenames are content-hashed and rotate ~94% per release (docs/CHECK_AUTHORING.md),
so a filename is the one thing in the dist guaranteed not to survive.

TRAP, unchanged and still guarded: a dist-wide grep for `CREATE TABLE` also finds
`DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL` in a DIFFERENT file — a legacy schema for an
unrelated debug-proxy sidecar database that happens to declare a table also named
`capture_events`. Searching for the marker `const OPENCLAW_STATE_SCHEMA_SQL = "` cannot
match it, because the marker names the constant. That is strictly stronger than the old
glob: the glob avoided the trap by being narrow, this avoids it by being specific.

A SECOND declaration of the same constant exists — `= process.getBuiltinModule("node:fs")
.readFileSync(... "openclaw-state-schema.sql" ...)`. It is NOT the one to read: that .sql
file ships in neither 2026.8.2 nor 2026.9.1 (checked both), so the form is a build-time
artifact. The `= "` in the marker excludes it. `_find_state_schema_defining_js` asserts
EXACTLY one match rather than trusting the first hit.

Regenerating the snapshot is part of the OpenClaw-upgrade protocol's re-baseline, on a
machine with the matching OpenClaw installed:

    PYTHONPATH=tests:. python3 tests/test_state_schema_grounding.py --write-state-snapshot

`PYTHONPATH=tests` is load-bearing — `REAL_HOME` comes from `tests/_realhome.py`, because
the suite redirects `$HOME` for the rest of the run. Hand-editing the snapshot is the
guard writing its own evidence — regenerate it, never patch it by hand.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest

from _distgrounding import _JS_EXTS
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
SCHEMA_SQL_CONST_MARKER = 'const OPENCLAW_STATE_SCHEMA_SQL = "'

# B-834: how the vendor spells the state-schema VERSION, oldest to newest form. Through
# 2026.9.4 it was a named constant in `openclaw-state-db-contract-*`; 2026.9.5 removed the
# constant and inlined the number as a literal at each use, so a reader that looked only for
# the constant kept returning "not found" and, being reached only by the `--write-state-*`
# regenerators, no test went red. Each anchor is one place the number is spelled OUT;
# `_state_schema_version_from` needs at least one to fire and all that fire to agree, so a
# release that renames every one of them fails loudly instead of stamping a stale number.
# Two hardenings from the independent review of B-834: the digit capture is terminated
# (`(?![\w.])`, so `0x11`, `1_7`, `1e1` and `17.5` do not match and reach the loud failure
# rather than yielding 0, 1, 1 and 17), and the argument span of the two guards is bounded
# (`{0,200}`; an unbounded `[^)]*` backtracked quadratically on an unterminated call -- 413 s
# on a 5 MB line).
_SCHEMA_VERSION_ANCHORS = (
    ("named constant (<= 2026.9.4)",
     re.compile(r"\bOPENCLAW_STATE_SCHEMA_VERSION\s*=\s*(\d+)(?![\w.])")),
    ("content-version guard",
     re.compile(r"\breadStateSchemaContentVersion\s*\([^)]{0,200}\)\s*!==\s*(\d+)(?![\w.])")),
    ("migration-version guard",
     re.compile(r"\breadStateSchemaMigrationVersion\s*\([^)]{0,200}\)\s*!==\s*(\d+)(?![\w.])")),
    ("newer-schema error",
     re.compile(r'\bcreateNewerSqliteSchemaVersionError\(\s*"OpenClaw state database"\s*,'
                r"[^,()]+,[^,()]+,\s*(\d+)\s*\)")),
)

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


def _state_schema_defining_files(dist_dir: Path) -> "list[Path]":
    """Every dist file that DEFINES `OPENCLAW_STATE_SCHEMA_SQL` as a string literal, sorted.

    Located by the constant, never by filename: see this module's docstring for why a
    filename glob broke on 2026.9.1 while still resolving to a real file. The TRAP is
    `DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL`, an unrelated sidecar schema that also declares a
    `capture_events` table. The marker names the constant, so that file cannot match it.
    """
    # B-784: the SELECTION is by constant, but the CANDIDATE SET was `*.js` -- a filename
    # anchor after all, and the half that 2026.9.3 broke by recompiling every chunk as
    # `.mjs`. `_JS_EXTS` is imported rather than restated so the two locators cannot drift
    # apart on the next rename.
    definers = []
    for ext in _JS_EXTS:
        for path in dist_dir.rglob("*" + ext):
            # A directory or a dangling symlink that merely LOOKS like a bundle cannot
            # define anything; skipping it is right. An unreadable REGULAR file could be the
            # one that does, so that fails loudly instead of being skipped.
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise AssertionError(
                    f"cannot read {path} while looking for {SCHEMA_SQL_CONST_MARKER!r}: {exc}. "
                    "An unreadable bundle could be the one that defines the state schema."
                ) from exc
            occurrences = text.count(SCHEMA_SQL_CONST_MARKER)
            if occurrences > 1:
                raise AssertionError(
                    f"{path} contains {SCHEMA_SQL_CONST_MARKER!r} {occurrences} times (a "
                    "second definition, a continued literal or the marker inside a comment). "
                    "Only the first would be read; decide which one the runtime uses."
                )
            if occurrences:
                definers.append(path)
    return sorted(definers)


def _find_state_schema_defining_js(dist_dir: Path) -> Path:
    """The dist file to READ the state schema from -- after proving every definition agrees.

    B-834: 2026.9.5 defines the constant in THREE bundles (the state-db chunk, a copy under
    `native-hook-relay/`, and `managed-handoff-runtime`) where 2026.9.4 defined it in one.
    "Exactly one" was a proxy for "unambiguous", and it stopped being true while the schema
    stayed unambiguous: the three extracted SQL blobs are byte-identical. What the guard is
    for is that picking a file must not be a coin toss, so it now asserts THAT: any number of
    definitions is fine when they are the same schema, and it fails loudly, naming the files
    and their digests, when they are not.

    SCOPE OF THAT PROOF, stated because an independent review found it narrower than the
    sentence above reads: it covers the definitions spelled `const OPENCLAW_STATE_SCHEMA_SQL
    = "..."` -- the spelling this module extracts. On every release 8.2 through 9.5 the
    worker thread (`worker/worker.mjs`) also embeds the constant as a TEMPLATE literal, and
    `config-doctor/runtime-*.js` reads the SQL from a `.sql` file the package does not ship;
    neither is compared here. The template copy was diffed against the string copy on all six
    releases and is byte-equal, so no wrong answer exists today, but a future divergence
    between those spellings would not be seen by this function.

    Returns the top-level `openclaw-state-db-*` chunk when there is one (the file the
    runtime's own state module lives in, and the one worth citing in a generated header),
    else the first in sort order.
    """
    matches = _state_schema_defining_files(dist_dir)
    if not matches:
        raise AssertionError(
            f"expected at least one file under {dist_dir} defining "
            f"{SCHEMA_SQL_CONST_MARKER!r}, found 0. That means the vendor changed how it "
            "declares the state schema -- re-ground before trusting anything downstream."
        )
    by_digest: "dict[str, list[Path]]" = {}
    for path in matches:
        sql = _extract_vendor_schema_sql(path.read_text(encoding="utf-8", errors="replace"))
        # surrogatepass: a lone or escaped-pair surrogate in the SQL must reach the identity
        # comparison, not crash it with a UnicodeEncodeError that is not an AssertionError.
        by_digest.setdefault(
            hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()[:12], []).append(path)
    if len(by_digest) != 1:
        listing = "; ".join(
            f"{digest}: {[str(p.relative_to(dist_dir)) for p in paths]}"
            for digest, paths in sorted(by_digest.items()))
        raise AssertionError(
            f"{len(matches)} files under {dist_dir} define {SCHEMA_SQL_CONST_MARKER!r} and "
            f"their SQL is NOT identical ({listing}). Picking either would be a coin toss: "
            "decide which definition the runtime actually opens before trusting a snapshot "
            "taken from one of them."
        )
    top = [p for p in matches if p.parent == dist_dir and p.name.startswith("openclaw-state-db-")]
    return (top or matches)[0]


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


def _state_schema_version_evidence(dist_dir: Path) -> "dict[str, set[int]]":
    """anchor name -> the version numbers that anchor spells out, across the state-db files.

    Scans every `openclaw-state-db-*` chunk at any depth plus every file defining the schema
    SQL, so a chunk moving between directories or being re-split does not lose the anchor.
    """
    files = set(_state_schema_defining_files(dist_dir))
    for ext in _JS_EXTS:
        files.update(dist_dir.rglob("openclaw-state-db-*" + ext))
    evidence: "dict[str, set[int]]" = {}
    for path in sorted(files):
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in _SCHEMA_VERSION_ANCHORS:
            for match in pattern.finditer(text):
                evidence.setdefault(name, set()).add(int(match.group(1)))
    return evidence


def _state_schema_version_from(dist_dir: Path) -> int:
    """The vendor's state-schema version (its `PRAGMA user_version` ladder top), or a loud
    failure. Never a guess: no anchor means UNKNOWN, and anchors that disagree mean one of
    them is describing something else."""
    evidence = _state_schema_version_evidence(dist_dir)
    values = {v for found in evidence.values() for v in found}
    if not values:
        raise AssertionError(
            f"could not read the state-schema version from any {len(_SCHEMA_VERSION_ANCHORS)} "
            f"known spelling under {dist_dir} ({[n for n, _ in _SCHEMA_VERSION_ANCHORS]}). "
            "The vendor changed how it writes the number -- re-ground the anchors; do not "
            "stamp a version you did not read."
        )
    if len(values) != 1:
        raise AssertionError(
            f"the state-schema version anchors disagree under {dist_dir}: "
            f"{ {name: sorted(v) for name, v in sorted(evidence.items())} }. One of them is "
            "describing something other than the schema version -- decide which before "
            "stamping a number."
        )
    return next(iter(values))


def _installed_state_schema_version() -> int:
    return _state_schema_version_from(OPENCLAW_DIST)


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
-- OpenClaw's `OPENCLAW_STATE_SCHEMA_SQL`, projected to the state-SQLite tables this tree
-- declares in a test DDL or that clawseccheck/ reads.
--
-- source-bundle: {source_file}
--   Recorded, not assumed: the generator writes the file it ACTUALLY resolved. The bundle
--   carrying this constant is build output and its name rotates -- 2026.9.1 moved it from
--   openclaw-state-db-readonly-*.js to openclaw-state-db-cache-*.js while BOTH files still
--   existed, so a name written here by hand would have kept naming a real file that no
--   longer holds the schema. The locator globs for the constant, never for a filename.
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
    """A `-- name: value` (SQL) or `# name: value` (text) header line's value.

    Both comment markers, because the two generated files this module ships are read by
    the same accessor: state_schema_snapshot.sql must executescript, so its header is SQL
    comments; vendor_state_tables.txt is a plain list, so its header is `#`. One parser
    rather than a second copy that can disagree with this one.
    """
    m = re.search(rf"^(?:--|#)\s*{re.escape(name)}:\s*(\S+)", header, re.MULTILINE)
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
    js_path = _find_state_schema_defining_js(OPENCLAW_DIST)
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
        source_file=js_path.name,
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
    "cron_run_logs is not a table in the CURRENT vendor schema: it is absent from "
    "vendor_state_tables.txt, which records every table OPENCLAW_STATE_SCHEMA_SQL "
    "declares in the installed build. The per-run log rows this table modelled now live "
    "on task_runs; kept as a deliberate legacy-shape fixture for the pre-retirement "
    "disclosure path. Deliberately NOT pinned to the version this was first measured on "
    "(2026.8.2): a dated claim in prose does not re-check itself, and this one is "
    "re-grounded against the current baseline on every run by "
    "test_retired_tables_are_absent_from_the_vendor_baseline."
)
_INSTALLED_PLUGIN_INDEX_RETIRED = (
    "installed_plugin_index is not a table in the CURRENT vendor schema: it is absent "
    "from vendor_state_tables.txt, which records every table OPENCLAW_STATE_SCHEMA_SQL "
    "declares in the installed build. Kept as a legacy-shape fixture for the plugin-trust "
    "checks that still read this table on older builds. Not pinned to a version, for the "
    "reason given on _CRON_RUN_LOGS_RETIRED."
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
_AUTH_PROFILE_TABLES_DIFFERENT_DB = (
    "auth_profile_store/auth_profile_state (F-187) live in the PER-AGENT database "
    "(agents/<agent>/agent/openclaw-agent.sqlite), never in the state database "
    "(state/openclaw.sqlite) this snapshot/registry classifies -- a different SQLite "
    "file, with its own separate schema this module does not model at all. Absent from "
    "the vendor snapshot for that reason, not because the shape is wrong; the fixture "
    "models the real per-agent shape closely enough to prove trajectorystore.corroborate() "
    "never reaches it (see that test file's own module docstring), but there is no vendor "
    "comparison possible for it within this file's scope."
)
_TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB = (
    "trajectory_runtime_events (F-187) lives in the PER-AGENT database "
    "(agents/<agent>/agent/openclaw-agent.sqlite), never in the state database "
    "(state/openclaw.sqlite) this snapshot/registry classifies -- same reasoning as "
    "_AUTH_PROFILE_TABLES_DIFFERENT_DB, for the table that database actually holds "
    "trajectory evidence in. The original declaration "
    "(tests/test_f187_trajectory_sqlite_corroborator.py:83) is an f-string "
    "(f\"CREATE TABLE {table} (...)\"), so the AST-constant extractor above does not see "
    "it -- these two are plain string-literal copies (B-810/B-811/B-813), each pinned to "
    "the exact column shape trajectorystore.TRAJECTORY_TABLE_NAME / "
    "_SELECT_TRAJECTORY_ROWS actually reads, matching test_f187's own DDL verbatim."
)
_CRON_JOBS_NO_CONSTRAINTS_LEGACY = (
    "C-476: same 15 column NAMES/types/order as the real cron_jobs (store_key, job_id, "
    "declaration_key, owner_agent_id, name, description, enabled, agent_id, payload_kind, "
    "job_json, state_json, runtime_updated_at_ms, schedule_identity, sort_order, "
    "updated_at), but with NOT NULL and the composite PRIMARY KEY(store_key, job_id) "
    "dropped from every column the vendor constrains. The fixture's own author named the "
    "constant `_MODERN_DDL`, but this guard's strict (name,type,notnull,pk) tuple "
    "comparison makes it LEGACY_COLS: identical column count to the vendor, so not a "
    "proper subset either -- the name is aspirational, not a vendor match."
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
    # B-813 shifted this site's line 585 -> 664; 2026-09-16 commits e308d73/46e16b1 added
    # more lines above it, shifting it again to 727 -- same _CRON_JOBS_PARTITIONED_DDL
    # constant, same classification, key renamed to match.
    "tests/test_b294_cron_run_logs.py:727": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b168_truncation_gates_pass.py:31": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b819_cron_dormant_payload.py:250": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
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
    "tests/test_b709_subagent_runs_shapes.py:54": _Entry(MODERN),
    "tests/test_b709_subagent_runs_shapes.py:63": _Entry(
        LEGACY_COLS,
        "an intermediate 13-column subagent_runs shape (task/cleanup/model/agent_dir/"
        "workspace_dir/outcome_json/ended_reason but no payload_json) -- a B-709 "
        "dual-shape reader fixture between the wide legacy table and the modern blob.",
    ),
    "tests/test_b709_subagent_runs_shapes.py:71": _Entry(
        LEGACY_COLS,
        "a synthetic decoy shape (`foo TEXT, bar TEXT`) named subagent_runs purely to "
        "exercise the 'neither generation matches' negative path -- never meant to "
        "resolve against any real subagent_runs shape.",
    ),
    # Both keys below shifted (238 -> 248, 280 -> 296) when later commits added lines
    # earlier in each file -- same single `unrelated_table (x TEXT)` decoy, key renamed
    # to match; verified exactly one such site remains in each file.
    "tests/test_b709_cron_run_logs_shapes.py:248": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    "tests/test_b709_cron_state_db_shapes.py:296": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    "tests/test_b709_subagent_runs_shapes.py:276": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),

    # ---- task_runs (B709) ----
    "tests/test_b709_cron_run_logs_shapes.py:52": _Entry(LEGACY_COLS, _TASK_RUNS_NO_NOTNULL_LEGACY),

    # ---- skill_library_entries / skill_uploads (B354 / CLAWSECCHECK-B-725) ----
    "tests/test_b354_b725_skill_library_reachability.py:31": _Entry(MODERN),
    "tests/test_b354_b725_skill_library_reachability.py:46": _Entry(MODERN),

    # ---- auth_profile_store / auth_profile_state (F-187, per-agent DB, different file) ----
    # B-811 (Option A) shifted both lines below (94->102, 101->109) by extending
    # _add_agent_db()'s docstring/loop above them -- same DDL, keys renamed to match.
    "tests/test_f187_trajectory_sqlite_corroborator.py:102": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:109": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 (Option A): a second auth_profile_store fixture, this one in
    # _write_agent_sqlite_db()'s own `auth_secret=` branch (the isolation test for the
    # new event_json-reading reader) -- same per-agent-DB reasoning as the two above.
    "tests/test_b185_compiled_tool_poisoning.py:114": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 (adversarial review, 2026-09-15): two more, each a standalone fixture (not
    # via _add_agent_db) in a test proving _table_kind refuses a VIEW named
    # trajectory_runtime_events that reads FROM this table -- same per-agent-DB
    # reasoning as every other entry in this section.
    "tests/test_f187_trajectory_sqlite_corroborator.py:470": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:796": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 3/4 (2026-09-15): `_plant_generated_column_bypass`'s own standalone
    # fixture -- the GENERATED ALWAYS AS bypass the round-3 review found (a real table,
    # not a VIEW/virtual table, so a different attack shape but the same per-agent-DB
    # isolation reasoning as every other entry in this section).
    "tests/test_f187_trajectory_sqlite_corroborator.py:514": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 4 (2026-09-15): `test_compiled_tool_reader_refuses_a_rootpage_
    # aliased_table`'s own standalone fixture -- round 2's rootpage-uniqueness check,
    # given real `PRAGMA writable_schema` behavioural coverage for the first time
    # (round 4's own adversarial review found it had none).
    "tests/test_f187_trajectory_sqlite_corroborator.py:619": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 3/4 (2026-09-15): the same generated-column bypass fixture, built
    # standalone (not via _plant_generated_column_bypass, which lives in the sibling
    # test file) for the CHECK-level end-to-end test.
    "tests/test_b185_compiled_tool_poisoning.py:513": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # CLAWSECCHECK-B-845: two more, in `_agent_home()`'s own `agent_auth_store_json=`
    # branch and its standalone second-agent fixture -- same DDL text (copied verbatim
    # from test_f187's own `_add_agent_db()`), same per-agent-DB reasoning. Shifted
    # 354->357, 459->462 by the C-135-rejection follow-up's new imports (threading/time/
    # trajectorystore) above them -- same DDL, keys renamed to match.
    "tests/test_b749_auth_profile_store_presence.py:357": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_b749_auth_profile_store_presence.py:462": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # CLAWSECCHECK-B-845 follow-up (2026-09-23): a third, `_make_agent_auth_db()`'s own
    # helper -- the cap-disclosure test's fixture builder -- same DDL text again, same
    # per-agent-DB reasoning. (The recursive-VIEW hang-guard fixture right above it uses
    # `CREATE VIEW`, not `CREATE TABLE`, so it is outside this extractor's surface --
    # confirmed by re-running `test_every_state_ddl_in_the_tree_is_registered` after
    # adding it: no new unregistered site appeared for that fixture.)
    "tests/test_b749_auth_profile_store_presence.py:586": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),

    # ---- trajectory_runtime_events (F-187, per-agent DB, different file) ----
    # B-813/B-811: plain-string-literal copies of test_f187's own f-string DDL (invisible
    # to the AST extractor -- see _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB's own comment).
    "tests/test_b294_cron_run_logs.py:62": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # B-811 (Option A) shifted this line (91->101) by extending _write_agent_sqlite_db()
    # to accept a real event dict per row -- same DDL, key renamed to match.
    "tests/test_b185_compiled_tool_poisoning.py:101": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # B-811 (adversarial review, 2026-09-15): two standalone fixtures (not via
    # _add_agent_db) in the DoS-bound regression tests -- same DDL, same reasoning.
    "tests/test_f187_trajectory_sqlite_corroborator.py:920": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:970": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),

    # ---- cron_jobs (C-476 payload-extras fixture -- vendor column set, no constraints) ----
    "tests/test_c476_cron_payload_extras.py:58": _Entry(LEGACY_COLS, _CRON_JOBS_NO_CONSTRAINTS_LEGACY),

    # ---- update_runs (F-192, real vendor table, snapshot not yet re-baselined) ----
    # 2026-09-17: re-baselined the snapshot (was last regenerated 2026-09-12, commit
    # 28322d5, four days before this fixture landed 2026-09-16, commit b9898b0) --
    # update_runs is a real, current vendor table (state schema v15+, 2026.9.2) that
    # genuinely matches the vendor shape now that the snapshot actually carries it.
    "tests/test_f192_update_runs.py:30": _Entry(MODERN),
}

assert len(_REGISTRY) == 57, f"registry has {len(_REGISTRY)} entries, expected 57"


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


def test_find_state_schema_defining_js_ignores_the_legacy_capture_trap(tmp_path):
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
    found = _find_state_schema_defining_js(tmp_path)
    assert found.name == "openclaw-state-db-readonly-XyZ123.js"


def test_find_state_schema_defining_js_raises_on_zero_matches(tmp_path):
    with pytest.raises(AssertionError, match="found 0"):
        _find_state_schema_defining_js(tmp_path)


_SAME_SQL = 'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS t (a TEXT);";'


def test_find_state_schema_defining_js_accepts_identical_copies_across_bundles(tmp_path):
    """B-834: 2026.9.5 defines the schema in three bundles (a top-level chunk, a
    `native-hook-relay/` copy and a runtime chunk) with byte-identical SQL. That is ONE
    schema; refusing it made both baseline generators unusable on the release."""
    (tmp_path / "native-hook-relay").mkdir()
    (tmp_path / "managed-handoff-runtime.mjs").write_text(_SAME_SQL, encoding="utf-8")
    (tmp_path / "native-hook-relay" / "openclaw-state-db-h6henlHr.mjs").write_text(
        _SAME_SQL, encoding="utf-8")
    (tmp_path / "openclaw-state-db-DS2iNFy4.mjs").write_text(_SAME_SQL, encoding="utf-8")
    found = _find_state_schema_defining_js(tmp_path)
    # the top-level state-db chunk is the one worth citing, not whichever sorts first
    assert found == tmp_path / "openclaw-state-db-DS2iNFy4.mjs"


def test_find_state_schema_defining_js_falls_back_to_the_first_when_no_chunk_is_named_state_db(tmp_path):
    (tmp_path / "b.mjs").write_text(_SAME_SQL, encoding="utf-8")
    (tmp_path / "a.mjs").write_text(_SAME_SQL, encoding="utf-8")
    assert _find_state_schema_defining_js(tmp_path).name == "a.mjs"


def test_find_state_schema_defining_js_raises_loudly_when_definitions_differ(tmp_path):
    """The guard's actual job: choosing a file must not be a coin toss. Two definitions that
    are NOT the same schema fail, and the message names both files and their digests."""
    (tmp_path / "openclaw-state-db-AAA.js").write_text(_SAME_SQL, encoding="utf-8")
    (tmp_path / "openclaw-state-db-BBB.js").write_text(
        'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS u (b TEXT);";',
        encoding="utf-8")
    with pytest.raises(AssertionError, match="NOT identical") as excinfo:
        _find_state_schema_defining_js(tmp_path)
    assert "openclaw-state-db-AAA.js" in str(excinfo.value)
    assert "openclaw-state-db-BBB.js" in str(excinfo.value)


def test_find_state_schema_defining_js_is_not_satisfied_by_the_legacy_capture_trap_alone(tmp_path):
    """Positive control for the marker: a file that declares ONLY the unrelated sidecar
    schema must still count as zero definitions, however many copies of it exist."""
    for name in ("runtime-A.mjs", "runtime-B.mjs"):
        (tmp_path / name).write_text(
            'const DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL = "CREATE TABLE capture_events (b TEXT);";',
            encoding="utf-8")
    with pytest.raises(AssertionError, match="found 0"):
        _find_state_schema_defining_js(tmp_path)


# ---- B-834: the version reader ---------------------------------------------------------

def _write_dist(root: Path, files: "dict[str, str]") -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def test_state_schema_version_reads_the_named_constant_of_2026_9_4_and_earlier(tmp_path):
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-contract-C8vwd-Ud.mjs":
            "const OPENCLAW_STATE_SCHEMA_VERSION = 17;\nconst OPENCLAW_STATE_STRICT_SCHEMA_VERSION = 3;\n",
    })
    assert _state_schema_version_from(dist) == 17


def test_state_schema_version_reads_the_inlined_literals_of_2026_9_5(tmp_path):
    """The constant is gone; the number survives as a literal at each use."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-DS2iNFy4.mjs":
            'if (readStateSchemaContentVersion(database) !== 17) throw new Error("x");\n'
            "const needsRepair = readStateSchemaMigrationVersion(database) !== 17 || y;\n",
        "openclaw-state-db-schema-version-BWuCSXsd.mjs":
            'if (contentVersion > 17) throw createNewerSqliteSchemaVersionError('
            '"OpenClaw state database", pathname, contentVersion, 17);\n',
    })
    assert _state_schema_version_from(dist) == 17
    evidence = _state_schema_version_evidence(dist)
    assert set(evidence) == {"content-version guard", "migration-version guard", "newer-schema error"}


def test_state_schema_version_does_not_confuse_the_strict_or_quarantine_versions(tmp_path):
    """`OPENCLAW_STATE_STRICT_SCHEMA_VERSION = 3` and the quarantine store's version 2 sit
    beside the real one; matching them would stamp the wrong number."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-contract-X.mjs":
            "const OPENCLAW_STATE_SCHEMA_VERSION = 16;\nconst OPENCLAW_STATE_STRICT_SCHEMA_VERSION = 3;\n",
        "openclaw-state-db-cache-Y.mjs": "const OPENCLAW_QUARANTINE_SCHEMA_VERSION = 2;\n",
    })
    assert _state_schema_version_from(dist) == 16


def test_state_schema_version_finds_the_anchor_in_a_nested_chunk(tmp_path):
    dist = _write_dist(tmp_path, {
        "native-hook-relay/openclaw-state-db-h6henlHr.mjs":
            "if (readStateSchemaMigrationVersion(db) !== 17) return;\n",
    })
    assert _state_schema_version_from(dist) == 17


def test_state_schema_version_fails_loudly_when_no_anchor_survives(tmp_path):
    """A release that renames every spelling must FAIL, not stamp a stale number."""
    dist = _write_dist(tmp_path, {"openclaw-state-db-DS2iNFy4.mjs": "const version = 17;\n"})
    with pytest.raises(AssertionError, match="could not read the state-schema version"):
        _state_schema_version_from(dist)


def test_state_schema_version_fails_loudly_when_anchors_disagree(tmp_path):
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-contract-X.mjs": "const OPENCLAW_STATE_SCHEMA_VERSION = 16;\n",
        "openclaw-state-db-DS2iNFy4.mjs":
            "if (readStateSchemaContentVersion(database) !== 17) throw 1;\n",
    })
    with pytest.raises(AssertionError, match="anchors disagree"):
        _state_schema_version_from(dist)


def test_the_version_anchors_are_all_exercised_by_the_shipped_examples():
    """Guard-the-guard: an anchor no example can reach would rot unnoticed."""
    samples = {
        "named constant (<= 2026.9.4)": "const OPENCLAW_STATE_SCHEMA_VERSION = 17;",
        "content-version guard": "readStateSchemaContentVersion(database) !== 17",
        "migration-version guard": "readStateSchemaMigrationVersion(db) !== 17",
        "newer-schema error":
            'createNewerSqliteSchemaVersionError("OpenClaw state database", pathname, v, 17)',
    }
    assert {name for name, _ in _SCHEMA_VERSION_ANCHORS} == set(samples)
    for name, pattern in _SCHEMA_VERSION_ANCHORS:
        found = pattern.search(samples[name])
        assert found and found.group(1) == "17", name


# ---- B-834: findings of the independent review, pinned ----------------------------------

@pytest.mark.parametrize("literal", ["0x11", "1_7", "1e1", "17.5", "17abc"])
def test_a_version_literal_that_is_not_a_plain_integer_does_not_yield_a_number(tmp_path, literal):
    """The digit capture used to stop at the first non-digit, so `0x11` read as 0, `1_7` and
    `1e1` as 1 and `17.5` as 17 -- a WRONG number returned silently by a sole anchor. It must
    reach the loud failure instead."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-contract-X.mjs": f"const OPENCLAW_STATE_SCHEMA_VERSION = {literal};\n",
    })
    with pytest.raises(AssertionError, match="could not read the state-schema version"):
        _state_schema_version_from(dist)


def test_the_guard_anchors_do_not_backtrack_quadratically_on_an_unterminated_call(tmp_path):
    """`[^)]*` after the call name backtracked quadratically when no `)` follows: 413 s on a
    5 MB line. Bounded now; 2 MB must finish in seconds."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-x.mjs": "readStateSchemaContentVersion(a," * 60_000,
    })
    started = time.monotonic()
    with pytest.raises(AssertionError, match="could not read the state-schema version"):
        _state_schema_version_from(dist)
    assert time.monotonic() - started < 10


def test_a_lone_surrogate_in_a_definition_reaches_the_identity_check_instead_of_crashing(tmp_path):
    sql = 'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS t (a TEXT); -- \\ud800";'
    (tmp_path / "openclaw-state-db-A.mjs").write_text(sql, encoding="utf-8")
    (tmp_path / "openclaw-state-db-B.mjs").write_text(sql, encoding="utf-8")
    assert _find_state_schema_defining_js(tmp_path).name == "openclaw-state-db-A.mjs"


def test_entries_that_only_look_like_bundles_are_skipped_not_fatal(tmp_path):
    """A directory named `vendor.js` and a dangling symlink named `dangling.js` cannot define
    anything; both used to escape as a raw IsADirectoryError / FileNotFoundError."""
    (tmp_path / "vendor.js").mkdir()
    (tmp_path / "dangling.js").symlink_to(tmp_path / "does-not-exist.js")
    (tmp_path / "openclaw-state-db-A.mjs").write_text(_SAME_SQL, encoding="utf-8")
    assert _find_state_schema_defining_js(tmp_path).name == "openclaw-state-db-A.mjs"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_an_unreadable_regular_file_fails_loudly_and_names_the_file(tmp_path):
    """Not skipped silently: an unreadable bundle could be the one that defines the schema."""
    (tmp_path / "openclaw-state-db-A.mjs").write_text(_SAME_SQL, encoding="utf-8")
    hidden = tmp_path / "openclaw-state-db-B.mjs"
    hidden.write_text(_SAME_SQL, encoding="utf-8")
    hidden.chmod(0)
    try:
        with pytest.raises(AssertionError, match="cannot read") as excinfo:
            _find_state_schema_defining_js(tmp_path)
        assert "openclaw-state-db-B.mjs" in str(excinfo.value)
    finally:
        hidden.chmod(0o600)


@pytest.mark.parametrize("text", [
    # a second definition in the same file: only the first would be read
    _SAME_SQL + "\n" + 'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS u (b TEXT);";',
    # the marker inside a comment ahead of the real definition
    '// const OPENCLAW_STATE_SCHEMA_SQL = "old";\n' + _SAME_SQL,
])
def test_a_file_with_the_marker_more_than_once_fails_loudly(tmp_path, text):
    (tmp_path / "openclaw-state-db-A.mjs").write_text(text, encoding="utf-8")
    with pytest.raises(AssertionError, match="2 times"):
        _find_state_schema_defining_js(tmp_path)


@pytest.mark.parametrize("variant", [
    'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS t (a TEXT); ";',       # trailing space
    'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE  TABLE IF NOT EXISTS t (a TEXT);";',       # inner whitespace
    'const OPENCLAW_STATE_SCHEMA_SQL = "create table if not exists t (a text);";',        # case only
])
def test_definitions_differing_only_in_whitespace_or_case_are_not_identical(tmp_path, variant):
    """Pins the strictness of the comparison: the generated files are byte-for-byte copies,
    so a 'helpful' normalisation of the digest must turn this red."""
    (tmp_path / "openclaw-state-db-A.mjs").write_text(_SAME_SQL, encoding="utf-8")
    (tmp_path / "openclaw-state-db-B.mjs").write_text(variant, encoding="utf-8")
    with pytest.raises(AssertionError, match="NOT identical"):
        _find_state_schema_defining_js(tmp_path)


def test_the_stamp_check_is_strict_about_the_whole_line_and_about_duplicates(tmp_path):
    """`_header_field` reads `17 (stale, was 16)` as `17`; the stamp comparison must not."""
    dist = _write_dist(tmp_path / "dist", {
        "openclaw-state-db-DS2iNFy4.mjs":
            "if (readStateSchemaContentVersion(database) !== 17) throw 1;\n",
    })
    stale_note = "-- state-schema-version: 17 (stale, was 16)\n"
    twice = "-- state-schema-version: 17\n-- state-schema-version: 16\n"
    in_body = "-- openclaw-version: x\nCREATE TABLE t (a TEXT);\n-- state-schema-version: 17\n"
    problems = _stamped_schema_version_mismatches(
        dist, {"note": stale_note, "twice": twice, "body_only_is_fine": in_body})
    assert [p.split(":")[0] for p in problems] == ["note", "twice"]


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

    # The `#` half. The two generated files use different comment markers -- SQL for the
    # snapshot, which must executescript, and `#` for the plain table list -- and one
    # parser reads both. Without this case the `#` branch is exercised only indirectly,
    # by tests that would blame the baseline for a parser fault.
    text_header = "# openclaw-version: 2026.9.1\n# tables: 121\n"
    assert _header_field(text_header, "openclaw-version") == "2026.9.1"
    assert _header_field(text_header, "tables") == "121"
    assert _header_field(text_header, "nonexistent-field") is None

    # Not a header line: the marker must start the line, or a table named `tables` in the
    # body could answer for the stamp.
    assert _header_field("openclaw-version: 9.9.9", "openclaw-version") is None


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
    js_path = _find_state_schema_defining_js(dist_dir)
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


_STATE_SCHEMA_STAMP_RE = re.compile(
    r"^(?:--|#)[ \t]*state-schema-version:[ \t]*(\d+)[ \t]*$", re.MULTILINE)


def _stamped_state_schema_versions(text: str) -> "list[str]":
    """Every `state-schema-version` header line in *text*, strictly: the whole line must be
    `<marker> state-schema-version: <digits>`. `_header_field` is looser on purpose (it also
    reads free-text headers), which let `17 (stale, was 16)` pass as `17`."""
    return _STATE_SCHEMA_STAMP_RE.findall(text)


def _stamped_schema_version_mismatches(dist_dir: Path, texts: "dict[str, str]") -> "list[str]":
    """One line per generated file whose `state-schema-version` stamp is not the version the
    dist spells out. Exactly ONE strict stamp line per file, no more, no less. Pure over its
    inputs so the comparison itself is testable offline."""
    installed = _state_schema_version_from(dist_dir)
    problems = []
    for label, text in texts.items():
        stamps = _stamped_state_schema_versions(text)
        if stamps != [str(installed)]:
            problems.append(
                f"{label}: stamped state-schema-version {stamps!r}, dist says {installed}")
    return problems


def test_stamped_state_schema_version_matches_the_installed_dist():
    """B-834, LOCAL-ONLY. The version a generated file is stamped with was read back by
    NOTHING: the one test that compared a stamp compared `openclaw-version`, and the schema
    version was only ever produced by `_installed_state_schema_version()`, which the
    `--write-state-*` regenerators alone reach. So when 2026.9.5 removed the constant the
    reader lost its subject and no test went red. This is the read-back."""
    dist_dir = _require_dist()
    problems = _stamped_schema_version_mismatches(dist_dir, {
        SNAPSHOT_FILE.name: _read_snapshot_sql(),
        VENDOR_TABLES_FILE.name: _read_vendor_table_baseline()[0],
    })
    assert not problems, (
        "; ".join(problems)
        + f". Regenerate: {REGENERATE_CMD} and {REGENERATE_TABLES_CMD}"
    )


def test_a_wrong_state_schema_stamp_is_reported_and_a_right_one_is_not(tmp_path):
    """Positive control for the comparison above, on a synthetic dist."""
    dist = _write_dist(tmp_path / "dist", {
        "openclaw-state-db-DS2iNFy4.mjs":
            "if (readStateSchemaContentVersion(database) !== 17) throw 1;\n",
    })
    right = "-- openclaw-version: 2026.9.5\n-- state-schema-version: 17\n"
    wrong = "# openclaw-version: 2026.9.5\n# state-schema-version: 16\n"
    missing = "# openclaw-version: 2026.9.5\n"
    assert _stamped_schema_version_mismatches(dist, {"a.sql": right}) == []
    problems = _stamped_schema_version_mismatches(
        dist, {"a.sql": right, "b.txt": wrong, "c.txt": missing})
    assert [p.split(":")[0] for p in problems] == ["b.txt", "c.txt"]
    assert "16" in problems[0] and "dist says 17" in problems[0]


# ========================================================================================
# B-721: the vendor's TABLE SET -- the oracle that was missing entirely.
#
# 2026.9.1 added five tables to the state schema: four of them a skill library
# (`skill_library_entries` / `_revisions` / `_uploads` / `_events`) and one recording
# GitHub personal publication requests. Both state-DB oracles reported clean, and each
# for its own structural reason:
#
#   * scripts/state_db_drift_gate.py derives its expectations from the SELECT statements
#     clawseccheck/ actually issues, so a table no reader names is invisible to it. Its
#     own docstring says exactly this ("A table we do not read at all -- a NEW surface").
#   * this module's snapshot is a PROJECTION, not the vendor schema: _target_table_names()
#     intersects with the tables this tree declares or reads, so a vendor table we neither
#     declare nor read is excluded BY DESIGN. It regenerated across the upgrade with 7
#     tables and only the version stamp moved, while the vendor schema grew by five.
#
# Two green oracles and one genuinely new surface. Measured on 2026.9.1: the vendor
# declares 121 tables and this tree models 7. Neither oracle was WRONG -- each was green
# about the surface it reads. Nothing enumerated the surface neither of them reads.
#
# So the baseline below is the vendor's table set, whole and unprojected, and the
# local-only test compares against it as a SET. A table added by an upgrade then arrives
# as a named delta instead of waiting for someone to notice it.
#
# It stores the SET but reports only the DELTA. The unmodelled set is 114 entries on this
# build, and a permanently-long list is not a signal -- the same reasoning
# state_db_drift_gate.py already applies to its `unread col` line.
#
# WHAT THIS DOES NOT CLAIM. Being in the baseline says the vendor DECLARES a table, not
# that any database has one: measured on this machine, 13 declared tables (the whole
# skill_library family among them) are absent from the live DB even though the DDL is all
# `CREATE TABLE IF NOT EXISTS`. So a check built on this surface must treat an absent
# table as UNKNOWN and never as a clean PASS -- "the table is not here" is not evidence
# the feature is unused.
# ========================================================================================

VENDOR_TABLES_FILE = Path(__file__).resolve().parent / "vendor_state_tables.txt"

REGENERATE_TABLES_CMD = (
    "PYTHONPATH=tests:. python3 tests/test_state_schema_grounding.py --write-state-tables"
)

# Tables clawseccheck/ still SELECTs from that the current vendor schema no longer
# declares. Names only -- the reasons are the disproofs already written for their
# fixtures, so there is one copy of each, not two.
# test_retired_tables_are_absent_from_the_vendor_baseline re-grounds both claims against
# the CURRENT baseline on every run, which is what stops the version named inside those
# strings from quietly going stale.
_RETIRED_TABLES_STILL_READ = {
    "cron_run_logs": _CRON_RUN_LOGS_RETIRED,
    "installed_plugin_index": _INSTALLED_PLUGIN_INDEX_RETIRED,
}

# CLAWSECCHECK-B-845: a THIRD, honestly-named exemption -- not a member of
# _RETIRED_TABLES_STILL_READ, because these tables are neither retired NOR absent from
# the vendor: they are live, current vendor tables that simply live in a DIFFERENT
# SQLite file (agents/<agent-id>/agent/openclaw-agent.sqlite, the per-agent database)
# than the one this baseline enumerates (state/openclaw.sqlite, the shared database).
# `_AUTH_PROFILE_TABLES_DIFFERENT_DB` above already carries this exact reasoning for the
# TEST-DDL side of this file; this is its CODE-side counterpart, needed for the first
# time now that collector.py issues a literal `SELECT ... FROM auth_profile_store`
# against the per-agent database (grounded against the installed dist, 2026.9.5:
# sqlite-Cp6HSWY4.mjs -- see collector._collect_agent_auth_profile_store_presence's own
# docstring).
#
# trajectorystore.py's own per-agent-DB reads (`trajectory_runtime_events`) are
# deliberately NOT listed here: that module binds its SQL through a module-level
# constant (`_SELECT_TRAJECTORY_ROWS`) rather than a literal string at the
# `.execute()` call site, so `_clawseccheck_read_tables()`'s AST extractor (anchored on
# `.execute()` arguments -- see scripts/state_db_drift_gate.py's own docstring) does not
# see it at all. That is a known, narrow extraction gap in a DIFFERENT script, not
# something this registration should paper over by imitating it -- registering a table
# the extractor cannot even find would assert nothing.
_DIFFERENT_DB_TABLES_STILL_READ = {
    "auth_profile_store": (
        "auth_profile_store (CLAWSECCHECK-B-845) lives in the PER-AGENT database "
        "(agents/<agent-id>/agent/openclaw-agent.sqlite), never in the shared state "
        "database (state/openclaw.sqlite) this baseline enumerates -- a different "
        "SQLite file this baseline's generator never visits, so its absence from the "
        "baseline is not drift. Live and current (grounded against the installed "
        "dist, 2026.9.5), not retired."
    ),
}

# B-811: a SEPARATE, honestly-named exemption from _RETIRED_TABLES_STILL_READ, not a
# member of it -- `sqlite_master` was never a vendor APPLICATION table to begin with,
# so calling it "retired" would be a false claim about something that was never true.
# It is SQLite's own built-in system catalog, present unconditionally in every SQLite
# file the engine has ever produced, completely independent of what
# OPENCLAW_STATE_SCHEMA_SQL declares in any version. trajectorystore.py's
# `_table_kind()` (added 2026-09-15, adversarial review of B-811) queries it to
# distinguish a real TABLE from a VIEW before trusting a name -- see that function's
# own docstring for why the check exists.
_SQLITE_BUILTIN_CATALOG_TABLES = {"sqlite_master"}

_VENDOR_TABLES_HEADER = """\
# vendor_state_tables.txt -- GENERATED. Do not hand-edit.
#
# openclaw-version: {version}
# state-schema-version: {schema_version}
# generated: {generated}
# tables: {count}
#
# source-bundle: {source_file}
#   Recorded, not assumed: the generator writes the file it ACTUALLY resolved. That name
#   is build output and rotates between releases, so it is evidence, not a locator.
#
# What this is
# ------------
# Every table name the installed OpenClaw's `OPENCLAW_STATE_SCHEMA_SQL` declares -- the
# vendor's whole state-SQLite surface, NOT the part this tree models. Its sibling
# state_schema_snapshot.sql is deliberately the opposite: full DDL, projected to the few
# tables we read.
#
# Why it exists
# -------------
# Both state-DB oracles are projections of what this tree already reads, so neither can
# report a table nobody reads. 2026.9.1 added a skill library to the state schema and
# both stayed green. This file is the unprojected set they lacked; the delta against it
# is what names a new vendor surface.
#
# Regenerate on a machine with the matching OpenClaw installed -- it is a step in the
# upgrade protocol's re-baseline, never a hand edit:
#   {regen_cmd}
#
"""


def _read_vendor_table_baseline() -> "tuple[str, list]":
    """(whole file text, table names in file order) from the shipped baseline."""
    text = VENDOR_TABLES_FILE.read_text(encoding="utf-8")
    names = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return text, names


def _table_set_delta(vendor, baseline) -> "tuple[list, list]":
    """(added, removed) -- what the vendor gained and lost relative to the baseline.

    A plain set difference, kept as its own function so it can be exercised on synthetic
    inputs. Without that control, "the baseline matches the dist" passes exactly as well
    on a comparison that is incapable of reporting anything at all.
    """
    return sorted(set(vendor) - set(baseline)), sorted(set(baseline) - set(vendor))


def _write_vendor_table_baseline() -> int:
    """Regenerate VENDOR_TABLES_FILE from a real installed OpenClaw. Raises rather than
    writing a vacuous file when no dist is present -- a script entry point, not a test."""
    if not OPENCLAW_DIST.is_dir():
        raise RuntimeError(
            f"OpenClaw dist not installed at {OPENCLAW_DIST} -- cannot regenerate a "
            "vacuous table baseline. Run this on a machine with the matching OpenClaw "
            "installed."
        )
    js_path = _find_state_schema_defining_js(OPENCLAW_DIST)
    sql_text = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    tables = sorted(_dist_table_ddl_texts(sql_text))
    if not tables:
        raise RuntimeError(
            "extracted ZERO tables from the vendor schema -- refusing to write an empty "
            "baseline, which would make every later comparison vacuously clean."
        )
    header = _VENDOR_TABLES_HEADER.format(
        version=_installed_openclaw_version(),
        schema_version=_installed_state_schema_version(),
        generated=date.today().isoformat(),
        count=len(tables),
        source_file=js_path.name,
        regen_cmd=REGENERATE_TABLES_CMD,
    )
    VENDOR_TABLES_FILE.write_text(header + "\n".join(tables) + "\n", encoding="utf-8")
    return len(tables)


def test_the_vendor_table_baseline_is_well_formed():
    """Always-on. A malformed or empty baseline would make the dist comparison below
    vacuously clean, which is the failure this whole section exists to prevent."""
    text, names = _read_vendor_table_baseline()

    assert names, f"{VENDOR_TABLES_FILE.name} lists no tables. Regenerate: {REGENERATE_TABLES_CMD}"
    assert names == sorted(names), "table names are not sorted -- the file is generated, not edited"
    assert len(names) == len(set(names)), (
        f"duplicate table names: {sorted({n for n in names if names.count(n) > 1})}"
    )

    stamped = _header_field(text, "tables")
    assert stamped is not None, "the header does not stamp a table count"
    assert int(stamped) == len(names), (
        f"the header stamps {stamped} tables but the body lists {len(names)} -- one of "
        f"the two was hand-edited. Regenerate: {REGENERATE_TABLES_CMD}"
    )
    for field in ("openclaw-version", "state-schema-version", "source-bundle"):
        assert _header_field(text, field), f"header is missing {field}"


def test_the_table_delta_reports_both_directions_and_is_quiet_when_nothing_moved():
    """The negative control for the comparison itself.

    An always-fires guard and a never-fires guard are indistinguishable from a single
    green run against a matching dist, so the delta is exercised on synthetic sets in
    both directions AND on the case where nothing changed.
    """
    baseline = {"a", "b", "c"}

    added, removed = _table_set_delta(baseline, baseline)
    assert (added, removed) == ([], []), "reported a delta between a set and itself"

    added, removed = _table_set_delta(baseline | {"skill_library_entries"}, baseline)
    assert added == ["skill_library_entries"] and removed == []

    added, removed = _table_set_delta(baseline - {"b"}, baseline)
    assert added == [] and removed == ["b"]


def test_every_state_table_clawseccheck_reads_is_declared_by_the_vendor():
    """Always-on, and it needs no dist: the baseline stands in for the vendor schema.

    Catches a reader pointed at a table the vendor does not have -- a typo, or a table
    retired by an upgrade -- on the CI floor as well as here. The two retired names our
    dual-shape readers still mention are registered, with the disproof already written
    for their fixtures.
    """
    _, names = _read_vendor_table_baseline()
    unknown = sorted(
        _clawseccheck_read_tables() - set(names) - set(_RETIRED_TABLES_STILL_READ)
        - _SQLITE_BUILTIN_CATALOG_TABLES - set(_DIFFERENT_DB_TABLES_STILL_READ)
    )
    assert not unknown, (
        f"clawseccheck/ SELECTs from table(s) the vendor schema does not declare: "
        f"{unknown}. Either the vendor retired them -- register them in "
        f"_RETIRED_TABLES_STILL_READ with the evidence -- or it is a SQLite built-in "
        f"system table (register it in _SQLITE_BUILTIN_CATALOG_TABLES instead) -- or "
        f"it is a live table in a DIFFERENT sqlite file than this baseline enumerates "
        f"(register it in _DIFFERENT_DB_TABLES_STILL_READ instead) -- or the reader is "
        f"misspelled."
    )


def test_retired_tables_are_absent_from_the_vendor_baseline():
    """The other half, and the one that keeps the registrations honest.

    Each entry in _RETIRED_TABLES_STILL_READ asserts a table is GONE from the vendor
    schema. That claim is written in prose naming a specific OpenClaw version, and prose
    does not re-check itself. This re-grounds both against the current baseline on every
    run: if a name comes back, the registration is stale and the test says so.
    """
    _, names = _read_vendor_table_baseline()
    resurrected = sorted(set(_RETIRED_TABLES_STILL_READ) & set(names))
    assert not resurrected, (
        f"registered as retired but present in the current vendor schema: {resurrected}. "
        "The disproof text for each is now false -- drop the registration and treat the "
        "table as live."
    )


def test_different_db_tables_are_genuinely_absent_from_the_shared_vendor_baseline():
    """CLAWSECCHECK-B-845's analogue of the retired-table re-grounding above.

    _DIFFERENT_DB_TABLES_STILL_READ asserts each table lives in the PER-AGENT database,
    never the shared one this baseline enumerates. If a future OpenClaw release folded
    one of these into the shared state DB too, its name would start appearing in
    `names` here -- not a failure by itself (the table would simply also be reachable
    the ordinary way), but a signal that the "different DB, not modelled here" reasoning
    in the registration's own text is now incomplete and should be revisited.
    """
    _, names = _read_vendor_table_baseline()
    also_shared = sorted(set(_DIFFERENT_DB_TABLES_STILL_READ) & set(names))
    assert not also_shared, (
        f"registered as per-agent-DB-only but ALSO present in the shared vendor "
        f"schema: {also_shared}. The 'never in the shared state database' claim in "
        f"the registration's own text is now stale -- re-read the current dist and "
        f"update or drop the registration."
    )


def test_the_baseline_captured_the_surface_that_prompted_it():
    """Positive control for the generator, not a coverage pin.

    A baseline built by accident from the projected 7-table set would satisfy every
    assertion above and still be blind to exactly what B-721 is about. The skill-library
    family is the concrete surface the two projecting oracles missed, so its presence is
    what proves this file records the vendor's schema rather than our model of it.

    Deliberately NOT asserted here: that these tables stay unmodelled. Reading them is
    the improvement this file exists to prompt, and a guard that reddens when someone
    makes it would be a tripwire pointed the wrong way.
    """
    _, names = _read_vendor_table_baseline()
    missing = sorted({"skill_library_entries", "skill_library_revisions",
                      "skill_library_uploads", "skill_library_events"} - set(names))
    assert not missing, (
        f"the baseline does not list {missing} -- it was generated from a projection "
        f"rather than from the vendor schema. Regenerate: {REGENERATE_TABLES_CMD}"
    )


def test_vendor_table_baseline_matches_the_installed_dist():
    """LOCAL-ONLY (needs the dist). The oracle itself.

    This is the run that would have named `skill_library_*` on the 2026.8.2 -> 2026.9.1
    upgrade, where both existing state-DB oracles came back clean.
    """
    dist_dir = _require_dist()
    js_path = _find_state_schema_defining_js(dist_dir)
    sql_text = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    vendor = set(_dist_table_ddl_texts(sql_text))

    text, names = _read_vendor_table_baseline()
    added, removed = _table_set_delta(vendor, names)

    modelled = _target_table_names(vendor)
    coverage = f"{len(modelled)} of {len(vendor)} vendor tables are modelled by this tree"
    assert not (added or removed), (
        f"the vendor's state-schema table set moved.\n"
        f"  added by the vendor : {added}\n"
        f"  gone from the vendor: {removed}\n"
        f"({coverage}.) Decide what each addition holds before re-baselining -- an added "
        f"table may be a surface this tool should read. Then: {REGENERATE_TABLES_CMD}"
    )

    stamped = _header_field(text, "openclaw-version")
    installed = _installed_openclaw_version()
    assert stamped == installed, (
        f"{VENDOR_TABLES_FILE.name} is stamped openclaw-version: {stamped!r} but the "
        f"installed OpenClaw is {installed!r}. An unread stamp is how a stale baseline "
        f"stays green. Regenerate: {REGENERATE_TABLES_CMD}"
    )


def test_write_vendor_table_baseline_raises_without_a_dist(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "OPENCLAW_DIST", Path("/nonexistent/openclaw/dist"))
    with pytest.raises(RuntimeError, match="cannot regenerate a vacuous table baseline"):
        _write_vendor_table_baseline()


if __name__ == "__main__":
    if "--write-state-snapshot" in sys.argv:
        n = _write_state_snapshot()
        print(f"wrote {SNAPSHOT_FILE} -- {n} tables")
    elif "--write-state-tables" in sys.argv:
        n = _write_vendor_table_baseline()
        print(f"wrote {VENDOR_TABLES_FILE} -- {n} vendor tables")
    else:
        # Exit NON-zero. This is a re-baseline step, and the upgrade protocol runs it
        # chained behind other commands: a usage error that exits 0 lets a run that wrote
        # NOTHING report success, after which an unchanged snapshot reads as "the vendor
        # did not move" instead of "the generator never ran".
        print(
            "usage: python3 tests/test_state_schema_grounding.py "
            "[--write-state-snapshot | --write-state-tables]",
            file=sys.stderr,
        )
        sys.exit(2)
