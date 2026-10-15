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

`PYTHONPATH=tests` is load-bearing — `OPENCLAW_DIST` comes from `tests/_distgrounding.py`
(which in turn reads `REAL_HOME` from `tests/_realhome.py`), because the suite redirects
`$HOME` for the rest of the run. Hand-editing the snapshot is the guard writing its own
evidence — regenerate it, never patch it by hand.

To re-baseline against a CANDIDATE OpenClaw before upgrading the real machine
(CLAWSECCHECK-C-583): extract its tarball anywhere and point `CSC_OPENCLAW_DIST` — read
once, in `tests/_distgrounding.py` — at its `dist/` dir, instead of symlinking a fake
`$HOME` over it:

    CSC_OPENCLAW_DIST=/path/to/candidate/package/dist PYTHONPATH=tests:. python3 \\
        tests/test_state_schema_grounding.py --write-state-snapshot

Unset, this module's `OPENCLAW_DIST` is exactly the REAL_HOME-derived path it always was.
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

from _distgrounding import OPENCLAW_DIST, _JS_EXTS

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
FIXTURES_DIR = REPO_ROOT / "fixtures"
PACKAGE_DIR = REPO_ROOT / "clawseccheck"
DRIFT_GATE_SCRIPT = REPO_ROOT / "scripts" / "state_db_drift_gate.py"

SNAPSHOT_FILE = Path(__file__).resolve().parent / "state_schema_snapshot.sql"

# Imported from `_distgrounding` (same value `test_schema_grounding.py` uses) rather than
# hand-rolled here: it is the single reader of CLAWSECCHECK-C-583's test-only
# CSC_OPENCLAW_DIST override (see the module docstring above and `_distgrounding.py`).
# Unset, it is byte-identical to the REAL_HOME-derived path this used to hard-code (B-519:
# REAL_HOME, not Path.home() — see tests/_realhome.py).
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
#
# KNOWN, ACCEPTED LIMIT (C-580, a later independent review): "content-version guard" and
# "migration-version guard" match on SYNTAX (`<call> !== N`) alone, which a per-step
# migration precondition can share -- nothing here proves the N a lone such match reports
# describes the CURRENT schema version rather than some earlier step's target. Requiring a
# second, distinct anchor before trusting one was considered and rejected: it would turn
# real single-anchor states this reader must keep accepting (the pre-9.5 named-constant-only
# era; test_state_schema_version_finds_the_anchor_in_a_nested_chunk's single migration-guard
# case) into false failures, trading a narrow, never-yet-observed risk for a guaranteed one.
# Pinned by test_a_lone_ambiguous_anchor_cannot_be_told_from_a_step_precondition_guard,
# not fixed.
#
# THE LIMIT BIT ON 2026.9.7, and the narrower fix is the one the note above did NOT reject.
# `if (readStateSchemaContentVersion(database) !== 1 || tableExists(database,
# "config_machine_state") || ...)` is a legacy-migration precondition ("is this the pre-
# `config_machine_state` database?"), so the content-version guard read {1, 19} beside the
# ladder top 19 and both `--write-state-*` regenerators failed. Requiring corroboration for a
# LONE match is still rejected (it would break the single-anchor states named above); what
# is added is a ranking when the evidence is plentiful: the two anchors that spell the
# vendor's own "highest version I understand" (`_HIGHEST_VERSION_ANCHORS`) are authoritative
# once they agree on one value, and every `!== N` guard must then be at or below it, with at
# least one AT it. A guard ABOVE the top, or a top no guard corroborates, is still a loud
# disagreement, and so is any state where the two authority anchors are absent or differ.
_HIGHEST_VERSION_ANCHORS = ("named constant (<= 2026.9.4)", "newer-schema error")
_STEP_GUARD_ANCHORS = ("content-version guard", "migration-version guard")
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
    sentence above reads: it covers only the definitions spelled `const
    OPENCLAW_STATE_SCHEMA_SQL = "..."` -- the spelling this module extracts.
    `config-doctor/runtime-*.js` reads the SQL from a `.sql` file the package does not ship;
    that one is still not compared here (it is a build-time artifact, not something a
    running OpenClaw can open).

    C-580: the worker thread (`worker/worker.mjs`) also embeds the constant, on every
    release 8.2 through 9.5, but as a TEMPLATE literal, minified (no `const`, no spaces
    around `=`) unlike the readable top-level chunk this function locates -- a different
    enough spelling that folding it into THIS function's own multi-file digest comparison
    would require every synthetic unit test below to grow a matching `worker/worker.mjs`
    fixture just to keep constructing a valid dist. Grounded byte-equal against the
    installed 2026.9.5 dist and diffed against the string copy on all six releases before
    that, so no wrong answer exists today -- but "diffed once by hand" is exactly the
    unverified claim this whole module exists to stop trusting (see the module docstring's
    own B-710 history). `_assert_worker_template_copy_matches_primary` below is the
    verification: a separate, explicit second half of the identity proof, called by every
    real-dist caller of this function (`_write_state_snapshot`,
    `_write_vendor_table_baseline`, `test_worker_template_copy_matches_the_installed_dist`)
    but never by this function's own synthetic unit tests, whose tmp_path dists are
    deliberately too small to carry a worker bundle.

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


# --------------------------------------------------------------------------------------
# C-580: the worker thread's TEMPLATE-LITERAL copy of the schema (see
# `_find_state_schema_defining_js`'s "SCOPE OF THAT PROOF" note). A second spelling needs
# a second extractor -- a template literal is delimited by backticks, not double quotes,
# and (unlike a double-quoted string) may embed a real, unescaped newline directly, so it
# needs no `\n`-unescaping to reproduce the SQL's line breaks. It can also embed a `${...}`
# interpolation, which a double-quoted string cannot; the loop below fails loudly on one
# rather than silently returning literal `${...}` text as if it were SQL.
# --------------------------------------------------------------------------------------

# C-683 (2026.10.1): the build moved the worker's copy out of `worker/worker.mjs` (a template
# literal) into `state/openclaw-state-read.worker.js`, where it is a DOUBLE-QUOTED string
# assigned after a bare `var OPENCLAW_STATE_SCHEMA_SQL;`. A filename is build output, so the
# copy is located the way the primary definition is: by the constant, anywhere in the dist,
# in either spelling. A `const`/`let` declaration is the primary definition, not a copy.
_WORKER_TEMPLATE_MARKER_RE = re.compile(r"\bOPENCLAW_STATE_SCHEMA_SQL\s*=\s*([`\"])")
_DECLARATION_BEFORE_RE = re.compile(r"\b(?:const|let)\s+$")


def _read_assigned_schema_literal(js_text: str, m: "re.Match") -> str:
    """The unescaped SQL of the literal opening just past *m* (a `_WORKER_TEMPLATE_MARKER_RE`
    match). A template literal fails loudly on a `${...}`; a double-quoted string cannot
    interpolate. Both spellings share one escape table (ECMA-262 11.8.4 / 11.8.6)."""
    start = m.end()
    i, n = start, len(js_text)
    if m.group(1) == '"':
        while i < n and js_text[i] != '"':
            i += 2 if js_text[i] == "\\" else 1
        if i >= n:
            raise AssertionError("unterminated worker-thread double-quoted schema string in the dist")
        return _unescape_js_double_quoted(js_text[start:i])
    while i < n:
        c = js_text[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            break
        if c == "$" and js_text[i:i + 2] == "${":
            raise AssertionError(
                "the worker template literal contains an unescaped ${...} interpolation "
                "-- it is not a static string, so it cannot be compared as one; re-ground "
                "the extractor before trusting anything downstream."
            )
        i += 1
    else:
        raise AssertionError("unterminated worker-thread template literal in the dist")
    return _unescape_js_double_quoted(js_text[start:i])


def _extract_worker_template_schema_sql(js_text: str) -> str:
    """The unescaped SQL of the first `OPENCLAW_STATE_SCHEMA_SQL = <backtick or double-quote
    literal>` assignment in *js_text* -- the worker thread's copy of the schema (a template literal in
    `worker/worker.mjs` through 2026.9.9, a double-quoted string in
    `state/openclaw-state-read.worker.js` on 2026.10.1). The regex tolerates optional spacing
    either way, not because spacing has been observed to vary on its own, but because nothing
    about this proof depends on it staying minified.

    Reuses `_unescape_js_double_quoted` for the escape table: `\\n`/`\\t`/`\\\\`/`\\uXXXX`/
    the JS fallback rule are the same set for a template literal as for a double-quoted
    string. A raw, unescaped newline needs no special handling either -- the unescape pass
    only transforms backslash-prefixed sequences and leaves it as-is.
    """
    m = _WORKER_TEMPLATE_MARKER_RE.search(js_text)
    if m is None:
        raise AssertionError(
            f"{_WORKER_TEMPLATE_MARKER_RE.pattern!r} not found in the text -- the worker "
            "thread no longer embeds the state schema as a literal the way this "
            "guard expects; re-ground it against the current bundle before trusting "
            "anything downstream."
        )
    return _read_assigned_schema_literal(js_text, m)


def _worker_copy_sqls(js_text: str) -> "list[str]":
    """The SQL of every assignment of the constant that is NOT its `const`/`let` declaration."""
    return [
        _read_assigned_schema_literal(js_text, m)
        for m in _WORKER_TEMPLATE_MARKER_RE.finditer(js_text)
        if not _DECLARATION_BEFORE_RE.search(js_text[max(0, m.start() - 16):m.start()])
    ]


def _worker_schema_copies(dist_dir: Path) -> "list[tuple[Path, str]]":
    """(file, SQL) for every non-declaration copy of the schema constant anywhere in the dist.
    An unreadable regular file fails loudly (it could be the one that holds the copy)."""
    copies = []
    for ext in _JS_EXTS:
        for path in sorted(dist_dir.rglob("*" + ext)):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise AssertionError(
                    f"cannot read {path} while looking for the worker's copy of the state "
                    f"schema: {exc}. An unreadable bundle could be the one that holds it.") from exc
            if "OPENCLAW_STATE_SCHEMA_SQL" not in text:
                continue
            copies.extend((path, sql) for sql in _worker_copy_sqls(text))
    return copies


def _assert_worker_template_copy_matches_primary(dist_dir: Path, primary_sql: str) -> None:
    """C-580: the second half of `_find_state_schema_defining_js`'s identity proof --
    verifying, not merely asserting in a docstring, that the worker thread's copy of the
    schema is the SAME schema as *primary_sql* (the text that function already proved every
    primary definition agrees on).

    C-683: the copy is found by the constant, in any bundle of the dist and in either
    spelling, never by `worker/worker.mjs` -- 2026.10.1 moved it. At least one copy must
    exist and EVERY copy must equal the primary; none found is a loud failure, never a skip.

    Deliberately a standalone function, not folded into `_find_state_schema_defining_js`
    itself: that function's own synthetic unit tests build tiny tmp_path dists with none
    of the surrounding bundle layout, and requiring a worker bundle in every one of them
    to keep constructing a valid dist would test this proof's plumbing, not its logic.
    """
    copies = _worker_schema_copies(dist_dir)
    if not copies:
        raise AssertionError(
            f"no worker-thread copy of the state schema (an `OPENCLAW_STATE_SCHEMA_SQL = ...` "
            f"assignment outside its const declaration) was found in any bundle under "
            f"{dist_dir} -- the worker thread embedded one on every release 8.2 through "
            "10.1; re-ground this guard against the current bundle layout before trusting "
            "anything downstream."
        )
    # surrogatepass: matches _find_state_schema_defining_js's own digest comparison.
    primary_digest = hashlib.sha256(primary_sql.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    for path, sql in copies:
        if sql != primary_sql:
            copy_digest = hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()[:12]
            raise AssertionError(
                f"{path}'s copy of the state schema ({copy_digest}) does NOT match the "
                f"primary definition ({primary_digest}). Byte-identical on every release 8.2 "
                "through 10.1 until now -- decide which the runtime actually uses before "
                "trusting a snapshot taken from either."
            )


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
    highest = {v for name in _HIGHEST_VERSION_ANCHORS for v in evidence.get(name, ())}
    if len(highest) == 1:
        top = next(iter(highest))
        guards = {v for name in _STEP_GUARD_ANCHORS for v in evidence.get(name, ())}
        if all(g <= top for g in guards) and (not guards or top in guards):
            return top
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
    # C-580: the second half of the identity proof -- worker/worker.mjs's template-literal
    # copy must be the SAME schema before a baseline is regenerated from either.
    _assert_worker_template_copy_matches_primary(OPENCLAW_DIST, sql_text)
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
_CONFIG_MACHINE_STATE_UPDATED_AT_LEGACY = (
    "carries `updated_at INTEGER` where the vendor's config_machine_state has `updated_at_ms "
    "INTEGER NOT NULL`, and `state_key` without the vendor's NOT NULL -- a column the vendor "
    "table does not have, so not a subset. The test reads only the cron.store row's "
    "value_json, never the timestamp column."
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
    "(tests/test_f187_trajectory_sqlite_corroborator.py:94) is an f-string "
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
_B909_TRAJECTORY_SIDECAR_STRIPPED_SHAPE = (
    "trajectory_runtime_events (B-909) lives in the PER-AGENT database "
    "(agents/<agent>/agent/openclaw-agent.sqlite), never in the state database "
    "(state/openclaw.sqlite) this snapshot/registry classifies -- same 'different DB' "
    "reasoning as _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB. Registered separately, not "
    "under that constant, because this site's DDL is NOT a verbatim copy of test_f187's "
    "own fixture: this test only exercises the read-only-open-materializes-WAL-sidecars "
    "side effect (B-909) via trajectorystore._open_readonly, never "
    "trajectorystore.corroborate()'s actual row reads, so it declares a stripped-down "
    "(session_id TEXT, seq INTEGER, event_json TEXT) shape -- missing run_id, "
    "created_at, every NOT NULL, and the PRIMARY KEY the real per-agent table (and every "
    "_TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB site) carries. Still absent from the state "
    "snapshot for the same different-database reason, so still LEGACY_TABLE."
)
_B909_IMMUTABLE_DEMO_DECOY = (
    "a deliberately generic, single-column table (`t`) used only by "
    "test_immutable_1_would_silently_hide_uncommitted_wal_rows to demonstrate SQLite's "
    "mode=ro vs immutable=1 WAL-visibility difference in a bare tmp_path SQLite file -- "
    "never opened through collect() or any per-agent-DB reader, never a real OpenClaw "
    "table name, never meant to resolve against any vendor shape."
)
_B176_SOMETHING_ELSE_PREDATES_TABLE = (
    "a single-column table named `something_else`, used only to prove "
    "_collect_paired_devices_sqlite treats a database that predates the "
    "device_pairing_paired table entirely as \"not found\" (found=False), never as a "
    "parse error and never as a confident absence -- never a real OpenClaw table name, "
    "never meant to resolve against any vendor shape."
)
_B176_VIEW_MASQUERADE_DECOY = (
    "a `decoy` table backing a VIEW named `device_pairing_paired`, used by this file's "
    "two view-masquerade hardening tests (fabricate a false WARN by giving the view a "
    "full column set with a spoofed high-scope row; suppress a genuine WARN by giving it "
    "a minimal one-column shape) -- same `_table_kind` sqlite_master-type refusal already "
    "proven for config_machine_state/installed_plugin_index. The decoy's own column shape "
    "is incidental to what each test actually checks (that the VIEW is refused by type "
    "before any row is read), so both sites share this entry despite differing column "
    "counts. Never a real OpenClaw table name itself."
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
    "tests/test_limit_hit_domains.py:54": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    # CLAWSECCHECK test-suite-drift sweep (2026-09-24): B-909's own state-DB cron_jobs
    # fixture (test_collect_also_creates_state_db_sidecars_from_nothing, run through the
    # real collect() path, unlike the per-agent-DB entries above) -- never previously
    # registered. Byte-identical to test_b294_cron_run_logs.py's own _CRON_JOBS_DDL
    # constant (same 7 columns: job_id, name, enabled, delete_after_run, trigger_script,
    # payload_kind, payload_message), so the same _CRON_JOBS_LEGACY reason applies
    # verbatim -- no new reason constant needed.
    "tests/test_b909_wal_sidecar_creation.py:108": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),

    # ---- cron_run_logs (retired table) ----
    "tests/test_b294_cron_run_logs.py:49": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),
    "tests/test_b709_cron_run_logs_shapes.py:43": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),
    "tests/test_limit_hit_domains.py:58": _Entry(LEGACY_TABLE, _CRON_RUN_LOGS_RETIRED),

    # ---- installed_plugin_index (retired table) ----
    "tests/test_b177_installed_index_shapes.py:68": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:53": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:288": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b177_plugin_clawhub_trust.py:313": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b187_plugin_tool_result_middleware.py:82": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_b187_plugin_tool_result_middleware.py:332": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_f150_plugin_sweep.py:82": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    "tests/test_f153_dashboard_full.py:352": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),
    # C-654: the plugin-vet FIFO tests build the same retired-table home as test_f150_plugin_sweep.
    "tests/test_c654_plugin_tree_fifo.py:620": _Entry(LEGACY_TABLE, _INSTALLED_PLUGIN_INDEX_RETIRED),

    # ---- config_machine_state (F-183) ----
    "tests/test_b177_installed_index_shapes.py:55": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_LOOSE_LEGACY),
    # B-862 reuses the same loose 3-column shape verbatim to build an oversized
    # plugins.installedIndex row; same classification, same reason.
    "tests/test_b862_sarif_limit_hits_delimited_paths.py:138": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_LOOSE_LEGACY),
    # B-704's -shm sidecar test builds a state DB from the same two copied shapes
    # (cron_jobs from test_b294, config_machine_state from test_f183/b177); same
    # classifications, same reasons.
    "tests/test_b704_state_db_shm_sidecar.py:42": _Entry(LEGACY_COLS, _CRON_JOBS_LEGACY),
    "tests/test_b704_state_db_shm_sidecar.py:46": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_LOOSE_LEGACY),
    # C-680c: the cron.store machine-state key test builds a config_machine_state with the
    # column `updated_at` (the vendor's is `updated_at_ms`) and no NOT NULL on state_key --
    # a hand-written shape no OpenClaw release ever shipped.
    "tests/test_c680c_elided_disclosure.py:168": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_UPDATED_AT_LEGACY),
    # B-889 round 1: the decoy table a `CREATE VIEW config_machine_state AS SELECT ...
    # FROM decoy_secrets` view-masquerade fixture projects from -- never a real
    # OpenClaw table, same shape as every other _UNRELATED_DECOY entry above/below. The
    # extractor does not see the `CREATE VIEW` statement itself (it only walks
    # `CREATE TABLE`), so only this one site needs registering. (Line renumbered from
    # :342 to :925 by the merge that placed the B-845 per-agent test class earlier in
    # this file, ahead of B-889's own class.)
    "tests/test_b749_auth_profile_store_presence.py:1050": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    # B-889 round 2: the embedded-NUL-byte regression fixture -- same loose (no NOT
    # NULL) 3-column shape as tests/test_b177_installed_index_shapes.py:55, same DDL
    # text verbatim, same classification. (Renumbered from :409 to :992, same reason.)
    "tests/test_b749_auth_profile_store_presence.py:1117": _Entry(LEGACY_COLS, _CONFIG_MACHINE_STATE_LOOSE_LEGACY),
    # B-977: the decoy table a `CREATE VIEW config_machine_state AS SELECT ... FROM
    # decoy_state` view-masquerade fixture projects from -- never a real OpenClaw
    # table, same shape/reason as B-889's own decoy_secrets entry above. The extractor
    # does not see the `CREATE VIEW` statement itself (it only walks `CREATE TABLE`),
    # so only this one site needs registering.
    "tests/test_f183_config_machine_state.py:389": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    # B-990: the decoy table a `CREATE VIEW config_machine_state AS SELECT ... FROM
    # decoy_plugin_state` view-masquerade fixture projects from -- never a real
    # OpenClaw table, same shape/reason as B-889's own decoy_secrets entry above. The
    # extractor does not see the `CREATE VIEW` statement itself (it only walks
    # `CREATE TABLE`), so only this one site needs registering.
    "tests/test_b177_installed_index_shapes.py:440": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),
    # B-994: the decoy table a `CREATE VIEW installed_plugin_index AS SELECT ... FROM
    # decoy_plugin_index` view-masquerade fixture projects from -- never a real
    # OpenClaw table, same shape/reason as B-990's own decoy_plugin_state entry above.
    # The extractor does not see the `CREATE VIEW` statement itself (it only walks
    # `CREATE TABLE`), so only this one site needs registering.
    "tests/test_b177_installed_index_shapes.py:557": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),

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
    # Re-verified 2026-09-23 (B-852 round 11 cleanup): both had drifted AGAIN
    # (102->108, 109->115) from an earlier, untracked edit to this same docstring/loop
    # -- pre-existing staleness, not introduced by round 11's own trajectorystore.py
    # changes (which never touch this test file's header) -- same DDL, keys renamed.
    # Re-verified 2026-09-24 (test-suite-drift sweep): both had drifted again by a
    # uniform +14 (108->122, 115->129), same DDL, keys renamed to match.
    "tests/test_f187_trajectory_sqlite_corroborator.py:122": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:129": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 (Option A): a second auth_profile_store fixture, this one in
    # _write_agent_sqlite_db()'s own `auth_secret=` branch (the isolation test for the
    # new event_json-reading reader) -- same per-agent-DB reasoning as the two above.
    # Re-verified 2026-09-23: had drifted (114->119), same pre-existing-staleness note
    # as test_f187's pair above. Re-verified again same day (119->120, B-933 merge
    # added lines earlier in the file).
    "tests/test_b185_compiled_tool_poisoning.py:120": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 (adversarial review, 2026-09-15): two more, each a standalone fixture (not
    # via _add_agent_db) in a test proving _table_kind refuses a VIEW named
    # trajectory_runtime_events that reads FROM this table -- same per-agent-DB
    # reasoning as every other entry in this section. Re-verified 2026-09-23: both had
    # drifted (470->486, 796->812). Re-verified 2026-09-24: both had drifted again by
    # a uniform +14 (486->500, 812->826).
    "tests/test_f187_trajectory_sqlite_corroborator.py:500": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:826": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 3/4 (2026-09-15): `_plant_generated_column_bypass`'s own standalone
    # fixture -- the GENERATED ALWAYS AS bypass the round-3 review found (a real table,
    # not a VIEW/virtual table, so a different attack shape but the same per-agent-DB
    # isolation reasoning as every other entry in this section). Re-verified
    # 2026-09-23: had drifted (514->530). Re-verified 2026-09-24: had drifted again by
    # the same uniform +14 (530->544).
    "tests/test_f187_trajectory_sqlite_corroborator.py:544": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 4 (2026-09-15): `test_compiled_tool_reader_refuses_a_rootpage_
    # aliased_table`'s own standalone fixture -- round 2's rootpage-uniqueness check,
    # given real `PRAGMA writable_schema` behavioural coverage for the first time
    # (round 4's own adversarial review found it had none). Re-verified 2026-09-23:
    # had drifted (619->635). Re-verified 2026-09-24: had drifted again by the same
    # uniform +14 (635->649).
    "tests/test_f187_trajectory_sqlite_corroborator.py:649": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # B-811 round 3/4 (2026-09-15): the same generated-column bypass fixture, built
    # standalone (not via _plant_generated_column_bypass, which lives in the sibling
    # test file) for the CHECK-level end-to-end test. Re-verified 2026-09-23: had
    # drifted (513->631) when B-852's own new mixed-host/partial-readability tests
    # landed earlier in this file. Re-verified again same day (631->667, B-933 merge
    # added lines earlier in the file).
    "tests/test_b185_compiled_tool_poisoning.py:667": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # CLAWSECCHECK-B-845: two more, in `_agent_home()`'s own `agent_auth_store_json=`
    # branch and its standalone second-agent fixture -- same DDL text (copied verbatim
    # from test_f187's own `_add_agent_db()`), same per-agent-DB reasoning. Shifted
    # 354->357, 459->462 by the C-135-rejection follow-up's new imports (threading/time/
    # trajectorystore) above them -- same DDL, keys renamed to match.
    "tests/test_b749_auth_profile_store_presence.py:386": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_b749_auth_profile_store_presence.py:508": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # CLAWSECCHECK-B-845 follow-up (2026-09-23): a third, `_make_agent_auth_db()`'s own
    # helper -- the cap-disclosure test's fixture builder -- same DDL text again, same
    # per-agent-DB reasoning. (The recursive-VIEW hang-guard fixture right above it uses
    # `CREATE VIEW`, not `CREATE TABLE`, so it is outside this extractor's surface --
    # confirmed by re-running `test_every_state_ddl_in_the_tree_is_registered` after
    # adding it: no new unregistered site appeared for that fixture.) Shifted 586->606
    # by the round-3 review-response's own docstring/comment additions above it (the
    # widened VIEW-fixture docstring, the C-135-status comment, the new stat-guard
    # commentary) -- same DDL, key renamed to match; the FIFO-guard tests added in the
    # same change reuse this same helper rather than any new literal DDL.
    "tests/test_b749_auth_profile_store_presence.py:731": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    # 4.4.0 schema-refusal pins (2026-10-05): the same file gained two more DDL sites and
    # every key above and below moved (357->386, 462->508, 606->731, 925->1050,
    # 992->1117); same DDL text at each moved site, keys renamed to match.
    #   :702 is the per-agent `auth_profile_store` with a GENERATED column that the
    #   reader must refuse -- same table name, same per-agent DB file, so the same
    #   different-DB reason applies (the snapshot covers the shared state DB only).
    #   :671 is `unrelated_table`, the decoy a VIEW named auth_profile_store projects
    #   from -- never a real OpenClaw table.
    "tests/test_b749_auth_profile_store_presence.py:702": _Entry(LEGACY_TABLE, _AUTH_PROFILE_TABLES_DIFFERENT_DB),
    "tests/test_b749_auth_profile_store_presence.py:671": _Entry(LEGACY_TABLE, _UNRELATED_DECOY),

    # ---- trajectory_runtime_events (F-187, per-agent DB, different file) ----
    # B-813/B-811: plain-string-literal copies of test_f187's own f-string DDL (invisible
    # to the AST extractor -- see _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB's own comment).
    "tests/test_b294_cron_run_logs.py:62": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # B-811 (Option A) shifted this line (91->101) by extending _write_agent_sqlite_db()
    # to accept a real event dict per row -- same DDL, key renamed to match.
    # Re-verified 2026-09-23: had drifted again (101->105). Re-verified again same day
    # (105->106, B-933 merge added an import line earlier in the file).
    "tests/test_b185_compiled_tool_poisoning.py:106": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # B-811 (adversarial review, 2026-09-15): two standalone fixtures (not via
    # _add_agent_db) in the DoS-bound regression tests -- same DDL, same reasoning.
    # Re-verified 2026-09-23: both had drifted (920->936, 970->986). Re-verified
    # 2026-09-24: both had drifted again by a uniform +14 (936->950, 986->1000).
    "tests/test_f187_trajectory_sqlite_corroborator.py:950": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:1000": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # B-852 round 11 cleanup (2026-09-23): four more standalone
    # `trajectory_runtime_events` fixtures this registry had never covered (a
    # pre-existing gap, not introduced by round 11's trajectorystore.py changes) -- the
    # `rowid`-vs-`created_at` ordering regression tests
    # (test_newest_row_wins_when_two_rows_share_the_same_created_at /
    # test_event_json_query_plan_has_no_sort_step) and the excluded-COUNT-query skip
    # tests (test_excluded_count_query_is_skipped_once_already_capped /
    # test_excluded_count_query_still_runs_when_not_already_capped) -- same per-agent-DB
    # reasoning as every other entry in this section. Re-verified 2026-09-24: all four
    # had drifted by a uniform +14 (1170->1184, 1228->1242, 1354->1368, 1399->1413).
    "tests/test_f187_trajectory_sqlite_corroborator.py:1184": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:1242": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:1368": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    "tests/test_f187_trajectory_sqlite_corroborator.py:1413": _Entry(LEGACY_TABLE, _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB),
    # CLAWSECCHECK test-suite-drift sweep (2026-09-24): B-909's own standalone
    # trajectory_runtime_events fixture (test_open_readonly_creates_shm_and_wal_
    # sidecars_from_nothing) -- never previously registered. Per-agent-DB table like
    # every other entry in this section, but a stripped-down (session_id, seq,
    # event_json) shape rather than a verbatim copy of test_f187's own DDL, so it gets
    # its own reason rather than reusing _TRAJECTORY_RUNTIME_EVENTS_DIFFERENT_DB's
    # "matching test_f187's own DDL verbatim" claim.
    "tests/test_b909_wal_sidecar_creation.py:54": _Entry(LEGACY_TABLE, _B909_TRAJECTORY_SIDECAR_STRIPPED_SHAPE),

    # ---- cron_jobs (C-476 payload-extras fixture -- vendor column set, no constraints) ----
    "tests/test_c476_cron_payload_extras.py:58": _Entry(LEGACY_COLS, _CRON_JOBS_NO_CONSTRAINTS_LEGACY),

    # ---- t (B-909 mode=ro vs immutable=1 demo decoy) ----
    # CLAWSECCHECK test-suite-drift sweep (2026-09-24): never previously registered.
    "tests/test_b909_wal_sidecar_creation.py:143": _Entry(LEGACY_TABLE, _B909_IMMUTABLE_DEMO_DECOY),

    # ---- update_runs (F-192, real vendor table, snapshot not yet re-baselined) ----
    # 2026-09-17: re-baselined the snapshot (was last regenerated 2026-09-12, commit
    # 28322d5, four days before this fixture landed 2026-09-16, commit b9898b0) --
    # update_runs is a real, current vendor table (state schema v15+, 2026.9.2) that
    # genuinely matches the vendor shape now that the snapshot actually carries it.
    "tests/test_f192_update_runs.py:30": _Entry(MODERN),

    # ---- device_pairing_paired (B176 -- OpenClaw 2026.9.6 devices/paired.json migration) ----
    "tests/test_b176_paired_devices_sqlite_migration.py:51": _Entry(MODERN),
    "tests/test_b176_paired_devices_sqlite_migration.py:153": _Entry(
        LEGACY_TABLE, _B176_SOMETHING_ELSE_PREDATES_TABLE
    ),
    "tests/test_b176_paired_devices_sqlite_migration.py:258": _Entry(
        LEGACY_TABLE, _B176_VIEW_MASQUERADE_DECOY
    ),
    "tests/test_b176_paired_devices_sqlite_migration.py:570": _Entry(
        LEGACY_TABLE, _B176_VIEW_MASQUERADE_DECOY
    ),

    # ---- device_pairing_paired (B396 -- same view-masquerade decoy, new consumer) ----
    # check_paired_node_skill_coverage reads the SAME table via the SAME collector
    # reader (_collect_paired_devices_sqlite) B176 already exercises above, so its own
    # two view-masquerade tests build the identical `decoy` table backing a VIEW named
    # `device_pairing_paired` -- same entry, same reasoning, new call sites.
    "tests/test_b396_paired_node_skill_coverage.py:529": _Entry(
        LEGACY_TABLE, _B176_VIEW_MASQUERADE_DECOY
    ),
    "tests/test_b396_paired_node_skill_coverage.py:547": _Entry(
        LEGACY_TABLE, _B176_VIEW_MASQUERADE_DECOY
    ),

    # ---- exec_approvals_config (B172 reads the state-database exec-approvals store) ----
    # MODERN since the 2026.9.7 re-baseline (state schema v19): the regenerated snapshot
    # carries exec_approvals_config and this DDL equals the vendor's column for column. It
    # was registered LEGACY_TABLE only while the shipped snapshot still predated the table.
    "tests/test_c643_exec_approvals_sqlite_store.py:904": _Entry(MODERN),
}

# B-889: +2 (69, was 67) -- round 1's view-masquerade decoy-table DDL site
# (tests/test_b749_auth_profile_store_presence.py:925) and round 2's embedded-NUL-byte
# regression fixture (same file, :992). Line numbers renumbered from the peer branch's
# :342/:409 by the merge that placed the B-845 per-agent test class earlier in that file.
# B-977: +1 -- the identical view-masquerade decoy-table DDL site for
# `_collect_config_machine_state`'s own hardening (tests/test_f183_config_machine_state.py:389).
# B-990: +1 -- the config_machine_state view-masquerade hardening's own
# decoy-table DDL site for _collect_plugin_trust (tests/test_b177_installed_index_shapes.py:440).
# B-994: +1 -- the identical view-masquerade decoy-table DDL site for
# _collect_plugin_trust's legacy installed_plugin_index probes (tests/test_b177_installed_index_shapes.py:557).
# Combined: 72, was 71.
# B176 (OpenClaw 2026.9.6 upgrade re-baseline): +4 -- device_pairing_paired's own real DDL
# site (MODERN, verbatim from a live 2026.9.6 install) plus the three decoy/pre-migration
# sites in the same new test file. 76, was 72.
# B396: +2 -- check_paired_node_skill_coverage's own two view-masquerade hardening tests
# build the identical `decoy` table backing a VIEW named `device_pairing_paired` B176's
# own tests already register above; new call sites, same _B176_VIEW_MASQUERADE_DECOY
# reason. 78, was 76.
# B172 (exec-approvals store moved into the state database): +1 -- the vendor-shaped
# `exec_approvals_config` DDL in tests/test_c643_exec_approvals_sqlite_store.py, registered
# LEGACY_TABLE while the shipped snapshot predated the table, MODERN since the 2026.9.7
# re-baseline. 79, was 78.
# 81, was 79: the two test_b749 sites registered above (:702 and :671).
# 82, was 81: the one test_c654 site registered above (:605).
# 83, was 82: the one test_c680c_elided_disclosure site registered above (:168).
assert len(_REGISTRY) == 83, f"registry has {len(_REGISTRY)} entries, expected 83"


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


# ---- C-580: the worker-thread template-literal copy ------------------------------------

def test_extract_worker_template_schema_sql_finds_the_minified_spelling():
    """`worker/worker.mjs` on the real dist has no `const` and no spaces around `=` --
    the minified spelling this extractor must accept, not just a readable one."""
    js = 'other=1,OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE t (a TEXT);\n`,more=2'
    assert _extract_worker_template_schema_sql(js) == "CREATE TABLE t (a TEXT);\n"


def test_extract_worker_template_schema_sql_finds_the_spaced_spelling():
    js = 'const OPENCLAW_STATE_SCHEMA_SQL = `CREATE TABLE t (a TEXT);`;'
    assert _extract_worker_template_schema_sql(js) == "CREATE TABLE t (a TEXT);"


def test_extract_worker_template_schema_sql_unescapes_like_a_js_string():
    js = 'OPENCLAW_STATE_SCHEMA_SQL=`a\\`b\\\\c\\u0041d`'
    assert _extract_worker_template_schema_sql(js) == "a`b\\cAd"


def test_extract_worker_template_schema_sql_raises_when_marker_missing():
    with pytest.raises(AssertionError, match="not found"):
        _extract_worker_template_schema_sql("const SOMETHING_ELSE = 1;")


def test_extract_worker_template_schema_sql_raises_when_unterminated():
    with pytest.raises(AssertionError, match="unterminated"):
        _extract_worker_template_schema_sql("OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE t (a TEXT);")


def test_extract_worker_template_schema_sql_raises_on_unescaped_interpolation():
    """A `${...}` interpolation makes this NOT a static string -- must fail loudly rather
    than silently including the literal `${...}` text as if it were SQL."""
    with pytest.raises(AssertionError, match=r"\$\{\.\.\.\} interpolation"):
        _extract_worker_template_schema_sql("OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE ${t} (a TEXT);`")


def test_extract_worker_template_schema_sql_tolerates_an_escaped_interpolation_marker():
    """`\\${` is a literal `${`, not an interpolation -- the backslash-skip branch must
    reach it before the interpolation guard does."""
    assert (
        _extract_worker_template_schema_sql("OPENCLAW_STATE_SCHEMA_SQL=`a\\${b}c`")
        == "a${b}c"
    )


def test_assert_worker_template_copy_matches_primary_accepts_an_identical_copy(tmp_path):
    (tmp_path / "worker").mkdir()
    (tmp_path / "worker" / "worker.mjs").write_text(
        "OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE t (a TEXT);`", encoding="utf-8")
    _assert_worker_template_copy_matches_primary(tmp_path, "CREATE TABLE t (a TEXT);")


def test_assert_worker_template_copy_matches_primary_raises_when_it_diverges(tmp_path):
    (tmp_path / "worker").mkdir()
    (tmp_path / "worker" / "worker.mjs").write_text(
        "OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE u (b TEXT);`", encoding="utf-8")
    with pytest.raises(AssertionError, match="does NOT match"):
        _assert_worker_template_copy_matches_primary(tmp_path, "CREATE TABLE t (a TEXT);")


def test_assert_worker_template_copy_matches_primary_raises_when_the_file_is_missing(tmp_path):
    with pytest.raises(AssertionError, match="no worker-thread copy"):
        _assert_worker_template_copy_matches_primary(tmp_path, "CREATE TABLE t (a TEXT);")


# ---- C-683: the 2026.10.1 layout -- a double-quoted copy in state/*.worker.js -------------

_T = "CREATE TABLE t (a TEXT);\n"
_V101_COPY = 'var OPENCLAW_STATE_SCHEMA_SQL;\nfoo();\n\tOPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE t (a TEXT);\\n";\n'


def test_extract_worker_template_schema_sql_reads_a_double_quoted_assignment():
    assert _extract_worker_template_schema_sql(_V101_COPY) == _T


def test_a_double_quoted_copy_in_any_bundle_is_found_and_compared(tmp_path):
    _write_dist(tmp_path, {"state/openclaw-state-read.worker.js": _V101_COPY})
    _assert_worker_template_copy_matches_primary(tmp_path, _T)


def test_a_double_quoted_copy_that_diverges_is_refused(tmp_path):
    _write_dist(tmp_path, {"state/openclaw-state-read.worker.js": _V101_COPY})
    with pytest.raises(AssertionError, match="does NOT match"):
        _assert_worker_template_copy_matches_primary(tmp_path, "CREATE TABLE u (b TEXT);\n")


def test_one_diverging_copy_among_agreeing_ones_is_refused(tmp_path):
    _write_dist(tmp_path, {
        "a/one.js": _V101_COPY,
        "b/two.mjs": 'OPENCLAW_STATE_SCHEMA_SQL=`CREATE TABLE u (b TEXT);\n`',
    })
    with pytest.raises(AssertionError, match="does NOT match"):
        _assert_worker_template_copy_matches_primary(tmp_path, _T)


def test_a_const_declaration_alone_is_the_primary_not_a_copy(tmp_path):
    """The primary definition must not satisfy the copy check: a dist whose only assignment is
    the `const` declaration has NO worker copy, and that fails loudly instead of passing."""
    _write_dist(tmp_path, {"main.mjs": 'const OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE t (a TEXT);\\n";'})
    with pytest.raises(AssertionError, match="no worker-thread copy"):
        _assert_worker_template_copy_matches_primary(tmp_path, _T)


def test_a_non_literal_assignment_is_not_mistaken_for_a_copy(tmp_path):
    _write_dist(tmp_path, {"x.mjs": "OPENCLAW_STATE_SCHEMA_SQL = build();\nif (OPENCLAW_STATE_SCHEMA_SQL == 1) {}"})
    with pytest.raises(AssertionError, match="no worker-thread copy"):
        _assert_worker_template_copy_matches_primary(tmp_path, _T)


def test_an_unterminated_double_quoted_copy_fails_loudly(tmp_path):
    _write_dist(tmp_path, {"x.js": 'OPENCLAW_STATE_SCHEMA_SQL = "CREATE TABLE t (a TEXT);'})
    with pytest.raises(AssertionError, match="unterminated"):
        _assert_worker_template_copy_matches_primary(tmp_path, _T)


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


def test_a_step_precondition_guard_below_the_ladder_top_does_not_break_the_reader(tmp_path):
    """2026.9.7, measured: the ladder top is 19 (`contentVersion !== 19`, the migration guard
    and the newer-schema error all say so), while a legacy-migration precondition in the same
    chunk reads `readStateSchemaContentVersion(database) !== 1 || tableExists(...)`. The
    reader used to see {1, 19} and refuse to stamp anything."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-uBGB4L5P.mjs":
            'if (readStateSchemaContentVersion(database) !== 1 || tableExists(database, "t")) x();\n'
            "if (readStateSchemaContentVersion(database) !== 19) migrate();\n"
            "const needsRepair = readStateSchemaMigrationVersion(database) !== 19;\n",
        "openclaw-state-db-schema-version-CXDs-azs.mjs":
            'if (contentVersion > 19) throw createNewerSqliteSchemaVersionError('
            '"OpenClaw state database", pathname, contentVersion, 19);\n',
    })
    assert _state_schema_version_evidence(dist)["content-version guard"] == {1, 19}
    assert _state_schema_version_from(dist) == 19


def test_the_step_guard_ranking_does_not_hide_a_guard_above_the_ladder_top(tmp_path):
    """The ranking is a tolerance for guards BELOW the top, not a licence to ignore a guard
    that says the schema is newer than the named top: that is a real disagreement."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-a.mjs": "if (readStateSchemaContentVersion(db) !== 20) x();\n",
        "openclaw-state-db-schema-version-b.mjs":
            'throw createNewerSqliteSchemaVersionError("OpenClaw state database", p, v, 19);\n',
    })
    with pytest.raises(AssertionError, match="anchors disagree"):
        _state_schema_version_from(dist)


def test_the_step_guard_ranking_needs_a_guard_at_the_top_when_any_guard_exists(tmp_path):
    """Guards that all sit below the top and none corroborates it describe some earlier step,
    not the current schema: nothing has confirmed the top, so the run must fail loudly."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-a.mjs": "if (readStateSchemaContentVersion(db) !== 1) x();\n",
        "openclaw-state-db-schema-version-b.mjs":
            'throw createNewerSqliteSchemaVersionError("OpenClaw state database", p, v, 19);\n',
    })
    with pytest.raises(AssertionError, match="anchors disagree"):
        _state_schema_version_from(dist)


def test_the_step_guard_ranking_needs_the_two_authority_anchors_to_agree(tmp_path):
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-contract-X.mjs": "const OPENCLAW_STATE_SCHEMA_VERSION = 18;\n",
        "openclaw-state-db-schema-version-b.mjs":
            'throw createNewerSqliteSchemaVersionError("OpenClaw state database", p, v, 19);\n',
        "openclaw-state-db-a.mjs": "if (readStateSchemaContentVersion(db) !== 19) x();\n",
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


def test_a_lone_ambiguous_anchor_cannot_be_told_from_a_step_precondition_guard(tmp_path):
    """C-580, documenting a known limit an independent review found and this repo is
    choosing NOT to fix: the two `!== N` anchors ("content-version guard",
    "migration-version guard") are matched by SYNTAX alone. A per-step migration
    precondition -- "only run this repair step while the database is still at version
    12" -- has the exact same shape (`readStateSchemaMigrationVersion(db) !== 12`) as the
    real "is this the CURRENT schema version" guard, and no regex can tell them apart.

    Grounded against the installed 2026.9.5 dist: today every real occurrence of every
    surviving anchor spelling agrees on the same number (measured: {17} for all three of
    content-version guard, migration-version guard and newer-schema error), so this is
    harmless in practice. But if a release removed every OTHER spelling and left exactly
    ONE occurrence of a precondition-shaped `!== N`, this function has no way to know 12
    was never meant to describe the CURRENT version, and would return it anyway -- this
    test proves that by construction.

    The fix considered and rejected: require a second, distinct anchor NAME before
    trusting a lone `!==` match. That would break real, legitimate single-anchor states
    this reader must keep accepting --
    test_state_schema_version_reads_the_named_constant_of_2026_9_4_and_earlier (the
    pre-9.5 era genuinely had only the named-constant spelling) and
    test_state_schema_version_finds_the_anchor_in_a_nested_chunk both construct a dist
    with exactly one anchor firing and correctly expect a version back, not a failure.
    Demanding corroboration trades this narrow, never-yet-observed risk for a guaranteed
    false failure on those. So this is pinned, not patched -- see this module's own
    docstring on the version anchors for the cross-reference."""
    dist = _write_dist(tmp_path, {
        "openclaw-state-db-DS2iNFy4.mjs":
            "function migrateFromV12(db) {\n"
            "  if (readStateSchemaMigrationVersion(db) !== 12) return;\n"
            "  // ... apply the v12 -> v13 repair step ...\n"
            "}\n",
    })
    # Accepted, not fixed: nothing here distinguishes 12-as-a-step-precondition from
    # 12-as-the-current-version when it is the only anchor present.
    assert _state_schema_version_from(dist) == 12


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


def test_worker_template_copy_matches_the_installed_dist():
    """C-580, LOCAL-ONLY: the second half of `_find_state_schema_defining_js`'s identity
    proof, exercised for real. That function's own docstring used to say the worker
    thread's template-literal copy was "diffed against the string copy on all six
    releases" -- true, but a manual diff someone ran once and wrote down is exactly the
    kind of unverified claim this whole module exists to stop trusting (see the module
    docstring's B-710 history: a comment claiming a fixture "cannot drift" drifted
    anyway). This re-checks it, on THIS machine's installed OpenClaw, every run."""
    dist_dir = _require_dist()
    js_path = _find_state_schema_defining_js(dist_dir)
    primary_sql = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    _assert_worker_template_copy_matches_primary(dist_dir, primary_sql)


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
# that any database has one: measured on this machine (2026.9.9), 25 declared tables (the
# whole skill_library family among them) are absent from the live DB even though the DDL is
# all `CREATE TABLE IF NOT EXISTS`; the vendor lists them itself as FIRST_USE_STATE_TABLES /
# LAZY_ADDITIVE_STATE_TABLES in `openclaw-state-db-contract-*`. So a check built on this
# surface must treat an absent table as UNKNOWN and never as a clean PASS -- "the table is
# not here" is not evidence the feature is unused.
#
# C-679: the set is NOT only `OPENCLAW_STATE_SCHEMA_SQL`. Three live tables (user_profiles,
# user_profile_emails, worker_environment_session_attachments) are created by satellite
# constants applied to the same database; the section below reads the allowlisted ones.
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
    "transcript_events": (
        "transcript_events (CLAWSECCHECK-C-699) lives in the PER-AGENT database "
        "(agents/<agent-id>/agent/openclaw-agent.sqlite), never in the shared state "
        "database (state/openclaw.sqlite) this baseline enumerates -- a different SQLite "
        "file, so its absence from the baseline is not drift. Live and current (measured "
        "on a 2026.10.2 per-agent database: session_id, seq, event_json, created_at, "
        "event_zstd, event_utf8_bytes, navigation_json); read for a row/session COUNT "
        "only, the payload columns are never selected "
        "(trajectorystore._count_transcript_events)."
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

# --------------------------------------------------------------------------------------
# C-679: the state database is declared by MORE than one constant.
#
# `OPENCLAW_STATE_SCHEMA_SQL` is the bulk, but on 2026.9.9 three live tables
# (user_profiles, user_profile_emails, worker_environment_session_attachments) come from
# SATELLITE constants that the vendor applies to the same state database at first use. A
# generator that read only the main constant would never name a table a future release
# adds the same way -- the exact blindness B-721 was written to remove.
#
# A blanket `*_SCHEMA_SQL` pattern over-collects (per-agent DB, workboard, memory index,
# retired shapes), so classification is by EXPLICIT NAME, in two lists. A `*_SCHEMA_SQL`
# name found anywhere in the dist that is in neither list stops the generator: a new
# constant has to be classified by someone who read where it is applied. Camel-case
# constants and constants not spelled `*_SCHEMA_SQL` are NOT covered by this net.
# --------------------------------------------------------------------------------------

_PRIMARY_STATE_SCHEMA_CONSTANT = "OPENCLAW_STATE_SCHEMA_SQL"

# name -> evidence: the write path that applies the DDL to the STATE database (grounded
# against the installed 2026.9.9 dist; function names, not rotating bundle hashes).
_STATE_SATELLITE_CONSTANTS = {
    "USER_PROFILES_SCHEMA_SQL": (
        "user-profiles-internal-*.mjs: ensureUserProfilesSchema -> runUserProfileWriteTransaction "
        "-> runOpenClawStateWriteTransaction, `db.exec(USER_PROFILES_SCHEMA_SQL)`; opens the "
        "database with openOpenClawStateDatabase"
    ),
    "WORKER_ENVIRONMENT_SESSION_ATTACHMENTS_SCHEMA_SQL": (
        "openclaw-state-worker-runtime-*.mjs: ensureWorkerEnvironmentStoreSchema -> "
        "runOpenClawStateWriteTransaction, `db.exec(SSH_FALLBACK_PORTS + SESSION_ATTACHMENTS)`"
    ),
}

_NOT_STATE_DB = "NOT the state database: "
_ALREADY_IN_MAIN = (
    "applied to the state database; declares only tables OPENCLAW_STATE_SCHEMA_SQL already "
    "lists (measured 2026.9.9), and is PARSED on every run to keep that true: "
)

# name -> what it re-declares. Applied to the state database but, today, adding no table of
# its own. They are parsed with the same extractor as the satellites and every table they
# declare must already be in the main constant: a table that is not stops the generator, so
# promoting the constant to _STATE_SATELLITE_CONSTANTS is a deliberate act, not a miss.
_STATE_REDECLARING_CONSTANTS = {
    "WORKER_ENVIRONMENT_SSH_FALLBACK_PORTS_SCHEMA_SQL":
        _ALREADY_IN_MAIN + "worker_environment_ssh_fallback_ports "
        "(openclaw-state-worker-runtime-*.mjs: ensureWorkerEnvironmentStoreSchema)",
    "STANDING_GRANT_SCHEMA_SQL":
        _ALREADY_IN_MAIN + "operator_approval_standing_grants, "
        "operator_approval_standing_grant_generations "
        "(operator-approval-standing-grants-*.mjs: ensureStandingGrantSchema)",
    "OPERATOR_APPROVAL_EXECUTION_IDENTITY_SCHEMA_SQL":
        _ALREADY_IN_MAIN + "operator_approval_execution_identities "
        "(operator-approval-store.operations-*.mjs: database.db.exec)",
}

# name -> evidence. C-683 (2026.10.1): applied to the state database, and defined NOT as a literal
# but as `NAME = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, <table>)`, so it declares a
# table the main constant already lists BY CONSTRUCTION. A distinct classification from the
# literal re-declarers above: the definition shape is parsed (`_DERIVED_DEFINITION_RE`), the
# named table must be in the main set, and any other shape of definition stops the generator.
_STATE_DERIVED_CONSTANTS = {
    "CRON_RUNTIME_AUTHORITY_SCHEMA_SQL":
        "applied to the state database (runtime-authority-store-*.mjs: "
        "replaceCronRuntimeAuthorityRows, same db as cron_jobs); 2026.10.1 derives it from the "
        "main constant for CRON_RUNTIME_AUTHORITY_TABLE = \"cron_job_runtime_authorities\"",
}

# name -> why it is not read.
_STATE_EXCLUDED_CONSTANTS = {
    **dict.fromkeys((
        "OPENCLAW_AGENT_SCHEMA_SQL", "OPENCLAW_AGENT_BOARD_SCHEMA_SQL",
        "AGENT_PROGRESS_CARD_SCHEMA_SQL", "AGENT_V14_BOARD_SCHEMA_SQL",
        "AGENT_V14_SESSION_SHARING_SCHEMA_SQL", "AGENT_V14_ADDITIVE_SCHEMA_SQL",
        "AGENT_V14_CORE_SCHEMA_SQL",
    ), _NOT_STATE_DB + "the per-agent database (agents/<id>/agent/openclaw-agent.sqlite)"),
    "WORKBOARD_SCHEMA_SQL": _NOT_STATE_DB + "the workboard extension's own sqlite store",
    "DEBUG_PROXY_CAPTURE_LEGACY_SCHEMA_SQL": (
        _NOT_STATE_DB + "a legacy debug-proxy sidecar; its capture_* tables are listed by the "
        "main constant in their current shape (the B-710 trap)"),
    **dict.fromkeys((
        "MEMORY_INDEX_CHUNKS_SCHEMA_SQL", "MEMORY_INDEX_CHUNK_PROVENANCE_SCHEMA_SQL",
        "MEMORY_INDEX_CHUNK_RECALL_METADATA_SCHEMA_SQL",
    ), _NOT_STATE_DB + "the memory index database; table names are interpolated"),
    **dict.fromkeys((
        "RETIRED_COMMITMENTS_SCHEMA_SQL", "SHIPPED_RETIRED_COMMITMENTS_SCHEMA_SQL",
        "RETIRED_AGENT_STATE_LEASE_SCHEMA_SQL",
    ), "retired shape, kept by the vendor only to migrate old databases away"),
}

_SCHEMA_SQL_NAME_RE = re.compile(r"\b[A-Z][A-Z0-9_]*_SCHEMA_SQL\b")
_CREATE_TABLE_RE = re.compile(r"\bCREATE\s+TABLE\b", re.IGNORECASE)
# The negative lookahead stops `CREATE TABLE IF NOT EXISTS ${name}` from reading "IF" as a
# table name once the optional group backtracks.
_CREATE_TABLE_NAMED_RE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?!IF\s+NOT\s+EXISTS\b)(\w+)", re.IGNORECASE)
# The one interpolation shape an allowlisted constant may carry: a table spliced from the
# MAIN constant. Anything else is unmodelled composition and stops the generator.
_STATE_TABLE_SPLICE_RE = re.compile(
    r"""\s*extractSqliteTableSchema\(\s*OPENCLAW_STATE_SCHEMA_SQL\s*,\s*(["'`])(\w+)\1\s*\)\s*""")


def _skip_js_expression(js_text: str, i: int) -> int:
    """Index of the `}` closing a `${` whose body starts at *i* (strings and nested
    template literals inside the expression are stepped over)."""
    depth, n = 1, len(js_text)
    while i < n:
        c = js_text[i]
        if c == "\\":
            i += 2
            continue
        if c in "\"'":
            j = i + 1
            while j < n and js_text[j] != c:
                j += 2 if js_text[j] == "\\" else 1
            i = j + 1
            continue
        if c == "`":
            i = _scan_js_template(js_text, i + 1)[2] + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise AssertionError("unterminated ${...} interpolation in a template literal")


def _scan_js_template(js_text: str, i: int) -> "tuple[list, list, int]":
    """(static pieces, interpolation expressions, index of the closing backtick) for the
    template literal whose body starts at *i*. `len(pieces) == len(exprs) + 1`. Unlike
    `_extract_worker_template_schema_sql`, an interpolation is TOLERATED here -- reported,
    not refused -- because the caller decides whether it understands each one."""
    pieces, exprs, start, n = [], [], i, len(js_text)
    while i < n:
        c = js_text[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            pieces.append(js_text[start:i])
            return pieces, exprs, i
        if c == "$" and js_text[i:i + 2] == "${":
            pieces.append(js_text[start:i])
            end = _skip_js_expression(js_text, i + 2)
            exprs.append(js_text[i + 2:end])
            i = start = end + 1
            continue
        i += 1
    raise AssertionError("unterminated template literal in the dist")


def _extract_satellite_schema_sql(js_text: str, start: int, delim: str, const: str) -> "tuple[str, list]":
    """(canonical SQL, tables spliced in from the main constant) for the literal opening at
    *start* (just past its delimiter). Each understood `${extractSqliteTableSchema(
    OPENCLAW_STATE_SCHEMA_SQL, "t")}` becomes a fixed marker, so the readable copy and the
    minified worker copy of the same constant compare equal; any other interpolation
    raises."""
    if delim != "`":
        i, n = start, len(js_text)
        while i < n and js_text[i] != delim:
            i += 2 if js_text[i] == "\\" else 1
        if i >= n:
            raise AssertionError(f"unterminated string literal for {const} in the dist")
        return _unescape_js_double_quoted(js_text[start:i]), []
    pieces, exprs, _ = _scan_js_template(js_text, start)
    spliced, out = [], [_unescape_js_double_quoted(pieces[0])]
    for expr, piece in zip(exprs, pieces[1:]):
        m = _STATE_TABLE_SPLICE_RE.fullmatch(expr)
        if m is None:
            raise AssertionError(
                f"{const} interpolates `${{{expr.strip()[:100]}}}` -- not the one shape this "
                "extractor models (a table spliced from OPENCLAW_STATE_SCHEMA_SQL). The "
                "constant composes its DDL in a way nothing here has read; re-ground it.")
        spliced.append(m.group(2))
        out.append(f"/*splice:{m.group(2)}*/" + _unescape_js_double_quoted(piece))
    return "".join(out), spliced


def _survey_schema_sql_constants(dist_dir: Path, wanted) -> "tuple[set, dict]":
    """(every `*_SCHEMA_SQL` name appearing in any dist bundle, name -> [(path, canonical
    SQL, spliced tables)] for each literal definition of a *wanted* constant). One read per
    file; an unreadable bundle fails loudly, as in `_state_schema_defining_files`."""
    seen: set = set()
    found: dict = {name: [] for name in wanted}
    for ext in _JS_EXTS:
        for path in sorted(dist_dir.rglob("*" + ext)):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise AssertionError(
                    f"cannot read {path} while classifying *_SCHEMA_SQL constants: {exc}. An "
                    "unreadable bundle could define a state-schema constant.") from exc
            if "_SCHEMA_SQL" not in text:
                continue
            seen.update(_SCHEMA_SQL_NAME_RE.findall(text))
            for name in wanted:
                if name not in text:
                    continue
                for m in re.finditer(rf"\b{name}\s*=\s*([`\"'])", text):
                    sql, spliced = _extract_satellite_schema_sql(text, m.end(), m.group(1), name)
                    found[name].append((path, sql, spliced))
    return seen, found


_DERIVED_DEFINITION_RE = re.compile(
    r"extractSqliteTableSchema\(\s*OPENCLAW_STATE_SCHEMA_SQL\s*,\s*"
    r"(?:\"([^\"\\\n]*)\"|([A-Za-z_$][\w$]*))\s*\)\s*;")


def _survey_derived_state_constants(dist_dir: Path, derived) -> "dict[str, list]":
    """name -> [(path, table)] for every definition of a *derived* constant. A definition is
    understood only as `NAME = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, <table>);`
    where <table> is a string literal or an identifier bound once, in the same file, to one.
    Any other right-hand side (a literal, a different source constant, an options argument, a
    computed table) raises: the constant composes its DDL in a way nothing here has read."""
    found: dict = {name: [] for name in derived}
    for ext in _JS_EXTS:
        for path in sorted(dist_dir.rglob("*" + ext)):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise AssertionError(
                    f"cannot read {path} while classifying derived *_SCHEMA_SQL constants: "
                    f"{exc}. An unreadable bundle could define one.") from exc
            for name in derived:
                if name not in text:
                    continue
                for m in re.finditer(rf"\b{name}\s*=(?!=)\s*", text):
                    d = _DERIVED_DEFINITION_RE.match(text, m.end())
                    if d is None:
                        raise AssertionError(
                            f"{name} is classified as derived from OPENCLAW_STATE_SCHEMA_SQL but "
                            f"{path} defines it as `{text[m.end():m.end() + 100].strip()}...` -- "
                            "not the one shape this guard models (`extractSqliteTableSchema("
                            "OPENCLAW_STATE_SCHEMA_SQL, <table>);`). Re-ground the classification.")
                    table = d.group(1)
                    if table is None:
                        bound = set(re.findall(
                            rf"\b(?:const|let|var)\s+{re.escape(d.group(2))}\s*=\s*\"([^\"\\\n]*)\"\s*[;,]",
                            text))
                        if len(bound) != 1:
                            raise AssertionError(
                                f"{name}: the table argument `{d.group(2)}` is not bound to exactly "
                                f"one string literal in {path} ({sorted(bound)}); re-ground.")
                        table = next(iter(bound))
                    found[name].append((path, table))
    return found


def _check_derived_state_constant(name: str, defs: list, dist_dir: Path, main_tables) -> None:
    if not defs:
        raise AssertionError(
            f"{name} is classified as derived from OPENCLAW_STATE_SCHEMA_SQL but no bundle under "
            f"{dist_dir} defines it -- the vendor renamed, moved or rewrote it; re-ground.")
    tables = sorted({t for _, t in defs})
    if len(tables) != 1:
        raise AssertionError(f"{name} is derived for DIFFERENT tables ({tables}); decide which "
                             "one the runtime applies before trusting either.")
    if tables[0] not in set(main_tables):
        raise AssertionError(
            f"{name} is derived from OPENCLAW_STATE_SCHEMA_SQL for {tables[0]!r}, which the main "
            "constant does not declare -- the derivation would fail at runtime; re-ground.")


def _resolve_state_constant(name: str, defs: list, dist_dir: Path, main_tables) -> dict:
    """{"tables", "adds", "bundle", "copies"} for one allowlisted constant's definitions."""
    if not defs:
        raise AssertionError(
            f"{name} is allowlisted as a state-database schema constant but no bundle under "
            f"{dist_dir} defines it as a string or template literal -- the vendor renamed, "
            "moved or rewrote it; re-ground the allowlist entry.")
    by_digest: "dict[str, list[Path]]" = {}
    for path, sql, _ in defs:
        by_digest.setdefault(
            hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()[:12], []).append(path)
    if len(by_digest) != 1:
        listing = "; ".join(f"{d}: {[str(p.relative_to(dist_dir)) for p in ps]}"
                            for d, ps in sorted(by_digest.items()))
        raise AssertionError(
            f"{name} is defined with DIFFERENT schemas ({listing}); decide which one the "
            "runtime applies before trusting a table set taken from either.")
    _, sql, spliced = defs[0]
    named = _CREATE_TABLE_NAMED_RE.findall(sql)
    if not named or len(named) != len(_CREATE_TABLE_RE.findall(sql)):
        raise AssertionError(
            f"{name}: {len(_CREATE_TABLE_RE.findall(sql))} CREATE TABLE statement(s) but "
            f"{len(named)} table name(s) read -- a quoted or computed name is not a bare "
            "identifier, so this extractor cannot name that table. Re-ground it.")
    absent = sorted(set(spliced) - set(main_tables))
    if absent:
        raise AssertionError(
            f"{name} splices {absent} from OPENCLAW_STATE_SCHEMA_SQL, which declares no "
            "such table -- the splice would fail at runtime; re-ground.")
    paths = [p for p, _, _ in defs]
    bundle = min(paths, key=lambda p: (len(p.relative_to(dist_dir).parts), p.stat().st_size, str(p)))
    tables = sorted(set(named))
    return {
        "tables": tables,
        "adds": sorted(set(tables) - set(main_tables)),
        "bundle": bundle.name,
        "copies": len(paths),
    }


def _satellite_state_tables(dist_dir: Path, main_tables, satellites=None, excluded=None,
                            redeclaring=None, derived=None) -> "dict[str, dict]":
    """name -> {"tables", "adds", "bundle", "copies"} for every allowlisted satellite.

    Raises on: a `*_SCHEMA_SQL` name in no list; an allowlisted constant with no literal
    definition (the vendor moved or renamed it); definitions that are not the same schema
    (any number of identical copies is fine -- the rule `_find_state_schema_defining_js`
    uses); a `CREATE TABLE` whose name is not a literal; a spliced table the main constant
    does not declare; a satellite that declares nothing; and a REDECLARING constant that
    declares a table the main constant does not (it must then be promoted to the allowlist
    deliberately). Redeclaring constants add no name, so they are checked, not returned. A
    DERIVED constant (`NAME = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, <table>)`)
    is checked the same way: its definition shape must be that one, its table must be in the
    main set, and anything else raises."""
    satellites = _STATE_SATELLITE_CONSTANTS if satellites is None else satellites
    excluded = _STATE_EXCLUDED_CONSTANTS if excluded is None else excluded
    redeclaring = _STATE_REDECLARING_CONSTANTS if redeclaring is None else redeclaring
    derived = _STATE_DERIVED_CONSTANTS if derived is None else derived
    seen, found = _survey_schema_sql_constants(dist_dir, set(satellites) | set(redeclaring))
    unclassified = sorted(seen - {_PRIMARY_STATE_SCHEMA_CONSTANT} - set(satellites)
                          - set(redeclaring) - set(derived) - set(excluded))
    if unclassified:
        raise AssertionError(
            f"unclassified *_SCHEMA_SQL constant(s) in {dist_dir}: {unclassified}. Read where "
            "each is applied. If the DDL reaches the STATE database "
            "(runOpenClawStateWriteTransaction / openOpenClawStateDatabase), add it to "
            "_STATE_SATELLITE_CONSTANTS (or _STATE_REDECLARING_CONSTANTS if it adds no table) "
            "with that evidence; otherwise add it to _STATE_EXCLUDED_CONSTANTS with the "
            "reason. Guessing here is how a vendor table goes unnamed.")
    for name in sorted(redeclaring):
        extra = _resolve_state_constant(name, found[name], dist_dir, main_tables)["adds"]
        if extra:
            raise AssertionError(
                f"{name} is listed as re-declaring only tables OPENCLAW_STATE_SCHEMA_SQL already "
                f"has, but it declares {extra}, which the main constant does not. Read where it "
                "is applied and move it to _STATE_SATELLITE_CONSTANTS deliberately.")
    derived_defs = _survey_derived_state_constants(dist_dir, set(derived)) if derived else {}
    for name in sorted(derived):
        _check_derived_state_constant(name, derived_defs[name], dist_dir, main_tables)
    return {name: _resolve_state_constant(name, found[name], dist_dir, main_tables)
            for name in sorted(satellites)}


def _vendor_state_table_surface(dist_dir: Path, satellites=None, excluded=None,
                                redeclaring=None, derived=None) -> "tuple[set, dict, Path]":
    """(every state-database table name the dist declares, per-satellite provenance, the
    bundle the main constant was read from). The one function the generator AND the
    dist-comparison test call, so they cannot disagree about what the file covers."""
    js_path = _find_state_schema_defining_js(dist_dir)
    main = set(_dist_table_ddl_texts(_extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))))
    provenance = _satellite_state_tables(dist_dir, main, satellites, excluded, redeclaring, derived)
    return main | {t for p in provenance.values() for t in p["tables"]}, provenance, js_path


def _satellite_header_block(provenance: "dict[str, dict]") -> str:
    """`#` comment lines naming each satellite, the bundle it was read from and the tables it
    adds. Provenance lives in the header, never on a data line: the reader treats a whole data
    line as a table name."""
    lines = []
    for name, p in sorted(provenance.items()):
        adds = ", ".join(p["adds"]) or "(none beyond the main constant)"
        lines.append(f"#   {name}  [{p['bundle']}, {p['copies']} cop{'y' if p['copies'] == 1 else 'ies'}]"
                     f"\n#     adds: {adds}")
    return "\n".join(lines)


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
# Every table name the installed OpenClaw declares for its STATE SQLite database
# (state/openclaw.sqlite) -- the vendor's whole state-SQLite surface, NOT the part this tree
# models. That is the whole `OPENCLAW_STATE_SCHEMA_SQL` constant PLUS the allowlisted
# satellite constants below, each applied to the same database through the state-database
# write path (runOpenClawStateWriteTransaction / openOpenClawStateDatabase). Its sibling
# state_schema_snapshot.sql is deliberately the opposite: full DDL, projected to the few
# tables we read.
#
# Not covered: the per-agent database, the workboard store, the memory index, the debug-proxy
# capture sidecar and the retired shapes (the explicit exclusions in
# tests/test_state_schema_grounding.py). A name here means the vendor DECLARES a table, not
# that a given database has it yet: many are created on first use.
#
# Satellite constants read (bundle it came from, tables it adds beyond the main constant):
{satellite_block}
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
    all_tables, provenance, js_path = _vendor_state_table_surface(OPENCLAW_DIST)
    sql_text = _extract_vendor_schema_sql(js_path.read_text(encoding="utf-8"))
    # C-580: same reasoning as _write_state_snapshot -- verify the worker.mjs copy before
    # trusting this text to build a baseline.
    _assert_worker_template_copy_matches_primary(OPENCLAW_DIST, sql_text)
    tables = sorted(all_tables)
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
        satellite_block=_satellite_header_block(provenance),
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
    # C-679: the main constant PLUS the allowlisted satellites; an unclassified
    # `*_SCHEMA_SQL` constant raises here, so this test also stops on one.
    vendor, _, _ = _vendor_state_table_surface(dist_dir)

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
