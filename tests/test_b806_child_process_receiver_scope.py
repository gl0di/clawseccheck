"""B-806 — JS_CHILD_PROCESS_DYNAMIC fired on any `.exec()`/`.spawn()`-named method call
anywhere in a file that also happened to import `child_process` for something else,
regardless of which object the matched call was actually on.

Found by real-install testing against OpenClaw's bundled `memory-core` plugin: a SQLite
`this.db.exec(...)` call false-positived because the same 6206-line file imports
`spawn` from `node:child_process` for an unrelated purpose. The finding's own detail text
also asserted a fabricated `` (`git ${x}`) `` example that was never extracted from the
actual match.

`_JS_CP_TEMPLATE_RE` matched the bare function name with no receiver check at all, and the
old gate — `if "child_process" in masked` — was a whole-FILE substring co-occurrence, not
scoped to the matched call. The fix resolves which local names actually trace to the
child_process module (a namespace binding, a direct destructure, or an inline
`require('child_process').exec(...)` chain) and only fires when the matched call's own
receiver/origin is one of them.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_javascript


def _cp_findings(src: str) -> list:
    return [f for f in analyze_javascript(src) if f.rule == "JS_CHILD_PROCESS_DYNAMIC"]


# --------------------------------------------------------------------------------- FP repro

def test_a_db_clients_own_exec_stays_silent_even_with_an_unrelated_child_process_import():
    """The exact reported shape: a `.exec()` call on some other object, in a file that
    imports child_process elsewhere for something unrelated."""
    src = (
        'import { spawn } from "node:child_process";\n'
        "class Store {\n"
        "  createTable(dimensions) {\n"
        "    this.db.exec(`CREATE VIRTUAL TABLE t USING vec(${dimensions})`);\n"
        "  }\n"
        "}\n"
    )
    assert _cp_findings(src) == []


def test_a_compiled_regexps_own_exec_stays_silent_the_original_fp_this_gate_was_built_for():
    """The FP the whole-file gate was originally added to prevent — RegExp.prototype.exec()
    — must still stay silent under the new, more precise receiver resolution."""
    src = (
        'const cp = require("child_process");\n'
        "const re = /foo/;\n"
        "re.exec(`bar ${x}`);\n"
    )
    assert _cp_findings(src) == []


def test_no_child_process_reference_at_all_stays_silent():
    """Baseline: nothing resembling child_process anywhere in the file."""
    src = "this.db.exec(`SELECT * FROM t WHERE id = ${id}`);\n"
    assert _cp_findings(src) == []


# --------------------------------------------------------------------------- genuine positives

def test_direct_member_call_on_the_modules_own_canonical_name_fires():
    src = 'child_process.exec(`git tag ${v}`);\n'
    findings = _cp_findings(src)
    assert len(findings) == 1
    assert "exec" in findings[0].reason


def test_a_namespace_bound_via_commonjs_require_fires():
    src = 'const cp = require("child_process");\ncp.exec(`git tag ${v}`);\n'
    assert len(_cp_findings(src)) == 1


def test_a_namespace_bound_via_esm_default_import_fires():
    src = 'import cp from "node:child_process";\ncp.spawn(`${bin}`, ["--v"]);\n'
    findings = _cp_findings(src)
    assert len(findings) == 1
    assert "spawn" in findings[0].reason


def test_a_namespace_bound_via_esm_star_import_fires():
    src = 'import * as cp from "child_process";\ncp.execFile(`${bin}`, ["--v"]);\n'
    assert len(_cp_findings(src)) == 1


def test_a_name_destructured_via_commonjs_require_fires():
    src = 'const { exec } = require("child_process");\nexec(`git tag ${v}`);\n'
    assert len(_cp_findings(src)) == 1


def test_a_name_destructured_via_esm_import_fires():
    src = 'import { exec } from "node:child_process";\nexec(`git tag ${v}`);\n'
    assert len(_cp_findings(src)) == 1


def test_an_inline_require_chain_with_no_assignment_fires():
    """`require('child_process').exec(...)` — no variable ever names it, but the module
    name is unambiguously right there in the same expression."""
    src = 'require("child_process").execSync(`git tag ${v}`);\n'
    assert len(_cp_findings(src)) == 1


def test_an_inline_require_chain_with_the_node_prefix_fires():
    src = 'require("node:child_process").exec(`git tag ${v}`);\n'
    assert len(_cp_findings(src)) == 1


# --------------------------------------------------------------------------- a receiver bound
# to something else entirely must never borrow child_process's license to fire

def test_a_receiver_bound_to_an_unrelated_module_stays_silent():
    """`fs` is never child_process, even though the file also imports child_process
    elsewhere under a different name — the two bindings must not be conflated."""
    src = (
        'const cp = require("child_process");\n'
        'const fs = require("fs");\n'
        "fs.exec(`rm ${path}`);\n"
    )
    assert _cp_findings(src) == []
