"""CLAWSECCHECK-B-713 — advice must follow the same roster shape the reading side does.

B-699 taught every module to READ the agent roster through `collector.agent_roster()`,
which understands both the legacy `agents.list` array and the 2026.8.1 `agents.entries`
record. The ADVICE did not automatically follow: a `Finding.detail`/`.fix` string is
plain text authored by hand, so nothing forced it to route through the version-aware
`checks/_shared.py::_key_advice` helper B-700 introduced for exactly this. B-700 fixed
three remediation strings it found (B351, B352, B18); this closes the fourth — a
`detail` string in B328's WARN branch (`_lifecycle.py::check_exec_safe_bin_trusted_dirs`)
that still named only the retired `agents.list.<id>.tools.exec.safeBins` spelling.

Two layers:

* ALWAYS ON — an AST sweep (`test_no_shipped_string_names_agents_list_alone`) over every
  `clawseccheck/**/*.py` file: no shipped, non-docstring string constant may contain
  `agents.list` without also containing `agents.entries` in the same literal, unless it
  is (a) an argument to `_key_advice`/`_retired_key_note` — those helpers already pair
  the two names by construction, so a bare `'agents.list'` literal passed to one is not
  itself the defect — or (b) one of four explicitly allowlisted "label builder" call
  sites that intentionally name ONE shape alone because the roster genuinely IS that
  shape at the point they run (a position on disk, not advice about what to write).
  Anchored on the AST rather than a grep, per the task: a grep-based version of this
  guard matches its own explanatory comment.
* Fixture/config coverage — `check_exec_safe_bin_trusted_dirs`'s WARN branch (the fixed
  site) is driven with a config on each roster shape, on a build whose generation the
  shape actually matches, and the rendered `detail` is asserted to name the shape that
  build/config has — never the other one unqualified, and both when the generation
  cannot be determined at all.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

from clawseccheck.catalog import WARN
from clawseccheck.checks._lifecycle import check_exec_safe_bin_trusted_dirs
from clawseccheck.collector import collect

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO_ROOT / "clawseccheck"

_MODERN = "2026.8.1"
_LEGACY = "2026.7.1-2"

# ---------------------------------------------------------------------------
# Layer 1 (always on): AST sweep for a hardcoded, unqualified 'agents.list'.
# ---------------------------------------------------------------------------

# Helpers whose whole job is to name the RIGHT key for the reader's build. A bare
# 'agents.list' string literal passed to one of these is paired with 'agents.entries'
# by the CALLEE (checks/_shared.py::_key_advice / _retired_key_note), not by the call
# site's own text -- exempt by callee name so a new call added later is covered
# automatically, rather than needing its own allowlist line.
_ADVICE_HELPER_NAMES = {"_key_advice", "_retired_key_note"}

# The label-builders that intentionally name ONE shape alone, because at the point
# each runs the roster genuinely IS that shape -- a label for where an entry already
# sits on disk, never advice about what a user should write. Allowlisted by
# (relative path, lineno) rather than by file, so a NEW hardcoded 'agents.list' added
# anywhere else -- including elsewhere in these same files -- is still caught.
_LABEL_BUILDER_SITES = {
    # AgentEntry.labelled(): reached only when self.path does not start with
    # "agents.entries." -- i.e. this entry really did come from the legacy array.
    ("clawseccheck/collector.py", "labelled", "agents.list[]"):
        "AgentEntry.labelled() legacy-array branch",
    # agent_roster()'s "list" branch: reads the raw legacy key, reached only after
    # the config's own `agents` object was found to carry "list" rather than "entries".
    ("clawseccheck/collector.py", "agent_roster", "agents.list"):
        "agent_roster() legacy dig() key read",
    # Same branch: the per-entry path label, built from the real array index that
    # entry sits at on disk.
    ("clawseccheck/collector.py", "agent_roster", "agents.list[]"):
        "agent_roster() legacy AgentEntry.path label",
    # The per-agent sandbox finding's `where` label: the ternary already tests the
    # roster's own shape and only falls to the else-branch when it genuinely is the
    # legacy array.
    ("clawseccheck/checks/_config.py", "_multi_agent_note", "agents.list"):
        "per-agent sandbox finding's `where` label",
}


def _docstring_node_ids(tree: ast.AST) -> set:
    """id() of every Constant node that IS a module/class/function docstring."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr):
                value = body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    ids.add(id(value))
    return ids


def _advice_helper_arg_ids(tree: ast.AST) -> set:
    """id() of every node inside an argument to an advice-pairing helper call."""
    ids = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name not in _ADVICE_HELPER_NAMES:
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                ids.add(id(sub))
    return ids


def _joinedstr_piece_ids(tree: ast.AST) -> set:
    """id() of Constant nodes that are pieces of a JoinedStr -- checked via the parent
    JoinedStr's combined static text instead, so a piece like "agents.list[" is not
    flagged standalone just because it is one fragment of a longer f-string."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                ids.add(id(v))
    return ids


def _static_text(node) -> "str | None":
    """The literal text of a plain string Constant, or the concatenation of a
    JoinedStr's literal pieces (dynamic `{...}` parts contribute nothing -- exactly
    what a reader sees regardless of what the expression evaluates to)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [v.value for v in node.values
                 if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        return "".join(parts)
    return None


def _enclosing_fn(tree) -> dict:
    """{id(node): enclosing function name} for every node inside a def.

    The allowlist is keyed on the SYMBOL that builds a label, not on the line it
    sits at. A line number is not checkable: any integer resolves to some line, so
    a pinned one goes stale silently and starts exempting whatever drifts onto it.
    A function name that stops existing is a loud failure -- and a moved site keeps
    its exemption for free, which is the behaviour we actually want.
    """
    out = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                out.setdefault(id(node), fn.name)
    return out


def _offending_sites() -> "list[str]":
    out = []
    for py_file in sorted(SOURCE_DIR.rglob("*.py")):
        rel = str(py_file.relative_to(REPO_ROOT)).replace(os.sep, "/")
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        doc_ids = _docstring_node_ids(tree)
        helper_ids = _advice_helper_arg_ids(tree)
        piece_ids = _joinedstr_piece_ids(tree)
        fn_of = _enclosing_fn(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in piece_ids:
                    continue  # covered via its parent JoinedStr below
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = _static_text(node)
            else:
                continue
            if id(node) in doc_ids or id(node) in helper_ids:
                continue
            if text is None or "agents.list" not in text or "agents.entries" in text:
                continue
            if (rel, fn_of.get(id(node)), text) in _LABEL_BUILDER_SITES:
                continue
            out.append(f"{rel}:{node.lineno}: {text[:160]!r}")
    return out


def test_no_shipped_string_names_agents_list_alone():
    """No shipped, non-docstring string constant may tell a user to look at
    `agents.list` without also naming `agents.entries` -- a 2026.8.1 user on the
    modern shape would be sent to a key their config does not contain."""
    offenders = _offending_sites()
    assert not offenders, (
        "these shipped strings name the retired 'agents.list' alone:\n  "
        + "\n  ".join(offenders)
        + "\n\nRoute the advice through checks/_shared.py::_key_advice(ctx, "
          "'agents.list', 'agents.entries'), or add a justified, call-site-scoped "
          "entry to _LABEL_BUILDER_SITES if this is a genuine on-disk position label "
          "rather than advice about what to write."
    )


def test_the_ast_sweep_is_not_vacuous(tmp_path):
    """Proves the sweep can actually fail: an unroutable, unqualified 'agents.list'
    string in a throwaway module must be reported."""
    bogus = tmp_path / "bogus.py"
    bogus.write_text(
        'def f():\n'
        '    return "check your agents.list entry"\n'
    )
    offenders = []
    tree = ast.parse(bogus.read_text(encoding="utf-8"), filename=str(bogus))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "agents.list" in node.value and "agents.entries" not in node.value:
                offenders.append(node.value)
    assert offenders, "the sweep's own logic cannot detect an unqualified literal"


def test_every_allowlisted_label_builder_still_exists():
    """A stale allowlist entry must fail loudly, not quietly stop exempting.

    This table was first keyed on `(path, lineno)`. That was wrong for the reason a
    sibling task spent hours proving on a different register: a line number cannot be
    validated -- every integer names *some* line -- so a pinned one both goes stale
    without complaint and, worse, silently exempts whatever unrelated statement drifts
    onto that number later. Keyed on the enclosing function plus the literal, a moved
    site keeps its exemption and a deleted one is reported by name.
    """
    for (rel_path, fn_name, literal), why in _LABEL_BUILDER_SITES.items():
        tree = ast.parse((REPO_ROOT / rel_path).read_text(encoding="utf-8"))
        fn_of = _enclosing_fn(tree)
        found = any(
            fn_of.get(id(n)) == fn_name and _static_text(n) == literal
            for n in ast.walk(tree)
            if isinstance(n, (ast.Constant, ast.JoinedStr))
        )
        assert found, (
            f"allowlist entry {rel_path}::{fn_name} ({literal!r}) -- {why} -- no longer "
            "exists. Either the site moved to a different function (update the key) or "
            "the exemption is obsolete (delete it). Do not leave it: an entry that "
            "matches nothing is an exemption nobody can audit."
        )


# ---------------------------------------------------------------------------
# Layer 2: fixture/config coverage for the fixed site (B328 WARN branch).
# ---------------------------------------------------------------------------

def _warn_ctx(tmp_path: Path, agents_block: dict, installed_dist_version):
    """A config that reaches check_exec_safe_bin_trusted_dirs' WARN branch: a
    world-writable trusted dir, with the global safe-bin fast path explicitly
    disabled (mirrors tests/test_b328_exec_safebin_trusted_dirs.py)."""
    target = tmp_path / "writable-bin"
    target.mkdir()
    os.chmod(target, 0o777)
    cfg = {
        "agents": agents_block,
        "tools": {"exec": {"safeBins": [], "safeBinTrustedDirs": [str(target)]}},
    }
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    ctx = collect(home)
    ctx.include_host = True
    ctx.installed_dist_version = installed_dist_version
    return ctx


def test_modern_entries_config_names_agents_entries_only(tmp_path):
    ctx = _warn_ctx(tmp_path, {"entries": {"main": {}}}, _MODERN)
    finding = check_exec_safe_bin_trusted_dirs(ctx)
    assert finding.status == WARN, finding.detail
    assert "agents.entries" in finding.detail
    assert "agents.list." not in finding.detail


def test_legacy_list_config_names_agents_list_only(tmp_path):
    ctx = _warn_ctx(tmp_path, {"list": [{"id": "main"}]}, _LEGACY)
    finding = check_exec_safe_bin_trusted_dirs(ctx)
    assert finding.status == WARN, finding.detail
    assert "agents.list." in finding.detail
    assert "agents.entries" not in finding.detail


def test_undeterminable_build_is_told_both(tmp_path):
    """A hermetic run cannot see the version at all. It must not silently pick one
    shape and send a user on the other build looking at a key they do not have."""
    ctx = _warn_ctx(tmp_path, {"list": [{"id": "main"}]}, None)
    finding = check_exec_safe_bin_trusted_dirs(ctx)
    assert finding.status == WARN, finding.detail
    assert "agents.entries" in finding.detail
    assert "agents.list" in finding.detail
