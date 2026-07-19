"""Schema grounding coherence guard (§4, C-010).

Enforces Golden Rule #4 — no fabricated OpenClaw config paths. Every configuration path
queried in the codebase via the `dig()` helper must be grounded in the real OpenClaw
schema. The ground truth lives in the internal recon doc
`docs/research/openclaw-schema-recon.md`, which sits at the workspace root and
intentionally does NOT ship with the `skill/` repo.

B-106: because the recon doc is absent in CI (CI checks out only the `skill/` tree), the
old single test skipped there — so the guard was OFF exactly where PRs merge. The grounded
path set is now VENDORED into the shipped repo as `tests/grounded_schema_paths.txt`, and
enforcement is split into two guards:

  * `test_dig_paths_match_shipped_manifest` — ALWAYS runs (CI included): every `dig()` path
    in the source must be listed in the shipped manifest, and the manifest must have no
    stale entries (exact set equality). This is the guard that now runs where merges happen.
  * `test_manifest_is_grounded_in_recon` — runs locally (skips when the recon doc is
    absent, i.e. in CI): every manifest entry is documented in the recon doc, so the
    manifest cannot rubber-stamp an ungrounded path. Adding a new `dig()` path therefore
    requires updating the manifest (or CI fails) AND grounding it in the recon (or this
    local test fails).

The manifest lists only config-path strings that are already visible in the shipped source
(`checks.py` etc.) and public docs — it carries no internal research content.

B-251: `_parse_source_dig_paths()` originally only recognized a literal string sitting
directly in `dig(...)`'s own 2nd-argument source text (`ast.Name` func == "dig" +
`ast.Constant` arg). A real path routed through one level of indirection — a wrapper
function forwarding one of its own parameters (`clawseccheck/logdiscovery.py`'s
`_config_path_sink`), or a `for`-loop over a module-level literal collection
(`checks/_config.py`'s `_DANGER_FIXED` / `_DANGER_AGENT_SANDBOX`) — was invisible to it,
so the §4 gate passed *vacuously* on those paths (never grounded, never flagged either).
The parser now resolves both indirection shapes (see `_resolve_dig_path_arg` and
`_harvest_wrapper_call_sites` below); anything it still can't prove is a closed set of
string literals raises `RuntimeError` naming the offending file:line instead of silently
dropping the path — a guard that can silently see nothing is worse than no guard.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# The skill repo root is the parent of tests/ — in BOTH layouts (locally it is
# <workspace>/skill/, in CI the checkout root itself). Resolve the source dir and manifest
# relative to it so the guard works in CI, where the repo root IS the skill tree. Only the
# recon doc lives at the workspace root (one level up) and is local-only.
REPO_ROOT = Path(__file__).resolve().parent.parent
RECON_FILE = REPO_ROOT.parent / "docs" / "research" / "openclaw-schema-recon.md"
SOURCE_DIR = REPO_ROOT / "clawseccheck"
MANIFEST_FILE = Path(__file__).resolve().parent / "grounded_schema_paths.txt"

# Allowlist for configuration paths that are allowed even if not parsed from markdown
ALLOWLISTED_PATHS: set[str] = set()


def _parse_recon_paths() -> set[str]:
    """Parse all backticked and dotted paths from the markdown file."""
    text = RECON_FILE.read_text(encoding="utf-8")

    # Extract backtick paths
    paths = set(re.findall(r"`([a-zA-Z0-9_\-\.\*\{\}\[\]]+)`", text))

    # Extract dotted words to capture paths mentioned in tables or descriptions
    for match in re.findall(r"[a-zA-Z0-9_\-\.\*\{\}\[\]\<\>]+", text):
        if "." in match:
            paths.add(match)

    # Clean up and normalize path fragments
    cleaned = set()
    for p in paths:
        p = p.strip(".").strip().strip('"').strip("'")
        if not p:
            continue
        # Expand braces like: gateway.auth.{mode,token}
        if "{" in p and "}" in p:
            prefix, rest = p.split("{", 1)
            suffix = rest.rstrip("}")
            parts = [part.strip() for part in suffix.split(",")]
            for part in parts:
                cleaned.add(prefix + part)
        else:
            cleaned.add(p.replace("{", "").replace("}", ""))

    return cleaned


class _ParamRef:
    """`dig()`'s 2nd arg resolved to a *parameter* of its own enclosing function — the
    literal(s) live at that wrapper's call sites, not here. Deferred to a second pass
    (see ``_harvest_wrapper_call_sites``)."""

    __slots__ = ("func_name", "param_name")

    def __init__(self, func_name: str, param_name: str) -> None:
        self.func_name = func_name
        self.param_name = param_name


def _string_constant(node) -> "str | None":
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _attach_parents(tree: ast.AST) -> None:
    """Stamp every node with `._guard_parent` so name-binding resolution can walk
    upward from a `dig()` argument to the `For`/`FunctionDef` that binds its name."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._guard_parent = node  # type: ignore[attr-defined]


def _collect_module_level_sequences(tree: ast.Module) -> dict:
    """Map `NAME -> [elt, ...]` for module-level `NAME = [...]` / `(...)` / `{...}`
    literal-collection assignments (e.g. `_DANGER_FIXED`, `_DANGER_AGENT_SANDBOX`) — the
    closed sets a `for`-loop indirection can be proven to iterate over."""
    sequences = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
        ):
            sequences[node.targets[0].id] = list(node.value.elts)
    return sequences


def _sequence_elements(iter_node, sequences: dict):
    """The element nodes a `for ... in <iter_node>:` denotes, or None when `<iter_node>`
    isn't a closed literal collection (inline literal, or a module-level name in
    `sequences`) we can enumerate."""
    if isinstance(iter_node, (ast.List, ast.Tuple, ast.Set)):
        return list(iter_node.elts)
    if isinstance(iter_node, ast.Name):
        return sequences.get(iter_node.id)
    return None


def _find_binding_for_name(name_node: ast.Name, sequences: dict):
    """Resolve what binds `name_node`, walking outward via `._guard_parent`:

    * an enclosing `for NAME in SEQ:` / `for ..., NAME, ... in SEQ:` where `SEQ` is a
      closed literal collection -> returns the concrete `set[str]` of values `NAME` can
      take (None if any element isn't provably a string literal at that position);
    * an enclosing function's own parameter -> returns a `_ParamRef` for the caller to
      harvest from that function's call sites;
    * anything else (crosses a function boundary without matching a param, reaches
      module scope, a comprehension, an assignment, ...) -> returns None, i.e.
      unresolvable — deliberately conservative: a wrong "I don't know" is safe, a wrong
      guess would reintroduce exactly the vacuity this guard exists to prevent.
    """
    node = name_node
    while True:
        parent = getattr(node, "_guard_parent", None)
        if parent is None:
            return None
        if isinstance(parent, ast.For):
            target = parent.target
            if isinstance(target, ast.Name) and target.id == name_node.id:
                elements = _sequence_elements(parent.iter, sequences)
                if elements is None:
                    return None
                values = set()
                for el in elements:
                    s = _string_constant(el)
                    if s is None:
                        return None
                    values.add(s)
                return values
            if isinstance(target, ast.Tuple):
                index = next(
                    (i for i, elt in enumerate(target.elts) if isinstance(elt, ast.Name) and elt.id == name_node.id),
                    None,
                )
                if index is not None:
                    elements = _sequence_elements(parent.iter, sequences)
                    if elements is None:
                        return None
                    arity = len(target.elts)
                    values = set()
                    for el in elements:
                        if not (isinstance(el, (ast.Tuple, ast.List)) and len(el.elts) == arity):
                            return None
                        s = _string_constant(el.elts[index])
                        if s is None:
                            return None
                        values.add(s)
                    return values
        if isinstance(parent, ast.FunctionDef):
            positional = [a.arg for a in parent.args.posonlyargs] + [a.arg for a in parent.args.args]
            kwonly = [a.arg for a in parent.args.kwonlyargs]
            if name_node.id in positional or name_node.id in kwonly:
                return _ParamRef(parent.name, name_node.id)
            return None  # crossed a function boundary without matching a param
        node = parent


def _resolve_joined_str(node: ast.JoinedStr, sequences: dict):
    """Resolve an f-string `dig()` 2nd arg (e.g. `f"sandbox.docker.{flag}"`) to a closed
    set of literal strings, or None. Every `{...}` segment must itself be a plain `Name`
    that resolves to a concrete literal set (a `for`-loop binding) — a `_ParamRef` or
    anything more exotic inside an f-string is conservatively unresolvable."""
    parts = [""]
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts = [p + value.value for p in parts]
            continue
        if (
            isinstance(value, ast.FormattedValue)
            and value.conversion == -1
            and value.format_spec is None
            and isinstance(value.value, ast.Name)
        ):
            resolved = _find_binding_for_name(value.value, sequences)
            if not isinstance(resolved, set):
                return None
            parts = [p + seg for p in parts for seg in resolved]
            continue
        return None
    return set(parts)


def _resolve_dig_path_arg(arg, sequences: dict):
    """Resolve `dig()`'s 2nd argument node to `set[str]` (closed literal path set),
    `_ParamRef` (defer to wrapper-call-site harvesting), or None (unresolvable)."""
    s = _string_constant(arg)
    if s is not None:
        return {s}
    if isinstance(arg, ast.Name):
        return _find_binding_for_name(arg, sequences)
    if isinstance(arg, ast.JoinedStr):
        return _resolve_joined_str(arg, sequences)
    return None


def _harvest_wrapper_call_sites(trees: dict, func_name: str, param_name: str):
    """Every call to `func_name(...)` anywhere in `trees`, harvesting the literal string
    passed for `param_name`. Returns None only when the wrapper's own definition (to
    learn `param_name`'s position) can't be found anywhere, or it is never called — the
    caller raises for that. Raises RuntimeError itself, naming the exact call site, the
    moment any call passes something other than a string literal for `param_name` — a
    *partial* harvest would be exactly the silent vacuity this guard exists to prevent."""
    position = None
    is_kwonly = False
    found_def = False
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                positional = [a.arg for a in node.args.posonlyargs] + [a.arg for a in node.args.args]
                kwonly = [a.arg for a in node.args.kwonlyargs]
                if param_name in positional:
                    position = positional.index(param_name)
                elif param_name in kwonly:
                    is_kwonly = True
                found_def = True
                break
        if found_def:
            break
    if not found_def:
        return None

    values: set = set()
    call_found = False
    for py_file, tree in trees.items():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == func_name):
                continue
            call_found = True
            matched = False
            literal = None
            for kw in node.keywords:
                if kw.arg == param_name:
                    matched = True
                    literal = _string_constant(kw.value)
                    break
            if not matched and not is_kwonly and position is not None and position < len(node.args):
                matched = True
                literal = _string_constant(node.args[position])
            if not matched:
                continue  # this call relies on the wrapper's own default — not our concern
            if literal is None:
                raise RuntimeError(
                    f"unresolvable dig path in {py_file}:{node.lineno} — this call to "
                    f"wrapper '{func_name}' passes a non-literal value for parameter "
                    f"'{param_name}', which reaches dig() as its 2nd argument inside "
                    f"'{func_name}'. Golden Rule #4 requires every dig() path to be "
                    "traceable to a string literal."
                )
            values.add(literal)

    if not call_found:
        return None
    return values


def _parse_source_dig_paths() -> set[str]:
    """Parse every string literal that reaches `dig(...)`'s 2nd argument in the source
    tree — including through one level of indirection: a wrapper function forwarding one
    of its own parameters (harvested from that wrapper's call sites), or a `for`-loop
    iterating a module-level literal list/tuple/set (optionally through one f-string
    substitution).

    CLAWSECCHECK-B-251: the original version of this parser only recognized a literal
    sitting directly in the call's own source text (`ast.Name` func + `ast.Constant`
    arg), so a real path routed through either indirection was invisible to it — the §4
    anti-fabrication gate passed *vacuously* on those paths, neither confirming nor
    denying they were grounded. Anything this resolver still can't prove is a closed set
    of string literals now raises `RuntimeError` naming the file:line responsible,
    instead of silently vanishing from the returned set — a guard that can silently see
    nothing is worse than no guard.
    """
    paths: set = set()
    trees: dict = {}
    sequences_by_file: dict = {}

    for py_file in sorted(SOURCE_DIR.rglob("*.py")):
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError as e:  # pragma: no cover
                raise SyntaxError(f"Failed to parse AST of {py_file}: {e}") from e
        _attach_parents(tree)
        trees[py_file] = tree
        sequences_by_file[py_file] = _collect_module_level_sequences(tree)

    pending: dict = {}  # (func_name, param_name) -> [(file, lineno), ...] (first-seen dig() site, for the error)

    for py_file, tree in trees.items():
        sequences = sequences_by_file[py_file]
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dig"):
                continue
            if len(node.args) < 2:
                continue
            resolved = _resolve_dig_path_arg(node.args[1], sequences)
            if isinstance(resolved, set):
                paths.update(resolved)
            elif isinstance(resolved, _ParamRef):
                pending.setdefault((resolved.func_name, resolved.param_name), []).append((py_file, node.lineno))
            else:
                raise RuntimeError(
                    f"unresolvable dig path in {py_file}:{node.lineno} — the second "
                    "argument to dig() is not a string literal, and could not be traced "
                    "through a for-loop over a module-level literal collection or a "
                    "wrapper-function parameter. Golden Rule #4 requires every dig() "
                    "path to be grounded in the schema recon (workspace root, "
                    "docs/research/openclaw-schema-recon.md) — either use a literal "
                    "here, or teach _parse_source_dig_paths() (tests/test_schema_"
                    "grounding.py) to resolve this new indirection."
                )

    for (func_name, param_name), sites in pending.items():
        harvested = _harvest_wrapper_call_sites(trees, func_name, param_name)
        if harvested is None:
            first_file, first_line = sites[0]
            raise RuntimeError(
                f"unresolvable dig path in {first_file}:{first_line} — dig()'s second "
                f"argument here is parameter '{param_name}' of wrapper function "
                f"'{func_name}', but no call site of '{func_name}' could be found "
                "anywhere in the source tree to harvest a literal from. A guard that "
                "can silently see nothing is worse than no guard (CLAWSECCHECK-B-251)."
            )
        paths.update(harvested)

    return paths


def _parse_manifest_paths() -> set[str]:
    """Read the shipped, vendored grounded-path manifest (comments/blank lines ignored)."""
    paths = set()
    for line in MANIFEST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            paths.add(line)
    return paths


def _is_grounded(path: str, recon_paths: set[str]) -> bool:
    """True when *path* is documented in the recon set — exact, wildcard, or placeholder."""
    if path in recon_paths:
        return True
    for recon_p in recon_paths:
        # 1. Match paths ending in * (wildcard)
        if recon_p.endswith("*"):
            prefix = recon_p[:-1]
            escaped_prefix = re.escape(prefix)
            reg_pattern = "^" + escaped_prefix.replace(r"\[\]", r"\[\d*\]") + ".*$"
            if re.match(reg_pattern, path):
                return True
        # 2. Match placeholder tags like <name>, <p>, <provider>
        if "<" in recon_p and ">" in recon_p:
            escaped_recon_p = re.escape(recon_p)
            reg_pattern = "^" + re.sub(r"\\<[^\\>]+\\>", "[^.]+", escaped_recon_p) + "$"
            if re.match(reg_pattern, path):
                return True
    return False


def test_dig_paths_match_shipped_manifest():
    """CI-enforced §4 guard: every dig() path is in the shipped manifest and vice versa.

    Runs everywhere (no recon dependency). A new ungrounded `dig("fake.path")` fails here
    until it is added to tests/grounded_schema_paths.txt — and adding it there requires
    grounding it in the recon (test_manifest_is_grounded_in_recon)."""
    source_paths = _parse_source_dig_paths() - ALLOWLISTED_PATHS
    manifest_paths = _parse_manifest_paths()

    ungrounded = sorted(source_paths - manifest_paths)
    stale = sorted(manifest_paths - source_paths)

    assert not ungrounded and not stale, (
        ("Ungrounded config path(s) used in code but missing from the manifest:\n"
         + "\n".join(f"  - {p}" for p in ungrounded) + "\n"
         if ungrounded else "")
        + ("Stale manifest entries no longer queried by any dig():\n"
           + "\n".join(f"  - {p}" for p in stale) + "\n"
           if stale else "")
        + f"\nReconcile {MANIFEST_FILE.name} with the dig() paths in the source. "
        "A newly-added path must also be grounded in the recon doc (§4)."
    )


def test_manifest_is_grounded_in_recon():
    """Local guard: every vendored manifest path is documented in the recon doc.

    Skips when the recon doc is absent (e.g. CI, or a fresh clone without the sibling
    research dir) — the manifest-vs-source equality above is what runs there. This keeps
    the manifest from silently vendoring a fabricated path."""
    if not RECON_FILE.exists():
        pytest.skip(f"Recon doc not present at {RECON_FILE} — manifest-vs-recon check is local-only")

    recon_paths = _parse_recon_paths()
    manifest_paths = _parse_manifest_paths() - ALLOWLISTED_PATHS

    missing = sorted(p for p in manifest_paths if not _is_grounded(p, recon_paths))

    assert not missing, (
        f"Found {len(missing)} manifest path(s) NOT grounded in the recon doc:\n"
        + "\n".join(f"  - {p}" for p in missing)
        + f"\n\nEvery entry in {MANIFEST_FILE.name} must be documented in:\n  {RECON_FILE}"
    )
