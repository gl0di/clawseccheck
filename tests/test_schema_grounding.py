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
  * `test_manifest_root_paths_resolve_against_installed_dist` — C-249, the third layer,
    also local-only (skips when OpenClaw is not installed). See below.

The manifest lists only config-path strings that are already visible in the shipped source
(`checks/` etc.) and public docs — it carries no internal research content.

C-249 — why two authorities were not enough
-------------------------------------------
Both layers above compare one INTERNAL artifact against another: source `dig()` paths vs
the manifest, and the manifest vs the recon. Neither ever consults OpenClaw itself. So when
the recon and the manifest carry the SAME error, the guard rubber-stamps a path OpenClaw's
own validator rejects — which is exactly how B-262 survived a full schema re-baseline: with
`logging.cacheTrace.filePath` in the manifest and the recon vouching for it, both layers ran
green while the real field was `diagnostics.cacheTrace.filePath`.

The third layer resolves each manifest path's PARENT CHAIN against the installed dist
(`~/.npm-global/lib/node_modules/openclaw/dist/zod-schema*.js`), which carries the real zod
config schema. Matching leaf keys alone would NOT have caught B-262 — `filePath` does exist,
just under `diagnostics.cacheTrace` rather than `logging.cacheTrace` — so this layer walks
every component in order, from `OpenClawSchema` down, and a path is grounded only when each
component is a direct key of the object its parent denotes.

`_dist_direct_keys()` is a small zod-expression reader, not a JS engine: it follows const
aliases (`tools: ToolsSchema`), object-literal shapes (`object(ToolExecBaseShape)`), spreads
(`...CommonToolPolicyFields`) and union branches. Its verdicts were cross-checked against a
real `OpenClawSchema.safeParse()` on 14 probes — six disputed paths, seven controls and the
B-262 phantom — and agreed on all of them.

Paths the current schema does NOT contain live in `_NOT_IN_CURRENT_SCHEMA` with their
disproof, because a few are legitimate: Golden Rule #6 asks the audit to read legacy and
alternate config shapes, and an older OpenClaw's field is absent from today's dist by
definition. That register is the point of the layer — the reads are declared and reviewed
rather than merely believed. `test_register_entries_are_still_absent_from_the_dist` keeps it
shrinking: the moment a registered path becomes resolvable, the entry has to go.

B-251 — how a path becomes visible to this guard
------------------------------------------------
`_parse_source_dig_paths()` originally only recognized a literal string sitting directly
in `dig(...)`'s own 2nd-argument source text (`ast.Name` func == "dig" + `ast.Constant`
arg). A real path routed through one level of indirection — a wrapper function forwarding
one of its own parameters (`clawseccheck/logdiscovery.py`'s `_config_path_sink`), or a
`for`-loop over a module-level literal collection (`checks/_config.py`'s `_DANGER_FIXED` /
`_DANGER_AGENT_SANDBOX`) — was invisible to it, so the §4 gate passed *vacuously* on
those paths: never grounded, but never flagged either.

The parser now resolves both indirection shapes and, just as importantly, **refuses to
stay quiet**. Every one of these raises `RuntimeError` naming a concrete `file:line`
instead of dropping the path:

  * the 2nd argument is neither a literal, nor a resolvable `for`-loop variable, nor a
    resolvable wrapper parameter;
  * a `dig()` call has no resolvable path argument at all (no positional 2nd arg and no
    `path=` keyword);
  * a wrapper's call site passes a non-literal, `*args`, or `**kwargs` for the forwarded
    parameter — including the case where the call OMITS the parameter and the wrapper's
    own *default* is therefore the string that reaches `dig()`;
  * the wrapper name is ambiguous (a same-named `def` exists elsewhere in the tree, so
    call sites cannot be attributed to it), or has no call site at all, or the harvest
    comes back empty.

Both `ast.Name` (`dig(...)`) and attribute-qualified (`collector.dig(...)`) call forms
are recognized.

Base objects are namespaced
---------------------------
`dig()`'s FIRST argument decides which object a path is relative to. `sandbox.docker.X`
read off an entry of `agents.list` and `sandbox.docker.X` read off the config ROOT are
different claims about the schema — openclaw.json has no top-level `sandbox` key. Paths
read off the config root keep their bare spelling in the manifest; every other base is
namespaced with `RELATIVE_PREFIX`, so a relative leaf can never launder a fabricated
absolute path (or the reverse) through the manifest.

Known limits (deliberate, documented rather than papered over)
--------------------------------------------------------------
  * Root detection is by exact base-expression text (`_CONFIG_ROOT_EXPRESSIONS`), not by
    dataflow. An unrecognized base is treated as non-root, which is the safe direction —
    it forces an explicit namespaced manifest entry. A *new* spelling of the config root
    must be added to that set, or its paths will show up as `relative:` and fail loudly.
  * `test_manifest_is_grounded_in_recon` grounds the field path itself and strips the
    namespace prefix; the recon doc has no base-object dimension. So the recon layer can
    attest "this field is real", not "this field is real *at the config root*". The
    manifest-vs-source equality above is what pins the base — which means adding a bare
    entry for a path that the recon only documents in its relative form is a deliberate
    human act, not something the guard will do silently.
  * Wrapper resolution is one hop deep. A two-hop chain is refused loudly, not guessed.
"""
from __future__ import annotations

import ast
import re
import sys
import textwrap
from collections import Counter
from functools import lru_cache
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

# C-249 third authority: the INSTALLED OpenClaw package. Local-only, like the recon —
# absent in CI and on a machine without OpenClaw, where the layer skips. Read-only.
OPENCLAW_DIST = Path.home() / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"
# The zod object the whole openclaw.json is parsed against. Anchoring the walk here is what
# makes a ROOT-namespace manifest entry a checkable claim ("this is a real top-level key").
DIST_ROOT_SCHEMA = "OpenClawSchema"

# Allowlist for configuration paths that are allowed even if not parsed from markdown
ALLOWLISTED_PATHS: set[str] = set()

# DENYLIST — paths PROVEN not to exist in the OpenClaw schema. This closes a hole in the
# recon layer: `_parse_recon_paths()` harvests every dotted token in the doc, and it cannot
# tell an attestation ("`x.y` is a real field") from a CORRECTION ("`x.y` does not exist").
# So the moment the recon documents a phantom in order to warn about it, that phantom
# starts passing `_is_grounded()` — which is exactly how B-262 stayed invisible: the recon
# AND the manifest were both wrong about `logging.cacheTrace.filePath`, and the guard
# rubber-stamped it. A denylisted path is never grounded, however the recon phrases it.
#
# Add an entry only with the disproof recorded next to it, and only for a path some part of
# the codebase might plausibly reach for again.
_PHANTOM_PATHS = frozenset(
    {
        # B-262. `grep -rF "logging.cacheTrace"` over the installed package = 0 hits, and
        # the `logging` zod object is `.strict()` with exactly {level, file, maxFileBytes,
        # consoleLevel, consoleStyle, redactSensitive, redactPatterns}
        # (zod-schema-O9ml_nmo.js:1059-1070), so a config carrying it is rejected at load
        # time. The real object is `diagnostics.cacheTrace` (:1050-1056).
        "logging.cacheTrace",
        # B-263. The four would-be GLOBAL egress allowlists C014 used to accept as proof of
        # a restricted posture. OpenClaw exposes no static egress-control config field at
        # all, and each of these is rejected at config load. Disproof against the installed
        # 2026.7.1-2 dist: `grep -rF` = 0 hits for `network.egress`, `gateway.egress` and
        # `tools.http`; and safeParse against the real root schema (47 keys, no `network`,
        # no `egress`) rejects every one of them —
        #   {"network": {"egress": [...]}}       -> unrecognized_keys@<root>
        #   {"gateway": {"egress": {...}}}       -> unrecognized_keys@gateway
        #   {"egress": [...]}                    -> unrecognized_keys@<root>
        #   {"tools": {"http": {"allow": [...]}}} -> unrecognized_keys@tools
        # while the controls `gateway.port` and `tools.allow` parse cleanly.
        #
        # These need the denylist MORE than B-262 did, because the recon does not merely
        # mention them in a correction: it ALSO still lists `tools.http.allow` in its
        # positive field inventory ("allowed HTTP endpoints or profiles"). Both spellings
        # feed `_parse_recon_paths()` as ordinary dotted tokens, so all four scored as
        # grounded — a re-added `dig(cfg, "gateway.egress")` plus a manifest line passed
        # BOTH layers green. Verified before this entry existed, not assumed.
        #
        # `tools.http` is denylisted at the PARENT, not at `tools.http.allow`: the whole
        # object is absent from the strict `ToolsSchema`, so every child is a phantom and
        # `_is_phantom`'s prefix match must cover siblings too.
        "gateway.egress",
        "network.egress",
        "egress",
        "tools.http",
    }
)


def _is_phantom(path: str) -> bool:
    """True when *path* is a denylisted phantom, or hangs off one."""
    return any(path == p or path.startswith(p + ".") for p in _PHANTOM_PATHS)

# Manifest namespace for a path read off something other than the OpenClaw config root
# (an entry of `agents.list`, an MCP server entry, a skill's frontmatter metadata, ...).
RELATIVE_PREFIX = "relative:"

# Exact `ast.unparse` texts of `dig()` first arguments verified by inspection to BE the
# OpenClaw config root object. Everything else is namespaced with RELATIVE_PREFIX — an
# unrecognized base erring towards "relative" is the safe direction, because a bare
# manifest entry is the stronger claim (this string is a real TOP-LEVEL config key).
_CONFIG_ROOT_EXPRESSIONS = frozenset(
    {
        "cfg",  # every `cfg = ctx.config` / `cfg = json.loads(<home>/openclaw.json)`
        "ctx.config",
        "getattr(ctx, 'config', None) or {}",
        "getattr(ctx, 'config', {}) or {}",
    }
)

# Methods that mutate a list/set/dict in place. A module-level literal collection that is
# touched by any of these is no longer a closed set, so it stops being resolvable.
_MUTATING_METHODS = frozenset(
    {
        "append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse",
        "add", "discard", "update", "setdefault", "popitem",
        "difference_update", "intersection_update", "symmetric_difference_update",
        "__setitem__", "__delitem__",
    }
)


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
    (see ``_harvest_wrapper_call_sites``).

    Carries the resolved ``FunctionDef`` NODE and the file it lives in, not merely the
    function's name. Re-resolving the wrapper by bare name would pick whichever same-named
    ``def`` happened to sort first across the source tree — and this repo already has many
    duplicate function names across modules, so that lookup could silently land on a def
    that has no such parameter and harvest nothing at all: the exact B-251 vacuity,
    reintroduced inside the fix for it."""

    __slots__ = ("func_def", "param_name", "def_file", "site_file", "site_lineno")

    def __init__(self, func_def, param_name: str, source_file, lineno: int) -> None:
        self.func_def = func_def
        self.param_name = param_name
        # The dig() call is lexically inside func_def, so they share a file.
        self.def_file = source_file
        self.site_file = source_file
        self.site_lineno = lineno


def _string_constant(node) -> "str | None":
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_call_to(node, name: str) -> bool:
    """True for `name(...)` AND `something.name(...)` — an attribute-qualified call (e.g.
    `from . import collector as _c` then `_c.dig(...)`) is the same call as far as the §4
    gate is concerned, and matching only `ast.Name` made it a zero-effort bypass."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == name
    if isinstance(func, ast.Attribute):
        return func.attr == name
    return False


def _attach_parents(tree: ast.AST) -> None:
    """Stamp every node with `._guard_parent` so name-binding resolution can walk
    upward from a `dig()` argument to the `For`/`FunctionDef` that binds its name."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._guard_parent = node  # type: ignore[attr-defined]


def _unsafe_sequence_names(tree: ast.Module) -> "tuple[set[str], set[str]]":
    """`(rebound, mutated)` names in one module.

    * `rebound` — names bound more than once anywhere in the module (so a module-level
      literal assignment is not the last word on their contents).
    * `mutated` — names that are the object of an in-place mutation: a mutating method
      call (`NAME.append(...)`, and also `mod.NAME.append(...)` so a cross-module mutation
      is caught), an augmented assignment, or a subscript/attribute store. `from x import
      NAME as ALIAS` is followed, so `ALIAS.append(...)` disqualifies `NAME` too.

    A harvested module-level sequence that appears in either set stops being a closed
    literal collection, so `_collect_module_level_sequences` drops it and any `for`-loop
    over it becomes unresolvable — i.e. LOUD, not silently narrowed.
    """
    stores: Counter = Counter()
    mutated: set = set()
    aliases: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if imported.asname:
                    aliases[imported.asname] = imported.name
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[node.id] += 1
        elif isinstance(node, ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name):
                mutated.add(target.id)
            elif isinstance(target, ast.Attribute):
                mutated.add(target.attr)
        elif isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            base = node.value if isinstance(node, ast.Subscript) else node
            if isinstance(base, ast.Name):
                mutated.add(base.id)
            elif isinstance(base, ast.Attribute):
                mutated.add(base.attr)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _MUTATING_METHODS:
                obj = node.func.value
                if isinstance(obj, ast.Name):
                    mutated.add(obj.id)
                elif isinstance(obj, ast.Attribute):
                    mutated.add(obj.attr)
    # `from ._config import _DANGER_FIXED as _DF` then `_DF.append(...)` mutates the
    # ORIGINAL list; without this the alias would hide the mutation from the check.
    mutated |= {aliases[name] for name in mutated if name in aliases}
    rebound = {name for name, count in stores.items() if count > 1}
    return rebound, mutated


def _collect_module_level_sequences(tree: ast.Module, unsafe: "set[str]") -> dict:
    """Map `NAME -> [elt, ...]` for module-level `NAME = [...]` / `(...)` / `{...}`
    literal-collection assignments (e.g. `_DANGER_FIXED`, `_DANGER_AGENT_SANDBOX`).

    Names in *unsafe* — rebound or mutated somewhere in the source tree — are excluded:
    the initial assignment does not describe their final contents, so a `for`-loop over
    them cannot be enumerated. Callers turn "not enumerable" into a loud error."""
    sequences = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
            and node.targets[0].id not in unsafe
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


def _find_binding_for_name(name_node: ast.Name, sequences: dict, py_file):
    """Resolve what binds `name_node`, walking outward via `._guard_parent`:

    * an enclosing `for NAME in SEQ:` / `for ..., NAME, ... in SEQ:` where `SEQ` is a
      closed literal collection -> returns the concrete `set[str]` of values `NAME` can
      take (None if any element isn't provably a string literal at that position);
    * an enclosing function's own parameter -> returns a `_ParamRef` carrying that
      function's AST node, for the caller to harvest from its call sites;
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
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = [a.arg for a in parent.args.posonlyargs] + [a.arg for a in parent.args.args]
            kwonly = [a.arg for a in parent.args.kwonlyargs]
            if name_node.id in positional or name_node.id in kwonly:
                return _ParamRef(parent, name_node.id, py_file, name_node.lineno)
            return None  # crossed a function boundary without matching a param
        if isinstance(parent, ast.Lambda):
            return None
        node = parent


def _resolve_joined_str(node: ast.JoinedStr, sequences: dict, py_file):
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
            resolved = _find_binding_for_name(value.value, sequences, py_file)
            if not isinstance(resolved, set):
                return None
            parts = [p + seg for p in parts for seg in resolved]
            continue
        return None
    return set(parts)


def _resolve_dig_path_arg(arg, sequences: dict, py_file):
    """Resolve `dig()`'s 2nd argument node to `set[str]` (closed literal path set),
    `_ParamRef` (defer to wrapper-call-site harvesting), or None (unresolvable)."""
    s = _string_constant(arg)
    if s is not None:
        return {s}
    if isinstance(arg, ast.Name):
        return _find_binding_for_name(arg, sequences, py_file)
    if isinstance(arg, ast.JoinedStr):
        return _resolve_joined_str(arg, sequences, py_file)
    return None


def _dig_base_namespace(base_node) -> str:
    """`""` when `dig()`'s 1st argument is a verified spelling of the OpenClaw config
    ROOT, `RELATIVE_PREFIX` otherwise (including when there is no first argument to look
    at). Unknown-base -> namespaced is the safe direction: it can never launder a
    fabricated top-level path into the bare manifest namespace."""
    if base_node is not None:
        try:
            text = ast.unparse(base_node)
        except Exception:  # pragma: no cover - unparse is total for real source
            text = None
        if text in _CONFIG_ROOT_EXPRESSIONS:
            return ""
    return RELATIVE_PREFIX


def _call_arg(node: ast.Call, position: int, keyword: str):
    """The node supplied for a parameter that sits at `position` positionally and is
    spelled `keyword` by name, or None when the call supplies neither."""
    if position < len(node.args):
        return node.args[position]
    for kw in node.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def _wrapper_param_slot(func_def, param_name: str):
    """`(position, is_kwonly, default_node)` for `param_name` in `func_def`'s signature,
    or None when the signature has no such parameter. `default_node` is the AST node of
    the parameter's DEFAULT — when a call site omits the parameter, that default is the
    string that actually reaches `dig()`, so it is very much this guard's concern."""
    args = func_def.args
    positional = [a.arg for a in args.posonlyargs] + [a.arg for a in args.args]
    kwonly = [a.arg for a in args.kwonlyargs]
    if param_name in positional:
        position = positional.index(param_name)
        first_defaulted = len(positional) - len(args.defaults)
        default = args.defaults[position - first_defaulted] if position >= first_defaulted else None
        return position, False, default
    if param_name in kwonly:
        return None, True, args.kw_defaults[kwonly.index(param_name)]
    return None


def _harvest_wrapper_call_sites(trees: dict, ref: _ParamRef):
    """Every call to the wrapper `ref.func_def` anywhere in `trees`, harvesting the string
    literal supplied for `ref.param_name` (or, when a call omits it, the parameter's own
    default). Returns None only when the wrapper is never called — the caller raises for
    that. Raises `RuntimeError` itself, naming the exact `file:line`, the moment any call
    supplies something other than a string literal, splats `*args`/`**kwargs`, or omits
    the parameter without a string-literal default — a *partial* harvest would be exactly
    the silent vacuity this guard exists to prevent."""
    func_name = ref.func_def.name
    slot = _wrapper_param_slot(ref.func_def, ref.param_name)
    if slot is None:  # pragma: no cover - _ParamRef is only built after a signature match
        raise RuntimeError(
            f"unresolvable dig path in {ref.site_file}:{ref.site_lineno} — parameter "
            f"'{ref.param_name}' vanished from the signature of wrapper '{func_name}' "
            f"({ref.def_file}:{ref.func_def.lineno})."
        )
    position, is_kwonly, default_node = slot

    # Call sites can only be matched by NAME. If a same-named def exists anywhere else in
    # the tree, that attribution is not trustworthy, so refuse rather than harvest some
    # other function's literals (or, worse, none at all).
    same_named = [
        (py_file, node)
        for py_file, tree in trees.items()
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name
    ]
    if len(same_named) > 1:
        where = ", ".join(f"{f}:{n.lineno}" for f, n in same_named)
        raise RuntimeError(
            f"unresolvable dig path in {ref.site_file}:{ref.site_lineno} — dig()'s second "
            f"argument here is parameter '{ref.param_name}' of wrapper '{func_name}', but "
            f"'{func_name}' is defined more than once in the source tree ({where}), so its "
            "call sites cannot be attributed to one definition. Rename one of them, or "
            "pass a string literal directly at the dig() call."
        )

    values: set = set()
    call_sites = 0
    for py_file, tree in trees.items():
        for node in ast.walk(tree):
            if not _is_call_to(node, func_name):
                continue
            call_sites += 1
            if any(isinstance(a, ast.Starred) for a in node.args) or any(kw.arg is None for kw in node.keywords):
                raise RuntimeError(
                    f"unresolvable dig path in {py_file}:{node.lineno} — this call to "
                    f"wrapper '{func_name}' splats *args/**kwargs, so the value reaching "
                    f"dig() through parameter '{ref.param_name}' cannot be determined "
                    "statically. Golden Rule #4 requires every dig() path to be traceable "
                    "to a string literal."
                )
            supplied = None
            for kw in node.keywords:
                if kw.arg == ref.param_name:
                    supplied = kw.value
                    break
            if supplied is None and not is_kwonly and position is not None and position < len(node.args):
                supplied = node.args[position]
            if supplied is not None:
                literal = _string_constant(supplied)
                if literal is None:
                    raise RuntimeError(
                        f"unresolvable dig path in {py_file}:{node.lineno} — this call to "
                        f"wrapper '{func_name}' passes a non-literal value for parameter "
                        f"'{ref.param_name}', which reaches dig() as its 2nd argument "
                        f"inside '{func_name}'. Golden Rule #4 requires every dig() path "
                        "to be traceable to a string literal."
                    )
                values.add(literal)
                continue
            # The call omits the parameter, so the wrapper's OWN DEFAULT is the string
            # that reaches dig(). A fabricated path can hide in a parameter default just
            # as easily as at a call site.
            if default_node is None:
                raise RuntimeError(
                    f"unresolvable dig path in {py_file}:{node.lineno} — this call to "
                    f"wrapper '{func_name}' supplies no value for parameter "
                    f"'{ref.param_name}' and the parameter has no default "
                    f"({ref.def_file}:{ref.func_def.lineno}), so the path reaching dig() "
                    "cannot be determined statically."
                )
            literal = _string_constant(default_node)
            if literal is None:
                raise RuntimeError(
                    f"unresolvable dig path in {ref.def_file}:{ref.func_def.lineno} — the "
                    f"call at {py_file}:{node.lineno} omits parameter '{ref.param_name}' "
                    f"of wrapper '{func_name}', so that parameter's DEFAULT is what "
                    "reaches dig(), and it is not a string literal. Golden Rule #4 "
                    "requires every dig() path to be traceable to a string literal."
                )
            values.add(literal)

    if not call_sites:
        return None
    if not values:  # pragma: no cover - every matched call either adds a value or raises
        raise RuntimeError(
            f"unresolvable dig path in {ref.site_file}:{ref.site_lineno} — "
            f"{call_sites} call site(s) of wrapper '{func_name}' were found but not one "
            f"literal could be harvested for parameter '{ref.param_name}'. A guard that "
            "can silently see nothing is worse than no guard (B-251)."
        )
    return values


def _parse_source_dig_paths() -> set[str]:
    """Parse every string literal that reaches `dig(...)`'s 2nd argument in the source
    tree, keyed by base object (bare for the config root, `relative:`-prefixed otherwise
    — see the module docstring).

    Resolves one level of indirection: a wrapper function forwarding one of its own
    parameters (harvested from that wrapper's call sites, including parameter defaults),
    or a `for`-loop iterating a module-level literal collection (optionally through one
    f-string substitution).

    B-251: the original version of this parser only recognized a literal sitting directly
    in the call's own source text (`ast.Name` func + `ast.Constant` arg), so a real path
    routed through either indirection was invisible to it — the §4 anti-fabrication gate
    passed *vacuously* on those paths, neither confirming nor denying they were grounded.
    Anything this resolver still can't prove is a closed set of string literals now raises
    `RuntimeError` naming the file:line responsible, instead of silently vanishing from
    the returned set — a guard that can silently see nothing is worse than no guard.
    """
    paths: set = set()
    trees: dict = {}

    for py_file in sorted(SOURCE_DIR.rglob("*.py")):
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError as e:  # pragma: no cover
                raise SyntaxError(f"Failed to parse AST of {py_file}: {e}") from e
        _attach_parents(tree)
        trees[py_file] = tree

    # Rebinding is per-module (a same-named local elsewhere is irrelevant); in-place
    # mutation is collected across the whole tree, because `other_module.NAME.append(...)`
    # reopens a collection just as effectively as an in-file `NAME.append(...)`.
    rebound_by_file: dict = {}
    mutated_anywhere: set = set()
    for py_file, tree in trees.items():
        rebound, mutated = _unsafe_sequence_names(tree)
        rebound_by_file[py_file] = rebound
        mutated_anywhere |= mutated

    sequences_by_file = {
        py_file: _collect_module_level_sequences(tree, rebound_by_file[py_file] | mutated_anywhere)
        for py_file, tree in trees.items()
    }

    pending: dict = {}  # (def id, param, namespace) -> (_ParamRef, [(file, lineno), ...])

    for py_file, tree in trees.items():
        sequences = sequences_by_file[py_file]
        for node in ast.walk(tree):
            if not _is_call_to(node, "dig"):
                continue
            # `dig(d, path, default=None)` — `path` is a legal keyword, so looking only at
            # `node.args[1]` let `dig(cfg, path="fabricated.path")` sail straight past.
            path_arg = _call_arg(node, 1, "path")
            if path_arg is None:
                raise RuntimeError(
                    f"unresolvable dig path in {py_file}:{node.lineno} — this dig() call "
                    "supplies no positional 2nd argument and no `path=` keyword, so the "
                    "config path it queries cannot be determined statically. Golden Rule "
                    "#4 requires every dig() path to be traceable to a string literal."
                )
            namespace = _dig_base_namespace(_call_arg(node, 0, "d"))
            resolved = _resolve_dig_path_arg(path_arg, sequences, py_file)
            if isinstance(resolved, set):
                paths.update(namespace + p for p in resolved)
            elif isinstance(resolved, _ParamRef):
                key = (id(resolved.func_def), resolved.param_name, namespace)
                pending.setdefault(key, (resolved, []))[1].append((py_file, node.lineno))
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

    for (_def_id, param_name, namespace), (ref, sites) in pending.items():
        harvested = _harvest_wrapper_call_sites(trees, ref)
        if harvested is None:
            first_file, first_line = sites[0]
            raise RuntimeError(
                f"unresolvable dig path in {first_file}:{first_line} — dig()'s second "
                f"argument here is parameter '{param_name}' of wrapper function "
                f"'{ref.func_def.name}', but no call site of '{ref.func_def.name}' could "
                "be found anywhere in the source tree to harvest a literal from. A guard "
                "that can silently see nothing is worse than no guard (B-251)."
            )
        paths.update(namespace + p for p in harvested)

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
    """True when *path* is documented in the recon set — exact, wildcard, or placeholder.

    The `relative:` namespace is stripped first: the recon doc records real schema FIELDS
    and has no base-object dimension, so it can attest that a field exists, not which
    object it hangs off. Pinning the base is the manifest-vs-source guard's job."""
    if path.startswith(RELATIVE_PREFIX):
        path = path[len(RELATIVE_PREFIX):]
    # A proven phantom is never grounded, no matter how the recon spells it out. The recon
    # mentions these paths precisely to warn about them, and the harvester cannot tell that
    # apart from an attestation — see _PHANTOM_PATHS.
    if _is_phantom(path):
        return False
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
        f"A '{RELATIVE_PREFIX}' prefix means the path is read off a nested object, not "
        "the config root. A newly-added path must also be grounded in the recon doc (§4)."
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


def test_proven_phantom_paths_are_never_grounded():
    """B-262 regression, on the GUARD rather than the check.

    The recon documents `logging.cacheTrace.filePath` at length — to say it does not
    exist. `_parse_recon_paths()` harvests dotted tokens and cannot tell a correction from
    an attestation, so before the denylist the disproven path scored as grounded, and a
    future `dig()` of it plus a manifest entry would have passed BOTH layers silently:
    exactly the failure mode that let B-262 ship. Recon prose must not be able to
    resurrect it."""
    # Synthetic recon set, so this runs in CI too (the recon doc is local-only). It is
    # deliberately the WORST case: the phantom present as a bare harvested token, which is
    # precisely what the real doc's corrective prose produces.
    recon_paths = {"logging.cacheTrace.filePath", "logging.cacheTrace", "logging.file"}
    assert not _is_grounded("logging.cacheTrace", recon_paths)
    assert not _is_grounded("logging.cacheTrace.filePath", recon_paths)
    # children of a phantom are phantoms too
    assert not _is_grounded("logging.cacheTrace.enabled", recon_paths)
    # ... and the namespaced form cannot sneak past by prefixing
    assert not _is_grounded(RELATIVE_PREFIX + "logging.cacheTrace.filePath", recon_paths)


def test_proven_phantom_egress_paths_are_never_grounded():
    """B-263 regression, on the GUARD rather than on C014.

    C014 used four would-be global egress allowlists as proof of a restricted posture; all
    four are rejected by the real schema. Removing them from the check and the manifest is
    not enough on its own — the grounding layers still scored them as REAL, so re-adding a
    `dig()` of any one plus a manifest line passed both guards green. Worse than B-262: the
    recon does not only correct these, it ALSO still lists `tools.http.allow` among its
    positive field inventory, and `_parse_recon_paths()` harvests both spellings
    identically.
    """
    # Deliberately the worst case: every phantom present as a bare harvested token, exactly
    # what the recon's corrective prose AND its positive inventory line both produce.
    recon_paths = {
        "network.egress", "gateway.egress", "egress", "tools.http.allow",
        "tools.allow", "gateway.bind",
    }
    for phantom in ("network.egress", "gateway.egress", "egress", "tools.http.allow"):
        assert not _is_grounded(phantom, recon_paths), phantom
        assert not _is_grounded(RELATIVE_PREFIX + phantom, recon_paths), phantom
    # `tools.http` is denylisted at the parent, so unlisted siblings are phantoms too.
    assert not _is_grounded("tools.http.deny", recon_paths)
    # The real neighbours must survive: denylisting these must not cost real coverage.
    assert _is_grounded("tools.allow", recon_paths)
    assert _is_grounded("gateway.bind", recon_paths)


def test_phantom_denylist_does_not_shadow_the_real_path():
    """The denylist must be surgical: `diagnostics.cacheTrace.*` is the REAL object and
    has to stay groundable, and a merely similar prefix must not be caught either."""
    recon_paths = {"diagnostics.cacheTrace.filePath", "logging.cacheTrace.filePath"}
    assert _is_grounded("diagnostics.cacheTrace.filePath", recon_paths)
    assert not _is_phantom("diagnostics.cacheTrace.filePath")
    assert not _is_phantom("logging.cacheTraceExtra")
    assert not _is_phantom("logging.file")
    # B-263: the bare `egress` entry must match the top-level key and its children only —
    # a name that merely STARTS WITH "egress" is a different key and must stay groundable.
    assert _is_phantom("egress")
    assert _is_phantom("egress.allow")
    assert not _is_phantom("egressPolicy")
    assert not _is_phantom("gateway.egressPolicy")
    # ... and denylisting `tools.http` must not swallow the real `tools.*` siblings.
    assert not _is_phantom("tools.allow")
    assert not _is_phantom("tools.httpTimeout")


def test_no_manifest_entry_is_a_proven_phantom():
    """The denylist is only worth having if it is actually applied to the manifest."""
    assert not [p for p in _parse_manifest_paths() if _is_phantom(p.replace(RELATIVE_PREFIX, ""))]


# --------------------------------------------------------------------------------------
# Resolver regression tests (B-251).
#
# The two guards above only assert that the resolver's output matches the manifest TODAY.
# They cannot tell "the resolver saw every path" apart from "the resolver saw nothing new"
# — which is precisely how the original vacuity survived for so long, and how a first cut
# at fixing it silently reintroduced the same hole via a bare-name wrapper lookup.
#
# These tests run the real resolver over synthetic source trees in `tmp_path` so each
# indirection shape is pinned directly: what must be SEEN, and what must FAIL LOUDLY.
# Offline, read-only outside tmp_path.
# --------------------------------------------------------------------------------------


def _resolve_synthetic_source(tmp_path, monkeypatch, files: "dict[str, str]") -> "set[str]":
    """Write `files` as a synthetic `clawseccheck/` package and run the real resolver."""
    pkg = tmp_path / "clawseccheck"
    pkg.mkdir()
    for name, body in files.items():
        target = pkg / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "SOURCE_DIR", pkg)
    return _parse_source_dig_paths()


def test_config_root_and_nested_bases_get_separate_namespaces(tmp_path, monkeypatch):
    """The same path string read off the config root and off a nested object are two
    different claims about the schema, so they must not share one manifest key."""
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "a.py": """
            def check(ctx, agent):
                dig(ctx.config, "tools.allow")
                dig(agent, "tools.allow")
        """,
    })
    assert paths == {"tools.allow", RELATIVE_PREFIX + "tools.allow"}


def test_relative_leaf_does_not_ground_the_same_path_at_the_config_root(tmp_path, monkeypatch):
    """openclaw.json has no top-level `sandbox` key. A per-agent `sandbox.docker.<flag>`
    read must not launder a fabricated ROOT-level read of the identical string."""
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "a.py": """
            def check(ctx, agent):
                dig(agent, "sandbox.docker.dangerouslyAllowExternalBindSources")
        """,
    })
    assert paths == {RELATIVE_PREFIX + "sandbox.docker.dangerouslyAllowExternalBindSources"}
    assert "sandbox.docker.dangerouslyAllowExternalBindSources" not in paths


def test_wrapper_parameter_is_harvested_from_its_call_sites(tmp_path, monkeypatch):
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "sink.py": """
            def _sink(ctx, dotted_path, kind):
                return dig(ctx.config, dotted_path)

            def discover(ctx):
                _sink(ctx, "logging.file", "config_log")
                _sink(ctx, dotted_path="diagnostics.cacheTrace.filePath", kind="cache_trace")
        """,
    })
    assert paths == {"logging.file", "diagnostics.cacheTrace.filePath"}


def test_duplicate_wrapper_name_raises_instead_of_resolving_the_wrong_def(tmp_path, monkeypatch):
    """B-251 regression: resolving the wrapper by BARE NAME picked whichever same-named
    def sorted first. When that def had no matching parameter the harvest came back empty
    and every real path silently vanished — the original vacuity, restored inside its fix.
    `aaa.py` sorts before `sink.py`, so it wins any first-match-by-name lookup."""
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "aaa.py": """
                def _sink(ctx, other, kind):
                    return None
            """,
            "sink.py": """
                def _sink(ctx, dotted_path, kind):
                    return dig(ctx.config, dotted_path)

                def discover(ctx):
                    _sink(ctx, "logging.file", "config_log")
            """,
        })
    message = str(excinfo.value)
    assert "defined more than once" in message
    assert "sink.py:1" in message and "aaa.py:1" in message


def test_wrapper_parameter_default_is_harvested_when_a_call_omits_it(tmp_path, monkeypatch):
    """When a call site omits the parameter, the wrapper's DEFAULT is the string that
    actually reaches dig() — so a fabricated path can hide in a parameter default."""
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "sink.py": """
            def _sink(ctx, dotted_path="logging.file", kind="config_log"):
                return dig(ctx.config, dotted_path)

            def discover(ctx):
                _sink(ctx)
        """,
    })
    assert paths == {"logging.file"}


def test_non_literal_wrapper_parameter_default_raises_naming_the_def(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "sink.py": """
                _COMPUTED = "logging" + ".file"

                def _sink(ctx, dotted_path=_COMPUTED):
                    return dig(ctx.config, dotted_path)

                def discover(ctx):
                    _sink(ctx)
            """,
        })
    assert "sink.py:3" in str(excinfo.value)


def test_path_keyword_argument_form_is_seen(tmp_path, monkeypatch):
    """`dig(d, path, default=None)` — `path` is a legal keyword, and looking only at
    `node.args[1]` let `dig(cfg, path="…")` sail straight past the gate."""
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "a.py": """
            def check(ctx):
                dig(ctx.config, path="gateway.bind")
        """,
    })
    assert paths == {"gateway.bind"}


def test_dig_call_without_any_resolvable_path_argument_raises(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                def check(ctx, args):
                    dig(*args)
            """,
        })
    assert "a.py:2" in str(excinfo.value)


def test_attribute_qualified_dig_call_is_seen(tmp_path, monkeypatch):
    """`from . import collector as _c` then `_c.dig(...)` is the same call; matching only
    `ast.Name` made it a zero-effort bypass of the §4 gate."""
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "a.py": """
            from . import collector as _c

            def check(ctx):
                _c.dig(ctx.config, "gateway.bind")
        """,
    })
    assert paths == {"gateway.bind"}


def test_for_loop_over_module_level_literal_sequence_is_resolved(tmp_path, monkeypatch):
    paths = _resolve_synthetic_source(tmp_path, monkeypatch, {
        "a.py": """
            _FLAGS = (("alpha", "a"), ("beta", "b"))
            _PATHS = ["gateway.bind", "gateway.host"]

            def check(ctx, agent):
                for path in _PATHS:
                    dig(ctx.config, path)
                for flag, _label in _FLAGS:
                    dig(agent, f"sandbox.docker.{flag}")
        """,
    })
    assert paths == {
        "gateway.bind",
        "gateway.host",
        RELATIVE_PREFIX + "sandbox.docker.alpha",
        RELATIVE_PREFIX + "sandbox.docker.beta",
    }


def test_mutated_module_level_sequence_stops_being_resolvable(tmp_path, monkeypatch):
    """A module-level literal list is only a closed set while nothing appends to it. The
    initial assignment is not proof on its own."""
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                _PATHS = ["gateway.bind"]
                _PATHS.append("fabricated.appended.path")

                def check(ctx):
                    for path in _PATHS:
                        dig(ctx.config, path)
            """,
        })
    assert "a.py:6" in str(excinfo.value)


def test_cross_module_mutation_through_an_import_alias_is_caught(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError):
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                _PATHS = ["gateway.bind"]

                def check(ctx):
                    for path in _PATHS:
                        dig(ctx.config, path)
            """,
            "b.py": """
                from .a import _PATHS as _P

                _P.append("fabricated.appended.path")
            """,
        })


def test_two_hop_wrapper_chain_is_refused_rather_than_guessed(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError):
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                def _hop2(ctx, p):
                    return dig(ctx.config, p)

                def _hop1(ctx, p):
                    return _hop2(ctx, p)

                def check(ctx):
                    _hop1(ctx, "gateway.bind")
            """,
        })


def test_splatted_wrapper_call_site_raises(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                def _sink(ctx, dotted_path):
                    return dig(ctx.config, dotted_path)

                def check(ctx, pair):
                    _sink(ctx, *pair)
            """,
        })
    assert "a.py:5" in str(excinfo.value)


def test_wrapper_with_no_call_site_anywhere_raises(tmp_path, monkeypatch):
    """The harvest must never come back empty and be treated as "nothing to ground"."""
    with pytest.raises(RuntimeError) as excinfo:
        _resolve_synthetic_source(tmp_path, monkeypatch, {
            "a.py": """
                def _sink(ctx, dotted_path):
                    return dig(ctx.config, dotted_path)
            """,
        })
    assert "no call site" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# C-249 — the THIRD authority: the installed OpenClaw dist.
#
# The two guards above only ever compare one internal artifact against another, so a shared
# error passes both. This layer resolves each manifest path's PARENT CHAIN against the real
# zod config schema shipped in the installed package. Local-only: it skips cleanly when
# OpenClaw is not installed, exactly as the recon layer skips without the recon doc (B-106),
# so CI stays green on a checkout that has neither.
#
# Read-only, offline, stdlib-only: the dist files are parsed as text, never imported or run.
# --------------------------------------------------------------------------------------

_JS_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
# Characters after which a `/` opens a regex literal rather than meaning division. The zod
# schema is full of `.regex(/^svc:[a-z0-9]{0,61}$/)`, whose braces would otherwise wreck
# every bracket count downstream.
_JS_REGEX_PRECEDERS = frozenset("(,=:[!&|?{};+-*%~^<>\n")
# zod object constructors whose argument carries the shape.
_ZOD_OBJECT_CTORS = ("object", "strictObject", "looseObject")
# Alias/spread expansion is bounded; the schema's real nesting is far shallower than this.
_DIST_MAX_DEPTH = 8

# Manifest paths the CURRENT dist does not contain, each with the disproof that put it here.
#
# This register is the layer's whole point, so treat adding to it as the reviewed act it is.
# An entry is legitimate only when the read is deliberate — Golden Rule #6 asks the audit to
# understand legacy and alternate config shapes, and a field an older OpenClaw accepted is
# absent from today's dist by definition. What makes these six benign, and B-262 not, is
# that every one of them is read BESIDE the real path in the same expression: the real key
# is consulted first and the dead term only ever contributes when it is absent. A phantom
# read ALONE (B-262) or read as positive proof of a safe posture (B-263) is a defect, not a
# register entry.
#
# Verdicts below are from `OpenClawSchema.safeParse()` on the installed 2026.7.1-2 dist, not
# from this file's reader — the reader was cross-checked against it, not trusted over it.
_NOT_IN_CURRENT_SCHEMA = {
    "agents.subagents": (
        "safeParse: unrecognized_keys@agents (the object holds exactly {defaults, list}); "
        "the real path is agents.defaults.subagents. checks/_agents.py:119 tries it as the "
        "first of three branches in _has_subagents(), which also tests the real "
        "agents.defaults.subagents and a multi-entry agents.list — a dead branch, and the "
        "function's answer does not depend on it."
    ),
    "gateway.host": (
        "safeParse: unrecognized_keys@gateway; binding is configured via gateway.bind / "
        "gateway.customBindHost. monitor.py:418 reads it as the last term of a fallback "
        "chain that already ends in a literal default, so it cannot change the outcome."
    ),
    "gateway.token": (
        "safeParse: unrecognized_keys@gateway; the real path is gateway.auth.token. Every "
        "read is `dig(cfg, 'gateway.auth.token') or dig(cfg, 'gateway.token')` "
        "(report.py:298 and :521, checks/_config.py:809 and :1697) — legacy second term."
    ),
    "lastTouchedVersion": (
        "safeParse: unrecognized_keys@<root>; the real path is meta.lastTouchedVersion, and "
        "the root object is .strict(). Every read is "
        "`dig(cfg, 'meta.lastTouchedVersion') or dig(cfg, 'lastTouchedVersion')` "
        "(checks/_lifecycle.py:1035, :1319, :3637) — legacy second term."
    ),
    "plugins.mcp": (
        "safeParse: unrecognized_keys@plugins. checks/_shared.py:859 folds it into an MCP "
        "server map that has already merged the real mcp.servers plus the mcpServers / "
        "mcp_servers legacy spellings, so it only ever adds servers, never hides any."
    ),
    "tools.mcp": (
        "safeParse: unrecognized_keys@tools. Same call site and same reasoning as "
        "plugins.mcp (checks/_shared.py:859) — the two are the one `or` expression."
    ),
    # --- relative namespace ------------------------------------------------------------
    # These are not absences at all: they are read off objects OpenClaw deliberately leaves
    # OPEN, or off files that are not openclaw.json. A schema cannot list keys it has handed
    # to plugins, channels and skill authors, so no dist evidence can exist either way and
    # the unanchored walk necessarily comes back empty.
    RELATIVE_PREFIX + "config.allowPrivateNetwork": (
        "Read off a plugin entry (checks/_config.py:981, over _plugins(cfg)). "
        "PluginEntrySchema.config is `record(string(), unknown())` "
        "(zod-schema-O9ml_nmo.js:788-806) — an open, plugin-defined bag, so its keys are "
        "outside the schema by design."
    ),
    RELATIVE_PREFIX + "config.permissionMode": (
        "Read off an MCP server entry (checks/_mcp.py:1660). MCP server entries carry "
        "server-defined config, not openclaw.json's own key space."
    ),
    RELATIVE_PREFIX + "config.appServer.command": (
        "Read off an MCP server entry (checks/_mcp.py:1717) — same open server-defined "
        "config object as config.permissionMode above."
    ),
    RELATIVE_PREFIX + "network.dangerouslyAllowPrivateNetwork": (
        "Read off a channel's node entries (checks/_config.py:965). ChannelsSchema is "
        "`.passthrough()` (zod-schema.channels-config-ORTHga0n.js:68-78), so per-channel "
        "entries are open and their keys are not enumerable from the schema."
    ),
    RELATIVE_PREFIX + "openclaw.user-invocable": (
        "Read off a SKILL.md frontmatter `metadata` object (checks/_content.py:4344), not "
        "off openclaw.json. Skill frontmatter is a separate file format."
    ),
    RELATIVE_PREFIX + "openclaw.disable-model-invocation": (
        "Read off a SKILL.md frontmatter `metadata` object (checks/_content.py:4349) — same "
        "file format as openclaw.user-invocable above."
    ),
    RELATIVE_PREFIX + "openclaw.install": (
        "Read off a SKILL.md frontmatter `metadata` object (checks/_content.py:6460) for "
        "B103's install-directive provenance check. Skill frontmatter, not openclaw.json."
    ),
    RELATIVE_PREFIX + "openclaw.install.npmSpec": (
        "Read off a package/plugin manifest (checks/_mcp.py:236), not off openclaw.json."
    ),
}


def _blank_js_noncode(text: str) -> str:
    """Overwrite comment, string and regex-literal CONTENT with spaces, keeping every other
    character at its original offset. Bracket counting downstream is only sound once braces
    that live inside `"{"` or `/x{2,3}/` are gone."""
    out = list(text)
    i, n = 0, len(text)
    prev = ""

    def blank(start: int, stop: int) -> None:
        for k in range(max(start, 0), min(stop, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if c in "\"'`":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i, prev = j, c
            continue
        if c == "/" and (prev == "" or prev in _JS_REGEX_PRECEDERS):
            j, in_class, closed = i + 1, False, False
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "\n":
                    break
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    j, closed = j + 1, True
                    break
                j += 1
            if closed:
                blank(i + 1, j - 1)
                i, prev = j, "/"
                continue
        if not c.isspace():
            prev = c
        i += 1
    return "".join(out)


def _match_bracket(code: str, start: int) -> int:
    """Index just past the bracket group that opens at `start`, or -1 if unbalanced."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[code[start]]]
    i = start + 1
    while i < len(code) and stack:
        c = code[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if c != stack[-1]:
                return -1
            stack.pop()
        i += 1
    return i if not stack else -1


def _depth0_brace(expr: str):
    """Index of the first `{` at bracket-depth 0 of `expr`, or None. Distinguishes
    `object({...})` (an inline shape) from `object(ToolExecBaseShape)` (a named one)."""
    depth = 0
    for i, c in enumerate(expr):
        if c == "{" and depth == 0:
            return i
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
    return None


def _object_body_members(body: str):
    """`(key -> value-expression, [spread names])` for members at depth 0 of an object
    literal body. Depth 0 is what makes this a DIRECT-key reader: a key belonging to some
    nested object cannot be mistaken for one of this object's own."""
    keys: dict = {}
    spreads: list = []

    def take(segment: str) -> None:
        spread = re.match(r"\s*\.\.\.\s*(" + _JS_IDENT + r")", segment)
        if spread:
            spreads.append(spread.group(1))
            return
        # String-literal keys arrive here already blanked, hence the `"\s*"` forms.
        member = re.match(r"\s*(" + _JS_IDENT + r"|\"\s*\"|'\s*')\s*:", segment)
        if member:
            keys[member.group(1)] = segment[member.end():]

    depth, start = 0, 0
    for i, c in enumerate(body):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            take(body[start:i])
            start = i + 1
    take(body[start:])
    return keys, spreads


def _dist_direct_keys(expr: str, consts: dict, visited=None, depth: int = 0) -> dict:
    """`key -> [value-expression, ...]` for the keys DIRECTLY on the object(s) `expr`
    denotes, following the four indirections the real schema uses:

      * const aliases          `tools: ToolsSchema`
      * named shapes           `object(ToolExecBaseShape)`
      * spreads                `{ ...CommonToolPolicyFields, web: ... }`
      * union branches         `union([object({a}), object({b})])` -> both a and b

    A key maps to a LIST because unions and spreads can supply the same key from more than
    one branch; the walk then continues down every one of them.

    Known limits, deliberate and in the safe direction — every one of them can only make a
    real path look unresolved (a loud failure a human then grounds), never make a fabricated
    path look real:
      * `visited` expands each const at most once per top-level call, so a const reachable
        through two branches contributes only via the first.
      * Dynamic key spaces (`record(string(), X)`) end the walk: a record's keys are values,
        not schema, so nothing below one can be confirmed.
      * Alias/spread expansion stops at `_DIST_MAX_DEPTH`.
    """
    if depth > _DIST_MAX_DEPTH:
        return {}
    visited = set() if visited is None else visited
    result: dict = {}

    def absorb(body: str) -> None:
        keys, spreads = _object_body_members(body)
        for key, value in keys.items():
            result.setdefault(key, []).append(value)
        for name in spreads:
            if name in consts and name not in visited:
                visited.add(name)
                for key, values in _dist_direct_keys(consts[name], consts, visited, depth + 1).items():
                    result.setdefault(key, []).extend(values)

    ctor_re = re.compile(r"\b(" + "|".join(_ZOD_OBJECT_CTORS) + r")\s*\(")
    ident_re = re.compile(r"\b(" + _JS_IDENT + r")\b")
    i, n = 0, len(expr)
    while i < n:
        ctor = ctor_re.search(expr, i)
        ident = ident_re.search(expr, i)
        brace = expr.find("{", i)
        candidates = [x for x in (
            ctor.start() if ctor else None,
            ident.start() if ident else None,
            brace if brace >= 0 else None,
        ) if x is not None]
        if not candidates:
            break
        first = min(candidates)

        if ctor is not None and ctor.start() == first:
            paren = expr.index("(", ctor.end() - 1)
            close = _match_bracket(expr, paren)
            if close < 0:
                break
            inner = expr[paren + 1:close - 1]
            inner_brace = _depth0_brace(inner)
            if inner_brace is not None:
                body_close = _match_bracket(inner, inner_brace)
                if body_close > 0:
                    absorb(inner[inner_brace + 1:body_close - 1])
            else:
                # `object(ToolExecBaseShape)` — the shape is a named object literal.
                for key, values in _dist_direct_keys(inner, consts, visited, depth + 1).items():
                    result.setdefault(key, []).extend(values)
            i = close
            continue

        if brace >= 0 and brace == first:
            # A bare object literal, e.g. `const CommonToolPolicyFields = { allow: ... }`.
            body_close = _match_bracket(expr, brace)
            if body_close < 0:
                break
            absorb(expr[brace + 1:body_close - 1])
            i = body_close
            continue

        name = ident.group(1)
        if name in consts and name not in visited:
            visited.add(name)
            for key, values in _dist_direct_keys(consts[name], consts, visited, depth + 1).items():
                result.setdefault(key, []).extend(values)
        i = ident.end()
    return result


@lru_cache(maxsize=4)
def _dist_schema_consts_at(dist_dir: str) -> dict:
    """`NAME -> value-expression` for every top-level `const NAME = ...` across the dist's
    zod-schema modules. The schema is spread over several of them (`ToolsSchema` lives in
    `zod-schema.agent-runtime-*.js`, not the main module), so all are read as one namespace.

    Cached on the directory PATH rather than on nothing, so a test that repoints
    `OPENCLAW_DIST` gets a fresh parse instead of the previous directory's schema. Callers
    must treat the result as read-only — it is shared."""
    consts: dict = {}
    for js_file in sorted(Path(dist_dir).glob("zod-schema*.js")):
        code = _blank_js_noncode(js_file.read_text(encoding="utf-8", errors="replace"))
        for match in re.finditer(r"(?m)^(?:const|let|var)\s+(" + _JS_IDENT + r")\s*=\s*", code):
            start, depth, i = match.end(), 0, match.end()
            while i < len(code):
                c = code[i]
                if c in "([{":
                    depth += 1
                elif c in ")]}":
                    depth -= 1
                elif c == ";" and depth == 0:
                    break
                i += 1
            consts.setdefault(match.group(1), code[start:i])
    return consts


def _dist_schema_consts() -> dict:
    return _dist_schema_consts_at(str(OPENCLAW_DIST))


def _resolves_in_dist(path: str, expr: str, consts: dict) -> bool:
    """True when every component of `path` is a direct key of the object its parent denotes,
    walking down from `expr`.

    Walking the FULL CHAIN is the whole point. A leaf-key sweep would have called B-262's
    `logging.cacheTrace.filePath` grounded, because `filePath` is a real key — of
    `diagnostics.cacheTrace`. Here the walk stops at `cacheTrace`, which `logging` (a strict
    object holding exactly {level, file, maxFileBytes, consoleLevel, consoleStyle,
    redactSensitive, redactPatterns}) does not have."""
    frontier = [expr]
    for part in path.split("."):
        nxt: list = []
        for candidate in frontier:
            keys = _dist_direct_keys(candidate, consts)
            if part in keys:
                nxt.extend(keys[part])
        if not nxt:
            return False
        frontier = nxt
    return True


def _require_dist() -> dict:
    """The parsed dist schema, or a clean skip when OpenClaw is not installed."""
    if not OPENCLAW_DIST.is_dir():
        pytest.skip(
            f"OpenClaw dist not present at {OPENCLAW_DIST} — the dist-grounding layer is "
            "local-only (CI checks out only the skill tree, which cannot contain it)"
        )
    consts = _dist_schema_consts()
    # Anti-vacuity. If a future OpenClaw renames the root schema or reshapes these modules,
    # this layer must say so rather than quietly grade every path against an empty schema —
    # a guard that can silently see nothing is worse than no guard (B-251).
    assert DIST_ROOT_SCHEMA in consts, (
        f"'{DIST_ROOT_SCHEMA}' was not found in {OPENCLAW_DIST}/zod-schema*.js "
        f"({len(consts)} top-level schema consts parsed). The installed OpenClaw has "
        "reshaped its config schema; re-ground DIST_ROOT_SCHEMA before trusting this layer."
    )
    return consts


def _manifest_root_paths() -> set:
    return {p for p in _parse_manifest_paths() if not p.startswith(RELATIVE_PREFIX)}


def _synthetic_dist_consts(mapping: dict) -> dict:
    """A synthetic `NAME -> expression` schema, blanked exactly as `_dist_schema_consts()`
    blanks the real dist. Tests below must exercise the SAME composition production uses —
    handing raw source straight to the reader would test a pipeline that does not exist."""
    return {name: _blank_js_noncode(expr) for name, expr in mapping.items()}


def test_dist_root_schema_parses_to_a_plausible_config_shape():
    """Anti-vacuity for the layer itself: prove the reader actually SEES the schema.

    Every test below is a negative check ("nothing failed to resolve"), and negative checks
    pass just as happily against an empty schema as against a correct one. This pins the
    positive side: the root object parsed, it has a realistic number of top-level keys, and
    keys known to be there are there."""
    consts = _require_dist()
    root_keys = _dist_direct_keys(consts[DIST_ROOT_SCHEMA], consts)
    assert len(root_keys) >= 30, (
        f"Only {len(root_keys)} top-level keys parsed out of {DIST_ROOT_SCHEMA} "
        f"({sorted(root_keys)}). The reader has lost track of the schema's shape."
    )
    for expected in ("gateway", "tools", "agents", "logging", "diagnostics", "mcp", "hooks"):
        assert expected in root_keys, f"{expected!r} missing from the parsed root schema"


def test_manifest_root_paths_resolve_against_installed_dist():
    """C-249 third layer: every ROOT-namespace manifest path resolves, component by
    component, in the installed OpenClaw config schema — or is registered as a known
    absence with its disproof.

    This is the layer that consults OpenClaw itself instead of another internal artifact, so
    it is the one that can catch a path the manifest AND the recon are both wrong about."""
    consts = _require_dist()
    root = consts[DIST_ROOT_SCHEMA]

    unresolved = sorted(
        p for p in _manifest_root_paths()
        if p not in _NOT_IN_CURRENT_SCHEMA and not _resolves_in_dist(p, root, consts)
    )

    assert not unresolved, (
        f"{len(unresolved)} manifest path(s) do not exist in the installed OpenClaw config "
        f"schema ({OPENCLAW_DIST}):\n"
        + "\n".join(f"  - {p}" for p in unresolved)
        + "\n\nThe walk failed at the first component that is not a direct key of its "
        "parent. Either the path is fabricated — fix the dig() call, the manifest AND the "
        "recon, since all three can be wrong together (B-262) — or the read is a deliberate "
        "legacy/alternate shape, in which case register it in _NOT_IN_CURRENT_SCHEMA with "
        "its safeParse disproof and the real path it sits beside."
    )


def test_manifest_relative_paths_resolve_somewhere_in_the_dist():
    """The same full-chain walk for `relative:` entries, but UNANCHORED.

    A relative path is read off some nested object the guard cannot identify — that is what
    the namespace means — so there is no parent to anchor to and this can only ask whether
    ANY schema object in the dist has the chain. Read the green as "this shape exists
    somewhere in OpenClaw", never as "this field is real at the object we read it from".
    Pinning the base object stays the manifest-vs-source guard's job."""
    consts = _require_dist()
    unresolved = sorted(
        p for p in _parse_manifest_paths()
        if p.startswith(RELATIVE_PREFIX)
        and p not in _NOT_IN_CURRENT_SCHEMA
        and not any(
            _resolves_in_dist(p[len(RELATIVE_PREFIX):], expr, consts) for expr in consts.values()
        )
    )
    assert not unresolved, (
        f"{len(unresolved)} relative manifest path(s) match no object anywhere in the "
        f"installed schema ({OPENCLAW_DIST}):\n"
        + "\n".join(f"  - {p}" for p in unresolved)
        + "\n\nRegister it in _NOT_IN_CURRENT_SCHEMA if it is deliberately a non-config "
        "shape (skill frontmatter, an MCP server entry, a plugin manifest)."
    )


def test_register_entries_are_still_absent_from_the_dist():
    """The register must SHRINK, never harden into an allowlist.

    A registered path that starts resolving means OpenClaw added the field (or the entry was
    wrong all along). Either way the read is no longer a known absence and the entry has to
    go, or the register would go on excusing a path nothing is checking any more — the
    rubber stamp this layer exists to remove, rebuilt one level up."""
    consts = _require_dist()
    root = consts[DIST_ROOT_SCHEMA]
    resurrected = []
    for path in sorted(_NOT_IN_CURRENT_SCHEMA):
        if path.startswith(RELATIVE_PREFIX):
            bare = path[len(RELATIVE_PREFIX):]
            found = any(_resolves_in_dist(bare, expr, consts) for expr in consts.values())
        else:
            found = _resolves_in_dist(path, root, consts)
        if found:
            resurrected.append(path)
    assert not resurrected, (
        "These paths are registered in _NOT_IN_CURRENT_SCHEMA as absent, but the installed "
        "OpenClaw schema now resolves them:\n"
        + "\n".join(f"  - {p}" for p in resurrected)
        + "\n\nDrop the register entry so the path is grounded normally."
    )


def test_register_has_no_entries_the_manifest_no_longer_carries():
    """A register entry outlives its dig() path silently unless something says otherwise."""
    stale = sorted(set(_NOT_IN_CURRENT_SCHEMA) - _parse_manifest_paths())
    assert not stale, (
        "_NOT_IN_CURRENT_SCHEMA excuses path(s) the manifest no longer lists:\n"
        + "\n".join(f"  - {p}" for p in stale)
        + "\n\nRemove them — the dig() call is gone, so the excuse is dead weight."
    )


def test_register_entries_carry_a_disproof():
    """An undocumented register entry is indistinguishable from a rubber stamp."""
    for path, reason in _NOT_IN_CURRENT_SCHEMA.items():
        assert reason and len(reason) > 30, f"{path} is registered without a real disproof"


def test_dist_layer_rejects_the_b262_phantom():
    """The DoD proof: the layer must go RED on the exact path B-262 shipped.

    `logging.cacheTrace.filePath` passed BOTH internal layers — the manifest listed it and
    the recon vouched for it — while OpenClaw's strict `logging` object rejects it outright.
    A leaf-key sweep would rubber-stamp it too, since `filePath` is a real key of the real
    `diagnostics.cacheTrace`. Only the full parent-chain walk separates them."""
    consts = _require_dist()
    root = consts[DIST_ROOT_SCHEMA]
    assert not _resolves_in_dist("logging.cacheTrace.filePath", root, consts)
    assert not _resolves_in_dist("logging.cacheTrace", root, consts)
    # The real path, and the shared leaf that makes a leaf-only check useless here.
    assert _resolves_in_dist("diagnostics.cacheTrace.filePath", root, consts)
    assert _resolves_in_dist("logging.file", root, consts)


def test_dist_layer_rejects_the_b263_egress_phantoms():
    """Same proof for the four would-be global egress allowlists (B-263). The recon still
    lists `tools.http.allow` in its POSITIVE field inventory, so the recon layer cannot be
    the one to catch these — the dist can."""
    consts = _require_dist()
    root = consts[DIST_ROOT_SCHEMA]
    for phantom in ("network.egress", "gateway.egress", "egress", "tools.http.allow", "tools.http"):
        assert not _resolves_in_dist(phantom, root, consts), phantom
    # The real neighbours must stay resolvable — a guard that rejects everything is no guard.
    for real in ("tools.allow", "gateway.bind", "gateway.port", "mcp.servers"):
        assert _resolves_in_dist(real, root, consts), real


def test_dist_layer_walks_the_whole_chain_not_just_the_leaf(tmp_path):
    """Pin the property that separates this layer from the coarse sweep that missed B-262,
    on a synthetic schema so it holds independently of what OpenClaw ships today."""
    consts = _synthetic_dist_consts({
        "OpenClawSchema": """object({
            logging: object({ level: string(), file: string() }).strict().optional(),
            diagnostics: object({
                cacheTrace: object({ filePath: string() }).strict().optional()
            }).strict().optional()
        }).strict()""",
    })
    root = consts["OpenClawSchema"]
    # The leaf exists — under the OTHER parent. Chain walking is what tells them apart.
    assert _resolves_in_dist("diagnostics.cacheTrace.filePath", root, consts)
    assert not _resolves_in_dist("logging.cacheTrace.filePath", root, consts)
    assert not _resolves_in_dist("logging.cacheTrace", root, consts)


def test_dist_reader_follows_aliases_spreads_named_shapes_and_unions():
    """The four indirections the real schema uses. Without any one of them the layer would
    report a real path as fabricated — a false alarm is as corrosive as a rubber stamp."""
    consts = _synthetic_dist_consts({
        "Shape": "{ allow: array(string()), deny: array(string()) }",
        "ExecSchema": "object(Shape).strict().optional()",
        "ToolsSchema": "object({ ...Shape, exec: ExecSchema }).strict().optional()",
        "Root": "object({ tools: ToolsSchema, either: union([object({ a: string() }), object({ b: string() })]) }).strict()",
    })
    root = consts["Root"]
    assert _resolves_in_dist("tools.allow", root, consts)        # spread
    assert _resolves_in_dist("tools.exec.deny", root, consts)    # alias + named shape
    assert _resolves_in_dist("either.a", root, consts)           # union branch 1
    assert _resolves_in_dist("either.b", root, consts)           # union branch 2
    assert not _resolves_in_dist("tools.exec.allowlist", root, consts)
    assert not _resolves_in_dist("either.c", root, consts)


def test_dist_reader_ignores_braces_inside_strings_and_regexes():
    """`.regex(/^svc:[a-z0-9]{0,61}$/)` and `"}"` appear throughout the real schema. An
    unblanked brace there throws off every bracket count that follows, which would make the
    layer's verdicts arbitrary rather than wrong in one direction."""
    consts = _synthetic_dist_consts({
        "Root": """object({
            name: string().regex(/^svc:[a-z0-9]{0,61}$/).optional(),
            note: literal("}) not a real close ({"),
            gateway: object({ bind: string() }).strict().optional()
        }).strict()""",
    })
    root = consts["Root"]
    assert _resolves_in_dist("gateway.bind", root, consts)
    assert not _resolves_in_dist("gateway.host", root, consts)


def test_dist_layer_skips_cleanly_when_openclaw_is_not_installed(monkeypatch):
    """B-106 constraint: CI checks out only the skill tree, so the dist is absent there and
    this layer must SKIP, exactly as the recon layer does — not error, and not fail."""
    monkeypatch.setattr(
        sys.modules[__name__], "OPENCLAW_DIST", Path("/nonexistent/openclaw/dist")
    )
    with pytest.raises(pytest.skip.Exception) as excinfo:
        _require_dist()
    assert "local-only" in str(excinfo.value)
