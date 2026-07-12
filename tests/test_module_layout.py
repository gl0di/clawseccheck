"""I-022 R1 — module-layout / anti-bloat guard.

Mechanized structure enforcement so the package can't silently re-bloat and the
public import surface of `clawseccheck.checks` can't silently shrink. Stdlib-only,
offline, deterministic — same spirit as tests/test_public_boundary.py.

Three guards:
  (a) per-file line budget (<= _MAX_LINES) with an explicit, reasoned _EXEMPT dict —
      blocks a NEW file from growing into another 14k-line monolith;
  (b) export-contract: tests/checks_public_api.txt MUST be a subset of
      dir(clawseccheck.checks), so every name tests/siblings import stays importable
      no matter how the engine is internally split (see CLAUDE.md §3.1-a);
  (c) placement lint: a checks/_shared.py leaf (created by the I-022 R2 split) may
      hold only shared helpers/constants — no check_*/vet_* entry point.

The line budget deliberately records the over-budget checks/ topic modules
(_content / _vet / _mcp / _config / _lifecycle) in _EXEMPT as *tracked debt*, not a
free pass — each carries a reason and the companion test fails if an exemption goes
stale, so the guard tightens on its own as any finer split lands.
"""
from __future__ import annotations

import ast
from pathlib import Path

import clawseccheck.checks as checks_mod

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG = REPO_ROOT / "clawseccheck"
MANIFEST = REPO_ROOT / "tests" / "checks_public_api.txt"

_MAX_LINES = 1200

# Files intentionally over budget. Every entry MUST carry a reason. An entry here is
# tracked debt, not a free pass — trim it as the I-022 modularization lands (the
# companion staleness test fails if an exemption no longer applies).
_EXEMPT = {
    "checks/_config.py": "~1,300 lines — the config-hardening topic (15 checks + helpers); "
                         "topic-faithful and over budget by design. A finer split is a "
                         "later cycle (I-022 secondary target).",
    "checks/_lifecycle.py": "~1,340 lines — the approval / update-pinning / self-modification "
                            "/ supply-chain topic (17 checks + helpers); topic-faithful and "
                            "over budget by design. A finer split is a later cycle.",
    "checks/_content.py": "~4,800 lines — the content-security ring (30 skill-malware / "
                          "prompt-injection checks + the fence/decode/typosquat machinery). "
                          "Kept as ONE unit on purpose (SKILL_CONTENT_RING is the single "
                          "source consumed by both the full audit and --vet); do not split.",
    "checks/_vet.py": "~2,000 lines — the --vet entry engine (vet_skill/vet_source/"
                      "detect_vet_type/check_installed_skills + SKILL_CONTENT_RING + the "
                      "shared effect/sink analysis); consumes the content ring. Over budget "
                      "by design; a finer split is a later cycle.",
    "checks/_mcp.py": "~1,400 lines — the MCP / plugin checks + vet_mcp / vet_plugin (40 "
                      "symbols); topic-faithful and over budget by design. A finer split is "
                      "a later cycle.",
    "skillast.py": "2,139 lines — the python/shell/js parser families; its own split is "
                   "deferred to a later cycle (I-022 secondary target).",
    "report.py": "1,720 lines — the output renderers; its own split is deferred to a "
                 "later cycle (I-022 secondary target).",
    "catalog.py": "1,585 lines — the CheckMeta CATALOG (one entry per check) + BY_ID; "
                  "reference data / a manifest, not branching logic.",
    "collector.py": "~1,240 lines — the read-only collection layer (config / bootstrap / skill "
                    "collection + the Context dataclass + byte-format classify_bytes); a "
                    "cohesive foundational module. Crossed the budget with F-116 (.ipynb->AST "
                    "+ .pyc/.wasm sniffing); a finer split (byte-format sniffing -> a leaf "
                    "module) is a later cycle.",
    "cli.py": "~1,200 lines — the Layer-4 shell (all flags + the dispatch cascade); every new "
              "primary mode adds a few lines here by design. Crossed the budget with F-113 "
              "(--judge-packet); a finer split (e.g. flag registration -> its own module) is "
              "a later cycle.",
}


def _line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def _package_py_files() -> list[Path]:
    """Top-level package modules + the checks/ subpackage (empty until I-022 R2)."""
    files = sorted(PKG.glob("*.py"))
    files += sorted((PKG / "checks").glob("*.py"))
    return files


def _exempt_key(path: Path) -> str | None:
    """Return the _EXEMPT key matching this file (basename or pkg-relative), or None."""
    rel = str(path.relative_to(PKG))
    if path.name in _EXEMPT:
        return path.name
    if rel in _EXEMPT:
        return rel
    return None


def test_no_module_exceeds_line_budget() -> None:
    offenders = []
    for f in _package_py_files():
        n = _line_count(f)
        if n <= _MAX_LINES or _exempt_key(f) is not None:
            continue
        offenders.append(f"{f.relative_to(PKG)}: {n} lines (> {_MAX_LINES})")
    assert not offenders, (
        f"Module(s) over the {_MAX_LINES}-line budget with no exemption:\n"
        + "\n".join(offenders)
        + "\n\nSplit the file into a topic module (see CLAUDE.md §3.1 'Where new code "
        "goes'); or, if the size is genuinely justified, add it to _EXEMPT here WITH a "
        "reason AND update the §3 module map in the same change (rule §3.1-b)."
    )


def test_exempt_entries_are_not_stale() -> None:
    """Keep _EXEMPT honest: an entry that vanished or dropped under budget is stale —
    remove it so the guard tightens automatically (that is the whole point)."""
    present = {}
    for f in _package_py_files():
        key = _exempt_key(f)
        if key is not None:
            present.setdefault(key, []).append(f)
    stale = []
    for key in _EXEMPT:
        matches = present.get(key)
        if not matches:
            stale.append(f"{key}: exempt but no such file exists — remove the exemption")
            continue
        if all(_line_count(f) <= _MAX_LINES for f in matches):
            n = max(_line_count(f) for f in matches)
            stale.append(f"{key}: now {n} lines (<= {_MAX_LINES}) — drop the exemption")
    assert not stale, "Stale _EXEMPT entries (tighten the guard):\n" + "\n".join(stale)


def _load_manifest() -> list[str]:
    names = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def test_public_api_manifest_is_subset_of_live_surface() -> None:
    """The export contract: every name tests/siblings import from clawseccheck.checks
    stays importable. One-directional (subset) so adding new public names never fails
    — only losing one that callers still use does."""
    manifest = _load_manifest()
    assert manifest, "checks_public_api.txt parsed empty — the export-contract guard is inert."
    assert manifest == sorted(set(manifest)), (
        "checks_public_api.txt must be sorted and duplicate-free."
    )
    live = set(dir(checks_mod))
    missing = [n for n in manifest if n not in live]
    assert not missing, (
        "Names in the export contract are no longer importable from clawseccheck.checks:\n"
        + "\n".join(missing)
        + "\n\nA rename/move dropped a re-export and shrank the public surface. The "
        "aggregator must keep every manifest name importable (CLAUDE.md §3.1-a). If a "
        "name was intentionally removed and no caller uses it, delete it from the "
        "manifest in the same change."
    )


def test_shared_leaf_holds_no_check_definitions() -> None:
    """Placement lint (active once I-022 R2 creates checks/_shared.py): the shared leaf
    is helpers + constants only; check_*/vet_* entry points belong in a topic module."""
    shared = PKG / "checks" / "_shared.py"
    if not shared.exists():
        return  # pre-R2: nothing to lint yet
    tree = ast.parse(shared.read_text(encoding="utf-8"))
    misplaced = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (node.name.startswith("check_") or node.name.startswith("vet_"))
    ]
    assert not misplaced, (
        "checks/_shared.py must hold only shared helpers/constants, but it defines "
        "check/vet entry points: " + ", ".join(misplaced)
        + " — move them to the owning topic module (CLAUDE.md §3.1)."
    )
