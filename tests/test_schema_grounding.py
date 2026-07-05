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
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
RECON_FILE = ROOT / "docs" / "research" / "openclaw-schema-recon.md"
SOURCE_DIR = ROOT / "skill" / "clawseccheck"
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


def _parse_source_dig_paths() -> set[str]:
    """Parse all string literals passed to `dig(...)` in python source files."""
    paths = set()

    class DigVisitor(ast.NodeVisitor):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "dig":
                if len(node.args) >= 2:
                    arg = node.args[1]
                    # Handle python 3.8+ Constant
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        paths.add(arg.value)
            self.generic_visit(node)

    for py_file in SOURCE_DIR.rglob("*.py"):
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
                DigVisitor().visit(tree)
            except SyntaxError as e:  # pragma: no cover
                raise SyntaxError(f"Failed to parse AST of {py_file}: {e}") from e

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
