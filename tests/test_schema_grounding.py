"""Schema grounding coherence guard (§4, C-010).

Automates the verification that every configuration path queried in the codebase
via the `dig()` helper is documented/grounded in `docs/research/openclaw-schema-recon.md`.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
RECON_FILE = ROOT / "docs" / "research" / "openclaw-schema-recon.md"
SOURCE_DIR = ROOT / "skill" / "clawseccheck"

# Allowlist for configuration paths that are allowed even if not parsed from markdown
ALLOWLISTED_PATHS: set[str] = set()


def _parse_recon_paths() -> set[str]:
    """Parse all backticked and dotted paths from the markdown file."""
    if not RECON_FILE.exists():
        pytest.skip(f"Schema grounding recon file not found at: {RECON_FILE} (running in CI)")


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
                    # Handle older python versions Str
                    elif isinstance(arg, ast.Str):  # pragma: no cover
                        paths.add(arg.s)
            self.generic_visit(node)

    for py_file in SOURCE_DIR.rglob("*.py"):
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
                DigVisitor().visit(tree)
            except SyntaxError as e:  # pragma: no cover
                raise SyntaxError(f"Failed to parse AST of {py_file}: {e}") from e

    return paths


def test_schema_grounding():
    """Verify that every config path used in dig() is grounded in the recon doc."""
    recon_paths = _parse_recon_paths()
    source_paths = _parse_source_dig_paths()

    missing = []

    for path in sorted(source_paths):
        if path in ALLOWLISTED_PATHS:
            continue

        matched = False
        if path in recon_paths:
            matched = True
        else:
            # Check wildcard/placeholder matches
            for recon_p in recon_paths:
                # 1. Match paths ending in * (wildcard)
                if recon_p.endswith("*"):
                    prefix = recon_p[:-1]
                    escaped_prefix = re.escape(prefix)
                    # Replace list bracket wildcards like []
                    reg_pattern = "^" + escaped_prefix.replace(r"\[\]", r"\[\d*\]") + ".*$"
                    if re.match(reg_pattern, path):
                        matched = True
                        break

                # 2. Match placeholder tags like <name>, <p>, <provider>
                if "<" in recon_p and ">" in recon_p:
                    escaped_recon_p = re.escape(recon_p)
                    # Replace \<...\> with regex matching any segment without dots
                    reg_pattern = "^" + re.sub(r"\\<[^\\>]+\\>", "[^.]+", escaped_recon_p) + "$"
                    if re.match(reg_pattern, path):
                        matched = True
                        break

        if not matched:
            missing.append(path)

    assert not missing, (
        f"Found {len(missing)} ungrounded config path(s) used in code:\n"
        + "\n".join(f"  - {p}" for p in missing)
        + f"\n\nEvery config path queried in checks must be documented in:\n  {RECON_FILE}"
    )
