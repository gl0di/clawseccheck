"""C-688 drift guard: every path OpenClaw's own schema marks sensitive is either covered by
our detection or listed in an explicit, reasoned exclusion.

The vendor list is DERIVED, not transcribed: the installed dist's `walkConfigSchema` is
executed in node over the root `OpenClawSchema` and a path is kept when the vendor's own
`sensitive` registry (`zod-schema.sensitive-*.mjs`) holds the visited schema node - the same
walk `mapSensitivePaths` does. Measured on openclaw 2026.10.2: 91 paths, 68 of whose leaf name
`SECRET_KEY_RE` does not match. This is the row-per-vendor-change rule of the upgrade protocol
for this surface: it names `storage.locations.*.encryption.passphrase` the day the build that
adds it is installed.

Local-only: skips when the installed dist or node is absent (CI). Bundles are located by the
symbol they DECLARE (tests/_distgrounding.py), never by their hashed filename; the minified
export names are resolved from each bundle's own `export { x as y }` statement.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from _distgrounding import dist_declaring, require_dist

from clawseccheck.checks import (
    _VENDOR_NOT_SECRET_PATHS,
    _vendor_slot_covers,
)

_HARNESS = r"""
import { readFileSync } from "node:fs";
const cfg = JSON.parse(readFileSync(0, "utf8"));
const zod = await import("file://" + cfg.zod);
const reg = await import("file://" + cfg.sensitive);
const out = new Set();
zod[cfg.walk](zod[cfg.root], "", (node, p) => { if (reg[cfg.registry].has(node)) out.add(p); });
console.log(JSON.stringify([...out].sort()));
"""


def _alias(path: Path, name: str) -> str:
    """The name `name` is exported under (`export { name as a }` / `export { name }`)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"\bexport\s*\{[^}]*?\b" + re.escape(name) + r"(?:\s+as\s+(\w+))?\s*[,}]", text, re.S)
    assert m, f"{path.name} does not export {name!r} - re-locate the vendor walker (C-688)"
    return m.group(1) or name


def _vendor_sensitive_paths() -> "list[str]":
    require_dist()
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - the drift guard executes the vendor")
    zod = dist_declaring("function walkConfigSchema(", symbol="walkConfigSchema")
    sens = dist_declaring("const sensitive = ", symbol="sensitive registry")
    root = dist_declaring("const OpenClawSchema = ", symbol="OpenClawSchema")
    assert root == zod, "OpenClawSchema and walkConfigSchema no longer share a bundle - re-ground"
    payload = json.dumps({
        "zod": str(zod), "sensitive": str(sens),
        "walk": _alias(zod, "walkConfigSchema"), "root": _alias(zod, "OpenClawSchema"),
        "registry": _alias(sens, "sensitive"),
    })
    with tempfile.TemporaryDirectory(prefix="c688-drift-") as tmp:
        scratch = Path(tmp)
        (scratch / "home").mkdir()
        harness = scratch / "harness.mjs"
        harness.write_text(_HARNESS, encoding="utf-8")
        env = {"HOME": str(scratch / "home"), "PATH": os.environ.get("PATH", ""), "LANG": "C"}
        proc = subprocess.run(
            [node, str(harness)], input=payload, capture_output=True, text=True,
            env=env, cwd=str(scratch), timeout=120,
        )
    assert proc.returncode == 0, f"node exited {proc.returncode}: {proc.stderr.strip()[-600:]}"
    return json.loads(proc.stdout)


def _concrete(vendor_path: str) -> str:
    """`a.*.b[]` -> `a.x.b[0]`: a path a real config could hold."""
    return vendor_path.replace(".*", ".x").replace("[]", "[0]")


def test_every_vendor_sensitive_path_is_covered_or_excluded():
    paths = _vendor_sensitive_paths()
    # anti-vacuity: the walk saw the whole schema, and its controls are right
    assert len(paths) >= 80, f"only {len(paths)} sensitive paths - the walk saw too little"
    assert "gateway.auth.password" in paths and "hooks.token" in paths
    assert "gateway.port" not in paths
    gaps = [p for p in paths if _vendor_slot_covers(_concrete(p)) is None]
    assert not gaps, (
        f"{len(gaps)} vendor-sensitive path(s) are neither covered nor excluded: {gaps}. "
        "Add the leaf to checks/_shared.py's C-688 tables (name / path rule) or to "
        "_VENDOR_NOT_SECRET_PATHS with the reason it is not a secret."
    )


def test_every_exclusion_still_matches_a_vendor_path_and_has_a_reason():
    paths = [_concrete(p) for p in _vendor_sensitive_paths()]
    for rx, reason in _VENDOR_NOT_SECRET_PATHS:
        assert reason.strip(), f"exclusion {rx.pattern!r} has no reason"
        assert any(rx.search(re.sub(r"\[\d+\]", "[]", p)) for p in paths), (
            f"exclusion {rx.pattern!r} matches no vendor-sensitive path any more - stale"
        )


def test_the_unambiguous_names_are_covered_by_name_and_the_rest_by_path():
    paths = _vendor_sensitive_paths()
    assert _vendor_slot_covers(_concrete("storage.locations.*.encryption.passphrase")) == "name"
    assert "storage.locations.*.encryption.passphrase" in paths
    assert _vendor_slot_covers(_concrete("models.providers.*.request.tls.key")) == "path"
    assert _vendor_slot_covers(_concrete("models.providers.*.request.tls.ca")) == "excluded"


# ---------------------------------------------------------------- always on: machinery

def test_a_path_nobody_covers_is_reported_as_a_gap():
    """Positive control: the comparison can fail (a control that cannot fail controls nothing)."""
    assert _vendor_slot_covers("some.new.vendor.field") is None
    assert _vendor_slot_covers("some.unrelated.key") is None
    assert _vendor_slot_covers("storage.locations.x.encryption.passphrase") == "name"
    assert _vendor_slot_covers("hooks.mappings[0].sessionKey") == "excluded"


def test_the_concretiser_matches_the_walker_notation():
    assert _concrete("tools.media.models[].request.auth.value") == "tools.media.models[0].request.auth.value"
    assert _concrete("mcp.servers.*.env.*") == "mcp.servers.x.env.x"
