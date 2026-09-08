"""B-665 — a recommended VALUE must be one the target schema accepts.

`tests/test_schema_grounding.py` pins the field PATHS every `dig()` reads, in three layers.
Nothing pinned the VALUES the shipped advice tells a user to write, and five remediation
strings recommended `tools.exec.security='ask'` — a value OpenClaw's own enum rejects
(`security` is `deny|allowlist|full`; `ask` is a value of `mode` and of `ask`, never of
`security`). A user who followed that advice got a config OpenClaw refuses, concluded the
tool was wrong, and was left with no approval gate at all. Worse than saying nothing.

Found by doing a live readout of the real fleet config, where B8 fires — so this was advice
a real user was being given, not a dormant string.

## Two layers, the same shape as the path grounding, one level deeper

  * `_VALID` is the SHIPPED table, and `test_every_recommended_value_is_in_the_shipped_table`
    is always on. It is what CI enforces.
  * `test_the_shipped_table_matches_the_installed_dist` is local-only: where an OpenClaw is
    installed, the enums are read out of its zod schema and the shipped table must equal
    them. That is what stops the table from rotting into its own private truth — the same
    reason the dist snapshot exists for paths.

Deliberately scoped to `tools.exec.*`. Widening it to every field is worth doing, but a
guard that tries to parse every value out of every sentence will produce false failures on
prose, and a guard that cries wolf gets deleted. This one covers the family that actually
shipped a wrong value.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from _distgrounding import dist_file

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG = REPO_ROOT / "clawseccheck"

#: `ToolExecBaseShape`, as the installed dist declares it.
_VALID = {
    "mode": {"deny", "allowlist", "ask", "auto", "full"},
    "security": {"deny", "allowlist", "full"},
    "ask": {"off", "on-miss", "always"},
    "host": {"auto", "sandbox", "gateway", "node"},
}

#: `tools.exec.<field>='<value>'` — the direct-assignment form the bug took.
_ASSIGN = re.compile(r"tools\.exec\.(mode|security|ask|host)\s*=\s*['\"]([a-z-]+)['\"]")
#: `tools.exec.<field> to 'x'` / `to 'x' or 'y'` / `to 'x'/'y'` — the prose form. Only the
#: quoted tokens in the clause that follows are read; unquoted prose is never a value.
_PROSE = re.compile(r"tools\.exec\.(mode|security|ask|host)\s+to\s+((?:['\"][a-z-]+['\"][\s/,]*(?:or\s+)?){1,4})")


def _sources():
    return sorted(p for p in PKG.rglob("*.py"))


def _recommendations():
    """Every (file, line, field, value) a shipped string recommends."""
    out = []
    for path in _sources():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in _ASSIGN.finditer(line):
                out.append((path, i, m.group(1), m.group(2)))
            for m in _PROSE.finditer(line):
                for val in re.findall(r"['\"]([a-z-]+)['\"]", m.group(2)):
                    out.append((path, i, m.group(1), val))
    return out


def test_the_scan_finds_something():
    """Anti-vacuity: this file's whole value is the scan, and a regex that matches nothing
    passes every assertion below while checking nothing."""
    found = _recommendations()
    assert len(found) >= 5, found


def test_every_recommended_value_is_in_the_shipped_table():
    """The guard proper. A wrong value here is not a typo — it is advice that produces a
    config OpenClaw refuses to load, offered as the fix for a security finding."""
    bad = [(str(p.relative_to(REPO_ROOT)), i, f, v)
           for p, i, f, v in _recommendations() if v not in _VALID[f]]
    assert not bad, (
        "shipped advice recommends a value the schema rejects:\n"
        + "\n".join(f"  {p}:{i}  tools.exec.{f}={v!r}  not in {sorted(_VALID[f])}"
                    for p, i, f, v in bad)
    )


def test_the_shipped_table_matches_the_installed_dist():
    """The table above is a copy, and a copy rots. Where the real schema is present, it is
    the authority — read out of `ToolExecBaseShape`, not from documentation.

    B-728: the pin used to be the content-hashed filename
    `zod-schema.agent-runtime-C02vY4RT.js` in a `skipif`, and 2026.9.1 rotated it away, so
    this test was skipping on a machine that HAS the dist while blaming a missing install.
    Anchored on `ToolExecBaseShape` now — the thing it actually reads."""
    src = dist_file("zod-schema.agent-runtime-*.js", symbol="ToolExecBaseShape",
                    contains="const ToolExecBaseShape = {").read_text(
        encoding="utf-8", errors="replace")
    i = src.index("const ToolExecBaseShape = {")
    window = src[i:i + 900]
    for field, shipped in _VALID.items():
        m = re.search(field + r"\s*:\s*_enum\(\[([^\]]+)\]\)", window)
        assert m, f"the dist no longer declares an enum for tools.exec.{field}"
        real = set(re.findall(r'"([a-z-]+)"', m.group(1)))
        assert real == shipped, (
            f"tools.exec.{field}: shipped table {sorted(shipped)} != dist {sorted(real)}"
        )
