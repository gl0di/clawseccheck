"""B-100: vet_skill was ~66s on a long alternating-whitespace file (" \\n" * 40000).

Root cause: three regexes used a leading `^\\s*` / `(?:^|\\n)\\s*` under re.M, so the
whitespace class gobbled a multi-line run across `\\n` at every line start, then
backtracked when the anchor keyword didn't follow — O(lines) x O(n) = quadratic.
Fix: the leading indent is horizontal-only (`[ \\t]*`) in all three; a keyword line /
role marker sits at the start of ONE line, so no real match is clipped.

These tests pin the perf ceiling (generous vs the measured ~0.18s) and that each
fixed regex still matches its real targets and still rejects benign look-alikes.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from clawseccheck.checks import (
    _SKILL_HIGH,
    _SKILL_TOOLS_LINE_RE,
    _B74_ROLE_BLOCK_RE,
    _skill_declared_tools,
    normalize_for_scan,
    vet_skill,
)


def _mk_skill(td: str, big: str) -> str:
    d = Path(td) / "s"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
    (d / "big.md").write_text(big, encoding="utf-8")
    return str(d)


def test_vet_skill_is_fast_on_whitespace_pathological_file():
    with tempfile.TemporaryDirectory() as td:
        target = _mk_skill(td, " \n" * 40_000)  # the task's exact repro (was ~66s)
        t = time.perf_counter()
        vet_skill(target)
        assert time.perf_counter() - t < 5.0


def test_b74_role_block_still_matches_and_rejects():
    def hit(s):
        return _B74_ROLE_BLOCK_RE.search(normalize_for_scan(s)) is not None
    assert hit("SYSTEM: do the thing")
    assert hit("  \n  SYSTEM: indented")
    assert hit("\tSYSTEM: tabbed")
    assert hit("<system>")
    assert hit("[ASSISTANT] x")
    assert not hit("the ecosystem: is fine")
    assert not hit("plain prose, no markers")


def test_excessive_agency_still_matches_wildcard_grants():
    rx = next(rx for label, rx in _SKILL_HIGH if label.startswith("excessive agency"))

    def hit(s):
        return rx.search(normalize_for_scan(s)) is not None
    assert hit('tools: ["*"]')
    assert hit("  tools: [*]")
    assert hit("permissions: all")
    assert hit('  permissions: "all"')
    assert hit("auto-approve all")
    assert not hit('tools: ["read"]')
    assert not hit("the tools: are fine")


def test_skill_declared_tools_still_extracts():
    assert _skill_declared_tools("---\nallowed-tools: [read, write, exec]\n---") == [
        "read", "write", "exec"]
    assert _skill_declared_tools("  tools: bash, curl") == ["bash", "curl"]
    assert _skill_declared_tools("name: x\ndescription: y") == []


def test_fixed_regexes_are_linear_on_whitespace():
    blob = " \n" * 20_000
    for rx in (_B74_ROLE_BLOCK_RE, _SKILL_TOOLS_LINE_RE):
        t = time.perf_counter()
        rx.search(blob)
        assert time.perf_counter() - t < 0.5
