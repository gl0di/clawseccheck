"""B-485 — `--vet` answers INSTALL about a package it could not read, and the obvious
fix is worse. Both halves are pinned here so neither can be lost.

## The gap (real, open)

A skill whose only bundled script is prose in a `.py` file renders:

    ✅  RISK DOSSIER — skill 'probe'    INSTALL
      Danger  ❔ UNKNOWN  could not analyze probe: scripts/helper.py — parse
                         error(s); file(s) not scanned by the AST/taint layer

A green check and an imperative, two lines above the tool's own statement that the axis
whose job is "is this dangerous" never got to look. `docs/USAGE.md` documents
`--vet … || fail` as an install gate, so the gate passes on an unscanned package.

Where the signal is lost: `_run_content_ring`'s bare `except Exception: continue`
swallows `skillast.ScriptProseCoverageIncomplete` with no `note_limit()`, no finding and
no `skipped` entry — while the two budget handlers ten lines above it do all three. So
`ctx.limit_hits` stays empty and `dossier._danger_coverage_gap`'s leg (1) never fires.
`verdict_for` and `_grade_profile` are both already correct and need no change: a
coverage gap that reaches them DOES roll up to WARN → CAUTION.

## Why it is not fixed (C-135, 2026-08-08)

The five-line fix was built, verified against the reported case, and **retracted**.

Whether a bundled file parses depends on the interpreter *we* run under. Measured on an
ordinary skill whose only script uses a `match` statement — Python 3.10+, standard since
2021:

| interpreter | verdict | exit code |
| --- | --- | --- |
| 3.12 | INSTALL | 0 |
| 3.9 (the CI floor) | **CAUTION** | **1** |

Same bytes, opposite verdict, and `rc=1` trips the documented install gate. That is a
false non-clean verdict on a benign package (Golden Rule #5), and it would hit a large
share of modern skills.

No sound narrowing exists with the current machinery: `_danger_coverage_gap` matches on
`coverage_gap_finding`'s own "coverage is incomplete" wording, so emitting the disclosure
IS what moves the verdict — there is no disclose-without-capping variant. And separating
"unparseable because hostile" from "unparseable because newer than us" is not decidable
from 3.9's view of the file.

Closing this properly means making the scanner version-tolerant, not patching the handler.

## What this module pins

1. Today's real behaviour, so the gap stays visible and nobody believes it is fixed.
2. The false positive that blocks the obvious fix, so the next person to reach for it
   finds the measurement instead of rediscovering it.
3. The invariant any real fix must preserve — B-092's distinction between "could not
   scan" and "nothing to scan".

Stdlib-only, offline, writes only under pytest's `tmp_path`.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.dossier import build_profile

_FRONTMATTER = (
    "---\nname: {name}\ndescription: A small benign skill for testing.\n---\n\n"
    "# {name}\n\nDoes one ordinary thing. Ask before reading other files.\n"
)

# Python 3.10+ structural pattern matching. Ordinary, non-hostile, and unparseable by
# `ast.parse` on 3.9 — which is the whole point.
_MATCH_STATEMENT_SOURCE = (
    "def describe(value):\n"
    "    match value:\n"
    '        case {"kind": k}:\n'
    '            return f"mapping:{k}"\n'
    "        case _:\n"
    '            return "other"\n'
)


def _skill(tmp_path: Path, name: str, files: dict) -> Path:
    sk = tmp_path / name
    (sk / "scripts").mkdir(parents=True)
    (sk / "SKILL.md").write_text(_FRONTMATTER.format(name=name), encoding="utf-8")
    for rel, body in files.items():
        (sk / rel).write_text(body, encoding="utf-8")
    return sk


def _profile(sk: Path):
    return build_profile(vet_skill(str(sk)), str(sk), "skill")


# ── 1. the gap, pinned as it really is ───────────────────────────────────────

def test_unreadable_bundled_file_still_reads_install(tmp_path):
    """B-485, OPEN. The Danger axis says it could not look; the headline says INSTALL.

    When B-485 is genuinely fixed, THIS is the assertion to flip — to
    `overall_status == WARN` and `verdict == "CAUTION"`. Do not flip it by routing the
    bare `except` into `note_limit()`; see this module's docstring and the retraction
    note in `checks/_vet.py` for why that was tried and reverted.
    """
    sk = _skill(tmp_path, "probe", {
        "scripts/helper.py": "This file is English prose, not Python.\nIt will not parse.\n",
    })
    p = _profile(sk)

    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == UNKNOWN
    assert "not scanned" in danger.reason or "parse error" in danger.reason

    # The real, current value — not the aspirational one.
    assert p.overall_status == PASS
    assert p.verdict == "INSTALL"


def test_a_readable_bundled_file_is_genuinely_clean(tmp_path):
    """Control: byte-identical skill whose helper parses. Its INSTALL is earned."""
    sk = _skill(tmp_path, "ctrl", {
        "scripts/helper.py": 'def hello():\n    return "world"\n',
    })
    p = _profile(sk)
    assert next(a for a in p.axes if a.axis == "danger").status == PASS
    assert p.verdict == "INSTALL"


# ── 2. the false positive that blocks the obvious fix ────────────────────────

def test_parseability_depends_on_the_interpreter_not_on_the_skill():
    """The measurement that retracted the fix, reduced to something CI can check.

    A `match` statement is ordinary modern Python. `ast.parse` accepts it on 3.10+ and
    rejects it on 3.9 — so any fix that turns "this file did not parse" into a non-clean
    verdict makes the answer depend on which interpreter the SCANNER runs under. On the
    3.9 CI floor that produced CAUTION and `rc=1` on a benign skill, tripping the
    documented `--vet … || fail` install gate.

    This test states the fact rather than the consequence, so it holds on both floors:
    on 3.9 the parse fails, on 3.10+ it succeeds, and either way the source is benign.
    """
    import sys

    if sys.version_info >= (3, 10):
        ast.parse(_MATCH_STATEMENT_SOURCE)     # fine here …
    else:
        with pytest.raises(SyntaxError):        # … and a "coverage gap" here
            ast.parse(_MATCH_STATEMENT_SOURCE)


def test_a_modern_syntax_skill_is_not_flagged_today(tmp_path):
    """Whatever a fix does, it must not make this skill non-clean on an old interpreter.

    Green on 3.12 because the file parses; green on 3.9 because the gap is currently
    swallowed. A fix that closes the gap without addressing version skew turns this red
    on the CI floor only — which is exactly the failure mode that must not ship.
    """
    sk = _skill(tmp_path, "modern", {"scripts/helper.py": _MATCH_STATEMENT_SOURCE})
    assert _profile(sk).verdict == "INSTALL"


# ── 3. the invariant any real fix must preserve ──────────────────────────────

def test_no_code_at_all_is_not_a_coverage_gap(tmp_path):
    """B-092's distinction: "nothing to scan" is not "could not scan".

    A documentation-only skill must keep its clean verdict under any future fix. If this
    ever fails alongside the first test flipping, the fix has collapsed the two UNKNOWN
    flavours into one and is punishing users for shipping prose.
    """
    sk = tmp_path / "docsonly"
    sk.mkdir()
    (sk / "SKILL.md").write_text(_FRONTMATTER.format(name="docsonly"), encoding="utf-8")
    (sk / "README.md").write_text("# Notes\n\nJust prose. No code at all.\n", encoding="utf-8")
    assert _profile(sk).verdict == "INSTALL"


def test_a_raising_ring_check_still_cannot_break_vet(tmp_path, monkeypatch):
    """The bare `except` exists for this, and any fix must keep it true."""
    from clawseccheck.checks import _vet as vet_mod

    def _explode(ctx):
        raise RuntimeError("ring check blew up")

    ring = list(vet_mod.SKILL_CONTENT_RING)
    assert ring, "the content ring is empty; this test would be vacuous"
    monkeypatch.setattr(vet_mod, "SKILL_CONTENT_RING", [_explode] + ring[1:])

    sk = _skill(tmp_path, "boom", {"scripts/helper.py": "x = 1\n"})
    p = _profile(sk)          # must not raise
    assert p.verdict in {"INSTALL", "CAUTION", "DO-NOT-INSTALL"}
