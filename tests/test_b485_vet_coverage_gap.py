"""B-485 — `--vet` answered INSTALL about a package it could not read. CLOSED 2026-08-14.

Route coverage for the fix lives in `tests/test_b485_danger_coverage_routes.py`. THIS
module keeps the history: what the gap was, what the first attempt at fixing it got
wrong, and the version-skew measurement that must keep being re-checked.

## The gap (fixed)

A skill whose only bundled script is prose in a `.py` file used to render:

    ✅  RISK DOSSIER — skill 'probe'    INSTALL
      Danger  ❔ UNKNOWN  could not analyze probe: scripts/helper.py — parse
                         error(s); file(s) not scanned by the AST/taint layer

A green check and an imperative, two lines above the tool's own statement that the axis
whose job is "is this dangerous" never got to look. `docs/USAGE.md` documents
`--vet … || fail` as an install gate, so the gate passes on an unscanned package.

## The first attempt, and why it was retracted (C-135, 2026-08-08)

The original diagnosis blamed `_run_content_ring`'s bare `except Exception: continue`,
which swallows `skillast.ScriptProseCoverageIncomplete` with no `note_limit()`, no
finding and no `skipped` entry — so `ctx.limit_hits` stayed empty. The five-line fix
routed that handler into `note_limit()`, and was retracted on this measurement:

whether a bundled file parses depends on the interpreter *we* run under, so on an
ordinary skill whose only script uses a `match` statement (Python 3.10+, standard since
2021) the verdict became 3.12 → INSTALL / rc=0 and 3.9 → CAUTION / rc=1. Same bytes,
opposite verdict, tripping the documented `--vet … || fail` install gate.

## How it was actually closed (2026-08-14)

Not through the handler. `check_installed_skills`' parse-error branch was ALREADY
emitting an UNKNOWN with `engine_degraded=True`; `dossier._danger_coverage_gap` was
simply not reading that flag, keying instead on `ctx.limit_hits` and on the English
substring "coverage is incomplete", which that branch does not use. The predicate now
keys on the structural flag first.

That does not make the retraction wrong — it makes its premise measurable. Re-measured
before landing, with the flip set defined as "targets this predicate floors that the old
one did not":

| corpus | py3.12 | py3.9 (CI floor) |
| --- | --- | --- |
| real installed skills (16) | 0 flips | 0 flips |
| `fixtures/` (1,119 targets) | 1 (`unknown_b347_deaddrop_unparseable`) | same 1 |

Two things the retraction did not have. First, the version-dependent *finding* already
shipped: on 3.9 the `match`-statement skill already produced `UNKNOWN /
engine_degraded=True / "could not analyze … parse error(s)"` and already printed it on
the Danger axis. The predicate did not introduce the divergence; it stopped the profile
from laundering it into a green headline. Second, "a large share of modern skills" was
never measured — the real-fleet rate is 0, on both interpreters.

So the skew is real and is now visible in the verdict on 3.9, and the residual close is
still the one the retraction named: make the scanner version-tolerant, so a file newer
than the interpreter is not reported as unreadable at all. Until then the honest reading
of a 3.9 CAUTION is that the scanner genuinely did not read the file.

## What this module pins

1. The version-skew fact and its bounded consequence, so the next person reaching for a
   version-tolerant parser finds the measurement instead of rediscovering it.
2. The invariant the fix had to preserve — B-092's distinction between "could not scan"
   and "nothing to scan".
3. That a raising ring check still cannot break `--vet` (R1, an unclosed residual).

Stdlib-only, offline, writes only under pytest's `tmp_path`.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
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

def test_unreadable_bundled_file_no_longer_reads_install(tmp_path):
    """B-485, CLOSED. The Danger axis says it could not look, and so does the headline.

    This is the assertion the open version of this test named as the one to flip. It was
    flipped by keying `dossier._danger_coverage_gap` on `Finding.engine_degraded`, NOT by
    routing the bare `except` into `note_limit()` — see this module's docstring.
    """
    sk = _skill(tmp_path, "probe", {
        "scripts/helper.py": "This file is English prose, not Python.\nIt will not parse.\n",
    })
    p = _profile(sk)

    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == UNKNOWN
    assert "not scanned" in danger.reason or "parse error" in danger.reason

    assert p.overall_status == WARN
    assert p.verdict == "CAUTION"


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


def test_version_skew_on_a_modern_syntax_skill_is_bounded(tmp_path):
    """The consequence of the skew, stated as it really is on each interpreter.

    On 3.10+ the file parses and the skill earns its clean verdict. On the 3.9 CI floor
    it does not parse, the AST/taint layer genuinely never read it, and the verdict is
    the coverage-gap CAUTION — which is now the honest answer rather than a laundered
    INSTALL, but is still an answer about OUR interpreter and not about the skill.

    The invariant that must hold on BOTH floors, and the reason this shipped despite the
    skew: a benign modern-syntax skill is never called dangerous. The worst version skew
    can do is withhold the clean verdict; it can never manufacture DO-NOT-INSTALL. If
    that ever breaks, the version-tolerant-parser work is no longer optional.
    """
    import sys

    sk = _skill(tmp_path, "modern", {"scripts/helper.py": _MATCH_STATEMENT_SOURCE})
    p = _profile(sk)

    assert p.verdict != "DO-NOT-INSTALL"
    if sys.version_info >= (3, 10):
        assert p.verdict == "INSTALL"
        assert next(a for a in p.axes if a.axis == "danger").status == PASS
    else:
        assert p.verdict == "CAUTION"
        assert next(a for a in p.axes if a.axis == "danger").status == UNKNOWN


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
