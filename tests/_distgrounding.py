"""B-728 — one dist locator with THREE outcomes, because ``skip`` was answering two questions.

Every module that grounds a claim against the installed OpenClaw dist had written its own
locator, and each one collapsed two different states into a single stand-down::

    files = sorted(OPENCLAW_DIST.glob(pattern))
    if not files:
        pytest.skip("installed OpenClaw dist not found")

"OpenClaw is not installed" and "OpenClaw IS installed and this anchor no longer matches"
are different answers, and only the first is a reason to stand down. Bundle filenames are
content-hashed and rotate heavily per release (``docs/CHECK_AUTHORING.md``; 2026.9.1
rotated ~65% of them), so the second is the EXPECTED outcome of an upgrade — which means
that line turned the guard off at exactly the moment it was needed, and printed a false
cause on the way out. A guard able to disable itself and misreport why is worse than no
guard: the run stays green and the reason in the log sends the reader to the wrong place.

Three outcomes, and every caller gets all three:

==============================================  ==========================================
dist directory absent                           ``pytest.skip`` — the one honest stand-down
dist present, zero matches                      FAIL, naming the symbol to re-locate
more than one match where one file is needed    FAIL — picking the first is a coin toss
==============================================  ==========================================

The third is not hypothetical either. ``test_state_schema_grounding.py``'s docstring
records 2026.9.1 moving ``OPENCLAW_STATE_SCHEMA_SQL`` into a different bundle while KEEPING
a file the old glob still matched, so the glob resolved happily to a module that no longer
defined the schema. That module's ``_find_state_schema_defining_js`` is this one's
exemplar, and its lesson is baked in here as ``contains=``: anchoring on a CONSTANT rather
than a filename is strictly stronger, and it also turns a coin toss into a determinate
choice (measured on 2026.9.1: ``agent-id-*.js`` matches four files, exactly one of which
declares ``normalizeAgentIdStrict``).

The second in-tree exemplar is ``test_schema_grounding.py::_require_dist``, whose
anti-vacuity assertion (B-251) is the same idea one level up: a layer that can silently see
nothing must say so rather than grade everything against an empty schema.

WHAT A GREEN GROUNDING TEST MEANS — read this before citing one as evidence. It means the
citation is **live**, not that it is **correct**. These helpers prove a symbol still exists
where a docstring says it does; nothing here can prove the docstring describes what that
symbol actually DOES. A claim about vendor BEHAVIOUR is grounded by EXECUTING the vendor
over a case battery (``test_toolgrant_dist_grounding.py``'s 3,354-case differential,
``test_b666_read_reach.py``), never by a successful grep. A locator that resolves is the
precondition for evidence, not the evidence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _realhome import REAL_HOME

#: The installed OpenClaw's ``dist``. ``REAL_HOME``, never ``Path.home()`` — ``conftest``
#: redirects ``$HOME`` for the session, so ``Path.home()`` would find no dist and skip
#: every grounding test vacuously (B-519).
OPENCLAW_DIST = REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"


def require_dist() -> Path:
    """The installed dist directory, or the one honest skip.

    Local-only: absent in CI (B-106 — CI checks out only the skill tree) and on any machine
    without OpenClaw. This is the ONLY condition under which a grounding test may stand
    down; every other failure to locate something is a finding, not an excuse.
    """
    if not OPENCLAW_DIST.is_dir():
        pytest.skip(
            f"OpenClaw is not installed at {OPENCLAW_DIST} — dist grounding is local-only"
        )
    return OPENCLAW_DIST


def _matches(pattern: str, symbol: str, contains: str | None) -> list:
    dist = require_dist()
    named = sorted(dist.glob(pattern))
    if contains is None:
        found = named
    else:
        found = [
            p for p in named
            if contains in p.read_text(encoding="utf-8", errors="replace")
        ]
    if found:
        return found

    if contains is not None and named:
        raise AssertionError(
            f"{len(named)} file(s) under {dist} match {pattern!r} "
            f"({', '.join(p.name for p in named)}) but none declares {contains!r}. The "
            f"dist IS installed, so this is a symbol that moved or was renamed, not a "
            f"missing install — re-locate {symbol!r} with "
            f"`grep -rl {symbol!r} {dist}/*.js` and re-ground this citation."
        )
    raise AssertionError(
        f"nothing under {dist} matches {pattern!r}. The dist IS installed, so this is a "
        f"bundle that was renamed (filenames are content-hashed and rotate per release), "
        f"not a missing install — re-locate {symbol!r} with "
        f"`grep -rl {symbol!r} {dist}/*.js` and re-ground this citation. Standing down "
        f"here would turn the guard off at exactly the moment it is needed."
    )


def dist_files(pattern: str, *, symbol: str, contains: str | None = None) -> list:
    """Every dist file matching ``pattern`` (and declaring ``contains``, when given).

    At least one, guaranteed: zero is an ``AssertionError`` naming ``symbol``, never a
    skip. Use this where the citation legitimately spans several bundles; use
    :func:`dist_file` where exactly one file must be chosen.
    """
    return _matches(pattern, symbol, contains)


def dist_file(pattern: str, *, symbol: str, contains: str | None = None) -> Path:
    """The ONE dist file this citation names — never ``sorted(...)[0]``.

    More than one match is an ``AssertionError``, because choosing the first is a coin
    toss and the loser is silent. Narrow with ``contains=`` (anchor on the symbol, not the
    filename) rather than trusting sort order.
    """
    found = _matches(pattern, symbol, contains)
    if len(found) != 1:
        raise AssertionError(
            f"{len(found)} files under {OPENCLAW_DIST} match {pattern!r}"
            + (f" and declare {contains!r}" if contains else "")
            + f" ({', '.join(p.name for p in found)}), but this citation for {symbol!r} "
            f"needs exactly one — taking the first would be a coin toss. Narrow it with "
            f"contains=<a constant the right bundle declares>, or split the citation."
        )
    return found[0]


def dist_text(pattern: str, *, symbol: str, contains: str | None = None) -> str:
    """The matching dist files' text, joined. See :func:`dist_files` for the guarantees."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in _matches(pattern, symbol, contains)
    )
