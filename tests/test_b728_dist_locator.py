"""B-728 — the dist locator must distinguish "not installed" from "anchor moved".

Two halves, and the second is the one that matters. The first proves
``tests/_distgrounding.py`` behaves; the second proves the CALL SITES use it, because a
correct helper nobody routes through is a helper that changes nothing (the recurring
lesson: test the wiring, not the helper).

The defect this closes was live, not theoretical. ``test_b664_exec_policy_dimension.py``
pinned the content-hashed filename ``exec-approvals-BIKWP8_V.js`` and
``test_b665_recommended_values_are_real.py`` pinned ``zod-schema.agent-runtime-C02vY4RT.js``,
both inside a ``skipif``. OpenClaw 2026.9.1 rotated both away, so on the maintainer's own
machine — dist installed, node present — those two differential guards were SKIPPING, each
printing "needs the installed OpenClaw dist". A guard that switches itself off and names
the wrong cause is worse than an absent one: the run is green and the reason sends the
reader somewhere else entirely.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path

import pytest

import _distgrounding
from _distgrounding import dist_file, dist_files, dist_text, require_dist

TESTS_DIR = Path(__file__).resolve().parent


@contextmanager
def _no_skipping(what: str):
    """A happy-path assertion must go RED, not quiet, when the helper starts skipping.

    Without this, an "always skip" mutation turned six of this module's tests into skips
    and the run still reported no failures.
    """
    try:
        yield
    except pytest.skip.Exception as exc:  # noqa: PT017 - see above
        pytest.fail(f"{what} SKIPPED ({exc}) — a stand-down where an answer was available")


def _fails_rather_than_skips(call, what: str) -> str:
    """Run `call`, require an AssertionError, and return its message.

    A plain ``pytest.raises(AssertionError)`` is NOT enough here, and finding that out is
    part of this task. Mutating the helper back to its old ``pytest.skip`` on a zero match
    left this module reporting "10 passed" — the two tests that should have caught the
    regression SKIPPED, because a ``Skipped`` raised inside ``pytest.raises`` propagates
    and marks the test skipped rather than failed. The guard against a silent stand-down
    was itself standing down silently, which is B-728 reproduced one level up.
    """
    try:
        call()
    except AssertionError as exc:
        return str(exc)
    except pytest.skip.Exception as exc:  # noqa: PT017 - the whole point of this helper
        pytest.fail(f"{what} SKIPPED instead of failing ({exc}) — that is the B-728 defect")
    pytest.fail(f"{what} neither failed nor skipped — it returned")


# --------------------------------------------------------------------- the helper

def test_require_dist_skips_only_when_openclaw_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path / "nope")
    with pytest.raises(pytest.skip.Exception) as exc:
        require_dist()
    assert "not installed" in str(exc.value)


def test_require_dist_returns_the_directory_when_present(tmp_path, monkeypatch):
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    with _no_skipping("require_dist on a present dist"):
        assert require_dist() == tmp_path


def test_zero_matches_with_the_dist_present_fails_and_names_the_symbol(tmp_path, monkeypatch):
    """THE defect. A skip here is the guard turning itself off on upgrade day."""
    (tmp_path / "something-else-AAA.js").write_text("x", encoding="utf-8")
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    message = _fails_rather_than_skips(
        lambda: dist_files("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS"),
        "a zero match with the dist present")
    assert "CORE_TOOL_DEFINITIONS" in message, "the symbol to re-locate must be named"
    assert "grep -rl" in message, "the message must carry the re-location recipe"
    assert "not a missing install" in message, "the false cause must be ruled out in words"


def test_a_name_match_whose_content_lacks_the_symbol_says_so_distinctly(tmp_path, monkeypatch):
    """"the bundle was renamed" and "the bundle is there but the symbol left it" are
    different repairs, so they get different messages."""
    (tmp_path / "tool-catalog-AAA.js").write_text("nothing useful", encoding="utf-8")
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    message = _fails_rather_than_skips(
        lambda: dist_files("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS",
                           contains="CORE_TOOL_DEFINITIONS"),
        "a name match whose content lacks the symbol")
    assert "none declares" in message
    assert "tool-catalog-AAA.js" in message, "name the file that DID match, to aim the search"


def test_dist_file_refuses_to_pick_one_of_several(tmp_path, monkeypatch):
    for name in ("agent-id-AAA.js", "agent-id-BBB.js"):
        (tmp_path / name).write_text("normalizeAgentIdStrict", encoding="utf-8")
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    message = _fails_rather_than_skips(
        lambda: dist_file("agent-id-*.js", symbol="normalizeAgentIdStrict"),
        "two files matching where one is needed")
    assert "coin toss" in message


def test_contains_resolves_several_name_matches_to_the_one_that_declares_it(tmp_path, monkeypatch):
    (tmp_path / "agent-id-AAA.js").write_text("imports normalizeAgentIdStrict", encoding="utf-8")
    (tmp_path / "agent-id-BBB.js").write_text("unrelated", encoding="utf-8")
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    with _no_skipping("resolving by contains"):
        found = dist_file("agent-id-*.js", symbol="normalizeAgentIdStrict",
                          contains="normalizeAgentIdStrict")
    assert found.name == "agent-id-AAA.js"


def test_dist_text_joins_every_match(tmp_path, monkeypatch):
    (tmp_path / "a-1.js").write_text("first", encoding="utf-8")
    (tmp_path / "a-2.js").write_text("second", encoding="utf-8")
    monkeypatch.setattr(_distgrounding, "OPENCLAW_DIST", tmp_path)
    with _no_skipping("joining every match"):
        text = dist_text("a-*.js", symbol="whatever")
    assert "first" in text and "second" in text


def test_the_docstring_states_that_green_means_live_not_correct():
    """The caveat is load-bearing: these helpers prove a citation resolves, never that it
    says what the citing docstring claims. Only executing the vendor proves that."""
    doc = " ".join((_distgrounding.__doc__ or "").split())
    assert "It means the citation is **live**, not that it is **correct**." in doc, (
        "the live-vs-correct sentence is the caveat a reader must not be able to skim past"
    )
    assert "grounded by EXECUTING the vendor over a case battery" in doc, (
        "the caveat has to say what DOES ground a behavioural claim, or it is only a "
        "disclaimer"
    )
    assert "never by a successful grep" in doc


# --------------------------------------------------------------------- the wiring

#: Modules that ground a claim against the installed dist and must route through the
#: shared locator. Each was carrying its own two-outcome copy before B-728.
_MIGRATED = (
    "test_toolgrant_dist_grounding.py",
    "test_b666_read_reach.py",
    "test_b667_sensitive_tool_ids.py",
    "test_b353_mcp_preapproved_tools.py",
    "test_b706_codex_annotations_enforced.py",
    "test_b664_exec_policy_dimension.py",
    "test_b665_recommended_values_are_real.py",
)

#: The two modules that predate the shared helper and keep their own locator DELIBERATELY:
#: both already carry the stronger form this helper generalises — a constant-anchored
#: search plus an anti-vacuity assertion (B-251/B-710) — and both need a dist path shaped
#: differently (a parsed schema namespace, a snapshot re-derivation) rather than a file.
_KEEP_THEIR_OWN = {
    "test_schema_grounding.py": "_require_dist asserts DIST_ROOT_SCHEMA is present (B-251)",
    "test_state_schema_grounding.py": "_find_state_schema_defining_js — this helper's exemplar",
    "_distgrounding.py": "the helper itself",
}

#: A locator resolves the REAL installed dist root — either from ``REAL_HOME`` or as an
#: absolute literal ending at ``dist``. Deliberately NOT a bare "node_modules/openclaw"
#: grep: several modules carry synthetic operator paths inside fixtures
#: (``test_sbom.py``'s ``/home/someoperator/...openclaw/dist/extensions/browser``) that
#: read nothing and must not be swept in. Measured: the broad form named 16 modules, 13 of
#: them false.
_DIST_PATH_RE = re.compile(
    r'(REAL_HOME\s*/.{0,80}?"openclaw".{0,40}?"dist")'
    r'|(["\'][^"\']*node_modules/openclaw/dist["\'])'
)


def _modules_naming_the_dist_path():
    out = {}
    for path in sorted(TESTS_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        code = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        if _DIST_PATH_RE.search(code):
            out[path.name] = text
    return out


def test_every_migrated_module_routes_through_the_shared_locator():
    """Wiring, not helper. Mutating the helper leaves these green; deleting an import
    from a call site is what this catches."""
    missing = [
        name for name in _MIGRATED
        if "from _distgrounding import" not in (TESTS_DIR / name).read_text(encoding="utf-8")
    ]
    assert not missing, f"these ground against the dist without the shared locator: {missing}"


def test_no_new_module_hand_rolls_its_own_dist_path():
    """The B-483 shape: one table, or the next author writes a second one that drifts.

    A module that constructs the OpenClaw dist path itself is either using the shared
    locator's constant (fine — it imports it) or writing a fresh copy of the two-outcome
    bug. Anything new must be added to `_KEEP_THEIR_OWN` with a reason, which is the point
    at which someone reads this docstring.
    """
    offenders = sorted(
        name for name, text in _modules_naming_the_dist_path().items()
        if name not in _KEEP_THEIR_OWN and "from _distgrounding import" not in text
    )
    assert not offenders, (
        f"{offenders} build the OpenClaw dist path themselves. Use "
        "`tests/_distgrounding.py` (skip only when OpenClaw is absent; fail, naming the "
        "symbol, when it is installed and the anchor moved), or register the module in "
        "_KEEP_THEIR_OWN with the reason its own locator is stronger."
    )


def test_the_locator_sweep_recognises_both_forms_it_must_catch():
    """A negative needs a positive control. `test_no_new_module_hand_rolls_its_own_dist_path`
    asserts an EMPTY set, which is exactly what a regex that matches nothing also produces
    — so pin that the two real forms are recognised. Both are forms this change removed
    from the tree: b664/b665/b706/b353 held the absolute literal, the rest the REAL_HOME
    expression."""
    assert _DIST_PATH_RE.search(
        'OPENCLAW_DIST = REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"'
    ), "the REAL_HOME form must be recognised"
    assert _DIST_PATH_RE.search(
        '_DIST = Path("/home/someone/.npm-global/lib/node_modules/openclaw/dist")'
    ), "the hardcoded absolute form must be recognised"
    assert not _DIST_PATH_RE.search(
        'root_dir="/home/someoperator/.npm-global/lib/node_modules/openclaw/dist/extensions/browser"'
    ), "a synthetic path INSIDE a fixture is not a locator and must not be swept in"


def test_no_migrated_module_still_pins_a_content_hashed_filename():
    """What actually switched b664 and b665 off: a literal like
    `exec-approvals-BIKWP8_V.js`. Bundle names are content hashes and rotate per release,
    so a pinned one is a guard with an expiry date nobody wrote down."""
    hashed = re.compile(r"[\"'][a-z0-9.\-]+-[A-Za-z0-9_\-]{8}\.js[\"']")
    offenders = []
    for name in _MIGRATED:
        for line in (TESTS_DIR / name).read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = hashed.search(line)
            if match:
                offenders.append(f"{name}: {match.group(0)}")
    assert not offenders, (
        f"content-hashed dist filenames pinned in source: {offenders}. Anchor on a symbol "
        "via `contains=` instead — a rotated hash makes the guard vanish, not fail."
    )
