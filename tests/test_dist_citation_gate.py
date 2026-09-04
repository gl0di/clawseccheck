"""Dist-citation gate suite wiring (C-480).

``scripts/dist_citation_gate.py`` stops new UNQUALIFIED stale OpenClaw dist-bundle
citations from creeping into the tree (see its own module docstring for the full
rationale). It shipped with nothing invoking it: no test module, no CI step, no entry
in the release gate -- a stale baseline, a broken extractor, or a newly-added
unqualified citation had no signal short of a human remembering to run a script
mentioned in one line of ``docs/CHECK_AUTHORING.md``. This module closes that gap the
same way ``tests/test_state_schema_grounding.py`` closes the analogous one for
``scripts/state_db_drift_gate.py``: load the script BY PATH with
``importlib.util.spec_from_file_location`` and run it for real, rather than
re-implementing its citation extractor here.

Local-only: ``_locate_dist()`` is the gate's OWN resolver
(``deptree.find_package_root``), so this test cannot disagree with the gate about
where OpenClaw lives, and it skips cleanly on a machine with no OpenClaw installed --
CI checks out only the skill tree (B-106), so
``test_dist_citation_gate_passes_against_the_installed_dist`` below never runs there.
``test_baseline_file_parses_to_a_nonempty_pair_list`` needs no dist and stays
always-on, so this module is not left fully skipped in CI.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_SCRIPT = REPO_ROOT / "scripts" / "dist_citation_gate.py"


def _load_gate():
    """Load ``scripts/dist_citation_gate.py`` by path -- do not re-implement its
    citation extractor. Mirrors ``tests/test_state_schema_grounding.py``'s
    ``_load_drift_gate``."""
    spec = importlib.util.spec_from_file_location("_dist_citation_gate", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_baseline_file_parses_to_a_nonempty_pair_list():
    """Always-on, no dist needed: the shipped baseline exists and parses to at least
    one (file, bundle) pair. Without this, an empty/corrupt baseline would make the
    dist-anchored test below pass vacuously the next time it actually runs."""
    gate = _load_gate()
    pairs = gate._read_baseline(gate.BASELINE_DEFAULT)
    assert pairs is not None, f"baseline file missing/unreadable: {gate.BASELINE_DEFAULT}"
    assert len(pairs) > 0, "baseline is empty -- compare() would pass vacuously"


def test_dist_citation_gate_passes_against_the_installed_dist():
    """Local-only: needs a real OpenClaw install to know which bundle names currently
    exist. Skips cleanly, via the gate's own ``_locate_dist()``, when none is found --
    CI has none (B-106)."""
    gate = _load_gate()
    dist_dir, _version = gate._locate_dist()
    if dist_dir is None:
        pytest.skip("OpenClaw dist not installed -- dist citation gate is local-only")

    rc = gate._run(gate.BASELINE_DEFAULT, REPO_ROOT, record=False)

    if rc == gate.EXIT_NEW_VIOLATION:
        pytest.fail(
            "dist_citation_gate reported a NEW unqualified stale dist citation -- "
            "add a live bundle filename or a date/version qualifier "
            "('grounded against openclaw@X.Y.Z (YYYY-MM-DD)', 'as of YYYY-MM-DD', or "
            "a bare date/version nearby), or run "
            "`python3 scripts/dist_citation_gate.py record` if this is a deliberate "
            "re-baseline."
        )
    if rc == gate.EXIT_CANNOT_RUN:
        pytest.fail(
            "dist_citation_gate could not run: either it extracted ZERO citations "
            "(the extractor is broken, not the tree clean) or the baseline file at "
            f"{gate.BASELINE_DEFAULT} is missing/unreadable."
        )
    assert rc == gate.EXIT_OK


# --- the extension boundary (B-734) --------------------------------------------------
#
# `_CITATION_RE` used to match a PREFIX of a longer extension, so `exec-approvals.json`
# -- a real OpenClaw data file our checks read, named in a dozen source comments -- was
# extracted as a citation of a bundle `exec-approvals.js` that does not exist. Twelve
# such phantoms had accumulated in the recorded baseline, and a thirteenth (a README
# command line naming `filled-template.json`) BLOCKED a CI run. These tests pin the
# boundary in both directions: no `.json`/`.jsx` may be read as a citation, and every
# real bundle shape must still be.

_NOT_CITATIONS = [
    "filled-template.json",       # the README example that tripped the gate
    "exec-approvals.json",        # OpenClaw's own approvals store
    "npm-shrinkwrap.json",        # an npm lockfile
    "user-allowFrom.json",        # trajaudit.py's fixture names
    "discord-allowFrom.json",
    "some-bundle-Ab12Cd34.jsx",   # a .jsx file is not the .js bundle either
]

_REAL_CITATIONS = [
    ("agent-scope-config-BxAUeF6t.js", "agent-scope-config-BxAUeF6t.js"),
    ("installed-plugin-index-store-C3LEu6Er.js", "installed-plugin-index-store-C3LEu6Er.js"),
    ("a-bundle-Ab12Cd34.mjs", "a-bundle-Ab12Cd34.mjs"),
    ("types-Ab12Cd34.d.ts", "types-Ab12Cd34.d.ts"),
    # the citing convention in this tree carries a :line or :range suffix
    ("see agent-scope-config-BxAUeF6t.js:66-69 for the resolver",
     "agent-scope-config-BxAUeF6t.js"),
]


@pytest.mark.parametrize("text", _NOT_CITATIONS)
def test_a_longer_extension_is_not_read_as_a_bundle_citation(text):
    gate = _load_gate()
    assert gate._CITATION_RE.findall(text) == [], (
        f"{text!r} was extracted as a dist-bundle citation. The gate would then check a "
        f"bundle that never existed, find it absent, and block the build over a filename "
        f"that has nothing to do with the dist."
    )


@pytest.mark.parametrize("text,expected", _REAL_CITATIONS)
def test_the_boundary_does_not_cost_a_real_citation(text, expected):
    """The positive control for the test above. Narrowing an extractor buys false
    negatives if it goes one character too far, so every shape the tree actually cites
    is asserted to still match."""
    gate = _load_gate()
    assert expected in gate._CITATION_RE.findall(text)


def test_the_boundary_guard_bites_on_the_pattern_it_replaced():
    """Without this, both tests above would pass against a pattern that never matched
    anything at all. Reproduce the retired regex and show it DID extract the phantom --
    so the fix is doing work, not the assertions agreeing with themselves."""
    import re

    retired = re.compile(r"[A-Za-z0-9._-]+-[A-Za-z0-9_-]{8,}\.(?:js|d\.ts|mjs)")
    assert retired.findall("filled-template.json") == ["filled-template.js"]
    assert retired.findall("exec-approvals.json") == ["exec-approvals.js"]
