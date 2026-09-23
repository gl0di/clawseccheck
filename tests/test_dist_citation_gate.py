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

B-734: the baseline's own ``openclaw-version:``/``generated:``/``violations:`` header was
inert -- ``scripts/dist_citation_gate.py`` writes it but nothing ever read it back, so it
sat stamped ``2026.8.2`` for two releases while the gate itself ran green against an
installed ``2026.9.1``. This is the identical failure ``test_state_schema_grounding.py``
already records and fixed for its own sibling snapshot (see that module's docstring):
"rewriting ``openclaw-version:`` to ``1999.1.1`` by hand left every other test green,
because nothing actually read the stamp." ``_header_field``/the header-stamp tests below
mirror that module's own fix, deliberately duplicated rather than shared -- the sibling
module keeps its own copy the same way, and a one-regex helper is not worth a new shared
module for two callers.

B-890: the qualifier is anchor-only now (a literal date or version), the prose verbs
("grounded against"/"grounded per"/"as of") having been retired after a C-135 round-2
review kept surfacing new leaks in that family -- see ``scripts/dist_citation_gate.py``'s
own module docstring and its ``_QUALIFIER_RE`` comment for the full history. The tests
below keep the retired B-885 patterns around as mutation-check controls (each negative
test has a paired "bites on the retired pattern" test proving it would have wrongly
qualified under the old design), then pin the current anchor-only contract.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_SCRIPT = REPO_ROOT / "scripts" / "dist_citation_gate.py"
BASELINE_FILE = REPO_ROOT / "tests" / "dist_citation_baseline.txt"


def _load_gate():
    """Load ``scripts/dist_citation_gate.py`` by path -- do not re-implement its
    citation extractor. Mirrors ``tests/test_state_schema_grounding.py``'s
    ``_load_drift_gate``."""
    spec = importlib.util.spec_from_file_location("_dist_citation_gate", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _header_field(header: str, name: str) -> "str | None":
    """A ``# name: value`` header line's value. Mirrors
    ``test_state_schema_grounding.py``'s helper of the same name/shape -- same idiom,
    deliberately duplicated (see module docstring)."""
    m = re.search(rf"^#\s*{re.escape(name)}:\s*(\S+)", header, re.MULTILINE)
    return m.group(1) if m else None


def _assert_stamp_matches_installed(baseline_path: Path, installed_version: str) -> None:
    """The actual enforcement: the baseline's ``openclaw-version:`` stamp must equal the
    version the caller resolved as installed. Factored out so the positive control below
    can prove this raises on a mutated stamp, rather than only ever running against the
    real (already-correct) baseline file."""
    header = baseline_path.read_text(encoding="utf-8")
    stamped = _header_field(header, "openclaw-version")
    if stamped != installed_version:
        raise AssertionError(
            f"{baseline_path.name} is stamped openclaw-version: {stamped!r} but the "
            f"installed OpenClaw is {installed_version!r} -- a stale/faked stamp used to "
            "leave a sibling guard green once (test_state_schema_grounding.py's own "
            "incident, and the exact bug B-734 was filed over). Re-record with "
            "`python3 scripts/dist_citation_gate.py record`."
        )


def test_baseline_header_parses_all_three_fields_and_violations_count_matches():
    """Always-on, no dist needed (B-734): a hand-mangled or truncated header must fail
    here, in CI, where the version-anchored test below never runs (B-106). ``violations:``
    self-describes the pair count, so it is checked against ``len(pairs)`` directly --
    no dist required for that half either."""
    text = BASELINE_FILE.read_text(encoding="utf-8")
    version = _header_field(text, "openclaw-version")
    generated = _header_field(text, "generated")
    violations = _header_field(text, "violations")

    assert version and re.match(r"^\d{4}\.\d+\.\d+$", version), (
        f"bad/missing openclaw-version stamp: {version!r}"
    )
    assert generated and re.match(r"^\d{4}-\d{2}-\d{2}$", generated), (
        f"bad/missing generated stamp: {generated!r}"
    )
    assert violations is not None and violations.isdigit(), (
        f"bad/missing violations stamp: {violations!r}"
    )

    gate = _load_gate()
    pairs = gate._read_baseline(BASELINE_FILE)
    assert pairs is not None
    assert int(violations) == len(pairs), (
        f"header says violations: {violations} but the baseline body actually has "
        f"{len(pairs)} pair(s) -- re-record with "
        "`python3 scripts/dist_citation_gate.py record`."
    )


def test_stamp_check_goes_red_on_a_mutated_version(tmp_path):
    """Positive control (B-734's own DoD): rewrite the stamp to a nonsense version in a
    tmp copy and assert the check actually fails. Without this, the version-anchored
    test below could pass against a header nothing reads -- which is the exact bug this
    task was filed over."""
    text = BASELINE_FILE.read_text(encoding="utf-8")
    mutated, n = re.subn(
        r"^# openclaw-version: .*$", "# openclaw-version: 1999.1.1", text,
        count=1, flags=re.MULTILINE,
    )
    assert n == 1, "the version-stamp line pattern did not match the real baseline header"

    tmp_baseline = tmp_path / "dist_citation_baseline.txt"
    tmp_baseline.write_text(mutated, encoding="utf-8")

    with pytest.raises(AssertionError, match="stamped openclaw-version"):
        _assert_stamp_matches_installed(tmp_baseline, "2026.9.1")

    # And the control's control: an UNmutated copy against the version it already
    # carries must pass cleanly.
    real_version = _header_field(text, "openclaw-version")
    _assert_stamp_matches_installed(BASELINE_FILE, real_version)


# ========================================================================================
# LOCAL-ONLY (needs the dist, B-106). Skip is pinned as a skip.
# ========================================================================================

def test_baseline_openclaw_version_stamp_matches_installed_dist():
    """The stamp must equal what's actually installed, from the gate's OWN
    ``_locate_dist()`` resolver -- so this test cannot disagree with the gate itself
    about which OpenClaw it means."""
    gate = _load_gate()
    dist_dir, version = gate._locate_dist()
    if dist_dir is None:
        pytest.skip("OpenClaw dist not installed -- dist citation gate is local-only")
    _assert_stamp_matches_installed(BASELINE_FILE, version)


def test_baseline_file_parses_to_a_nonempty_pair_list():
    """Always-on, no dist needed: the shipped baseline exists and parses to at least
    one (file, bundle) pair. Without this, an empty/corrupt baseline would make the
    dist-anchored test below pass vacuously the next time it actually runs."""
    gate = _load_gate()
    pairs = gate._read_baseline(gate.BASELINE_DEFAULT)
    assert pairs is not None, f"baseline file missing/unreadable: {gate.BASELINE_DEFAULT}"
    assert len(pairs) > 0, "baseline is empty -- compare() would pass vacuously"


# --- qualifier history: B-885 (case-insensitive prose) --------------------------------
#
# B-885 made the qualifier prose ("grounded against"/"grounded per"/"as of") match
# case-insensitively so a capitalized sentence-initial phrase -- "Grounded against the
# vendor's OWN canonical read..." (collector.py's `_collect_subagent_runs` docstring) --
# would qualify the same as its lowercase mid-sentence form; it also anchored
# `grounded per` with `\b(?!-)` so the compound "schema-grounded PER-AGENT" in
# checks/_agents.py stopped false-qualifying through a bare substring match. Both fixes
# are reproduced below as "retired pattern" controls only -- B-890 (next section)
# retires the prose branch entirely, so neither fix is live in `_QUALIFIER_RE` anymore.
# Always-on, no dist needed.

def test_qualifier_case_insensitivity_bites_on_the_pattern_it_replaced():
    """Reproduce the pre-B885 (no-``re.IGNORECASE``) regex and show it MISSES the
    sentence-initial capitalized phrase -- documents that B-885's fix, before B-890
    retired the whole prose branch, was doing real work at the time."""
    retired = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)|as of "
    )
    assert retired.search("Grounded against the vendor's OWN canonical read.") is None
    assert retired.search("Grounded per the installed dist, not the recon.") is None


def test_the_whole_word_anchor_bites_on_the_pattern_it_replaced():
    """The un-anchored B-885-round-1 pattern (f3f5613) accepted the PER-AGENT compound
    below; documents that the round-2 `\\b(?!-)` anchor was doing real work at the time,
    before B-890 retired the whole prose branch."""
    unanchored = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)|as of ",
        re.IGNORECASE,
    )
    assert unanchored.search(
        "the schema-grounded per-agent path agents.list[i].subagents"
    )


# --- qualifier contract: anchor-only (B-890) -------------------------------------------
#
# Dave's ruling (B-890, 2026-09-23): the gate REQUIRES an actual dated (`YYYY-MM-DD`) or
# versioned (`2026.N.N`) anchor in the citation's window. The prose verbs are retired
# from `_QUALIFIER_RE` entirely -- in this tree's own convention they are only ever the
# POINTER to an anchor ("grounded against openclaw@2026.7.1-2 (2026-07-25)"), never a
# substitute for one. This was chosen over patching the prose matcher a fourth time: a
# round-2 C-135 review of the B-885 fix found the approach kept leaking one member of
# the same family per patch (see the three sections below for each one, with a
# mutation-check control proving the retired B-885 pattern would have wrongly qualified
# it). Retiring the branch closes the whole family by construction -- no verb left to
# leak through -- rather than by a fifth lookahead.

_DATED_OR_VERSIONED = [
    "As of 2026-09-22 this still resolves.",
    "grounded against openclaw@2026.7.1-2 (2026-07-25)",
    "nothing but a bare 2026.9.5 nearby",
    "nothing but a bare 2026-09-22 nearby",
]

_UNDATED_PROSE_ONLY = [
    "Grounded against the vendor's OWN canonical read of the state DB.",
    "Grounded per the installed dist, not the recon.",
    "grounded per: the installed dist",
    "grounded against\nthe installed dist",
    "as of ",
]


@pytest.mark.parametrize("text", _DATED_OR_VERSIONED)
def test_a_dated_or_versioned_window_is_qualified(text):
    gate = _load_gate()
    assert gate._QUALIFIER_RE.search(text), (
        f"{text!r} carries a literal date or version but _QUALIFIER_RE did not match it."
    )


@pytest.mark.parametrize("text", _UNDATED_PROSE_ONLY)
def test_undated_prose_only_is_not_qualified(text):
    """B-890: the prose verbs no longer qualify on their own -- a window carrying prose
    but no date/version anchor must NOT qualify, even the exact sentence-initial
    capitalized shape B-885 (f3f5613) was written to accept."""
    gate = _load_gate()
    assert gate._QUALIFIER_RE.search(text) is None, (
        f"{text!r} has no date/version anchor but _QUALIFIER_RE matched it -- prose "
        "alone must not qualify a citation as history (B-890)."
    )


def test_undated_prose_only_bites_on_the_b885_pattern_it_replaced():
    """Mutation check: the B-885 pattern (9a6f123, the state this branch is stacked on)
    DID accept every ``_UNDATED_PROSE_ONLY`` entry -- so the negative test above is
    doing real work, not passing against a prose alternative that had already stopped
    matching anything."""
    retired = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)\b(?!-)|as of ",
        re.IGNORECASE,
    )
    for text in _UNDATED_PROSE_ONLY:
        assert retired.search(text), text


# --- leading-edge substring coincidences (B-885 C-135 round 2) ------------------------
#
# Neither prose verb had a boundary check on its LEADING edge, so it qualified wherever
# it occurred as a plain substring inside a longer, unrelated word: "an alias of"
# contains the literal substring "as of"; "ungrounded against" contains the literal
# substring "grounded against". Both would have false-qualified a dead, otherwise-
# unqualified citation sharing their window.

_LEADING_EDGE_COINCIDENCES = [
    "an alias of the real field",
    "this config is ungrounded against the schema",
]


@pytest.mark.parametrize("text", _LEADING_EDGE_COINCIDENCES)
def test_leading_edge_coincidence_is_not_qualified(text):
    gate = _load_gate()
    assert gate._QUALIFIER_RE.search(text) is None, (
        f"{text!r} was read as qualified -- it contains the substring 'as of' or "
        "'grounded against' inside an unrelated word, not the prose qualifier itself."
    )


def test_leading_edge_coincidence_bites_on_the_b885_pattern_it_replaced():
    retired = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)\b(?!-)|as of ",
        re.IGNORECASE,
    )
    for text in _LEADING_EDGE_COINCIDENCES:
        assert retired.search(text), text


# --- per-agent, ASCII and Unicode hyphen variants (B-885 C-135 round 2) ---------------
#
# `(?!-)` only ever excluded the ASCII hyphen U+002D. A Unicode hyphen variant right
# after "per" -- U+2010 HYPHEN or U+2011 NON-BREAKING HYPHEN -- slipped past the same
# guard exactly like the ASCII "per-agent" shape it was written to catch.

_NOT_QUALIFIERS = [
    "B-296 round 2: also recognizes the real, schema-grounded PER-AGENT path",
    "the schema-grounded per-agent path agents.list[i].subagents",
    "grounded perhaps on the recon",
    "the schema-grounded per‐agent path",   # U+2010 HYPHEN
    "the schema-grounded per‑agent path",   # U+2011 NON-BREAKING HYPHEN
]

# The last two entries above are the Unicode-hyphen variants; the ASCII-anchored B-885
# pattern still accepted them (see the mutation check below).
_UNICODE_HYPHEN_VARIANTS = _NOT_QUALIFIERS[-2:]


@pytest.mark.parametrize("text", _NOT_QUALIFIERS)
def test_a_hyphenated_or_longer_word_after_grounded_per_is_not_a_qualifier(text):
    gate = _load_gate()
    assert gate._QUALIFIER_RE.search(text) is None, (
        f"{text!r} was read as a dated/grounded qualifier. 'per-agent'/'perhaps' is not "
        "'grounded per <source>' -- accepting it lets a dead, undated bundle citation "
        "in the same window pass as history."
    )


def test_ascii_hyphen_guard_bites_on_the_pattern_it_replaced():
    """The un-anchored B-885-round-1 pattern (f3f5613) accepted every ``_NOT_QUALIFIERS``
    entry."""
    unanchored = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)|as of ",
        re.IGNORECASE,
    )
    for text in _NOT_QUALIFIERS:
        assert unanchored.search(text), text


def test_unicode_hyphen_variant_bites_on_the_ascii_only_pattern_it_replaced():
    """The ASCII-only ``(?!-)`` from B-885 round 2 (9a6f123) still accepted a Unicode
    hyphen right after 'per' -- so this negative test entry is doing real work, not
    passing against a lookahead that already excluded it."""
    ascii_hyphen_only = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)\b(?!-)|as of ",
        re.IGNORECASE,
    )
    for text in _UNICODE_HYPHEN_VARIANTS:
        assert ascii_hyphen_only.search(text), text


# --- Unicode case folding: long s (B-885 C-135 round 2) -------------------------------
#
# `re.IGNORECASE` on a `str` pattern is Unicode-aware case folding, not an ASCII
# upper/lower flip: U+017F LATIN SMALL LETTER LONG S folds to "s" under it, so
# "aſ of" ("aſ of") reads as "as of" to a case-insensitive prose match -- a
# visually similar, non-ASCII lookalike a reader would never type on purpose.

def test_long_s_lookalike_is_not_qualified():
    gate = _load_gate()
    text = "aſ of the installed dist"
    assert gate._QUALIFIER_RE.search(text) is None, (
        f"{text!r} (long-s lookalike of 'as of') was read as qualified."
    )


def test_long_s_lookalike_bites_on_the_b885_pattern_it_replaced():
    retired = re.compile(
        r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)\b(?!-)|as of ",
        re.IGNORECASE,
    )
    assert retired.search("aſ of the installed dist")


_PER_AGENT_MODULE = (
    "def _has_subagents(cfg):\n"
    "    \"\"\"True if any subagent delegation is configured.\n\n"
    "    B-296 round 2: also recognizes the real, schema-grounded PER-AGENT\n"
    "    path ``agents.list[i].subagents``. {verb} ``AgentEntrySchema`` (installed\n"
    "    dist ``zod-schema.agent-runtime-Ab12Cd34.js:658-711``).\n"
    "    \"\"\"\n"
)


def test_a_dead_citation_whose_only_prose_is_per_agent_is_a_violation(tmp_path):
    """End-to-end mirror of the real ``_has_subagents`` docstring, no dist needed
    (``dist_basenames`` is empty, so the bundle is dead): "Grounded on" is not a
    qualifier alternative and "schema-grounded PER-AGENT" must not be one either, so the
    pair is a violation."""
    gate = _load_gate()
    pkg_dir = tmp_path / "clawseccheck"
    pkg_dir.mkdir()
    (pkg_dir / "fake_agents.py").write_text(
        _PER_AGENT_MODULE.format(verb="Grounded on"), encoding="utf-8"
    )
    violations, total = gate.scan_citations(tmp_path, dist_basenames=set())
    assert total == 1, f"expected exactly one extracted citation, got {total}"
    assert violations == [
        ("clawseccheck/fake_agents.py", "zod-schema.agent-runtime-Ab12Cd34.js")
    ], (
        "a dead citation whose window's only 'grounded per' is the compound "
        f"'schema-grounded PER-AGENT' was accepted as qualified: {violations}"
    )


def test_grounded_per_without_a_date_is_still_a_violation(tmp_path):
    """B-890 flips this B-885 fixture's expected outcome (it used to become qualified
    here -- see git history of this test module): the documented 'Grounded per' verb no
    longer qualifies a citation on its own, so the identical window is STILL a
    violation without a date/version anchor."""
    gate = _load_gate()
    pkg_dir = tmp_path / "clawseccheck"
    pkg_dir.mkdir()
    (pkg_dir / "fake_agents.py").write_text(
        _PER_AGENT_MODULE.format(verb="Grounded per"), encoding="utf-8"
    )
    violations, total = gate.scan_citations(tmp_path, dist_basenames=set())
    assert total == 1, f"expected exactly one extracted citation, got {total}"
    assert violations == [
        ("clawseccheck/fake_agents.py", "zod-schema.agent-runtime-Ab12Cd34.js")
    ], violations


def test_the_same_window_qualifies_once_a_real_date_is_added(tmp_path):
    """Paired control for the test above: add a literal date next to the citation and
    the identical window becomes qualified -- proving `scan_citations` responds to an
    actual anchor, not to the grounding verb."""
    gate = _load_gate()
    pkg_dir = tmp_path / "clawseccheck"
    pkg_dir.mkdir()
    dated_module = (
        "def _has_subagents(cfg):\n"
        "    \"\"\"True if any subagent delegation is configured.\n\n"
        "    B-296 round 2: also recognizes the real, schema-grounded PER-AGENT\n"
        "    path ``agents.list[i].subagents``. Grounded per ``AgentEntrySchema``\n"
        "    (installed dist ``zod-schema.agent-runtime-Ab12Cd34.js:658-711``,\n"
        "    2026-09-22).\n"
        "    \"\"\"\n"
    )
    (pkg_dir / "fake_agents.py").write_text(dated_module, encoding="utf-8")
    violations, total = gate.scan_citations(tmp_path, dist_basenames=set())
    assert total == 1, f"expected exactly one extracted citation, got {total}"
    assert violations == [], violations


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
