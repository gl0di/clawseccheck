"""B-846 — the self-source `--vet` path (`checks/_vet.py::_vet_resolved_skill`
short-circuiting on `collector._is_own_source`) had two defects, now fixed:

1. **False claim about what ran.** `dossier._unmeasurable_reason`'s `self_source`
   branch used to claim "only the danger axis ran, by design" — but nothing ran at
   all: `_vet_resolved_skill` returns a canned B13 PASS `Finding` before any
   `read_skill_python`/`read_skill_shell`/`read_skill_js` call. Both the axis wording
   and danger's own PASS reason now say nothing was scanned; danger's PASS is a
   policy default, not a completed scan.

2. **Forgeable identity.** `_is_own_source` now recognises `_OWN_ENGINE_MARKERS` as
   real AST STRUCTURE — `_SKILL_CRIT` must be the target of a genuine
   `Assign`/`AnnAssign`, `check_installed_skills`/`vet_skill` must each be a real
   `FunctionDef`/`AsyncFunctionDef` name (`_own_engine_symbols_in_ast` in
   `collector.py`) — never a text/substring match. A comment, string, f-string, or
   lexer-confusing construct cannot forge any of these node types: forging one means
   literally writing the function/assignment, which is the accepted residual (see
   `_is_own_source`'s docstring) and no cheaper than the genuine engine's own code.

   RETRACTED APPROACHES — do not reintroduce; each was tried and defeated by a C-135
   reviewer, reproduced end-to-end against the real DO-NOT-INSTALL fixture
   `fixtures/bad_b335_runtime_persist_install/skills/envtools` (flipping its verdict
   to INSTALL / Danger PASS every time):
   - Bare substring match on marker text: a single `#`-commented line of marker text
     granted identity for free.
   - Stripping only comment-ONLY lines, then substring-matching: missed inline/
     trailing comments, comments after `;`, and markers in strings/docstrings.
   - Tokenizing (stdlib `tokenize`) and blanking COMMENT/STRING[/FSTRING_MIDDLE on
     3.12+] tokens, then substring-matching: still text-based, so it inherited every
     lexer-vs-grammar mismatch — PEP 701 changed f-string tokenizing on 3.12, and
     separately a pre-PEP-701 lexer's lack of `{}`-nesting awareness lets a
     syntactically INVALID same-quote nested f-string (`f"{"def vet_skill"}"`) still
     LEX cleanly into real NAME tokens on 3.9-3.11 with no exception raised. A pure
     lexer has no grammar validation, so reconstructing "real code text" from one and
     substring-matching it is unfixable in kind; only AST structure is sound.

   The short-circuit before parsing (skip a file when none of the still-missing
   markers' identifiers occur in its raw text) survived the move to AST and remains
   sound: an AST node's identifier is always spelled exactly as in source.

Every test below is offline and reads/writes only `tmp_path` / bundled fixtures.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from clawseccheck import collector as _collector_mod
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import (
    _MAX_OWN_SOURCE_BYTES,
    _OWN_ENGINE_MARKER_STATEMENTS,
    _OWN_ENGINE_MARKERS,
    _is_own_source,
)
from clawseccheck.dossier import build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "fixtures"
_ENVTOOLS = _FIXTURES / "bad_b335_runtime_persist_install" / "skills" / "envtools"

_SELF_SOURCE_PHRASE = "This is ClawSecCheck's own source"


def _axis(profile, name):
    for a in profile.axes:
        if a.axis == name:
            return a
    raise AssertionError(f"axis {name!r} not in profile")


def _plant_comment_only_spoof(root: Path) -> None:
    """The exact B-846 repro: one file, three lines, each a bare `#` comment."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    (pkg / "x.py").write_text(
        "\n".join(f"# {m}" for m in _OWN_ENGINE_MARKERS) + "\n",
        encoding="utf-8",
    )


def _plant_inline_comment_spoof(root: Path) -> None:
    """Each marker trails a real, unrelated statement — NOT a comment-only line."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f"x{i} = {i}  # {m}" for i, m in enumerate(_OWN_ENGINE_MARKERS)]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plant_semicolon_comment_spoof(root: Path) -> None:
    """A comment after a `;`-terminated statement — still just a comment, but on a
    line that does not start with `#` either, and not covered by a whole-line strip."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f"pass;  # {m}" for m in _OWN_ENGINE_MARKERS]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plant_string_literal_spoof(root: Path) -> None:
    """Markers as ordinary string VALUES, never as real `def`/assignment statements —
    a bare `#`-line strip does not even look at these lines."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_v{i} = "{m}"' for i, m in enumerate(_OWN_ENGINE_MARKERS)]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plant_docstring_spoof(root: Path) -> None:
    """Markers inside a multi-line module docstring — one STRING token spanning many
    physical lines, none of which is a `#` comment at all."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    body = "\n".join(_OWN_ENGINE_MARKERS)
    (pkg / "x.py").write_text(f'"""\n{body}\n"""\n', encoding="utf-8")


def _plant_fstring_spoof(root: Path) -> None:
    """Markers as plain f-string VALUES — a `JoinedStr`/`Constant` node either way,
    never a `FunctionDef`/`Assign`."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_v{i} = f"{m}"' for i, m in enumerate(_OWN_ENGINE_MARKERS)]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plant_nested_fstring_spoof(root: Path) -> None:
    """A same-quote NESTED f-string: `_v0 = f"{"def check_installed_skills"}"`. Not
    valid Python before 3.12 (PEP 701's same-quote-nesting allowance is 3.12+ only —
    this is a real `SyntaxError` on 3.9-3.11), yet a pre-PEP-701 LEXER (with no notion
    of `{}` nesting) mis-lexes it into real, un-blanked `NAME` tokens spelling out the
    marker text on those versions. AST-based matching closes this on every version:
    <3.12 fails to parse at all; 3.12+ parses it into a nested string `Constant`,
    never a `FunctionDef`/`Assign`."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_v{i} = f"{{"{m}"}}"' for i, m in enumerate(_OWN_ENGINE_MARKERS)]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─────────────────────────────────────────────────── item 2: the marker forgery

def test_comment_only_markers_do_not_grant_own_source_identity(tmp_path):
    """The oracle itself: three commented-out marker lines are not real engine code."""
    d = tmp_path / "clawseccheck"
    _plant_comment_only_spoof(d)
    assert _is_own_source(d) is False


def test_real_marker_code_still_grants_own_source_identity(tmp_path):
    """Non-regression: real `def`/assignment statements shaped like the genuine
    engine's own definitions are recognised via AST structure."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    (pkg / "_engine.py").write_text(
        "\n".join(_OWN_ENGINE_MARKER_STATEMENTS), encoding="utf-8"
    )
    assert _is_own_source(d) is True


def test_mixed_comment_and_code_still_recognised(tmp_path):
    """A marker repeated in a comment ELSEWHERE in the file must not blind the real
    definition — a comment mentioning a name is not an AST node with that name."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    lines = [f"# see {_OWN_ENGINE_MARKERS[0]} below", *_OWN_ENGINE_MARKER_STATEMENTS]
    (pkg / "_engine.py").write_text("\n".join(lines), encoding="utf-8")
    assert _is_own_source(d) is True


def test_planting_the_spoof_beside_a_real_malicious_skill_does_not_cloak_it(tmp_path):
    """End-to-end reproduction from the ticket: copy a real DO-NOT-INSTALL fixture,
    plant the three-comment-line spoof inside it, and confirm the verdict does not
    flip to INSTALL / Danger PASS."""
    assert _ENVTOOLS.is_dir(), "fixture layout moved; update this path"
    target = tmp_path / "envtools"
    shutil.copytree(_ENVTOOLS, target)

    # Non-vacuity: the unmodified copy is genuinely convicted.
    baseline = vet_skill(target)
    baseline_profile = build_profile(baseline, str(target), "skill")
    assert baseline_profile.verdict == "DO-NOT-INSTALL", (
        f"fixture must be malicious before the spoof is added: {baseline_profile.verdict}"
    )

    _plant_comment_only_spoof(target)
    assert _is_own_source(target) is False, (
        "the planted file must not grant own-source identity to the malicious tree"
    )

    finding = vet_skill(target)
    assert _SELF_SOURCE_PHRASE not in finding.detail, (
        f"own-source short-circuit fired on a target that is not our engine: {finding.detail!r}"
    )
    profile = build_profile(finding, str(target), "skill")
    assert profile.verdict == "DO-NOT-INSTALL", (
        f"planting a 3-line comment file must not cloak a real malicious skill as "
        f"INSTALL: verdict={profile.verdict!r}"
    )
    assert _axis(profile, "danger").status == FAIL


# ──────────────────────────────────── item 2 (continued): the other forgery shapes

def test_inline_comment_markers_do_not_grant_own_source_identity(tmp_path):
    """The exact C-135 rejection repro: markers trailing real, unrelated statements."""
    d = tmp_path / "clawseccheck"
    _plant_inline_comment_spoof(d)
    assert _is_own_source(d) is False


def test_semicolon_comment_markers_do_not_grant_own_source_identity(tmp_path):
    d = tmp_path / "clawseccheck"
    _plant_semicolon_comment_spoof(d)
    assert _is_own_source(d) is False


def test_string_literal_markers_do_not_grant_own_source_identity(tmp_path):
    d = tmp_path / "clawseccheck"
    _plant_string_literal_spoof(d)
    assert _is_own_source(d) is False


def test_docstring_markers_do_not_grant_own_source_identity(tmp_path):
    d = tmp_path / "clawseccheck"
    _plant_docstring_spoof(d)
    assert _is_own_source(d) is False


def test_fstring_markers_do_not_grant_own_source_identity(tmp_path):
    """A plain f-string VALUE (`f"def vet_skill"`) is a `JoinedStr`/`Constant` node,
    never a `FunctionDef`/`Assign` — not real code no matter how it lexes on any
    Python version."""
    d = tmp_path / "clawseccheck"
    _plant_fstring_spoof(d)
    assert _is_own_source(d) is False


def test_nested_same_quote_fstring_markers_do_not_grant_own_source_identity(tmp_path):
    """A same-quote NESTED f-string (`f"{"def vet_skill"}"`) is not valid Python on
    any version (PEP 701's same-quote-nesting allowance is 3.12+ syntax only; on
    3.9-3.11 this is a SyntaxError). Must resolve False on every supported version:
    on <3.12 the file fails to PARSE at all (fail-closed); on 3.12+ it parses, but the
    marker text is just a nested string `Constant`, never a `FunctionDef`/`Assign`."""
    d = tmp_path / "clawseccheck"
    _plant_nested_fstring_spoof(d)
    assert _is_own_source(d) is False


def test_mixed_string_and_code_still_recognised(tmp_path):
    """A marker repeated inside a STRING elsewhere in the file must not blind the
    real definition — a string VALUE is not an AST node with that name."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_decoy = "{_OWN_ENGINE_MARKERS[0]}"', *_OWN_ENGINE_MARKER_STATEMENTS]
    (pkg / "_engine.py").write_text("\n".join(lines), encoding="utf-8")
    assert _is_own_source(d) is True


def test_unparsable_source_fails_closed_not_open(tmp_path):
    """A source that does not PARSE (an unterminated triple-quoted string) must
    contribute NO markers — never fall back to any weaker text-based match. This is
    the same fail-closed direction that makes the nested-f-string shape safe: a
    source that cannot be parsed as real code cannot be credited with real code."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    broken = "\n".join(f"# {m}" for m in _OWN_ENGINE_MARKERS) + '\nx = """unterminated\n'
    (pkg / "x.py").write_text(broken, encoding="utf-8")
    assert _is_own_source(d) is False


def test_planting_the_inline_comment_spoof_beside_a_real_malicious_skill_does_not_cloak_it(
    tmp_path,
):
    """End-to-end reproduction of the C-135 rejection: copy the real DO-NOT-INSTALL
    `envtools` fixture, plant the inline-comment spoof inside it (three real
    statements, each with a trailing comment carrying a marker — no comment-only
    line among them), and confirm the verdict does not flip to INSTALL / Danger PASS.

    This is the shape the shipped round-1 fix (whole-line `#` stripping) missed: it
    only strips a line that STARTS with `#`, and none of these do.
    """
    assert _ENVTOOLS.is_dir(), "fixture layout moved; update this path"
    target = tmp_path / "envtools"
    shutil.copytree(_ENVTOOLS, target)

    baseline = vet_skill(target)
    baseline_profile = build_profile(baseline, str(target), "skill")
    assert baseline_profile.verdict == "DO-NOT-INSTALL", (
        f"fixture must be malicious before the spoof is added: {baseline_profile.verdict}"
    )

    _plant_inline_comment_spoof(target)
    assert _is_own_source(target) is False, (
        "the planted inline-comment file must not grant own-source identity to the "
        "malicious tree"
    )

    finding = vet_skill(target)
    assert _SELF_SOURCE_PHRASE not in finding.detail, (
        f"own-source short-circuit fired on a target that is not our engine: {finding.detail!r}"
    )
    profile = build_profile(finding, str(target), "skill")
    assert profile.verdict == "DO-NOT-INSTALL", (
        f"planting three inline-commented marker lines must not cloak a real "
        f"malicious skill as INSTALL: verdict={profile.verdict!r}"
    )
    assert _axis(profile, "danger").status == FAIL


def test_planting_the_nested_fstring_spoof_beside_a_real_malicious_skill_does_not_cloak_it(
    tmp_path,
):
    """End-to-end: copy the real DO-NOT-INSTALL `envtools` fixture, plant the
    same-quote nested-f-string spoof inside it, and confirm the verdict does not flip
    to INSTALL / Danger PASS on this interpreter."""
    assert _ENVTOOLS.is_dir(), "fixture layout moved; update this path"
    target = tmp_path / "envtools"
    shutil.copytree(_ENVTOOLS, target)

    baseline_profile = build_profile(vet_skill(target), str(target), "skill")
    assert baseline_profile.verdict == "DO-NOT-INSTALL", (
        f"fixture must be malicious before the spoof is added: {baseline_profile.verdict}"
    )

    _plant_nested_fstring_spoof(target)
    assert _is_own_source(target) is False, (
        "the planted nested-f-string file must not grant own-source identity to the "
        "malicious tree"
    )

    finding = vet_skill(target)
    assert _SELF_SOURCE_PHRASE not in finding.detail, (
        f"own-source short-circuit fired on a target that is not our engine: {finding.detail!r}"
    )
    profile = build_profile(finding, str(target), "skill")
    assert profile.verdict == "DO-NOT-INSTALL", (
        f"planting the nested-f-string spoof must not cloak a real malicious skill "
        f"as INSTALL: verdict={profile.verdict!r}"
    )
    assert _axis(profile, "danger").status == FAIL


# ────────────────────────────────────────────── item 1: the false "danger ran" claim

def test_self_source_wording_no_longer_claims_the_danger_axis_ran():
    """The real repo root (genuinely own source) must not claim danger "ran" in the
    text explaining why the other four axes are unmeasured, and danger's own PASS
    reason must not claim a completed scan either."""
    finding = vet_skill(_REPO)
    assert _SELF_SOURCE_PHRASE in finding.detail, (
        f"the real repo root must trip _is_own_source: {finding.detail!r}"
    )
    profile = build_profile(finding, str(_REPO), "skill")

    danger = _axis(profile, "danger")
    assert danger.status == PASS
    assert "no malware signature or known-bad indicator" not in danger.reason, (
        "danger's self-source PASS must not claim a completed scan: "
        f"{danger.reason!r}"
    )
    assert "scan" in danger.reason and "not" in danger.reason.lower(), danger.reason

    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN
        assert "only the danger axis ran" not in axis.reason, (
            f"{name}: still claims the danger axis ran when nothing ran: {axis.reason!r}"
        )
        assert "danger axis ran" not in axis.reason, axis.reason


# ────────────────────────────────────────────────── the performance short-circuit

def test_is_own_source_skips_files_that_cannot_contain_a_missing_marker(monkeypatch):
    """Deterministic (call-count, not timing) regression guard: `ast.parse` is the
    expensive step, so `_is_own_source` must never call it on a file whose RAW text
    holds none of the still-missing markers' identifiers. Against the real `checks/`
    package, 5 of 11 files mention `vet_skill`/`check_installed_skills` at all
    (including plain imports/re-exports that never define them) and so get parsed;
    the other 6 — including several of the largest — must never be."""
    import ast as _ast_mod

    calls = []
    real_parse = _ast_mod.parse

    def _counting_parse(source, *args, **kwargs):
        calls.append(source)
        return real_parse(source, *args, **kwargs)

    monkeypatch.setattr(_ast_mod, "parse", _counting_parse)
    assert _collector_mod._is_own_source(_REPO) is True
    assert len(calls) <= 5, (
        f"expected at most 5 files parsed against the real package, got {len(calls)}"
    )


def test_is_own_source_is_not_pathologically_slow_against_the_real_package():
    """Loose timing sanity check, generous enough not to flake on a slow runner:
    parsing every file in the real `checks/` package unconditionally (no
    short-circuit) would cost well over a second; measured with the short-circuit in
    place, the real repo root (a directory that genuinely impersonates our layout)
    costs well under a second on both supported Python versions. This asserts
    comfortably above that measured cost, so it only fails if the short-circuit
    regresses back toward "parse everything" — the call-count test above is the
    precise guard for that."""
    _is_own_source(_REPO)  # warm the filesystem cache before timing
    t0 = time.perf_counter()
    assert _is_own_source(_REPO) is True
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, (
        f"_is_own_source took {elapsed:.3f}s against the real repo root — the "
        f"short-circuit may have regressed (measured ~0.26-0.39s with it working)"
    )


class TestOversizedEngineSourceIsSkippedWhole:
    """B-846 round 5, C-135 follow-up: an oversized .py must not cost a parse.

    `_is_own_source` runs per candidate skill directory during discovery, and the AST
    round made each call a real `ast.parse` rather than a text scan. Planting one huge
    .py under `<root>/clawseccheck/checks/` in any real skill root would otherwise make
    every later audit and every --monitor run pay a parse proportional to its size. The
    C-135 reviewer measured ~3s against sub-ms. It is a denial-of-audit surface, not an
    identity forgery -- but it is unbounded, so it is capped.
    """

    def test_a_file_over_the_cap_is_skipped_and_costs_no_parse(self, tmp_path):
        checks = tmp_path / "clawseccheck" / "checks"
        checks.mkdir(parents=True)
        oversized = "x = 1  # " + ("p" * (_MAX_OWN_SOURCE_BYTES + 1_000)) + "\n"
        (checks / "decoy.py").write_text(oversized, encoding="utf-8")
        (checks / "engine.py").write_text(
            "\n".join(_OWN_ENGINE_MARKER_STATEMENTS), encoding="utf-8"
        )

        start = time.perf_counter()
        assert _is_own_source(tmp_path) is True
        elapsed = time.perf_counter() - start

        # Generous: the point is that the decoy is not parsed at all, which is orders of
        # magnitude below the ~3s the reviewer measured without the cap.
        assert elapsed < 1.0, f"the oversized decoy was parsed after all ({elapsed:.2f}s)"

    def test_skipping_an_oversized_file_fails_in_the_safe_direction(self, tmp_path):
        """If the ONLY copy of a marker sits in an oversized file, the answer is False.

        That costs recognition of a tree that really is ours, never a false identity --
        the tree then gets scanned, which is the safe way to be wrong.
        """
        checks = tmp_path / "clawseccheck" / "checks"
        checks.mkdir(parents=True)
        markers = list(_OWN_ENGINE_MARKER_STATEMENTS)
        (checks / "engine.py").write_text("\n".join(markers[:-1]), encoding="utf-8")
        padding = "# " + ("p" * (_MAX_OWN_SOURCE_BYTES + 1_000)) + "\n"
        (checks / "big.py").write_text(padding + markers[-1], encoding="utf-8")

        assert _is_own_source(tmp_path) is False
