"""B-846 — second-pass review of B-777 found two open defects in the self-source
`--vet` path (`checks/_vet.py::_vet_resolved_skill` short-circuiting on
`collector._is_own_source`):

1. **False claim about what ran.** `dossier._unmeasurable_reason`'s `self_source`
   branch told the reader "only the danger axis ran, by design" — but nothing ran at
   all: `_vet_resolved_skill` returns a canned B13 PASS `Finding` before any
   `read_skill_python`/`read_skill_shell`/`read_skill_js` call. The danger axis's own
   PASS reason ("no malware signature or known-bad indicator") made the identical
   false claim on its own axis line. Both now say nothing was scanned; danger's PASS
   is a policy default, not a completed scan.

2. **Forgeable identity.** `_is_own_source` matched `_OWN_ENGINE_MARKERS` as a bare
   substring test with no regard for whether the match was real code or a comment. A
   single file containing only three `#`-commented lines of marker text —
   `# def check_installed_skills` / `# def vet_skill` / `# _SKILL_CRIT` — satisfied
   it, so an attacker could plant that one file alongside a genuinely malicious skill
   and have the WHOLE tree recognised as "ClawSecCheck's own source" and skipped:
   measured turning a real DO-NOT-INSTALL fixture into INSTALL / Danger PASS. Whole-
   comment lines are now stripped before matching.

3. **ROUND 2 (a C-135 reviewer broke round 1).** Stripping only comment-ONLY lines
   left every OTHER zero-cost way to carry marker-shaped bytes wide open: an
   inline/trailing comment on a real statement (`a = 1  # def vet_skill` — not a
   comment-only line at all), a comment after a `;`, a marker inside a string
   literal, or one inside a multi-line docstring. Reproduced end-to-end exactly like
   item 2 — planting three such lines beside the real `envtools` fixture still flipped
   DO-NOT-INSTALL to INSTALL / Danger PASS. Fixed by tokenizing each candidate source
   with the stdlib `tokenize` module (the real Python lexer) and blanking every
   COMMENT and STRING token before matching, which closes all four shapes in one fix
   because none of them are actual code the genuine engine needs.

4. **ROUND 3.** Round 2's blanking only knew about `tokenize.COMMENT` and
   `tokenize.STRING`. On Python 3.12+, PEP 701 changed f-string tokenizing: an
   f-string is no longer one `STRING` token — `f"def vet_skill"` becomes
   `FSTRING_START`/`FSTRING_MIDDLE`/`FSTRING_END`, and the literal text lives in
   `FSTRING_MIDDLE`. Reproduced on python3.12.3 exactly like round 2's repro (three
   `f"..."`-wrapped markers beside `envtools`); confirmed the SAME source was never
   vulnerable on python3.9.25, where an f-string still tokenizes as one ordinary
   `STRING` token. Fixed by adding `FSTRING_MIDDLE` to the blanked set via
   `getattr(tokenize, "FSTRING_MIDDLE", None)` (absent before 3.12; this project
   supports 3.9+, and CI runs both).

5. **ROUND 4 (performance, no behaviour change).** Rounds 2-3's blanking
   unconditionally tokenized every engine source file on every `_is_own_source` call.
   Measured against the real repo root's `checks/` package (~3.4M characters across
   11 files) on python3.12.3: ~1.08s/call, against ~8ms before round 2. Fixed with two
   short-circuits in `_is_own_source` (see its code comment for the correctness
   argument): skip tokenizing a file when none of the still-missing markers appear in
   its RAW text, and stop once every marker is accounted for. Only `_vet.py` and
   `__init__.py` end up tokenized against the real package. Measured after this
   round: ~0.18s/call (~6x faster). The residual cost is tokenizing `_vet.py` itself,
   which genuinely carries the markers and so cannot be skipped without weakening
   the check.

Every test below is offline and reads/writes only `tmp_path` / bundled fixtures.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from clawseccheck import collector as _collector_mod
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import _OWN_ENGINE_MARKERS, _is_own_source
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
    """The C-135 ROUND-2 repro: each marker trails a real, unrelated statement — NOT a
    comment-only line, so a strip that only drops whole `#` lines misses every one."""
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
    """B-846 ROUND 3: markers as f-string VALUES. On Python 3.12+ (PEP 701) an
    f-string does not tokenize as a single STRING token the way it did on 3.9-3.11 —
    it becomes FSTRING_START/FSTRING_MIDDLE/FSTRING_END, and the literal text lives in
    FSTRING_MIDDLE. A strip that only blanks COMMENT/STRING misses it on 3.12+ while
    (coincidentally) already closing it on 3.9-3.11, where this exact source tokenizes
    the same way `_plant_string_literal_spoof`'s does."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_v{i} = f"{m}"' for i, m in enumerate(_OWN_ENGINE_MARKERS)]
    (pkg / "x.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ──────────────────────────────────────────────────── item 2: the marker forgery

def test_comment_only_markers_do_not_grant_own_source_identity(tmp_path):
    """The oracle itself: three commented-out marker lines are not real engine code."""
    d = tmp_path / "clawseccheck"
    _plant_comment_only_spoof(d)
    assert _is_own_source(d) is False


def test_real_marker_code_still_grants_own_source_identity(tmp_path):
    """Non-regression: the SAME markers as real (uncommented) statements still work —
    this closes the forgery without narrowing genuine recognition."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    (pkg / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")
    assert _is_own_source(d) is True


def test_mixed_comment_and_code_still_recognised(tmp_path):
    """A marker repeated in a comment ELSEWHERE in the file must not blind the real,
    uncommented occurrence — stripping comment lines must not go too far the other way."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    lines = [f"# see {_OWN_ENGINE_MARKERS[0]} below", *_OWN_ENGINE_MARKERS]
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


# ────────────────────────────────────── item 3 (C-135 ROUND 2): the four other shapes

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
    """B-846 ROUND 3 — the exact C-135 rejection: on Python 3.12+ an f-string's
    literal text is a FSTRING_MIDDLE token, not STRING, so a strip that only knows
    about STRING/COMMENT lets this shape straight through."""
    d = tmp_path / "clawseccheck"
    _plant_fstring_spoof(d)
    assert _is_own_source(d) is False


def test_mixed_string_and_code_still_recognised(tmp_path):
    """A marker repeated inside a STRING elsewhere in the file must not blind the
    real, uncommented occurrence — blanking strings must not go too far the other way."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    lines = [f'_decoy = "{_OWN_ENGINE_MARKERS[0]}"', *_OWN_ENGINE_MARKERS]
    (pkg / "_engine.py").write_text("\n".join(lines), encoding="utf-8")
    assert _is_own_source(d) is True


def test_unterminated_string_fails_closed_not_open(tmp_path):
    """A source that does not tokenize (an unterminated triple-quoted string) must
    contribute NO marker text — never fall back to raw, unstripped bytes. Falling
    back to raw text would hand an attacker a trivial bypass: break tokenizing on
    purpose, then plant forged comment markers anywhere else in the same file."""
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


# ────────────────────────────────────── item 5 (ROUND 4): the performance regression

def test_is_own_source_skips_files_that_cannot_contain_a_missing_marker(monkeypatch):
    """Deterministic (call-count, not timing) regression guard: tokenizing is the
    expensive step, so `_is_own_source` must never call `_strip_comments_and_strings`
    on a file whose RAW text holds none of the still-missing markers. Against the
    real `checks/` package only `_vet.py` (the markers' actual home) and `__init__.py`
    (which imports `_SKILL_CRIT` by name) contain any marker text at all — the other
    9 files, including the two largest, must never be tokenized."""
    calls = []
    real_strip = _collector_mod._strip_comments_and_strings

    def _counting_strip(text):
        calls.append(text)
        return real_strip(text)

    monkeypatch.setattr(_collector_mod, "_strip_comments_and_strings", _counting_strip)
    assert _collector_mod._is_own_source(_REPO) is True
    assert len(calls) <= 2, (
        f"expected at most 2 files tokenized against the real package, got {len(calls)}"
    )


def test_is_own_source_is_not_pathologically_slow_against_the_real_package():
    """Loose timing sanity check, generous enough not to flake on a slow runner: the
    pre-round-4 regression measured ~1.08s/call against the real repo root on
    python3.12.3 (tokenizing all 11 files unconditionally); post-fix measured ~0.18s.
    This asserts comfortably below the pre-fix number, not at the post-fix number, so
    it only fails if the short-circuit above regresses back toward "tokenize
    everything" — the call-count test above is the precise guard for that."""
    _is_own_source(_REPO)  # warm the filesystem cache before timing
    t0 = time.perf_counter()
    assert _is_own_source(_REPO) is True
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.6, (
        f"_is_own_source took {elapsed:.3f}s against the real repo root — the "
        f"ROUND 4 short-circuit may have regressed (pre-fix was ~1.08s, post-fix "
        f"~0.18s)"
    )
