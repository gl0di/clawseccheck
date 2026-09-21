"""B-777 — `--vet` on ClawSecCheck's own tree silently dropped the whole content ring.

`checks/_vet.py::_vet_resolved_skill` short-circuits on `_is_own_source(p)` (a security
auditor's own attack-signature database would otherwise flag itself as malware) and
returns a single B13 PASS `Finding` — no `read_skill_python`/`read_skill_shell`/
`read_skill_js` ever ran, so `ctx` never gained the fields `dossier.build_profile` reads
to decide measurability. Before this fix that produced two false claims on the SAME
dossier:

    Build quality  PASS     no least-privilege, pinning, or authoring-hygiene issue found
    Behavior       PASS     no override, jailbreak, or forged-provenance directive found
    Persistence    UNKNOWN  no executable code to analyze for staged / persistent behavior
    Connections    UNKNOWN  no executable code to analyze for outbound connections

"no executable code to analyze" is a claim about the ARTIFACT (B-628) and it was false —
code is present, in quantity (ClawSecCheck's own ~7,000-line engine). And the build/
behavior PASSes were unearned: nothing in that text was ever read either. The fix adds a
fourth `_unmeasurable_reason` state (`self_source`) and routes every axis but "danger" to
it whenever `build_profile`'s `target` basename appears in `ctx.self_excluded_skills` —
the same field report.py's `--emit-manifest` self-exclusion note already reads (B-786).

**The severe half of the original report — a verdict FLIP, not just a wording bug — was a
bisection inside `checks/_vet.py` itself**: a target built from SKILL.md + audit.py +
`clawseccheck/__init__.py` + a PREFIX of `_vet.py` flipped from DO-NOT-INSTALL (B13 FAIL)
to INSTALL (B13 PASS) the moment the prefix grew to include the literal text
`"def vet_skill"` — the second of `_OWN_ENGINE_MARKERS`'s three required substrings
(`collector.py`), the other two ("def check_installed_skills", "_SKILL_CRIT") sitting
well earlier in the file. Below that line, `_is_own_source` reads False and the huge
self-similar chunk gets scanned for real (and — being full of attack-signature strings
that are ClawSecCheck's OWN detection literals — convicts). At and above that line, it
reads True and the self-source short-circuit fires.

The original report pinned this at literal line numbers (head -6178 / head -6186), which
were already STALE by the time this fix landed (`def vet_skill` now sits at a different
line — the file grew ~950 lines in the interim). Hardcoding either number would have
pinned a boundary that no longer exists. `test_marker_boundary_flips_self_exclusion`
instead LOCATES the real marker line in the live `checks/_vet.py` source at test time and
bisects exactly one line either side of it — pinning the MECHANISM (one marker line
flips `_is_own_source`) rather than a number that drifts with every edit to the file.

Both tests are offline and read/write only `tmp_path` / bundled fixtures.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import _is_own_source
from clawseccheck.dossier import build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "fixtures"
_VET_SRC = _REPO / "clawseccheck" / "checks" / "_vet.py"

_NO_CODE = "no executable code to analyze"
_SELF_SOURCE_PHRASE = "This is ClawSecCheck's own source"


def _axis(profile, name):
    for a in profile.axes:
        if a.axis == name:
            return a
    raise AssertionError(f"axis {name!r} not in profile")


# ─────────────────────────────────────────────────────────── the wording defect itself

def test_self_scan_fixture_axes_are_honest_not_no_code_or_unearned_pass():
    """The bundled genuine-own-source fixture (B-265's own `clean_ownname_genuine_
    clawseccheck/.../skills/clawseccheck`) must produce a self-source disclosure on
    every axis but danger — never the false "no executable code" claim, and never an
    unearned PASS on build/behavior for text that was never read.
    """
    target = (
        _FIXTURES / "clean_ownname_genuine_clawseccheck" / "workspace-home"
        / "skills" / "clawseccheck"
    )
    assert target.is_dir(), "fixture layout moved; update this path"
    finding = vet_skill(target)
    assert _SELF_SOURCE_PHRASE in finding.detail, (
        "non-vacuity: this fixture must actually trip _is_own_source, or every "
        f"assertion below passes for the wrong reason — detail={finding.detail!r}"
    )

    profile = build_profile(finding, str(target), "skill")
    danger = _axis(profile, "danger")
    assert danger.status == PASS, danger.reason

    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, (
            f"{name} must be UNKNOWN (unmeasured), not a PASS earned by text this scan "
            f"never read: status={axis.status} reason={axis.reason!r}"
        )
        assert _NO_CODE not in axis.reason, (
            f"{name} denies the existence of code that is, in fact, present in "
            f"quantity (B-628): {axis.reason!r}"
        )
        assert "own source" in axis.reason, (
            f"{name} must name WHY it is unmeasured (self-source policy), not a bare "
            f"unmeasurable fallback: {axis.reason!r}"
        )


def test_self_scan_on_the_real_repo_root_is_honest():
    """End-to-end, not a trace: `--vet-skill` on ClawSecCheck's own checked-out tree —
    the exact repro from the bug report (`--vet-skill .`) — via its resolved absolute
    path (`vet_skill` and `build_profile` must agree on the SAME basename either way;
    see the dot-target unit test below for the literal `.` form).
    """
    finding = vet_skill(_REPO)
    assert _SELF_SOURCE_PHRASE in finding.detail, (
        f"the real repo root must trip _is_own_source: {finding.detail!r}"
    )
    profile = build_profile(finding, str(_REPO), "skill")
    assert _axis(profile, "danger").status == PASS
    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN
        assert _NO_CODE not in axis.reason, axis.reason


def test_dot_target_basename_matches_the_empty_string_self_exclusion_records():
    """`Path(".").name == ""` — `resolve_skill_target`/`_is_own_source` record that empty
    string verbatim on `ctx.self_excluded_skills` (B-777's own investigation: a first fix
    attempt fell back to `str(target)` ("." ) when the computed name was empty, which
    silently NEVER matched the "" `_is_own_source` actually appended, and the bug
    reproduced unchanged). Pinned directly against `build_profile`, without a real scan,
    since the point is the string-matching logic, not the scanner.
    """
    ctx = SimpleNamespace(self_excluded_skills=[""])
    finding = SimpleNamespace(status=PASS, id="B13", detail="x", ctx=ctx)
    profile = build_profile(finding, ".", "skill")
    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, (
            f"a '.' target must resolve the same self-exclusion a named directory "
            f"target does: {name}={axis.status} {axis.reason!r}"
        )
        assert _NO_CODE not in axis.reason, axis.reason


# ─────────────────────────────────────────────── the verdict-flip bisection (severe half)

def _own_engine_markers_before_and_after():
    """Locate the live `vet_skill` function in the real `checks/_vet.py` and return
    (before_prefix, after_prefix) — the file's own text up to, and up to the end of,
    that function. Dynamic on purpose: the original report's line numbers (6178/6186)
    are already stale (the file has grown substantially since), and a hardcoded pin
    would silently stop testing the real boundary the day it next moves.

    `_is_own_source` matches AST structure (B-846), so the boundary that flips it is
    the whole `vet_skill` FunctionDef, not merely its signature line — a bare
    signature with no body is not valid Python at all. Found via the file's own AST
    (`end_lineno`), not a hardcoded line count, so this keeps tracking the true
    boundary as the file grows.
    """
    text = _VET_SRC.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    marker_idx = next(
        i for i, line in enumerate(lines)
        if "def vet_skill(path: str | Path) -> Finding:" in line
    )
    # Sanity: the other two _OWN_ENGINE_MARKERS strings must already sit earlier in the
    # file, or this bisection would not isolate a single boundary.
    before_text = "".join(lines[:marker_idx])
    assert "def check_installed_skills" in before_text
    assert "_SKILL_CRIT" in before_text
    assert "def vet_skill" not in before_text
    tree = ast.parse(text)
    vet_skill_def = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "vet_skill"
    )
    after_text = "".join(lines[:vet_skill_def.end_lineno])
    assert "def vet_skill" in after_text
    return before_text, after_text


def _build_partial_own_source_tree(root: Path, vet_py_content: str) -> Path:
    (root / "clawseccheck" / "checks").mkdir(parents=True)
    (root / "clawseccheck" / "checks" / "_vet.py").write_text(vet_py_content, encoding="utf-8")
    (root / "clawseccheck" / "__init__.py").write_text("", encoding="utf-8")
    (root / "audit.py").write_text("import sys\nsys.path.insert(0, '.')\n", encoding="utf-8")
    (root / "SKILL.md").write_text("---\nname: clawseccheck\n---\n# ClawSecCheck\n", encoding="utf-8")
    return root


def test_marker_boundary_flips_self_exclusion(tmp_path):
    """The complete `vet_skill` function definition flips `_is_own_source`, and
    the dossier must stay honest on BOTH sides of that boundary:

      * below the marker: a real scan runs (the chunk is genuinely not our whole engine,
        just a same-shaped fragment) and must not silently read as a clean self-source
        skip — the verdict must NOT be the false "own source" PASS.
      * at/above the marker: `_is_own_source` correctly recognises the fragment as
        carrying our engine's identity and short-circuits — and must disclose that
        honestly (B-777's fix), never as "no executable code to analyze" over content
        that — one line up — was just scanned and convicted.

    This is deliberately end-to-end over real `_vet.py` bytes, not a trace: the original
    defect was a property of this file's actual content, and a synthetic stand-in would
    not have reproduced it. The "before" run reads ~6,400 real lines and takes on the
    order of 20-30s — see the module docstring.
    """
    before_text, after_text = _own_engine_markers_before_and_after()

    below = _build_partial_own_source_tree(tmp_path / "below", before_text)
    assert _is_own_source(below) is False, (
        "non-vacuity: the fragment below the marker must NOT read as our own source, or "
        "the 'real scan ran' half of this test is checking nothing"
    )
    below_finding = vet_skill(below)
    assert _SELF_SOURCE_PHRASE not in below_finding.detail, below_finding.detail

    above = _build_partial_own_source_tree(tmp_path / "above", after_text)
    assert _is_own_source(above) is True, (
        "non-vacuity: the fragment at/above the marker must read as our own source, or "
        "the self-exclusion half of this test is checking nothing"
    )
    above_finding = vet_skill(above)
    assert _SELF_SOURCE_PHRASE in above_finding.detail, above_finding.detail

    above_profile = build_profile(above_finding, str(above), "skill")
    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(above_profile, name)
        assert axis.status == UNKNOWN, (
            f"{name} must be an honest UNKNOWN on the self-excluded side of the "
            f"boundary: {axis.status} {axis.reason!r}"
        )
        assert _NO_CODE not in axis.reason, (
            f"{name} must not deny the code that the 'below' scan, one line down, just "
            f"read and convicted: {axis.reason!r}"
        )
