"""B-628: a plugin must not claim there is no code to analyze while describing that code.

`dossier.build_profile` asked one question of `pool[0]` alone:

    ctx = getattr(pool[0], "ctx", None) if pool else None
    has_code, families = _skill_capabilities(ctx)

On the skill path that is the whole story — `pool[0]` is `vet_skill`'s primary and
`checks/_vet.py` sets `primary.ctx = ctx` on it. On the PLUGIN path `pool[0]` is the
`PLUGIN-VET` container built by `_plugin_finding`, which never sets `.ctx`. So `has_code`
was False **by construction for every plugin ever vetted**, and the Persistence and
Connections axes printed a sentence about the artifact that was really a property of a
missing attribute.

Measured before the fix, on byte-identical content, one skill vetted twice:

    --vet-skill   Persistence  PASS     no dormant or staged code detected
                  Connections  PASS     outbound network calls present; no connection-axis
                                        finding fired
    --vet-plugin  Persistence  UNKNOWN  no executable code to analyze for staged /
                                        persistent behavior
                  Connections  UNKNOWN  no executable code to analyze for outbound
                                        connections

— four lines below a Danger FAIL naming `scripts/post_install.py:18`. The same dossier
denied the code existed and quoted it.

This is UNKNOWN-on-dirty-content, not the B-614 lying-PASS class, so the direction was
conservative; what was false is the stated REASON, on a surface whose entire job is the
install decision.

**What the fix deliberately does not touch.** `build_profile`'s `ctx` variable still points
at `pool[0]` for its two other consumers (`assessed`, `_danger_coverage_gap`). Those are
blind on the plugin path for the same missing-attribute reason, but changing them moves a
score cap rather than a sentence — a separate change needing its own measurement.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_plugin, vet_skill
from clawseccheck.checks._mcp import _plugin_finding
from clawseccheck.checks._vet import coverage_gap_finding
from clawseccheck.dossier import _normalize_pool, _pool_capabilities, build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "fixtures"
_EMPTY_SCHEMA = {"type": "object", "additionalProperties": False}

_NO_CODE = "no executable code to analyze"


def _bundle(dest: Path) -> Path:
    """The shipped fetch-to-exec fixture: real Python whose danger finding proves it was read."""
    shutil.copytree(_FIXTURES / "bad_b13_fetch_to_exec" / "skills" / "bootstrap-helper", dest)
    for p in dest.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    return dest


def _manifest(root: Path) -> None:
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"id": "demo", "configSchema": _EMPTY_SCHEMA, "skills": ["skills"]}),
        encoding="utf-8",
    )
    os.chmod(root / "openclaw.plugin.json", 0o600)


def _plugin_with_python(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _bundle(root / "skills" / "bootstrap-helper")
    _manifest(root)
    return root


def _plugin_prose_only(root: Path) -> Path:
    d = root / "skills" / "docs-only"
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        "---\nname: docs-only\ndescription: Documentation only, no scripts at all.\n---\n\n"
        "# Docs only\n\nThis skill ships prose and nothing else.\n",
        encoding="utf-8",
    )
    os.chmod(d / "SKILL.md", 0o600)
    _manifest(root)
    return root


def _axis(profile, name):
    for a in profile.axes:
        if a.axis == name:
            return a
    raise AssertionError(f"axis {name!r} not in profile")


def test_a_plugin_bundling_python_does_not_claim_there_is_no_code(tmp_path):
    """The defect itself — and the non-vacuity control that makes the assertion mean something."""
    root = _plugin_with_python(tmp_path / "plug")
    profile = build_profile(vet_plugin(root), str(root), "plugin")

    danger = _axis(profile, "danger")
    assert danger.status == FAIL, (
        "non-vacuity: this plugin's bundled Python must have been READ and convicted, "
        "or the axes below would honestly have nothing to measure and the test would "
        f"pass for the wrong reason (danger={danger.status})"
    )
    assert "post_install.py" in danger.reason, danger.reason

    for name in ("persistence", "connections"):
        assert _NO_CODE not in _axis(profile, name).reason, (
            f"{name} denies the existence of the code the danger axis just quoted: "
            f"{_axis(profile, name).reason}"
        )


def test_b_plugin_and_skill_agree_on_the_same_bytes(tmp_path):
    """Identical content vetted twice must not produce two different answers."""
    solo = _bundle(tmp_path / "solo")
    root = _plugin_with_python(tmp_path / "plug")

    as_skill = build_profile(vet_skill(solo), str(solo), "skill")
    as_plugin = build_profile(vet_plugin(root), str(root), "plugin")

    for name in ("persistence", "connections"):
        assert _axis(as_skill, name).status == PASS, "fixture drifted: the skill path itself moved"
        assert _axis(as_plugin, name).status == _axis(as_skill, name).status, (
            f"{name}: plugin={_axis(as_plugin, name).status} "
            f"skill={_axis(as_skill, name).status} on byte-identical content"
        )


def test_c_a_prose_only_plugin_still_says_there_is_no_code(tmp_path):
    """The negative control. Widening this must never turn 'nothing to look at' into PASS."""
    root = _plugin_prose_only(tmp_path / "prose")
    profile = build_profile(vet_plugin(root), str(root), "plugin")

    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, f"{name} claimed {axis.status} over prose: {axis.reason}"
        assert _NO_CODE in axis.reason, axis.reason


def test_d_fold_reaches_past_a_container_that_carries_no_context():
    """The unit shape: the answer lives on a later pool member, never on pool[0]."""
    with_code = SimpleNamespace(
        installed_skills={"bundled": object()},
        installed_skill_py={"bundled": [("run.py", "import os\nos.system('id')\n")]},
    )
    container = SimpleNamespace(ctx=None)          # PLUGIN-VET: no ctx, ever
    member = SimpleNamespace(ctx=with_code)

    assert _pool_capabilities([container, member])[0] is True, (
        "the fold must reach past the container — this is the whole defect"
    )
    assert _pool_capabilities([container])[0] is False, (
        "a plugin contributing no context at all still answers False, so the honest "
        "UNKNOWN survives"
    )
    assert _pool_capabilities([])[0] is False


def test_e_families_are_the_union_over_every_bundled_context():
    """Two bundled skills, two different capabilities: the plugin has both."""
    net = SimpleNamespace(
        installed_skills={"a": object()},
        installed_skill_py={"a": [("a.py", "import urllib.request\nurllib.request.urlopen('x')\n")]},
    )
    ex = SimpleNamespace(
        installed_skills={"b": object()},
        installed_skill_py={"b": [("b.py", "import os\nos.system('id')\n")]},
    )
    _, families = _pool_capabilities([SimpleNamespace(ctx=net), SimpleNamespace(ctx=ex)])
    only_net = _pool_capabilities([SimpleNamespace(ctx=net)])[1]
    only_ex = _pool_capabilities([SimpleNamespace(ctx=ex)])[1]

    assert only_net and only_ex, "fixture drifted: each context must contribute something"
    assert families == only_net | only_ex, f"{families} != {only_net | only_ex}"


def _plugin_clean_python(root: Path) -> Path:
    """A plugin whose bundled skill ships real Python and vets PASS.

    This is the shape C-135 found the first fix did not reach. `vet_plugin` keeps only
    FAIL/WARN/UNKNOWN sub-findings in `ring_findings`, so a bundled skill that vets clean
    is dropped from the pool with its ctx, and reading `.ctx` alone answered False here —
    the dirty plugin was fixed and the clean one, which is the common case, was not.
    """
    root.mkdir(parents=True, exist_ok=True)
    dest = root / "skills" / "text-tool"
    shutil.copytree(_FIXTURES / "clean_b98_no_risky_effects" / "skills" / "text-tool", dest)
    for p in dest.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    _manifest(root)
    return root


def test_f_a_plugin_bundling_clean_python_is_measured_not_unknown(tmp_path):
    """The C-135 residual: code that vets clean is still code."""
    root = _plugin_clean_python(tmp_path / "clean")
    profile = build_profile(vet_plugin(root), str(root), "plugin")

    assert (root / "skills" / "text-tool" / "tool.py").is_file(), (
        "non-vacuity: this fixture must actually ship Python, or the axes below are "
        "entitled to say there is nothing to measure"
    )
    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == PASS, (
            f"{name} read {axis.status} over a bundled .py file that vets clean: {axis.reason}"
        )
        assert _NO_CODE not in axis.reason, axis.reason


def test_g_a_truncated_scan_is_unknown_and_does_not_deny_the_code(tmp_path):
    """Finding code in one skill must not license a clean claim over an unread one.

    Built from the dossier's own inputs rather than by forcing a time budget: the partial
    window measured on the reviewer's fixture was ~0.02s wide, and a test that keys on
    wall/CPU timing is a flake waiting to happen. What the engine actually hands over in
    that state is a `coverage_gap_finding` (engine_degraded=True) beside a ctx that has
    code — so that is what this builds.
    """
    ctx_with_code = SimpleNamespace(
        installed_skills={"bundled": object()},
        installed_skill_py={"bundled": [("run.py", "import os\nos.system('id')\n")]},
    )
    container = _plugin_finding(  # a real PLUGIN-VET container, not a stand-in
        "HIGH", UNKNOWN, "plugin 'demo': scan incomplete", "Re-run without a budget cap."
    )
    container.bundled_contexts = [ctx_with_code]
    container.ring_findings = [coverage_gap_finding(
        "plugin scan coverage is incomplete: the scan exhausted its per-target time budget"
    )]

    profile = build_profile(container, "demo", "plugin")

    assert _pool_capabilities([container])[0] is True, (
        "non-vacuity: the fold must SEE the code, or this test would pass for the "
        "ordinary no-code reason and prove nothing about truncation"
    )
    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, f"{name} claimed {axis.status} over an unfinished scan"
        assert _NO_CODE not in axis.reason, (
            f"{name} denies code exists when the real reason is an unfinished scan: {axis.reason}"
        )
        assert "cut short" in axis.reason, axis.reason


def test_h_a_truncated_scan_says_so_even_when_no_code_was_established():
    """C-135 round 2, break 1: the wording must not be gated on `has_code`.

    `has_code` is precisely what a truncated scan fails to establish, so gating the
    "scan was cut short" wording on it meant the corner the wording existed for still
    printed "no executable code to analyze". The reviewer reached that state at the
    DEFAULT 900s budget through `vet_plugin`'s 400-file tree-sweep cap — no clock
    pressure at all — with a prose-only bundled skill and real Python in the plugin root.

    Built from the dossier's own inputs rather than by materialising 400+ files: what the
    engine hands over in that state is a VET-COVERAGE UNKNOWN with NO context carrying
    code, and that pair is the whole regression.
    """
    container = _plugin_finding(
        "HIGH", UNKNOWN, "plugin 'demo': content could not be fully swept", "Re-run."
    )
    container.bundled_contexts = []          # nothing established: the scan stopped first
    container.ring_findings = [coverage_gap_finding(
        "plugin scan coverage is incomplete: the tree sweep stopped at the file cap"
    )]

    profile = build_profile(container, "demo", "plugin")

    assert _pool_capabilities([container])[0] is False, (
        "non-vacuity: this test is only meaningful while has_code is False — that is the "
        "branch the first fix could not reach"
    )
    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, f"{name} claimed {axis.status} over a truncated scan"
        assert _NO_CODE not in axis.reason, (
            f"{name} says there is no code when the truth is the scan stopped: {axis.reason}"
        )
        assert "cut short" in axis.reason, axis.reason


def test_i_a_single_unparseable_file_does_not_read_as_a_truncated_scan(tmp_path):
    """C-135 round 2, break 2: `engine_degraded` alone was too wide a predicate.

    B13's parse-error branch sets `engine_degraded` per FILE on a scan that otherwise
    ran to completion. Keying the gate on that flag made an ordinary skill shipping one
    unparseable file report "the scan was cut short" — a fresh false sentence, on the
    path this change claimed not to touch. Measured across all 292 shipped fixture skill
    roots, exactly one flipped that way.

    The predicate is now the synthetic VET-COVERAGE id, whose stated purpose is "part of
    this target was never inspected". A parse error is a per-file gap the danger axis
    reports in its own words; it is not a truncation.
    """
    skill = tmp_path / "weather"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: weather\ndescription: Fetches a forecast.\n---\n\n# Weather\n",
        encoding="utf-8",
    )
    (skill / "fetch.py").write_text(
        "import urllib.request\n\n\ndef go():\n    return urllib.request.urlopen('https://example.com')\n",
        encoding="utf-8",
    )
    (skill / "legacy.py").write_text("print 'python 2 syntax'\n", encoding="utf-8")
    for p in skill.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)

    profile = build_profile(vet_skill(skill), str(skill), "skill")

    danger = _axis(profile, "danger")
    assert danger.status == UNKNOWN and "parse error" in danger.reason, (
        "non-vacuity: the parse gap must actually be present, or this test proves "
        f"nothing about how the gate treats it (danger={danger.status}: {danger.reason})"
    )
    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == PASS, (
            f"{name} read {axis.status} on a scan that COMPLETED — one file failed to "
            f"parse, which the danger axis already reports in its own words: {axis.reason}"
        )
        assert "cut short" not in axis.reason, axis.reason


def _plugin_with_unread_python(root: Path, *, at_root: bool) -> Path:
    """A clean bundled skill, plus a dangerous .py that NOTHING in the plugin vet reads.

    The sweep analyses .json (embedded MCP specs), sniffs for native stowaways, and
    lexically scans _PLUGIN_JS_EXT. Python is analysed only inside a dispatched skill
    dir — so this file is opened by no reader at all, whether it sits at the plugin root
    or merely beside the skill dir inside the manifest's `skills` entry.
    """
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        _FIXTURES / "clean_b98_no_risky_effects" / "skills" / "text-tool",
        root / "skills" / "text-tool",
    )
    payload = (
        _FIXTURES / "bad_b13_fetch_to_exec" / "skills" / "bootstrap-helper"
        / "scripts" / "post_install.py"
    )
    dest = (root / "install.py") if at_root else (root / "skills" / "shared_helper.py")
    shutil.copy(payload, dest)
    _manifest(root)
    for p in root.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    return root


def test_j_code_with_no_reader_is_never_an_affirmative_clean_claim(tmp_path):
    """C-135 round 3: the break this gate exists for, measured as INTRODUCED by the fold.

    `has_code` answers "did any analysed context contain Python" — it is not authority to
    assert PASS over the whole artifact. A plugin whose only dangerous file is a
    root-level `install.py` had `has_code=True` from its CLEAN bundled skill, nothing
    truncated, and printed "no dormant or staged code detected" over a file that fetches
    remote code and exec()s it. The reviewer measured both sides: those axes read UNKNOWN
    before the fold and PASS after, so the fold introduced it rather than inheriting it.

    Both placements are covered because they fail for the same reason and a reader might
    assume only the root one does.
    """
    for at_root in (True, False):
        root = _plugin_with_unread_python(tmp_path / f"p{int(at_root)}", at_root=at_root)
        out = vet_plugin(root)
        profile = build_profile(out, str(root), "plugin")

        assert _pool_capabilities(_normalize_pool(out))[0] is True, (
            "non-vacuity: the bundled skill's Python must have been measured, or this "
            "would pass for the ordinary no-code reason and prove nothing"
        )
        for name in ("persistence", "connections"):
            axis = _axis(profile, name)
            assert axis.status == UNKNOWN, (
                f"{name} asserted {axis.status} over code no reader opened "
                f"(at_root={at_root}): {axis.reason}"
            )
            # B-636 moved the wording, not the decision. When this was written, .py
            # outside a dispatched skill dir had no reader at all, so "no reader for" WAS
            # the whole truth. The sweep now runs the AST/taint pass over exactly those
            # files, and asserting the old sentence would demand the tool keep saying
            # something that stopped being true. What must not move — and is what this
            # test is named for — is that the axis never makes an affirmative clean claim
            # over code IT cannot see: reading a file for dangerous patterns is not
            # measuring its persistence or its outbound surface.
            assert any(
                phrase in axis.reason
                for phrase in ("no reader for", "read for dangerous patterns only")
            ), axis.reason
            assert "no dormant" not in axis.reason and "no outbound" not in axis.reason, (
                f"{name} made an affirmative clean claim: {axis.reason}"
            )


def test_k_a_truncated_scan_holds_even_when_a_definite_finding_is_present(tmp_path):
    """Closes a weakness C-135 round 3 found in tests g and h, not in the code.

    In both of those the `status == UNKNOWN` assertion is carried by `assessed=False` —
    the hand-built pool holds no PASS/WARN/FAIL, so every axis is UNKNOWN regardless of
    the predicate under test. Only their wording assertion exercised it. This pins the
    real-world shape instead: a truncated scan that ALSO carries a definite finding, so
    `assessed` is True and the UNKNOWN can only come from the coverage gate.
    """
    root = _plugin_with_python(tmp_path / "plug")          # produces a real FAIL
    out = vet_plugin(root)
    out.ring_findings = list(out.ring_findings or []) + [coverage_gap_finding(
        "plugin scan coverage is incomplete: the tree sweep stopped at the file cap"
    )]
    pool = _normalize_pool(out)

    assert any(f.status in (FAIL, PASS) for f in pool), (
        "non-vacuity: `assessed` must be True here, which is the whole point — "
        "otherwise the UNKNOWN below would be carried by the empty-pool branch"
    )
    profile = build_profile(out, str(root), "plugin")
    for name in ("persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN, (
            f"{name} read {axis.status}: a truncated scan must not yield an affirmative "
            "claim even when other findings prove the run reached the artifact"
        )
        assert "cut short" in axis.reason, axis.reason
