"""F-065 (--vet-plan) + F-067 (--advise) — the zero-network vet pipeline's default path.

F-065: a pure text emitter (mirrors --fix's "prints, never executes" doctrine). The tool
never fetches anything; it prints the fetch+isolate+advise+cleanup commands for a human
or host agent to run themselves, ecosystem-detected via F-073's own _parse_source_target
so the suggested verb matches exactly what --vet-source already identified.

F-067: reframes the exact same VetProfile --vet already computes (dossier.py/build_profile)
as an install decision — DANGEROUS/SUSPICIOUS/SAFE/UNKNOWN relabel to DO-NOT-INSTALL/
CAUTION/INSTALL/CAUTION. Reasons reuse each finding's own detail text, which already
carries F-055's source->sink trace for taint findings; no separate trace plumbing.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.checks import vet_skill
from clawseccheck.cli import main
from clawseccheck.dossier import build_profile
from clawseccheck.report import render_advise, render_advise_json, render_vet_plan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------- #
# F-065: render_vet_plan — ecosystem-specific fetch command + safety invariants
# --------------------------------------------------------------------------- #

def test_vet_plan_npm_ecosystem():
    out = render_vet_plan("npm:@openclaw/brave-plugin@2026.6.11")
    assert "npm pack @openclaw/brave-plugin@2026.6.11" in out
    assert "--pack-destination" in out


def test_vet_plan_pypi_ecosystem():
    out = render_vet_plan("pypi:some-mcp-server==1.0")
    assert "pip download --no-deps" in out
    assert "some-mcp-server==1.0" in out


def test_vet_plan_git_ecosystem_reconstructs_real_clone_url():
    """Regression: the raw 'git:<host>/<path>@<ref>' target is NOT a valid git URL —
    render_vet_plan must reconstruct a real https:// clone URL, not pass it through."""
    out = render_vet_plan("git:github.com/owner/repo@v1.2")
    assert "git clone" in out
    assert "https://github.com/owner/repo" in out
    assert "--branch v1.2" in out
    # the raw "git:" ecosystem marker must never appear as (part of) the clone URL itself
    assert "clone --depth 1 --branch v1.2 git:" not in out


def test_vet_plan_git_ecosystem_no_ref():
    out = render_vet_plan("git:github.com/owner/repo")
    assert "https://github.com/owner/repo" in out
    assert "--branch" not in out


def test_vet_plan_url_ecosystem_uses_curl():
    out = render_vet_plan("https://example.com/skill.zip")
    assert "curl -fsSL https://example.com/skill.zip" in out


def test_vet_plan_clawhub_ecosystem_no_fabricated_flag():
    """clawhub has no single verified 'pull one package' CLI flag — must not invent one."""
    out = render_vet_plan("clawhub:some-skill")
    assert "resolve 'some-skill'" in out
    assert "ClawHub client's normal pull/install path" in out


def test_vet_plan_bare_registry_name_no_fabricated_flag():
    out = render_vet_plan("someskill")
    assert "no resolvable ecosystem" in out


def test_vet_plan_always_includes_quarantine_and_cleanup():
    for target in ("npm:foo", "pypi:bar", "git:github.com/a/b", "https://x.com/y", "clawhub:z", "bare"):
        out = render_vet_plan(target)
        assert "mktemp -d" in out
        assert "clawseccheck --advise" in out
        assert "rm -rf" in out
        assert "--vet-source" in out  # nudges the pre-download gate first


def test_vet_plan_never_executes_anything():
    """The tool itself must never touch the network or filesystem for this mode —
    render_vet_plan is pure string construction with no I/O."""
    import inspect
    src = inspect.getsource(render_vet_plan)
    for banned in ("subprocess", "urllib", "socket", "requests"):
        assert banned not in src


def test_cli_vet_plan_exits_zero(capsys):
    rc = main(["--vet-plan", "npm:some-pkg"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "npm pack some-pkg" in out


# --------------------------------------------------------------------------- #
# F-067: render_advise / render_advise_json
# --------------------------------------------------------------------------- #

def _profile(fixture_name: str):
    path = FIXTURES / fixture_name
    f = vet_skill(str(path))
    return build_profile(f, str(path), "skill")


def test_advise_dangerous_skill_is_do_not_install():
    profile = _profile("bad_b13_runtime_fetch/skills/evil-fetch-skill")
    out = render_advise(profile)
    assert "DO-NOT-INSTALL" in out
    assert "Reasons:" in out


def test_advise_clean_skill_is_install():
    profile = _profile("clean_b13_doc_example/skills/security-guide")
    out = render_advise(profile)
    assert "INSTALL" in out
    assert "DO-NOT-INSTALL" not in out
    assert "CAUTION" not in out


def test_advise_json_shape_has_verdict_reasons_cleanup_coverage():
    profile = _profile("bad_b13_runtime_fetch/skills/evil-fetch-skill")
    payload = json.loads(render_advise_json(profile, version="0.0.0"))
    assert payload["advise_verdict"] == "DO-NOT-INSTALL"
    assert isinstance(payload["reasons"], list) and payload["reasons"]
    assert "cleanup" in payload
    assert "coverage" in payload
    assert "is_quarantine_path" in payload


def test_advise_never_suggests_bare_rm_rf_outside_temp_dir():
    """Safety: --advise can be pointed at a REAL installed skill, not just a --vet-plan
    quarantine copy. It must never hand out an unconditional rm -rf for a real path."""
    profile = _profile("bad_b13_runtime_fetch/skills/evil-fetch-skill")
    out = render_advise(profile)
    assert "do NOT delete it" in out
    payload = json.loads(render_advise_json(profile, version="0.0.0"))
    assert payload["is_quarantine_path"] is False
    assert payload["cleanup"].startswith("#")  # commented out, not a live command


def test_advise_suggests_direct_cleanup_for_a_real_quarantine_path():
    # tmp_path is NOT under tempfile.gettempdir() necessarily on every platform, so
    # build the fixture profile with a target explicitly inside the system temp dir.
    import tempfile
    real_tmp = Path(tempfile.mkdtemp())
    try:
        f = vet_skill(str(FIXTURES / "bad_b13_runtime_fetch" / "skills" / "evil-fetch-skill"))
        profile = build_profile(f, str(real_tmp), "skill")
        out = render_advise(profile)
        assert f"rm -rf {real_tmp}" in out
        assert "do NOT delete it" not in out
    finally:
        real_tmp.rmdir()


def test_cli_advise_dangerous_skill_exits_one(capsys):
    rc = main(["--advise", str(FIXTURES / "bad_b13_runtime_fetch" / "skills" / "evil-fetch-skill")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "DO-NOT-INSTALL" in out


def test_cli_advise_clean_skill_exits_zero(capsys):
    rc = main(["--advise", str(FIXTURES / "clean_b13_doc_example" / "skills" / "security-guide")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "INSTALL" in out


def test_cli_advise_json_is_valid_json(capsys):
    main(["--advise", str(FIXTURES / "bad_b13_runtime_fetch" / "skills" / "evil-fetch-skill"), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["mode"] == "advise"
    assert payload["advise_verdict"] == "DO-NOT-INSTALL"
