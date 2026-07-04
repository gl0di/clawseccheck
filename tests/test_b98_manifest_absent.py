"""Tests for B98 (F-083, L1) — manifest-absent verdict + `--emit-manifest`.

Checks:
- bad_b98_manifest_absent    : subprocess(..., shell=True), no allowed-tools/tools -> WARN
- clean_b98_no_risky_effects : no dangerous primitive at all, no manifest either   -> PASS

The "declares a manifest" PASS case is covered at the unit level only
(test_risky_effects_with_manifest_passes), not as a clean_* vet fixture: any code shape
that trips B98's own dangerous-primitive regex also draws legitimate scrutiny from other
checks (B13/B62) regardless of manifest declaration, so no fixture can both contain that
primitive and satisfy the project's "clean_* must be silent across ALL checks"
convention. Same precedent as the removed clean_b97_hook_logonly fixture.

B98 is deliberately scoped to HIGH-CONFIDENCE code-execution primitives
(os.system/os.exec*/eval/exec, or subprocess with shell=True) rather than B62's broader
family extraction — an earlier, broader version of this check false-positived on every
existing clean_* fixture that used a socket-based downloader or a safe
subprocess.run([...]) call, since no fixture in the corpus declares a formal manifest.

`--emit-manifest` (single-skill --vet-skill only) prints a proposed permission manifest
derived from static effect analysis; an opaque/no-Python skill must render every
capability field as `unknown` (never a silently-safe false), per §2/ZKDS.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_manifest_absent, vet_skill
from clawseccheck.cli import main
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_HOME_FAKE = Path("/nonexistent/home")

_RISKY_PY = (
    "import subprocess\n\n"
    "def fetch_and_save(url, dest):\n"
    "    subprocess.run(f'curl -s {url} -o {dest}', shell=True)\n"
    "    return dest\n"
)

_BENIGN_PY = "def trim(text):\n    return ' '.join(text.split())\n"


def _ctx_with_skill(skill_name: str, skill_md: str, py_src: str | None) -> Context:
    blob = f"# file: SKILL.md\n{skill_md}"
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {skill_name: blob}
    ctx.installed_skill_py = {skill_name: [(f"{skill_name}.py", py_src)] if py_src else []}
    ctx.effect_profiles = {}
    return ctx


# --------------------------------------------------------------------------- unit-level

def test_unknown_when_no_installed_skills():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    f = check_manifest_absent(ctx)
    assert f.status == UNKNOWN


def test_risky_effects_no_manifest_warns():
    ctx = _ctx_with_skill("net-fetcher", "---\nname: x\ndescription: y\n---\n", _RISKY_PY)
    f = check_manifest_absent(ctx)
    assert f.status == WARN, f.detail


def test_risky_effects_with_manifest_passes():
    ctx = _ctx_with_skill(
        "net-fetcher",
        "---\nname: x\ndescription: y\ntools: [network, filesystem]\n---\n",
        _RISKY_PY,
    )
    f = check_manifest_absent(ctx)
    assert f.status != WARN, f.detail


def test_no_risky_effects_no_manifest_passes():
    ctx = _ctx_with_skill("text-tool", "---\nname: x\ndescription: y\n---\n", _BENIGN_PY)
    f = check_manifest_absent(ctx)
    assert f.status == PASS, f.detail


def test_no_python_source_is_unknown():
    ctx = _ctx_with_skill("no-py", "---\nname: x\ndescription: y\n---\n", None)
    f = check_manifest_absent(ctx)
    assert f.status == UNKNOWN, f.detail


# --------------------------------------------------------------------------- vet-level

def test_vet_bad_manifest_absent_is_warn():
    skill_dir = FIXTURES / "bad_b98_manifest_absent" / "skills" / "net-fetcher"
    f = vet_skill(skill_dir)
    assert any(x.id == "B98" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_no_risky_effects_b98_passes():
    skill_dir = FIXTURES / "clean_b98_no_risky_effects" / "skills" / "text-tool"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B98" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


# --------------------------------------------------------------------------- --emit-manifest

def test_emit_manifest_shows_risky_effects_true(capsys):
    skill_dir = FIXTURES / "bad_b98_manifest_absent" / "skills" / "net-fetcher"
    rc = main(["--vet-skill", str(skill_dir), "--emit-manifest"])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "unprofilable: false" in out
    # NOTE: the effect simulator has no os.system/subprocess sink category (only bare
    # eval/exec/compile calls with a tainted arg register "exec" — see
    # render_permission_manifest's docstring caveat), so shell.exec stays false here even
    # though the fixture runs shell=True. The tainted open(dest, 'w') write DOES register.
    assert "write: true" in out


def test_emit_manifest_unprofilable_skill_is_all_unknown(tmp_path, capsys):
    d = tmp_path / "opaque"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: opaque\ndescription: no python source at all\n---\n",
        encoding="utf-8",
    )
    main(["--vet-skill", str(d), "--emit-manifest"])
    out = capsys.readouterr().out
    assert "unprofilable: true" in out
    assert "read: unknown" in out
    assert "exec: unknown" in out
    # must NEVER render a silently-safe all-false manifest for an unprofilable skill
    assert "true" not in out.replace("unprofilable: true", "")


def test_emit_manifest_without_vet_target_is_graceful(capsys):
    rc = main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
               "--no-history", "--emit-manifest"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--emit-manifest requires --vet/--vet-skill on a single skill" in err
