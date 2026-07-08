"""Regression tests for CLAWSECCHECK-B-155.

The AST effect simulator (clawseccheck/skillast.py, EffectSimulator.simulate_statement)
had no ast.With/ast.AsyncWith branch, so it fell into the generic ast.walk fallback,
which never called taint_target() for the `with ... as VAR:` binding and never
recursed into the with-body via simulate_statements(). A skill written with the
idiomatic context-manager form (`with urlopen(url) as resp: ...`, `with open(path, "wb")
as f: ...`) therefore had its filesystem/network capability silently under-reported as
`false` compared to the exact same logic written without `with`.

Covers both:
- the direct unit-level simulator (clawseccheck.skillast.simulate_effects) — see also
  tests/test_skillast.py for the plain simulator regressions;
- the end-to-end `--vet-skill --emit-manifest` CLI path (ctx.effect_profiles consumed by
  dossier.py/sarif.py/checks/_content.py B62/checks/_vet.py).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import vet_skill
from clawseccheck.cli import main
from clawseccheck.skillast import simulate_effects

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------- unit-level

def test_with_idiom_and_plain_form_agree_on_capabilities():
    """Skill A (`with ... as VAR:`) and Skill B (plain assignment) from the bug
    report must report the SAME reachable effects — the `with` form must no longer
    under-report."""
    src_with = """\
def fetch(url):
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    with open("/tmp/out.txt", "wb") as f:
        f.write(data)
"""
    src_plain = """\
def fetch(url):
    resp = urllib.request.urlopen(url); data = resp.read()
    f = open("/tmp/out.txt", "wb"); f.write(data); f.close()
"""
    res_with = simulate_effects(src_with)[0]
    res_plain = simulate_effects(src_plain)[0]
    assert set(res_with["reachable_effects"]) == set(res_plain["reachable_effects"])
    assert "read" in res_with["reachable_effects"]
    assert "write" in res_with["reachable_effects"]


# --------------------------------------------------------------------------- vet-level / emit-manifest

def test_vet_bad_with_fixture_populates_effect_profile():
    skill_dir = FIXTURES / "bad_effectsim_with_taint_dropped" / "skills" / "with-fetcher"
    f = vet_skill(skill_dir)
    ctx = getattr(f, "ctx", None)
    assert ctx is not None
    assert "with-fetcher" in ctx.effect_profiles
    entries = ctx.effect_profiles["with-fetcher"]
    all_effects = {eff for e in entries for eff in e.get("reachable_effects", [])}
    assert "network" in all_effects
    assert "read" in all_effects
    assert "write" in all_effects


def test_emit_manifest_with_idiom_shows_read_write_true(capsys):
    skill_dir = FIXTURES / "bad_effectsim_with_taint_dropped" / "skills" / "with-fetcher"
    rc = main(["--vet-skill", str(skill_dir), "--emit-manifest"])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "unprofilable: false" in out
    assert "read: true" in out
    assert "write: true" in out
    assert "reachable: true" in out  # network.reachable


def test_emit_manifest_benign_with_idiom_shows_all_false(capsys):
    """Companion clean fixture: threading.Lock()/tempfile.TemporaryDirectory() `with`
    blocks must render as no capability at all — no spurious true (C-135)."""
    skill_dir = FIXTURES / "clean_effectsim_with_benign" / "skills" / "with-lock-tool"
    rc = main(["--vet-skill", str(skill_dir), "--emit-manifest"])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "unprofilable: false" in out
    assert "read: false" in out
    assert "write: false" in out
    assert "reachable: false" in out  # network.reachable
