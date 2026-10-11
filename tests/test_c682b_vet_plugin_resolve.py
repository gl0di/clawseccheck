"""C-682: ``vet_plugin`` gives the same verdict whichever way ``Path.resolve`` treats a symlink loop.

``Path.resolve()`` on a path that loops raises ``RuntimeError`` on Python 3.9-3.12 and returns
the path on 3.14. ``vet_plugin`` calls it at nine sites; the tracer run behind this test (a
``Path.resolve`` wrapper over loop and mode-000 fixtures, on 3.12.3 and 3.14.4) saw a loop reach
exactly one of them, the declared ``manifest.skills`` entry, which already sits under
``except RuntimeError`` and is pinned by C-659. The other eight resolve a path that was probed
or listed first, so a loop never reaches them.

This file pins that, interpreter-independently: it runs ``vet_plugin`` over loop fixtures twice
in one process, once with ``Path.resolve`` patched to the 3.12 contract (``RuntimeError`` when
the resolved path loops) and once to the 3.14 contract (return it), and requires the two
findings to be identical. A resolve site a loop can reach, left without a handler, shows up here
as a crash on one side and a result on the other, on whichever Python the suite runs.

Nothing here reads a Python version.
"""
from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import WARN
from clawseccheck.checks import vet_plugin

pytestmark = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only")

_BENIGN = "---\nname: demo\ndescription: a demo skill\n---\nSummarise the text the user gives you.\n"
_COULD_NOT = "could not be examined"


def _resolve_314(self, strict=False):
    """3.14: ``os.path.realpath`` and nothing else, so a loop is returned, never raised."""
    return type(self)(os.path.realpath(self, strict=strict))


def _resolve_312(self, strict=False):
    """3.9-3.12: realpath, then a ``stat`` of the result, whose ELOOP becomes ``RuntimeError``."""
    out = _resolve_314(self, strict)
    if not strict:
        try:
            os.stat(out)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise RuntimeError(f"Symlink loop from {exc.filename!r}") from None
        except ValueError:
            pass
    return out


@contextlib.contextmanager
def _contract(monkeypatch, which: str):
    monkeypatch.setattr(Path, "resolve", _resolve_312 if which == "312" else _resolve_314)
    yield


def _plugin(base: Path, name: str, skills=None, manifest: bool = True) -> Path:
    d = base / name
    d.mkdir(parents=True)
    body = {"id": "d", "configSchema": {}}
    if skills is not None:
        body["skills"] = skills
    if manifest:
        (d / "openclaw.plugin.json").write_text(json.dumps(body), encoding="utf-8")
    return d


def _skill(root: Path, rel: str) -> Path:
    sd = root / rel
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    return sd


def _two_link_loop(d: Path, a: str = "a", b: str = "b") -> None:
    os.symlink(b, d / a)
    os.symlink(a, d / b)


def _self_loop(d: Path, name: str) -> None:
    os.symlink(name, d / name)


def _declared_loop(base):
    d = _plugin(base, "declared", ["a"])
    _two_link_loop(d)
    return d


def _declared_dotdot_loop(base):
    d = _plugin(base, "dotdot", ["a/../b"])
    _two_link_loop(d)
    return d


def _colocated_with_loops(base):
    d = _plugin(base, "colocated")
    (d / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    _two_link_loop(d, "l1", "l2")
    for n in ("x.py", "y.sh", "z.js"):
        _self_loop(d, n)
    return d


def _colocated_skill_md_is_a_loop(base):
    d = _plugin(base, "skillmdloop")
    _self_loop(d, "SKILL.md")
    return d


def _loose_code_beside_loops(base):
    d = _plugin(base, "loose")
    (d / "install.py").write_text("print(1)\n", encoding="utf-8")
    _two_link_loop(d, "l1", "l2")
    for n in ("loop.py", "loop.sh", "loop.js", "loop.json"):
        _self_loop(d, n)
    return d


def _declared_skill_with_inner_loops(base):
    d = _plugin(base, "inner", ["sk"])
    sd = _skill(d, "sk")
    _two_link_loop(sd, "n1", "n2")
    _self_loop(sd, "loop.py")
    _self_loop(sd, "loop.sh")
    return d


def _declared_dir_of_skills_beside_loops(base):
    d = _plugin(base, "kids", ["sk"])
    _skill(d, "sk/kid1")
    (d / "sk" / "kid1" / "x.py").write_text("print(1)\n", encoding="utf-8")
    _two_link_loop(d / "sk", "k2", "k3")
    return d


def _declared_entry_whose_skill_md_is_a_loop(base):
    d = _plugin(base, "mdloop", ["sk"])
    (d / "sk").mkdir()
    _self_loop(d / "sk", "SKILL.md")
    _skill(d, "sk/kid")
    return d


def _node_modules_wrapper_with_loops(base):
    d = base / "wrapper"
    d.mkdir()
    (d / "package.json").write_text('{"name": "w"}', encoding="utf-8")
    pkg = d / "node_modules" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "openclaw.plugin.json").write_text(json.dumps({"id": "d", "configSchema": {}}),
                                              encoding="utf-8")
    (d / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    _two_link_loop(d, "wl1", "wl2")
    _self_loop(d, "w.py")
    _self_loop(pkg, "p.py")
    _two_link_loop(pkg, "pl1", "pl2")
    return d


def _loops_under_swept_and_skipped_dirs(base):
    d = _plugin(base, "swept")
    (d / "sub").mkdir()
    _two_link_loop(d / "sub")
    _self_loop(d / "sub", "q.py")
    (d / "sub" / "ok.py").write_text("print(1)\n", encoding="utf-8")
    (d / "node_modules").mkdir()
    _two_link_loop(d / "node_modules", "n1", "n2")
    return d


_FIXTURES = {
    "declared entry is a two-link loop": _declared_loop,
    "declared entry loops after a dotdot": _declared_dotdot_loop,
    "co-located SKILL.md beside loops": _colocated_with_loops,
    "co-located SKILL.md is itself a loop": _colocated_skill_md_is_a_loop,
    "loose code beside loops": _loose_code_beside_loops,
    "declared skill with loops inside it": _declared_skill_with_inner_loops,
    "declared directory of skills beside loops": _declared_dir_of_skills_beside_loops,
    "declared entry whose SKILL.md is a loop": _declared_entry_whose_skill_md_is_a_loop,
    "node_modules wrapper with loops": _node_modules_wrapper_with_loops,
    "loops under swept and skipped directories": _loops_under_swept_and_skipped_dirs,
}


def _shape(f) -> tuple:
    """Everything a consumer reads off the finding (status, text, evidence, advice, sub-findings)."""
    return (
        f.status, f.severity, f.detail, f.fix, tuple(f.evidence or ()),
        tuple((r.id, r.status, r.detail, tuple(r.evidence or ())) for r in (f.ring_findings or ())),
    )


# ------------------------------------------------------------------------------ the contracts


def test_the_two_contracts_really_differ_on_a_loop(tmp_path, monkeypatch):
    """The control for everything below: with these patches in place a loop is a RuntimeError
    on one side and a returned path on the other, and an ordinary path is the same on both."""
    _two_link_loop(tmp_path)
    (tmp_path / "plain").mkdir()
    with _contract(monkeypatch, "312"):
        with pytest.raises(RuntimeError):
            (tmp_path / "a").resolve()
        assert (tmp_path / "plain").resolve() == Path(os.path.realpath(tmp_path / "plain"))
    with _contract(monkeypatch, "314"):
        assert (tmp_path / "a").resolve() == Path(os.path.realpath(tmp_path / "a"))
        assert (tmp_path / "plain").resolve() == Path(os.path.realpath(tmp_path / "plain"))


@pytest.mark.parametrize("build", list(_FIXTURES.values()), ids=list(_FIXTURES))
def test_a_loop_anywhere_in_a_plugin_gives_the_same_finding_on_either_contract(
        tmp_path, monkeypatch, build):
    d = build(tmp_path)
    shapes = {}
    for which in ("312", "314"):
        with _contract(monkeypatch, which):
            shapes[which] = _shape(vet_plugin(d))
    assert shapes["312"] == shapes["314"]


@pytest.mark.parametrize("build", [_declared_loop, _declared_dotdot_loop],
                         ids=["two-link loop", "dotdot loop"])
def test_a_declared_entry_that_loops_is_a_disclosed_warn_on_either_contract(
        tmp_path, monkeypatch, build):
    """Never a clean look: the entry is named as not examined, on both contracts."""
    d = build(tmp_path)
    for which in ("312", "314"):
        with _contract(monkeypatch, which):
            f = vet_plugin(d)
        assert f.status == WARN, (which, f.status, f.detail)
        assert [e for e in f.evidence if _COULD_NOT in e], (which, f.evidence)


def test_a_co_located_skill_is_vetted_by_its_own_name_on_either_contract(tmp_path, monkeypatch):
    """The empty-name site: ``--vet-plugin .`` hands over ``Path('.')``, whose directory is
    resolved to get a label. Loops beside it change nothing, on either contract."""
    d = _colocated_with_loops(tmp_path)
    monkeypatch.chdir(d)
    shapes = {}
    for which in ("312", "314"):
        with _contract(monkeypatch, which):
            shapes[which] = _shape(vet_plugin(Path(".")))
    assert shapes["312"] == shapes["314"]
    assert any("is not listed in manifest.skills" in e for e in shapes["312"][4]), shapes["312"][4]
