"""C-650 - a package.json that a wrapper wires in is NOT read; the limit is disclosed.

`--vet` / `--vet-plugin` open exactly one package.json per target: the one at the top of
the vetted directory (a plugin root's own, or an npm wrapper's, beside its `node_modules/`).
A package that file pulls in through `workspaces` or a `file:` dependency lives in a nested
directory with its own package.json, and an install script in it is never opened. This is
an accepted, documented limit: following wired-in manifests means modelling npm's workspace
and dependency-spec grammar by hand, an open-ended list (symlinked intermediate
directories, `overrides`, `FILE:` / bare-path / tarball specs, negated and character-class
patterns), and every shape missed would be a silent INSTALL.

What the report does instead is name the limit, as an evidence-only coverage note that never
moves a verdict. These tests pin that behaviour exactly - the verdict stays INSTALL on the
bug's fixtures, the note is present, and nothing else about them changes - so any future
change (a reader, a verdict floor) is a deliberate one, made by editing this file.

Everything is built inside pytest's tmp_path; nothing touches a real fleet.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import _mcp, vet_plugin
from clawseccheck.cli import main

_NOTE = (
    "coverage: this package.json declares workspaces or a local file:/link: dependency; "
    "npm can load packages from those paths, and this vet reads no package.json other "
    "than the one at the top of the target, so an install script in a package it wires "
    "in was not examined (the verdict does not account for it)"
)
_NESTED = {"name": "a", "version": "1.0.0", "scripts": {"postinstall": "echo nested"}}
_WORKSPACES = {"name": "w", "version": "1.0.0", "workspaces": ["pkgs/*"]}


def _write(p: Path, doc: object) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")


def _manifest(d: Path) -> None:
    _write(d / "openclaw.plugin.json", {"id": "x", "configSchema": {}})


def _wrapper(tmp_path: Path, name: str, top_pkg: dict, nested: bool = True) -> Path:
    """No manifest at the top; the only one sits under node_modules/x (the C-632 shape)."""
    d = tmp_path / name
    _manifest(d / "node_modules" / "x")
    _write(d / "package.json", top_pkg)
    if nested:
        _write(d / "pkgs" / "a" / "package.json", _NESTED)
    return d


def _plugin_root(tmp_path: Path, name: str, top_pkg: dict, nested: bool = True) -> Path:
    d = tmp_path / name
    _manifest(d)
    _write(d / "package.json", top_pkg)
    if nested:
        _write(d / "pkgs" / "a" / "package.json", _NESTED)
    return d


def _cli(path: Path, capsys) -> "tuple[int, str]":
    rc = main(["--vet", str(path)])
    return rc, capsys.readouterr().out


_WIRED = {
    "workspaces-array": {"name": "w", "workspaces": ["pkgs/*"]},
    "workspaces-object": {"name": "w", "workspaces": {"packages": ["pkgs/*"]}},
    "file-dependency": {"name": "w", "dependencies": {"a": "file:./pkgs/a"}},
    "file-dev-dependency": {"name": "w", "devDependencies": {"a": "file:./pkgs/a"}},
    "file-optional-dependency": {"name": "w", "optionalDependencies": {"a": "file:./pkgs/a"}},
    "link-dependency": {"name": "w", "dependencies": {"a": "link:./pkgs/a"}},
    "upper-case-scheme": {"name": "w", "dependencies": {"a": "FILE:./pkgs/a"}},
}


# ------------------------------------------- the bug's fixtures: verdict pinned, note present


@pytest.mark.parametrize("shape", sorted(_WIRED))
def test_wrapper_with_a_wired_in_nested_postinstall_stays_install_but_names_the_limit(
    tmp_path, capsys, shape
):
    d = _wrapper(tmp_path, "wrap", _WIRED[shape])
    f = vet_plugin(d)
    # The documented limit: the nested postinstall is not seen, so the verdict is the clean one.
    assert f.status == PASS, (shape, f.status, f.detail, f.evidence)
    assert not [x for x in f.ring_findings if x.id == "VET-COVERAGE"], shape
    assert _NOTE in f.evidence, (shape, f.evidence)
    rc, out = _cli(d, capsys)
    assert rc == 0, out
    assert "INSTALL" in out and "CAUTION" not in out
    assert "Not assessed" in out
    assert _NOTE.removeprefix("coverage: ") in out


def test_plugin_root_with_workspaces_and_a_nested_postinstall_stays_install_but_names_the_limit(
    tmp_path, capsys
):
    d = _plugin_root(tmp_path, "proot", _WORKSPACES)
    f = vet_plugin(d)
    assert f.status == PASS, (f.status, f.detail, f.evidence)
    assert _NOTE in f.evidence
    assert not any("npm lifecycle script" in e for e in f.evidence)
    rc, out = _cli(d, capsys)
    assert rc == 0, out
    assert _NOTE.removeprefix("coverage: ") in out


def test_the_note_appears_once_when_both_package_json_files_wire_something_in(tmp_path):
    """A re-rooted wrapper whose plugin package ALSO declares workspaces: one note, not two."""
    d = _wrapper(tmp_path, "wrap", _WORKSPACES)
    _write(d / "node_modules" / "x" / "package.json", _WORKSPACES)
    f = vet_plugin(d)
    assert f.evidence.count(_NOTE) == 1, f.evidence


# ------------------------------------------- the controls: nothing here gains the note


@pytest.mark.parametrize(
    "pkg",
    [
        {"name": "w", "version": "1.0.0"},
        {"name": "w", "workspaces": []},
        {"name": "w", "workspaces": {}},
        {"name": "w", "dependencies": {"left-pad": "1.3.0", "x": "npm:left-pad@1.3.0"}},
        {"name": "w", "dependencies": {"a": "workspace:*"}},
        {"name": "w", "scripts": {"test": "echo file:./pkgs/a"}},
        {"name": "w", "description": "mentions workspaces and file:./pkgs/a"},
    ],
    ids=["plain", "empty-array", "empty-object", "registry-and-alias", "pnpm-workspace-proto",
         "file-in-a-script", "file-in-prose"],
)
def test_unwired_nested_package_json_gets_no_note(tmp_path, pkg):
    """The unwired control: a nested postinstall nothing refers to stays a plain INSTALL."""
    for make in (_wrapper, _plugin_root):
        d = make(tmp_path, make.__name__ + "-d", pkg)
        f = vet_plugin(d)
        assert f.status == PASS, (make.__name__, f.status, f.detail)
        assert _NOTE not in f.evidence, (make.__name__, f.evidence)


def test_a_wrapper_with_no_package_json_gets_no_note(tmp_path):
    d = tmp_path / "bare"
    _manifest(d / "node_modules" / "x")
    f = vet_plugin(d)
    assert f.status == PASS
    assert _NOTE not in f.evidence


# ------------------------------------------- what the limit does NOT swallow


def test_the_wrappers_own_postinstall_is_still_caught_beside_a_wired_in_one(tmp_path):
    """C-632's own-package.json disclosure is untouched: CAUTION, and the note rides along."""
    pkg = dict(_WORKSPACES, scripts={"postinstall": "echo own"})
    d = _wrapper(tmp_path, "wrap", pkg)
    f = vet_plugin(d)
    assert f.status != PASS, (f.status, f.detail)
    assert any(x.id == "VET-COVERAGE" and "'package.json'" in x.detail for x in f.ring_findings)
    assert _NOTE in f.evidence


def test_the_plugin_root_lifecycle_warn_is_untouched_by_the_note(tmp_path):
    pkg = dict(_WORKSPACES, scripts={"postinstall": "echo own"})
    d = _plugin_root(tmp_path, "proot", pkg)
    f = vet_plugin(d)
    assert f.status == WARN, (f.status, f.detail)
    assert any("npm lifecycle script(s) declared: postinstall" in e for e in f.evidence)
    assert _NOTE in f.evidence


def test_a_wrapper_package_json_that_cannot_be_judged_is_still_unassessed_not_noted(tmp_path):
    """An over-cap wrapper package.json keeps its existing UNKNOWN; no marker is guessed."""
    d = _wrapper(tmp_path, "wrap", {"name": "w"}, nested=False)
    (d / "package.json").write_text(
        '{"name":"w","pad":"' + "x" * (_mcp._PLUGIN_JS_MAX_BYTES + 1) + '"}', encoding="utf-8"
    )
    f = vet_plugin(d)
    assert f.status != PASS, (f.status, f.detail)
    assert any(
        x.id == "VET-COVERAGE" and "own package.json could not be read" in x.detail
        for x in f.ring_findings
    )
    assert _NOTE not in f.evidence


# ------------------------------------------- the reader refactor changed no judgement


@pytest.mark.parametrize(
    "text, expected",
    [
        ('{"scripts":{"postinstall":"x"}}', (True, False)),
        ('{"scripts":{"test":"x"}}', (False, False)),
        ("not json", (False, False)),
        ("null", (False, False)),
        ("[1,2]", (False, False)),
        ('{"scripts":{"postinstall":"x"},"n":' + "9" * 5000 + "}", (True, False)),
    ],
)
def test_lifecycle_reader_answers_are_unchanged(tmp_path, text, expected):
    (tmp_path / "package.json").write_text(text, encoding="utf-8")
    assert _mcp._wrapper_declares_lifecycle_script(tmp_path) == expected


def test_lifecycle_reader_on_a_missing_and_an_oversized_file(tmp_path):
    assert _mcp._wrapper_declares_lifecycle_script(tmp_path) == (False, False)
    (tmp_path / "package.json").write_text(
        '{"p":"' + "x" * (_mcp._PLUGIN_JS_MAX_BYTES + 1) + '"}', encoding="utf-8"
    )
    assert _mcp._wrapper_declares_lifecycle_script(tmp_path) == (False, True)
