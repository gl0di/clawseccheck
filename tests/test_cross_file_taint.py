"""F-056: cross-file / import-graph taint (H1 structural blind spot).

Per-file AST taint (analyze_python) misses a payload split across two files — file A holds
an obfuscated (decode-derived) blob, file B imports and exec()s it; each half is clean in
isolation. analyze_python_package resolves sibling-import edges and flags the cross-module
exec. Decode-only source + exec-only sink keep it zero-FP on ordinary multi-file skills.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python_package


def _rules(files: list[tuple[str, str]]) -> list[str]:
    return [f.rule for f in analyze_python_package(files)]


def _mk_skill(root: Path, files: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return root


# --------------------------------------------------------------------------- #
# analyze_python_package unit cases                                            #
# --------------------------------------------------------------------------- #
def test_from_import_split_payload_flags():
    files = [("a.py", 'import base64\nPAYLOAD = base64.b64decode("cHJpbnQoMSk=")\n'),
             ("b.py", 'from a import PAYLOAD\nexec(PAYLOAD)\n')]
    assert "CROSS_FILE_EXEC" in _rules(files)


def test_import_attribute_split_payload_flags():
    files = [("a.py", 'import base64\nBLOB = base64.b64decode("eA==")\n'),
             ("main.py", 'import a\nexec(a.BLOB)\n')]
    assert "CROSS_FILE_EXEC" in _rules(files)


def test_cross_file_os_system_flags():
    files = [("payload.py", 'import base64\nCMD = base64.b64decode("aWQ=").decode()\n'),
             ("run.py", 'import os, payload\nos.system(payload.CMD)\n')]
    assert "CROSS_FILE_EXEC" in _rules(files)


def test_benign_two_file_skill_is_silent():
    files = [("util.py", 'def greet():\n    return "hi"\n'),
             ("main.py", 'from util import greet\nprint(greet())\n')]
    assert _rules(files) == []


def test_local_decode_not_crossing_module_is_silent():
    # a decode used locally in its own file, the other file benign -> no cross-file flow.
    files = [("a.py", 'import base64\nX = base64.b64decode("eA==")\nprint(len(X))\n'),
             ("b.py", 'def f():\n    return 2\n')]
    assert _rules(files) == []


def test_non_decode_cross_import_is_silent():
    # importing a plain (non-decode) value across files, plus a local exec of a constant.
    files = [("cfg.py", 'SETTINGS = {"k": 1}\n'),
             ("app.py", 'from cfg import SETTINGS\nexec("print(1)")\nprint(SETTINGS)\n')]
    assert _rules(files) == []


def test_single_file_is_not_cross_file():
    files = [("only.py", 'import base64\nexec(base64.b64decode("eA=="))\n')]
    assert _rules(files) == []


def test_unparseable_sibling_does_not_crash():
    files = [("a.py", 'import base64\nP = base64.b64decode("eA==")\n'),
             ("broken.py", 'def (: not python\n')]
    # must not raise; the broken file is simply skipped for cross-file analysis.
    assert isinstance(analyze_python_package(files), list)


# --------------------------------------------------------------------------- #
# Through vet_skill(): split payload FAILs, benign multi-file PASSes.          #
# --------------------------------------------------------------------------- #
def test_vet_split_payload_skill_fails(tmp_path):
    d = _mk_skill(tmp_path / "evil", {
        "a.py": 'import base64\nPAYLOAD = base64.b64decode("cHJpbnQoMSk=")\n',
        "b.py": 'from a import PAYLOAD\nexec(PAYLOAD)\n'})
    f = vet_skill(str(d))
    assert f.status == FAIL
    assert any("cross-file" in e.lower() for e in f.evidence)


def test_vet_benign_multifile_skill_is_safe(tmp_path):
    d = _mk_skill(tmp_path / "ok", {
        "util.py": 'def greet():\n    return "hi"\n',
        "main.py": 'from util import greet\nprint(greet())\n'})
    assert vet_skill(str(d)).status == PASS
