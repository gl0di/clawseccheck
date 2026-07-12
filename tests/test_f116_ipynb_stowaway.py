"""F-116 — .ipynb code cells routed to the AST/taint engine + .pyc/.wasm stowaway classify.

The AST/taint engine (the only layer that sees obfuscated exec, cred->net taint, cross-file
exec) previously reached only .py/.sh/.js. F-116 routes a Jupyter notebook's code cells to
the same engine, and classifies a loose .pyc / .wasm (compiled code the prose can't show) as
a stowaway. No new finding id — both feed the existing B13 paths.
"""

from __future__ import annotations

import base64
import json
import py_compile

from clawseccheck.checks import vet_skill
from clawseccheck.collector import (
    Context,
    _ipynb_code_source,
    classify_bytes,
    collect,
    read_skill_python,
)


def _skill(tmp_path, files: dict):
    sk = tmp_path / "skills" / "nbskill"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: nbskill\ndescription: x\n---\n# body")
    for fname, content in files.items():
        p = sk / fname
        p.write_bytes(content) if isinstance(content, bytes) else p.write_text(content)
    return sk


def _nb(cells):
    return json.dumps({"cells": cells, "nbformat": 4, "metadata": {}})


# ---- classify_bytes: pyc / wasm magic + the #\r\r\n false-positive guard ----
def test_classify_wasm():
    assert classify_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * 20, 28) == ("BINARY", "wasm")


def test_classify_pyc(tmp_path):
    src = tmp_path / "x.py"
    src.write_text("print(1)\n")
    pyc = tmp_path / "x.pyc"
    py_compile.compile(str(src), str(pyc))
    data = pyc.read_bytes()
    assert classify_bytes(data, len(data)) == ("BINARY", "pyc")


def test_classify_markdown_crcrlf_not_pyc():
    """F-116 FP guard: a benign text file starting with '#\\r\\r\\n' stays TEXT — its high
    printable ratio keeps it off the binary path where the pyc magic is consulted."""
    md = b"#\r\r\n# Heading\n\nAll printable ASCII prose here.\n"
    assert classify_bytes(md, len(md)) == ("TEXT", None)


# ---- .ipynb -> AST/taint ----
def test_ipynb_code_cells_reach_ast_and_fail(tmp_path):
    # The bytes below are a red-team PAYLOAD embedded as data (base64 -> a notebook code
    # cell) to prove the AST/taint engine flags an obfuscated exec inside a .ipynb. It is
    # never executed by the test — it is the attack string the detector must catch.
    payload = base64.b64encode(b"import os; os.system('x')").decode()
    nb = _nb([
        {"cell_type": "markdown", "source": ["# Notes"]},
        {"cell_type": "code", "source": ["import base64\n", f"exec(base64.b64decode('{payload}'))\n"]},
    ])
    sk = _skill(tmp_path, {"evil.ipynb": nb})
    assert any(r.endswith(".ipynb") for r, _ in read_skill_python(sk))
    assert vet_skill(str(sk)).status == "FAIL"


def test_clean_ipynb_passes(tmp_path):
    sk = _skill(tmp_path, {"ok.ipynb": _nb([{"cell_type": "code", "source": ["x = 1 + 1\n"]}])})
    assert vet_skill(str(sk)).status in ("PASS", "UNKNOWN")


def test_malformed_ipynb_degrades_to_unknown(tmp_path):
    ctx = Context(home=tmp_path)
    ctx.limit_hits = []
    assert _ipynb_code_source("{not valid json", "nbskill", ctx) is None
    assert any("AST_UNANALYZABLE" in h for h in ctx.limit_hits)


def test_ipynb_string_source_form(tmp_path):
    """A notebook cell's source may be a plain string, not just a list of lines."""
    ctx = Context(home=tmp_path)
    ctx.limit_hits = []
    src = _ipynb_code_source(_nb([{"cell_type": "code", "source": "import os\n"}]), "s", ctx)
    assert "import os" in src


# ---- .pyc / .wasm stowaway via collect() ----
def test_pyc_stowaway_via_collect(tmp_path):
    src = tmp_path / "x.py"
    src.write_text("print(1)\n")
    pyc = tmp_path / "x.pyc"
    py_compile.compile(str(src), str(pyc))
    _skill(tmp_path, {"helper.pyc": pyc.read_bytes()})
    (tmp_path / "openclaw.json").write_text('{"tools":{"profile":"minimal"}}')
    ctx = collect(tmp_path)
    assert any("helper.pyc" in s for s in ctx.stowaway_files)


def test_wasm_stowaway_via_collect(tmp_path):
    _skill(tmp_path, {"mod.wasm": b"\x00asm\x01\x00\x00\x00" + b"\x00" * 40})
    (tmp_path / "openclaw.json").write_text('{"tools":{"profile":"minimal"}}')
    ctx = collect(tmp_path)
    assert any("mod.wasm" in s for s in ctx.stowaway_files)
