"""F-116 — .ipynb code cells routed to the AST/taint engine + .pyc/.wasm stowaway classify.

The AST/taint engine (the only layer that sees obfuscated exec, cred->net taint, cross-file
exec) previously reached only .py/.sh/.js. F-116 routes a Jupyter notebook's code cells to
the same engine, and classifies a loose .pyc / .wasm (compiled code the prose can't show) as
a stowaway. No new finding id — both feed the existing B13 paths.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import py_compile

import pytest

from clawseccheck.checks import vet_skill
from clawseccheck.cli import main
from clawseccheck.collector import (
    _PYC_MAGIC_MAX,
    _PYC_MAGIC_MIN,
    Context,
    _ipynb_code_source,
    _pyc_fmt,
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


def _own_pyc(tmp_path) -> bytes:
    """A real .pyc written by the RUNNING interpreter (so every CI leg builds its own)."""
    src = tmp_path / "own_src.py"
    src.write_text("print(1)\n")
    pyc = tmp_path / "own.pyc"
    py_compile.compile(str(src), str(pyc), doraise=True)
    return pyc.read_bytes()


def _with_magic(pyc: bytes, n: int) -> bytes:
    """`pyc` with its 4-byte magic replaced by the one a CPython whose MAGIC_NUMBER is
    `n` writes: n as 16-bit little-endian, then CR LF. Header and body stay a real,
    binary-classified .pyc, so only the magic differs between the cases below."""
    return n.to_bytes(2, "little") + b"\r\n" + pyc[4:]


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


# 16-bit magic numbers N. The first three were MEASURED (importlib.util.MAGIC_NUMBER on
# CPython 3.9.25 / 3.12.3 / 3.14.4 on the project machine, 2026-10-05); the rest are
# taken from the magic-number tables installed with those interpreters, not measured as
# .pyc files (see the comment above collector._PYC_MAGIC_MIN).
_MEASURED_MAGIC = [(3425, "3.9"), (3531, "3.12"), (3627, "3.14")]
_DOCUMENTED_MAGIC = [
    (3330, "3.5b1, the lowest N in range"),
    (3571, "3.13b1, the last N with high byte 0x0d"),
    (3600, "3.14a1, the first N with high byte 0x0e"),
    (3650, "3.15, documented start"),
]


@pytest.mark.parametrize("n,label", _MEASURED_MAGIC + _DOCUMENTED_MAGIC)
def test_classify_pyc_for_every_known_magic(tmp_path, n, label):
    """The label is a property of the SCANNED file, not of the running interpreter: a
    CPython 3.14 .pyc must be named pyc on 3.12 and a 3.12 one on 3.14. The headers are
    assembled from bytes, so each CI leg proves every magic, not just its own."""
    data = _with_magic(_own_pyc(tmp_path), n)
    assert classify_bytes(data, len(data)) == ("BINARY", "pyc"), (n, label)


def test_the_running_interpreters_own_pyc_is_recognised(tmp_path):
    """Self-alarm for the closed range in collector._PYC_MAGIC_MIN.._PYC_MAGIC_MAX: the
    day a CI interpreter's own magic leaves it, this fails with the number to widen to."""
    n = int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")
    assert _PYC_MAGIC_MIN <= n <= _PYC_MAGIC_MAX, (
        f"this interpreter writes magic {n}; widen collector._PYC_MAGIC_MAX"
    )
    own = _own_pyc(tmp_path)
    assert own[:4] == importlib.util.MAGIC_NUMBER  # the premise: py_compile used it
    assert _pyc_fmt(own) == "pyc"


@pytest.mark.parametrize("n,why", [
    (_PYC_MAGIC_MIN - 1, "one below the range (CPython 3.5a1 is 3320)"),
    (_PYC_MAGIC_MAX + 1, "one above the range (high byte 0x0f)"),
    (3850, "3.19's derived start, 0x0f0a, outside by design"),
    (0x4142, "printable high byte: bytes 'BA' + CR LF is ordinary text-shaped data"),
    (62211, "a CPython 2.7 magic - not a 3.x pyc"),
])
def test_near_miss_magic_is_not_pyc(tmp_path, n, why):
    """Near-miss negatives for the widened byte: binary files whose bytes 2..3 are CR LF
    but whose 16-bit number is outside 3328..3839 are left as 'unrecognised binary'."""
    data = _with_magic(_own_pyc(tmp_path), n)
    assert classify_bytes(data, len(data)) == ("BINARY", None), why


@pytest.mark.parametrize("head", [
    b"\x2b\x0e\n\n",    # LF LF
    b"\x2b\x0e\r\r",    # CR CR
    b"\x2b\x0e\x0d\x00",  # CR NUL
    b"\x2b\x0e\x0a\x0d",  # LF CR (swapped)
    b"\x2b\x0e\r",      # truncated: three bytes only
])
def test_near_miss_terminator_is_not_pyc(tmp_path, head):
    """The CR LF half of the magic is part of the test, so 0x0e in the high-byte slot is
    not enough on its own."""
    data = head + _own_pyc(tmp_path)[4:]
    assert _pyc_fmt(data) is None
    assert _pyc_fmt(head) is None


def test_the_widened_byte_does_not_turn_text_into_pyc():
    """The text guard for the 3.14 byte: prose that starts exactly like a 3.14 header
    (`+`, 0x0e, CR, LF) is TEXT and never reaches the pyc test, same as the CR CR LF
    case below."""
    md = b"+\x0e\r\n# Heading\n\nAll printable ASCII prose here.\n"
    assert classify_bytes(md, len(md)) == ("TEXT", None)


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


@pytest.mark.parametrize("n,label", _MEASURED_MAGIC)
def test_pyc_stowaway_via_collect_for_every_measured_magic(tmp_path, n, label):
    """collect() side of the same property: the stowaway entry carries the (pyc) label
    whichever CPython wrote the file."""
    _skill(tmp_path, {"helper.pyc": _with_magic(_own_pyc(tmp_path), n)})
    (tmp_path / "openclaw.json").write_text('{"tools":{"profile":"minimal"}}')
    ctx = collect(tmp_path)
    assert any("helper.pyc (pyc)" in s for s in ctx.stowaway_files), (label, ctx.stowaway_files)


def _vet_skill_cli(tmp_path, capsys, magic):
    """Run `--vet-skill` on a skill holding SKILL.md + helper.pyc (magic `magic`) and
    return (exit code, stdout)."""
    sk = tmp_path / f"skill-{magic}"
    sk.mkdir()
    (sk / "SKILL.md").write_text("---\nname: weather-helper\ndescription: x\n---\n# weather\n")
    (sk / "helper.pyc").write_bytes(_with_magic(_own_pyc(tmp_path), magic))
    rc = main(["--vet-skill", str(sk), "--no-color", "--data-dir", str(tmp_path / "data")])
    return rc, capsys.readouterr().out


def test_vet_skill_labels_a_314_pyc_exactly_like_a_312_pyc(tmp_path, capsys):
    """End to end through the CLI: the Danger line carries the stowaway '(pyc)' label and
    the 'Not assessed' opacity disclosure for a 3.12-magic and a 3.14-magic .pyc alike,
    and the verdict and exit code are the same."""
    rc312, out312 = _vet_skill_cli(tmp_path, capsys, 3531)
    rc314, out314 = _vet_skill_cli(tmp_path, capsys, 3627)
    for out in (out312, out314):
        assert "native executable(s) bundled in the skill (stowaway)" in out
        assert "helper.pyc (pyc)" in out
        assert "compiled code is opaque to this scanner" in out
    assert rc312 == rc314
    assert "CAUTION" in out312 and "CAUTION" in out314
    # Same report once the one thing that legitimately differs (the skill dir name) is gone.
    assert out312.replace("skill-3531", "S") == out314.replace("skill-3627", "S")


def test_wasm_stowaway_via_collect(tmp_path):
    _skill(tmp_path, {"mod.wasm": b"\x00asm\x01\x00\x00\x00" + b"\x00" * 40})
    (tmp_path / "openclaw.json").write_text('{"tools":{"profile":"minimal"}}')
    ctx = collect(tmp_path)
    assert any("mod.wasm" in s for s in ctx.stowaway_files)
