"""F-054: stowaway detection — a native executable (ELF / PE / Mach-O / JVM class) bundled
inside a skill. Skills are text/config; a compiled binary the prose never needs is a
classic stowaway ("a commit formatter has no reason to ship an ELF"). WARN, low-FP: only
executable magic bytes trigger it, so media (PNG/PDF) and text skills stay quiet here.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import vet_skill


def _vet(files: dict) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
        for name, content in files.items():
            p = d / name
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content, encoding="utf-8")
        f = vet_skill(str(d))
        return f.status


def test_bundled_elf_executable_is_flagged():
    elf = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 64
    f = _vet({"helper.bin": elf})
    assert f == WARN


def test_bundled_pe_executable_is_flagged():
    pe = b"MZ" + b"\x90\x00" * 40
    assert _vet({"tool.exe": pe}) == WARN


def test_text_only_skill_has_no_stowaway():
    assert _vet({"readme.md": "# hi\nformats text.\n"}) == PASS
