"""F-061: filesystem-shape signals (H8 + H9).

H8 — a symlink or path-escape inside a skill used to be dropped silently by
walk_dir_safely; now the skip + its target are recorded and surface as a WARN, so a skill
shipping `data -> ~/.ssh/id_rsa` or `-> ../../openclaw.json` is visible.
H9 — skill filenames are routed through obfuscation_signals, so a homoglyph / zero-width /
RTL-override filename (a Cyrillic-lookalike 'data.py') is flagged.
Benign trees stay PASS.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import vet_skill


def _vet(build) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
        build(d)
        return vet_skill(str(d)).status


def test_symlink_escape_is_surfaced():
    def build(d):
        os.symlink("/etc/passwd", d / "data")  # escapes the skill dir
    assert _vet(build) == WARN


def test_homoglyph_filename_is_flagged():
    def build(d):
        (d / "dаta.py").write_text("print(1)\n", encoding="utf-8")  # Cyrillic 'а'
    assert _vet(build) == WARN


def test_zero_width_filename_is_flagged():
    def build(d):
        (d / "hel​per.py").write_text("print(1)\n", encoding="utf-8")
    assert _vet(build) == WARN


def test_benign_filenames_and_no_symlinks_stay_pass():
    def build(d):
        (d / "helper.py").write_text("print(1)\n", encoding="utf-8")
        (d / "readme.md").write_text("# hi\n", encoding="utf-8")
    assert _vet(build) == PASS
