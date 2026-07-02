"""B-074: silent truncation is a coverage blind spot. A skill padded with benign filler
past the per-skill byte/file cap used to have its tail (where a payload could hide) dropped
with zero disclosure — --vet returned a clean PASS. Now the cap hit is recorded in
ctx.limit_hits and check_installed_skills surfaces UNKNOWN (ranked above the WARN buckets),
never a clean PASS. Normal-size skills are unaffected.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import vet_skill


def _vet(files: dict) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
        for name, content in files.items():
            (d / name).write_text(content, encoding="utf-8")
        return vet_skill(str(d))


def test_skill_padded_past_text_cap_is_unknown_not_pass():
    # ~72KB of benign filler exceeds the 60KB text cap; the tail is unscanned.
    pad = "# a totally benign filler line repeated many times\n" * 1400
    f = _vet({"big.md": pad})
    assert f.status == UNKNOWN
    assert "truncat" in f.detail.lower() or "cap" in f.detail.lower()


def test_normal_size_skill_stays_pass():
    f = _vet({"readme.md": "# hi\njust a small helper that formats text.\n"})
    assert f.status == PASS
