"""B91 (F-102, L1-5) — a sink reached via a computed/decoded attribute or module name
(``getattr(os, 'sy' + 'stem')``, ``importlib.import_module(cfg['mod'])``) defeats a simple
text/keyword scan. Reuses the existing skillast.py AST rules (GETATTR_INDIRECTION,
DYNAMIC_IMPORT_EXEC) — pure wiring, no new AST logic. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_dynamic_dispatch_obfuscation, vet_skill
from clawseccheck.collector import Context
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# --- analyzer-level (already exists — confirm wiring assumption) ---

def test_getattr_computed_dangerous_attr_on_dangerous_obj_fires():
    src = "import os\ngetattr(os, 'sy' + 'stem')('id')\n"
    assert "GETATTR_INDIRECTION" in _rules(src)


def test_getattr_literal_attr_on_plain_object_does_not_fire():
    src = "class H:\n    def add(self): pass\nh = H()\ngetattr(h, 'add')()\n"
    assert "GETATTR_INDIRECTION" not in _rules(src)


# --- check-level: UNKNOWN / PASS / WARN ---

def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_dynamic_dispatch_obfuscation(ctx)
    assert f.status == UNKNOWN


# --- vet-level: B91 surfaces as WARN on the bad fixture, PASS on the clean one ---

def test_vet_bad_dynamic_dispatch_is_warn():
    skill_dir = FIXTURES / "bad_b91_dynamic_dispatch" / "skills" / "dispatcher"
    f = vet_skill(skill_dir)
    assert any(x.id == "B91" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_literal_dispatch_b91_passes():
    skill_dir = FIXTURES / "clean_b91_literal_dispatch" / "skills" / "dispatcher"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B91" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
