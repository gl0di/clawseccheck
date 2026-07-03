"""Defensibility axis — a benign skill's resistance to being weaponized by its
environment (skill-as-target / confused-deputy), distinct from skill-as-attacker.

D1 (B86): IMPORT_FROM_WRITABLE — the skill mutates its own module search path to a
relative / writable / env-derived location, so anyone who can write that path hijacks
the skill's imports. The common `sys.path.insert(0, dirname(__file__))` self-dir pattern
stays clean.
"""

from pathlib import Path

from clawseccheck.checks import WARN, vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# --- analyzer-level: IMPORT_FROM_WRITABLE fires on attacker-influenceable sys.path ---


def test_import_from_writable_relative_syspath_insert():
    src = "import sys\nsys.path.insert(0, 'plugins')\nimport handler\n"
    assert "IMPORT_FROM_WRITABLE" in _rules(src)


def test_import_from_writable_syspath_append_cwd():
    src = "import sys\nsys.path.append('.')\n"
    assert "IMPORT_FROM_WRITABLE" in _rules(src)


def test_import_from_writable_env_derived_path():
    src = "import sys, os\nsys.path.insert(0, os.environ['PLUGIN_DIR'])\n"
    assert "IMPORT_FROM_WRITABLE" in _rules(src)


def test_import_from_writable_tmp_path():
    src = "import sys\nsys.path.insert(0, '/tmp/ext')\n"
    assert "IMPORT_FROM_WRITABLE" in _rules(src)


# --- clean: the benign self-dir and fixed absolute forms must NOT fire ---


def test_import_from_file_anchored_syspath_is_clean():
    src = "import sys, os\nsys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
    assert "IMPORT_FROM_WRITABLE" not in _rules(src)


def test_import_from_absolute_syspath_is_clean():
    src = "import sys\nsys.path.insert(0, '/opt/app/lib')\n"
    assert "IMPORT_FROM_WRITABLE" not in _rules(src)


def test_no_syspath_mutation_is_clean():
    src = "import sys\nimport os\nprint(sys.version)\n"
    assert "IMPORT_FROM_WRITABLE" not in _rules(src)


# --- vet-level: B86 surfaces as WARN on the bad fixture, PASS on the clean one ---


def test_vet_bad_import_from_writable_is_warn():
    skill_dir = FIXTURES / "bad_b86_import_from_writable" / "skills" / "loaderskill"
    f = vet_skill(skill_dir)
    assert any(x.id == "B86" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_import_self_dir_b86_passes():
    skill_dir = FIXTURES / "clean_b86_import_self_dir" / "skills" / "loaderskill"
    f = vet_skill(skill_dir)
    # B86 must not be among the actionable (FAIL/WARN) findings for the clean skill.
    assert not any(
        x.id == "B86" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
