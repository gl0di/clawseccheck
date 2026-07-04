"""B92 (F-098, L1-1) — an unsafe deserialization sink (pickle/marshal/dill/torch.load, or
yaml.load without a safe Loader) can execute arbitrary code from a bundled "data" file — RCE
from what looks harmless. json.load / yaml.safe_load never reach the underlying AST rule at
all (different attribute name) and stay clean automatically. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_unsafe_deserialization, vet_skill
from clawseccheck.collector import Context
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# --- analyzer-level (extended by this task — confirm the extension) ---

def test_torch_load_fires():
    assert "DESERIALIZE_CODE" in _rules("import torch\ntorch.load('m.pt')\n")


def test_yaml_load_without_loader_fires():
    assert "DESERIALIZE_CODE" in _rules("import yaml\nyaml.load(open('x'))\n")


def test_yaml_load_with_safe_loader_is_clean():
    assert "DESERIALIZE_CODE" not in _rules(
        "import yaml\nyaml.load(open('x'), Loader=yaml.SafeLoader)\n"
    )


def test_yaml_safe_load_is_clean():
    assert "DESERIALIZE_CODE" not in _rules("import yaml\nyaml.safe_load(open('x'))\n")


def test_pickle_loads_still_fires():
    assert "DESERIALIZE_CODE" in _rules("import pickle\npickle.loads(b'x')\n")


# --- check-level ---

def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_unsafe_deserialization(ctx)
    assert f.status == UNKNOWN


# --- vet-level: B92 surfaces as WARN on the bad fixture, PASS on the clean one ---

def test_vet_bad_unsafe_deserialize_is_warn():
    skill_dir = FIXTURES / "bad_b92_unsafe_deserialize" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert any(x.id == "B92" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_safe_load_b92_passes():
    skill_dir = FIXTURES / "clean_b92_safe_load" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B92" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
