"""Tests for F-057: parse-failure signal in analyze_python and surface as UNKNOWN in vet_skill.

Three areas:
  (a) analyze_python emits AST_UNANALYZABLE on unparseable source (not []).
  (b) vet_skill surfaces UNKNOWN for an unparseable .py; clean .py stays PASS (zero-FP).
  (c) A skill with BOTH a crit pattern and an unparseable file → FAIL wins (crit precedence).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python


# ---------------------------------------------------------------------------
# (a) analyze_python unit-level: parse-failure signal
# ---------------------------------------------------------------------------

def test_analyze_python_unparseable_returns_nonempty():
    """A SyntaxError must yield a non-empty list, not []."""
    findings = analyze_python("def (: not python", "bad.py")
    assert findings, "expected at least one finding for an unparseable file"


def test_analyze_python_unparseable_rule_id():
    findings = analyze_python("def (: not python", "bad.py")
    rules = {f.rule for f in findings}
    assert "AST_UNANALYZABLE" in rules


def test_analyze_python_unparseable_severity_unknown():
    findings = analyze_python("def (: not python", "bad.py")
    f = next(x for x in findings if x.rule == "AST_UNANALYZABLE")
    assert f.severity == "unknown"


def test_analyze_python_unparseable_lineno_zero():
    findings = analyze_python("def (: not python", "bad.py")
    f = next(x for x in findings if x.rule == "AST_UNANALYZABLE")
    assert f.lineno == 0


def test_analyze_python_unparseable_reason_contains_filename():
    findings = analyze_python("def (: not python", "myskill.py")
    f = next(x for x in findings if x.rule == "AST_UNANALYZABLE")
    assert "myskill.py" in f.reason


def test_analyze_python_unparseable_reason_mentions_parse_failure():
    findings = analyze_python("def (: not python", "bad.py")
    f = next(x for x in findings if x.rule == "AST_UNANALYZABLE")
    assert "could not parse" in f.reason.lower()


def test_analyze_python_unparseable_reason_mentions_error_type():
    # The reason should name the exception class (e.g. SyntaxError)
    findings = analyze_python("def (: not python", "bad.py")
    f = next(x for x in findings if x.rule == "AST_UNANALYZABLE")
    assert "SyntaxError" in f.reason


def test_analyze_python_empty_source_still_returns_empty():
    """Empty source is valid Python — should return [] (no findings, no UNANALYZABLE)."""
    findings = analyze_python("", "empty.py")
    assert findings == []


def test_analyze_python_valid_source_no_unanalyzable():
    """A parseable clean file must never produce AST_UNANALYZABLE."""
    src = "def hello():\n    return 'world'\n"
    findings = analyze_python(src, "clean.py")
    assert all(f.rule != "AST_UNANALYZABLE" for f in findings)


# ---------------------------------------------------------------------------
# (b) vet_skill integration: UNKNOWN for unparseable .py; PASS for clean .py
# ---------------------------------------------------------------------------

def _mk_skill(root: Path, files: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    default_md = "---\nname: test-skill\ndescription: A test skill.\n---\n# a skill\n"
    (root / "SKILL.md").write_text(files.get("SKILL.md", default_md), encoding="utf-8")
    for name, content in files.items():
        if name != "SKILL.md":
            (root / name).write_text(content, encoding="utf-8")
    return root


def test_vet_skill_unparseable_py_is_unknown(tmp_path):
    """A skill with only an unparseable .py must surface as UNKNOWN, not PASS or FAIL."""
    d = _mk_skill(tmp_path / "bad", {"tool.py": "def (: not python\n"})
    result = vet_skill(d)
    assert result.status == UNKNOWN


def test_vet_skill_unparseable_py_detail_names_file(tmp_path):
    """The UNKNOWN detail or evidence must reference the filename and parse failure."""
    d = _mk_skill(tmp_path / "bad2", {"payload.py": "def (: not python\n"})
    result = vet_skill(d)
    combined = (result.detail or "") + " " + " ".join(str(e) for e in (result.evidence or []))
    assert "payload.py" in combined or "could not analyze" in combined.lower()


def test_vet_skill_clean_py_is_still_pass(tmp_path):
    """Zero-FP: a skill with a valid .py must remain PASS (not flip to UNKNOWN)."""
    d = _mk_skill(tmp_path / "clean", {"tool.py": "def hello():\n    return 'world'\n"})
    result = vet_skill(d)
    assert result.status == PASS


def test_vet_skill_no_py_files_is_pass(tmp_path):
    """A skill with no Python files at all must still PASS (not UNKNOWN)."""
    d = _mk_skill(tmp_path / "nocode", {
        "SKILL.md": "---\nname: nocode\ndescription: Does some task.\n---\n# a skill\nDoes some task.\n"})
    result = vet_skill(d)
    assert result.status == PASS


# ---------------------------------------------------------------------------
# (c) Crit precedence: crit FAIL wins over parse-error UNKNOWN
# ---------------------------------------------------------------------------

def test_vet_skill_crit_beats_parse_error(tmp_path):
    """A skill with a crit pattern in one file and an unparseable second file must FAIL,
    not be downgraded to UNKNOWN — dangerous patterns always win."""
    d = _mk_skill(tmp_path / "mixed", {
        # Crit: obfuscated exec in a parseable file
        "evil.py": 'import base64\nexec(base64.b64decode("eA=="))\n',
        # Parse failure in a second file
        "broken.py": "def (: not python\n",
    })
    result = vet_skill(d)
    assert result.status == FAIL
