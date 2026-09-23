"""B-893 (child A of B-543, follow-up to B-740): route the plain-assignment
hardcoded-provider-secret shape by file, not by a single fixed severity.

B-740 gave `skillast.py` a third `_is_hardcoded_provider_secret` call site (a plain
`NAME = "<provider-shaped-literal>"` assignment) under the SAME rule name the two
older, env-entangled call sites use (`os.environ["K"] = <secret>` /
`os.getenv("K", <secret>)`). Because all three shared one rule name and
`checks/_vet.py` had no explicit routing arm for any of them, all three fell through
to the generic crit/FAIL path alike. Measured on the SkillTrustBench corpus
(design-b-543.md §2 / b-543-measure.md): the plain-assignment site alone produced 32
NEW gold-normal FAILs, all `tests/conftest.py` `MOCK_*` fixtures — a byte-identical
template with zero pytest-shape signals.

Dave's D2 ruling on B-543 (quoted in this task's own Pulse description):

    A plain-assignment hardcoded provider key gets WARN. The two env-entangled call
    sites ... stay crit/FAIL. In a test-fixture FILE, the plain-assignment shape is
    evidence-only (does not move the verdict at all).

Fix shape:
- `skillast.py`'s plain-assignment call site now emits a DISTINCT rule name,
  `HARDCODED_PROVIDER_SECRET_ASSIGN` (the two env-entangled sites keep
  `HARDCODED_PROVIDER_SECRET`, unchanged — see tests/test_b140_hardcoded_provider_
  secret.py, which still expects crit/FAIL for both and is untouched by this task).
- `checks/_vet.py`'s B13 AST loop routes `HARDCODED_PROVIDER_SECRET_ASSIGN`:
  basename matches `_TEST_FIXTURE_BASENAME_RE` (test_*.py / *_test.py / conftest.py /
  JS spec) -> evidence-only (never a verdict winner, same carve-out as H6's
  `_h6_advisory`); otherwise -> a real WARN bucket (`warns_hardcoded_secret_assign`).
- `_AST_NEVER_FAIL_RULES` gained the new rule name, so `ast_finding_is_fail_capable`
  (shared with `checks/_mcp.py`'s plugin sweep) returns False for it everywhere.

Deliberately basename-only (NOT the shape-gated `_pos_in_test_fixture_file`/
`_PYTHON_TEST_SHAPE_SIGNALS` pair the prose side uses at `_vet.py:1174-1330`): every
corpus `tests/conftest.py` measured for B-543 has ZERO of those 7 signals, so a shape
gate here would still convict them. See `_vet.py`'s own comment at the new AST-loop
arm for the full C-135 reasoning on why that trade-off is sound here specifically
(the false negative is the author's own hygiene, not an attack on the installing
user) where it would NOT be sound for an exfiltration detector.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant
at parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text.

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES, ast_finding_is_fail_capable
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str, relpath: str = "t.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, relpath)}


# ---------------------------------------------------------------------------
# Unit: skillast.py emits the NEW, distinct rule name for the plain-assignment site
# ---------------------------------------------------------------------------


def test_plain_assignment_emits_the_new_rule_name():
    """The B-740 call site now tags its finding HARDCODED_PROVIDER_SECRET_ASSIGN, not
    the shared HARDCODED_PROVIDER_SECRET the two env-entangled sites still use."""
    src = (
        'STRIPE_SECRET_KEY = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef0123456789ABCDEF"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET_ASSIGN" in r
    assert "HARDCODED_PROVIDER_SECRET" not in r
    # skillast.py itself is unchanged on severity — crit at the AST layer; the WARN/
    # evidence-only routing decision is entirely _vet.py's, downstream of this.
    assert r["HARDCODED_PROVIDER_SECRET_ASSIGN"].severity == "crit"


def test_env_entangled_sites_keep_the_old_rule_name():
    """Regression: the two B-140 call sites this task must NOT touch."""
    src_environ = (
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    src_getenv = (
        'import os\n'
        'k = os.getenv("SKILLPAY_KEY", "sk_live_"\n'
        '    "0123456789abcdef01234567")\n'
    )
    for src in (src_environ, src_getenv):
        r = _rules(src)
        assert "HARDCODED_PROVIDER_SECRET" in r
        assert "HARDCODED_PROVIDER_SECRET_ASSIGN" not in r


def test_new_rule_name_is_never_fail_capable():
    assert "HARDCODED_PROVIDER_SECRET_ASSIGN" in _AST_NEVER_FAIL_RULES

    class _AF:
        def __init__(self, rule, severity):
            self.rule, self.severity = rule, severity

    assert not ast_finding_is_fail_capable(_AF("HARDCODED_PROVIDER_SECRET_ASSIGN", "crit"))
    # the old, unrenamed rule is UNCHANGED: still fail-capable at crit.
    assert ast_finding_is_fail_capable(_AF("HARDCODED_PROVIDER_SECRET", "crit"))


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_test_fixture_conftest_is_clean():
    """The exact corpus shape (b-543-measure.md's case_02160): MOCK_* provider-shaped
    literals in tests/conftest.py, zero pytest-shape signals. Must NOT FAIL — the
    B-893 fix routes this to evidence-only, so overall_status is PASS."""
    skill_dir = FIXTURES / "clean_b13_hardcoded_secret_test_fixture" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS, f"expected PASS; got {f.status}: {f.detail}"
    # Evidence-only means the fact is still disclosed, never silently dropped.
    assert any("MOCK_OPENAI_KEY" in e or "MOCK_STRIPE_KEY" in e for e in (f.evidence or [])), (
        f"the test-fixture secret must still be disclosed as evidence: {f.evidence}"
    )


def test_vet_live_key_in_non_fixture_file_still_warns():
    """The same rule, but the file's basename does NOT match
    _TEST_FIXTURE_BASENAME_RE (scripts/deploy.py) — must still WARN, not be silently
    dropped just because the plain-assignment call site is no longer FAIL-capable."""
    skill_dir = FIXTURES / "bad_b13_hardcoded_secret_assign_warns" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == WARN, f"expected WARN; got {f.status}: {f.detail}"
    assert f.severity == HIGH
    assert "DEPLOY_API_KEY" in f.detail
    # The basename-only trade-off is disclosed in `fix`, never in `detail`
    # (CLAUDE.md §2.5/B-555 — `detail` is what baseline.fingerprint() hashes).
    assert "test-fixture-named file" in f.fix


def test_vet_env_overwrite_fixture_still_critical_fail():
    """Regression: the B-140 os.environ[...] = <secret> site is untouched by this
    task and must still FAIL at crit — same fixture test_b140_hardcoded_provider_
    secret.py already covers, asserted again here so this file stands on its own."""
    skill_dir = FIXTURES / "bad_b13_hardcoded_env_overwrite" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_getenv_default_fixture_still_critical_fail():
    """Regression: the B-140 os.getenv(K, <secret>) site is untouched by this task
    and must still FAIL at crit."""
    skill_dir = FIXTURES / "bad_b13_hardcoded_getenv_default" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# UNKNOWN path
# ---------------------------------------------------------------------------


def test_vet_unparseable_python_is_unknown_not_a_guessed_verdict(tmp_path):
    """A skill whose only Python file cannot be parsed must report UNKNOWN (via
    parse_error_paths), never a guessed PASS/WARN/FAIL — this rule's own routing arm
    runs inside the SAME `for af in analyze_python(...)` loop as the AST_UNANALYZABLE
    finding, so a change to one must not silently break the other."""
    skill_dir = tmp_path / "s"
    (skill_dir / "scripts").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: s\ndescription: A skill whose script cannot be parsed.\n---\n"
        "\n# Broken Skill\n"
    )
    (skill_dir / "scripts" / "broken.py").write_text("def f(:\n    pass\n")
    f = vet_skill(skill_dir)
    assert f.status == UNKNOWN, f"expected UNKNOWN; got {f.status}: {f.detail}"
    assert "parse error" in f.detail
