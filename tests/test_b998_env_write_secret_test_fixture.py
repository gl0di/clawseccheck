"""B-998 (Dave's ruling, extending B-893's D2 carve-out to the env-write-site rule):
route the env-entangled `HARDCODED_PROVIDER_SECRET` rule by file basename too, the
same way B-893 already routes its plain-assignment sibling
`HARDCODED_PROVIDER_SECRET_ASSIGN`.

Background: B-893 gave the bare `NAME = "<provider-shaped-literal>"` assignment shape
its own rule name and a `_TEST_FIXTURE_BASENAME_RE` basename carve-out — WARN in an
ordinary file, evidence-only (never a verdict winner) when the file's own basename
says it is a test fixture (`test_*.py` / `*_test.py` / `conftest.py` / a JS spec).
The two env-entangled call sites in skillast.py (`os.environ[K] = "<secret>"` /
`os.getenv(K, "<secret>")`, including B-910's one-hop name-indirection variant) kept
the OLD shared rule name, `HARDCODED_PROVIDER_SECRET`, and had NO such carve-out at
all — every hit fell through to the generic crit/FAIL path regardless of the file's
basename, so a `tests/conftest.py` writing its own `MOCK_*` provider-shaped literal
into `os.environ` for its own test suite (the exact SkillTrustBench FP shape B-893
fixed for the plain-assignment case) still FAILed CRITICAL here.

Fix shape:
- `skillast.py` is UNCHANGED: both env-entangled call sites keep emitting
  `HARDCODED_PROVIDER_SECRET` at "crit" severity, same as before this task (a Layer-1
  module makes no test-fixture-path judgment itself, matching the ASSIGN rule's own
  layering).
- `checks/_vet.py`'s B13 AST loop gained a new arm for `HARDCODED_PROVIDER_SECRET`,
  right after the existing `HARDCODED_PROVIDER_SECRET_ASSIGN` arm: basename matches
  `_TEST_FIXTURE_BASENAME_RE` -> evidence-only (reuses the SAME
  `hardcoded_secret_fixture_note` bucket the ASSIGN arm already feeds — not a new
  bucket, so it renders and discloses identically); basename does NOT match -> falls
  through UNCHANGED to the generic crit/FAIL path (no `continue`), so a real
  CRIT/FAIL still fires exactly as before this task.
- `_AST_NEVER_FAIL_RULES` is DELIBERATELY UNCHANGED: `HARDCODED_PROVIDER_SECRET` is
  NOT added to it (unlike ASSIGN, which is WARN-only everywhere). This rule must stay
  fully FAIL-capable for every file whose basename does not match — only the
  test-fixture-basename case is demoted, not the rule itself.

C-135 risk-equivalence note (required before widening a CRIT-capable rule's PASS
surface, CLAUDE.md §4) — see the in-source comment at the new `checks/_vet.py` arm for
the full reasoning; summarized: both rules fire on nothing more than "a
provider-shaped literal is visible in source" (ASSIGN via a bare name binding, this
rule via that literal, or a same-file one-hop alias of it, being written into/read as
a default for `os.environ`). Neither shape alone proves the value ever leaves the
process. Actual credential exfiltration (`cred_exfil_signal`'s
`_has_same_line`/`_has_cross` cred-path-plus-network-sink co-occurrence, and the
independent `ENV_EXFIL_FLOW`/`HOST_INFO_EXFIL_FLOW` flow detectors) is computed from
the raw file blob by a code path that does not key off this rule name or this routing
arm at all — so a real secret-to-network-sink flow hiding in a test-fixture-named file
is still caught, unaffected by this exemption. The residual this shares with ASSIGN
(already accepted by Dave's D2 ruling): an attacker could name a real payload file
`test_x.py` to dodge BOTH rules' FAIL — not a new evasion this task introduces.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant
at parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text.

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES, ast_finding_is_fail_capable
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str, relpath: str = "t.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, relpath)}


# ---------------------------------------------------------------------------
# Unit: skillast.py's severity/rule-name on the env-entangled call sites is
# UNCHANGED by this task — the routing decision is entirely _vet.py's.
# ---------------------------------------------------------------------------


def test_env_write_call_sites_still_emit_the_old_rule_name_at_crit():
    """Regression: this task touches ONLY checks/_vet.py's routing, never
    skillast.py's rule name or severity for the two env-entangled call sites."""
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
        assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"


def test_rule_is_not_added_to_the_never_fail_set():
    """Unlike HARDCODED_PROVIDER_SECRET_ASSIGN (WARN-only everywhere), the
    env-write-site rule must stay FAIL-capable outside a test-fixture-named file —
    only the ASSIGN rule sits in _AST_NEVER_FAIL_RULES."""
    assert "HARDCODED_PROVIDER_SECRET" not in _AST_NEVER_FAIL_RULES
    assert "HARDCODED_PROVIDER_SECRET_ASSIGN" in _AST_NEVER_FAIL_RULES

    class _AF:
        def __init__(self, rule, severity):
            self.rule, self.severity = rule, severity

    # ast_finding_is_fail_capable alone does not know about file basenames — that
    # gate lives one level up, in the B13 loop's routing arm, exercised below via
    # vet_skill. At the predicate level the rule is unconditionally fail-capable.
    assert ast_finding_is_fail_capable(_AF("HARDCODED_PROVIDER_SECRET", "crit"))


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_env_write_secret_in_conftest_is_clean():
    """(a) The exact FP shape this task fixes: tests/conftest.py assigns its own
    MOCK_OPENAI_KEY and writes it into os.environ — B-910's one-hop resolver still
    fires HARDCODED_PROVIDER_SECRET, but the new basename routing now demotes it to
    evidence-only. Must PASS, and the fact must still be disclosed as evidence."""
    skill_dir = FIXTURES / "clean_b13_env_write_secret_conftest" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS, f"expected PASS; got {f.status}: {f.detail}"
    assert any("MOCK_OPENAI_KEY" in e for e in (f.evidence or [])), (
        f"the test-fixture secret must still be disclosed as evidence: {f.evidence}"
    )


def test_vet_env_write_secret_in_non_fixture_file_still_critical_fail():
    """(b) The identical env-write shape, but the file's basename does NOT match
    _TEST_FIXTURE_BASENAME_RE (scripts/deploy.py) — no regression on the real
    detection: must still FAIL at crit, exactly as before this task."""
    skill_dir = FIXTURES / "bad_b13_env_write_secret_non_fixture" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL, f"expected FAIL; got {f.status}: {f.detail}"
    assert f.severity == CRITICAL


def test_vet_name_indirection_test_fixture_shape_is_clean():
    """The B-910 one-hop-indirection variant of the same fixture-basename shape
    (renamed from bad_* to clean_* by this task) — also covered directly in
    tests/test_b910_env_entangled_name_indirection.py's own updated test, asserted
    again here so this file stands on its own."""
    skill_dir = (
        FIXTURES
        / "clean_b13_env_overwrite_name_indirection_test_fixture_file"
        / "skills"
        / "s"
    )
    f = vet_skill(skill_dir)
    assert f.status == PASS, f"expected PASS; got {f.status}: {f.detail}"


def test_vet_env_overwrite_fixture_still_critical_fail():
    """(c) Regression: the pre-existing B-140 os.environ[...] = <secret> fixture
    (non-fixture basename) is untouched by this task and must still FAIL at crit —
    same fixture tests/test_b893_secret_in_test_fixture.py already covers, asserted
    again here so this file stands on its own."""
    skill_dir = FIXTURES / "bad_b13_hardcoded_env_overwrite" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == CRITICAL
