"""B-140: hardcoded provider-shaped credential detection.

Covers two AST-shaped patterns the scanner previously missed:
- os.environ["KEY"] = "<provider-shaped-literal>" (unconditional overwrite)
- os.getenv("KEY", "<provider-shaped-literal>") / os.environ.get(...) (default arg)

Both fold into the existing B13 pipeline via a "crit"-severity ASTFinding — no new
catalog check ID. Must not fire on: env passthrough (no literal), documented
placeholder/example defaults, or a documented public key with no provider prefix
(the klaus-processos-br counter-example from CLAWSECCHECK-B-140).

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant
at parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text (verified: GitHub push
protection flagged the original single-literal form as a Stripe-key-shaped secret).

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# analyze_python unit tests
# ---------------------------------------------------------------------------


def test_env_overwrite_with_provider_token_fires():
    src = (
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"
    assert r["HARDCODED_PROVIDER_SECRET"].lineno == 2
    assert "TAVILY_API_KEY" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_getenv_default_with_provider_token_fires():
    src = (
        'import os\n'
        'k = os.getenv("SKILLPAY_KEY", "sk_live_"\n'
        '    "0123456789abcdef01234567")\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"
    assert "SKILLPAY_KEY" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_environ_get_default_with_provider_token_fires():
    src = (
        'import os\n'
        'k = os.environ.get("GH_TOKEN", "gh"\n'
        '    "p_0123456789abcdef012345")\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r


def test_reason_never_contains_the_matched_secret_value():
    secret = "tvly-" "0123456789abcdef01234567"
    src = (
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    r = _rules(src)
    assert secret not in r["HARDCODED_PROVIDER_SECRET"].reason


def test_env_passthrough_no_literal_is_clean():
    src = 'import os\nos.environ["X"] = os.getenv("X", "")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_placeholder_default_is_clean():
    src = 'import os\nk = os.getenv("API_KEY", "sk-your-key-here")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_public_key_no_provider_prefix_is_clean():
    src = 'import os\nk = os.getenv("CNJ_KEY", "cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpams")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_short_literal_default_is_clean():
    """A short default (e.g. a feature-flag string) must not be mistaken for a secret."""
    src = 'import os\nmode = os.getenv("MODE", "prod")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_dynamic_key_name_does_not_crash():
    """A non-literal env-var key (computed at runtime) must not raise."""
    src = (
        'import os\n'
        'name = "TAVILY_API_KEY"\n'
        'os.environ[name] = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert "<dynamic>" in r["HARDCODED_PROVIDER_SECRET"].reason


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_env_overwrite_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_hardcoded_env_overwrite" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_getenv_default_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_hardcoded_getenv_default" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_env_passthrough_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_env_passthrough" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_placeholder_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_placeholder" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_public_key_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_public_key" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS
