"""B-740: hardcoded provider-shaped credential in a PLAIN ASSIGNMENT.

B-140 already covers two AST shapes entangled with `os.environ`
(`os.environ["K"] = <secret>` and `os.getenv("K", <secret>)`/`os.environ.get(...)`),
but the plainest shape — an ordinary module-level (or class-body/function-local)
assignment, e.g. `STRIPE_SECRET_KEY = "sk_live_..."` — reached neither call site and
produced no finding at all. This is a THIRD call site of the same
`_is_hardcoded_provider_secret` predicate (unchanged); it folds into the existing B13
pipeline via the same "crit"-severity `HARDCODED_PROVIDER_SECRET` ASTFinding the other
two call sites already emit — no new catalog check ID.

Must not fire on: a placeholder/example value (existing `_PLACEHOLDER_TOKEN_RE` guard,
unchanged), or a provider-shaped string that appears only in a comment/docstring
example rather than as an actual assignment target's value (comments are invisible to
the AST; a docstring's text content is never parsed as code).

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant at
parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text.

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
# analyze_python unit tests — direct AST call-site coverage
# ---------------------------------------------------------------------------


def test_module_level_plain_assignment_fires():
    src = (
        'STRIPE_SECRET_KEY = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef0123456789ABCDEF"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"
    assert r["HARDCODED_PROVIDER_SECRET"].lineno == 1
    assert "STRIPE_SECRET_KEY" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_function_local_plain_assignment_fires():
    src = (
        'def charge():\n'
        '    key = (\n'
        '        "sk_live_"\n'
        '        "0123456789abcdef0123456789ABCDEF"\n'
        '    )\n'
        '    return key\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert "key" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_class_body_plain_assignment_fires():
    src = (
        'class Client:\n'
        '    API_KEY = (\n'
        '        "sk_live_"\n'
        '        "0123456789abcdef0123456789ABCDEF"\n'
        '    )\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r


def test_ann_assign_plain_assignment_fires():
    src = (
        'API_KEY: str = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef0123456789ABCDEF"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert "API_KEY" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_reason_never_contains_the_matched_secret_value():
    secret = "sk_live_" "0123456789abcdef0123456789ABCDEF"
    src = (
        'STRIPE_SECRET_KEY = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef0123456789ABCDEF"\n'
        ')\n'
    )
    r = _rules(src)
    assert secret not in r["HARDCODED_PROVIDER_SECRET"].reason


def test_placeholder_plain_assignment_is_clean():
    src = 'API_KEY = "sk-your-key-here"\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_public_key_no_provider_prefix_plain_assignment_is_clean():
    src = 'CNJ_PUBLIC_KEY = "cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpams"\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_short_literal_plain_assignment_is_clean():
    """A short value (e.g. a feature-flag string) must not be mistaken for a secret."""
    src = 'MODE = "prod"\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_comment_only_mention_does_not_fire():
    """A secret-shaped string in a COMMENT (never an AST node at all) must not fire."""
    src = (
        '# STRIPE_SECRET_KEY = "sk_live_0123456789abcdef0123456789ABCDEF"\n'
        'import os\n'
        'STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_docstring_example_does_not_fire():
    """A secret-shaped string inside a docstring's prose is a string CONTENT, not an
    assignment target's value — the AST never sees it as an ast.Assign node."""
    src = (
        '"""Example:\n'
        '\n'
        '    STRIPE_SECRET_KEY = "sk_live_0123456789abcdef0123456789ABCDEF"\n'
        '"""\n'
        'import os\n'
        'STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_tuple_target_assignment_does_not_crash():
    """A tuple-target assignment (out of this call site's scope) must not raise."""
    src = (
        'a, b = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef0123456789ABCDEF"\n'
        '), "other"\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_name_reference_value_does_not_fire():
    """Assigning from an existing name (not a literal) must not fire."""
    src = (
        'import os\n'
        'k = os.environ["STRIPE_SECRET_KEY"]\n'
        'STRIPE_SECRET_KEY = k\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_plain_assignment_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_hardcoded_plain_assignment" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_comment_only_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_plain_assignment_comment" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_placeholder_plain_assignment_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_plain_assignment_placeholder" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS
