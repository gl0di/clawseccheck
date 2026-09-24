"""B-910: resolve a one-hop `ast.Name` indirection into the two B-140 env-entangled
call sites in skillast.py, so `KEY = "sk-..."; os.environ["OPENAI_API_KEY"] = KEY`
FAILs at crit the same as writing the literal directly, instead of only being caught
by the separate, WARN-only `HARDCODED_PROVIDER_SECRET_ASSIGN` rule (B-893) for the
`KEY = "sk-..."` line alone.

Fix shape: `_secret_name_bindings(tree)` (skillast.py) maps a name to its literal
value ONLY when that name is the target of EXACTLY ONE same-file `Assign`/
`AnnAssign` (a single `Name` target) anywhere in the file, and that value passes
`_is_hardcoded_provider_secret`. Both env-entangled sites — `os.environ[K] = <name>`
and `os.getenv`/`os.environ.get`/`os.environ.setdefault`'s default arg — consult it
when the value/default-arg is an `ast.Name`, and fall through to their EXISTING
literal-only behavior otherwise. `os.environ.setdefault(...)` also newly joins
`os.environ.get(...)` as a recognized call shape at the same site (it was not
matched AT ALL before this task, literal or indirect). `os.environ.update({K:
<name>})` stays untouched — a dict-literal value, not a direct call-arg or
Assign/AnnAssign value, is out of scope for this resolver (documented residual,
CLAWSECCHECK-B-910 ticket's own explicit permission to skip).

C-135: this WIDENS a CRIT-severity, FAIL-capable rule (HARDCODED_PROVIDER_SECRET is
NOT in `_AST_NEVER_FAIL_RULES` — unlike its ASSIGN-only sibling — so every case this
resolves is a new FAIL). The FP-probe tests below are the adversarial pass: a name
bound in two different branches (ambiguous — which one reaches the env write?), a
name bound once to something that never resolves to a hardcoded-secret-shaped
literal (a non-secret string, a further `os.getenv(...)` read, a function call), and
the pre-existing multi-target-Assign guard, must all stay exactly as silent as they
were before this task.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant
at parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text.

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str, relpath: str = "scripts/main.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, relpath)}


# ---------------------------------------------------------------------------
# analyze_python unit tests — regression-matrix rows
# ---------------------------------------------------------------------------


def test_environ_bracket_assign_resolves_one_hop_name_indirection():
    src = (
        'KEY = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = KEY\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"
    assert "TAVILY_API_KEY" in r["HARDCODED_PROVIDER_SECRET"].reason
    assert "'KEY'" in r["HARDCODED_PROVIDER_SECRET"].reason


def test_environ_setdefault_recognized_and_resolves_name_indirection():
    """setdefault was not matched AT ALL before this task, literal or indirect."""
    src = (
        'KEY = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
        'import os\n'
        'os.environ.setdefault("SKILLPAY_KEY", KEY)\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert r["HARDCODED_PROVIDER_SECRET"].severity == "crit"


def test_environ_setdefault_with_direct_literal_now_fires_too():
    """The literal-value case for setdefault was ALSO never matched before this
    task (only os.environ.get / os.getenv were recognized call shapes)."""
    src = (
        'import os\n'
        'os.environ.setdefault("SKILLPAY_KEY", "sk_live_"\n'
        '    "0123456789abcdef01234567")\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r


def test_getenv_default_resolves_one_hop_name_indirection():
    src = (
        'KEY = (\n'
        '    "sk_live_"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
        'import os\n'
        'val = os.getenv("SKILLPAY_KEY", KEY)\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r


def test_environ_get_default_resolves_one_hop_name_indirection():
    src = (
        'KEY = (\n'
        '    "gh" "p_0123456789abcdef012345"\n'
        ')\n'
        'import os\n'
        'val = os.environ.get("GH_TOKEN", KEY)\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r


def test_environ_update_dict_literal_name_is_untouched_residual():
    """os.environ.update({K: <name>}) is a documented, deliberately out-of-scope
    residual — a dict-literal value, not a direct call-arg/Assign value."""
    src = (
        'KEY = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
        'import os\n'
        'os.environ.update({"TAVILY_API_KEY": KEY})\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r
    # The pre-existing plain-assignment rule (B-893) still sees the KEY = "..." line.
    assert "HARDCODED_PROVIDER_SECRET_ASSIGN" in r


def test_multitarget_assign_stays_unresolved_pre_existing_guard():
    """`os.environ[K] = KEY = "<lit>"` — both sites already require len(targets)==1;
    this task must not touch that pre-existing guard."""
    src = (
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = TAVILY_KEY = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r
    assert "HARDCODED_PROVIDER_SECRET_ASSIGN" not in r


def test_literal_value_case_is_unchanged_no_indirection_note():
    """Regression: the pre-existing literal-value path must not gain a spurious
    "(via ...)" indirection note, and must keep firing exactly as before."""
    src = (
        'import os\n'
        'os.environ["TAVILY_API_KEY"] = (\n'
        '    "tvly-"\n'
        '    "0123456789abcdef01234567"\n'
        ')\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" in r
    assert "via" not in r["HARDCODED_PROVIDER_SECRET"].reason


# ---------------------------------------------------------------------------
# C-135 adversarial FP probes — must stay exactly as silent as before this task
# ---------------------------------------------------------------------------


def test_fp_multiple_conditional_bindings_does_not_resolve():
    """A name bound to a (secret-shaped) literal in BOTH branches of an if/else is
    not "unique" — ambiguous which one reaches the env write, must not fire."""
    src = (
        'import os\n'
        'if True:\n'
        '    KEY = "tvly-" "0123456789abcdef01234567"\n'
        'else:\n'
        '    KEY = "tvly-" "fedcba9876543210fedcba98"\n'
        'os.environ["TAVILY_API_KEY"] = KEY\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r


def test_fp_bound_once_to_non_secret_shaped_literal_does_not_resolve():
    """A single binding whose value is NOT secret-shaped must not resolve — even
    when the name is later reused for something else entirely."""
    src = (
        'import os\n'
        'KEY = "just-a-plain-config-string"\n'
        'os.environ["MODE"] = KEY\n'
        'KEY = "unrelated-later-value"\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r


def test_fp_name_bound_via_getenv_read_does_not_resolve():
    """A name bound via another os.getenv(...) read (not a literal) must not
    resolve — _is_hardcoded_provider_secret requires an ast.Constant."""
    src = (
        'import os\n'
        'KEY = os.getenv("SOME_OTHER_VAR")\n'
        'os.environ["OPENAI_API_KEY"] = KEY\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r


def test_fp_name_bound_via_function_call_does_not_resolve():
    """A name bound via a function call must not resolve either."""
    src = (
        'import os\n'
        'def compute_key():\n'
        '    return "x"\n'
        'KEY = compute_key()\n'
        'os.environ["OPENAI_API_KEY"] = KEY\n'
    )
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r


def test_fp_unbound_name_default_arg_does_not_crash_or_resolve():
    """A getenv default that is a Name with NO same-file binding at all must not
    resolve (and must not raise)."""
    src = 'import os\nval = os.getenv("OPENAI_API_KEY", UNBOUND_NAME)\n'
    r = _rules(src)
    assert "HARDCODED_PROVIDER_SECRET" not in r


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_env_overwrite_name_indirection_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_env_overwrite_name_indirection" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL, f"expected FAIL; got {f.status}: {f.detail}"
    assert f.severity == CRITICAL


def test_vet_setdefault_name_indirection_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_setdefault_name_indirection" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL, f"expected FAIL; got {f.status}: {f.detail}"
    assert f.severity == CRITICAL


def test_vet_name_indirection_in_test_named_file_still_fails():
    """The env-entangled crit rule has NO test-fixture-basename dampening (unlike
    HARDCODED_PROVIDER_SECRET_ASSIGN) — matches the literal-value crit site's own
    existing, unconditional behavior."""
    skill_dir = (
        FIXTURES / "bad_b13_env_overwrite_name_indirection_test_fixture_file" / "skills" / "s"
    )
    f = vet_skill(skill_dir)
    assert f.status == FAIL, f"expected FAIL; got {f.status}: {f.detail}"
    assert f.severity == CRITICAL


def test_vet_conditional_name_indirection_fixture_does_not_fail():
    """The ambiguous multi-branch-binding shape must never win a FAIL from the new
    resolver — it may still WARN via the pre-existing, unrelated ASSIGN rule."""
    skill_dir = (
        FIXTURES / "clean_b13_env_overwrite_conditional_name_indirection" / "skills" / "s"
    )
    f = vet_skill(skill_dir)
    assert f.status != FAIL, f"must not FAIL; got {f.status}: {f.detail}"
    assert f.status == WARN
    assert f.severity == HIGH


def test_vet_cross_module_conftest_import_stays_pass():
    """Explicitly out of scope: cross-module (conftest -> main) import resolution.
    A same-file-only resolver never sees MOCK_OPENAI_KEY's binding in main.py (it
    is only imported there), so this stays PASS — a documented residual, not a
    bug to fix here."""
    skill_dir = FIXTURES / "clean_b13_env_overwrite_conftest_cross_module" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS, f"expected PASS; got {f.status}: {f.detail}"
