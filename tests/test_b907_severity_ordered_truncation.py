"""CLAWSECCHECK-B-907: the 25-finding cap on `analyze_python` silently dropped a real
crit finding (TT5_CMD_INJECTION, HARDCODED_PROVIDER_SECRET, OBFUSCATED_EXEC, ...)
behind enough lower-severity findings.

Round 1 fixed the INTER-pass shape: every finding-collection loop in `analyze_python`
gated on the SAME shared, global `if len(out) >= _MAX_FINDINGS_PER_FILE: break`, so an
earlier pass (e.g. the plain DANGEROUS_SINK sweep) that happened to fill `out` to the
cap made every LATER pass's loop break on its very first iteration — not merely capped
alongside the earlier pass's findings, but skipped entirely.

Round 1's fix (each pass tracks its own contribution via `_pass_start = len(out)` and
breaks only once IT has added `_MAX_FINDINGS_PER_FILE` (25) findings of its own) closed
that inter-pass gap but reintroduced the IDENTICAL starvation INSIDE a single pass that
emits mixed severities — a C-135 adversarial review round caught this (see the task's
Pulse history): `analyze_python`'s first main Call-walk loop is ONE pass that also
emits HARDCODED_PROVIDER_SECRET / OBFUSCATED_EXEC / GETATTR_INDIRECTION /
DYNAMIC_IMPORT_EXEC (all crit-capable) inline alongside plain DANGEROUS_SINK (info) —
25 padding DANGEROUS_SINK matches early in that one loop still exhausted THAT loop's
own 25-budget and broke before a later node's crit was ever reached. The very same
shape exists in the TT5/TT4/SSRF `ext_taint_map` pass (TT5_CMD_INJECTION crit sharing
one walk with TT5_ARG_INJECTION/TT4_FILE_NET/TT_SSRF info) — reproduced independently
below, not previously reported.

Round 2's fix (skillast.py): replace each pass's own `_MAX_FINDINGS_PER_FILE`-sized
budget with `_PASS_SAFETY_CEILING` (20x), a pure DoS-safety backstop far above what any
real pass produces — never a per-severity budget. Every genuine candidate, crit or
info, from every pass (including a pass that mixes severities) now actually reaches
`out`, and `analyze_python`'s final `return` truncates the (now possibly over-cap)
combined list by SEVERITY, not by discovery order — crit sorts ahead of info — and
appends one `AST_FINDINGS_TRUNCATED` disclosure finding when anything was actually cut,
so `len(result) <= _MAX_FINDINGS_PER_FILE` still holds for every caller.

checks/_vet.py: `AST_FINDINGS_TRUNCATED` is routed through its own `continue` arm
(alongside CHUNKED_FILE_EXEC/TUNNEL_LAUNCH_ARGV) and added to `_AST_NEVER_FAIL_RULES`,
so a cap-disclosure note can never itself become a B13 FAIL or bleed into the `high`
(cred-exfil) bucket.

Round 2's `_PASS_SAFETY_CEILING` was still a finite early-break inside each pass's own
`ast.walk` — a second C-135 adversarial review round showed it only raised the padding
count an attacker needs (25 -> 500), not closed the class: 500 padding `DANGEROUS_SINK`
matches (still well under the ~1MB single-file collector cap, so trivially attacker-
reachable) exhausted the SAME loop's budget before a later node's crit was reached,
identically to round 1. Round 3 removes the per-pass ceiling entirely — every loop now
runs to completion over `ast.walk(tree)`, relying solely on (a) the existing per-check
wall-clock deadline (`scanbudget.check_deadline` / `ScanBudgetExceeded`, armed by every
caller of `analyze_python`) as the DoS backstop, and (b) the unchanged, already-correct
final severity-ordered truncation at `return` as the sole enforcement of
`_MAX_FINDINGS_PER_FILE`. `_PASS_SAFETY_CEILING` no longer exists in `skillast.py`. The
tests below at n_pad=500+ (round 2's own exact breaking point, plus a further margin)
pin that no finite per-pass ceiling has been reintroduced.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3 / the B-740 idiom) — Python folds them into one `ast.Constant` at parse
time, so the AST detector still sees one joined value, but no contiguous secret-shaped
substring exists in this file's own raw text.

Every `os.system(...)` / `subprocess.*` / `exec(...)` call built below is TEST DATA — a
source string handed to `analyze_python()` for static AST analysis. None of it is ever
executed by this test file; it is Python source being scanned, not run.

Offline, deterministic. No network calls, no writes outside tmp_path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES, ast_finding_is_fail_capable, check_installed_skills
from clawseccheck.collector import Context
from clawseccheck.skillast import ASTFinding, _MAX_FINDINGS_PER_FILE, analyze_python

# ---------------------------------------------------------------------------
# Fixture-shaped sources
# ---------------------------------------------------------------------------

# NOTE: every `os.system(...)` / `subprocess.*` string below is TEST DATA — a source
# string handed to `analyze_python()` for static AST analysis. None of it is ever
# executed by this test file; it is Python source being scanned, not run.
#
# The task's own reproduction: 30 harmless, fixed-literal os.system() calls (each its
# own DANGEROUS_SINK info finding) ahead of a genuinely tainted subprocess wrapper.
_BAD_TT5_BEHIND_FLOOD = (
    "import os\nimport subprocess\n\n"
    + "\n".join(f'os.system("echo hi{i}")' for i in range(30))
    + "\n\n"
    "def sh(*args):\n"
    '    payload = os.environ["P"]\n'
    "    return subprocess.check_output(list(args) + [payload])\n\n"
    "def main():\n"
    '    print(sh("git"))\n'
)

# Same flood shape, but starving a DIFFERENT capped pass: the plain-assignment
# HARDCODED_PROVIDER_SECRET rule (crit) is the LAST capped loop in analyze_python, so
# it is the pass most exposed to every earlier pass having already filled `out`.
_BAD_SECRET_BEHIND_FLOOD = (
    "import os\n\n"
    + "\n".join(f'os.system("echo hi{i}")' for i in range(30))
    + "\n\n"
    "STRIPE_SECRET_KEY = (\n"
    '    "sk_live_"\n'
    '    "0123456789abcdef0123456789ABCDEF"\n'
    ")\n"
)

# A small source, well under the cap, with an INFO finding discovered before a CRIT
# one — the DANGEROUS_SINK main-loop pass runs before the plain-assignment secret
# pass, so an unmodified/pre-fix `analyze_python` would return them in exactly this
# (info-before-crit) discovery order. Used as the "unchanged below the cap" control.
_CLEAN_UNDER_CAP = (
    "import os\n\n"
    'os.system("echo hi")\n\n'
    "STRIPE_SECRET_KEY = (\n"
    '    "sk_live_"\n'
    '    "0123456789abcdef0123456789ABCDEF"\n'
    ")\n"
)

_UNPARSEABLE = "def f(:\n    pass\n"

# ---------------------------------------------------------------------------
# Round 2: INTRA-pass shapes — the crit-capable rule shares the SAME `ast.walk` loop
# as the padding findings, not a later one. This is what round 1's per-pass budget
# (sized at _MAX_FINDINGS_PER_FILE itself) did not close.
# ---------------------------------------------------------------------------

# The C-135 reviewer's exact repro: 25 os.system() calls, then a hardcoded-secret
# default arg to os.getenv(...) — BOTH shapes are handled inline in analyze_python's
# FIRST main Call-walk loop (DANGEROUS_SINK and HARDCODED_PROVIDER_SECRET are the same
# pass, not a later one), so round 1's per-pass 25-budget still starved the secret.
_BAD_SECRET_BEHIND_FLOOD_SAME_LOOP = (
    "import os\n\n"
    + "\n".join(f'os.system("echo hi{i}")' for i in range(25))
    + "\n\n"
    'TOKEN = os.getenv("API_KEY", "sk_live_" "0123456789abcdef0123456789ABCDEF")\n'
)

# Unpadded control for the same shape — proves the getenv-default-arg detector itself
# is unaffected; only the padded/capped interaction is what round 2 fixes.
_SECRET_ALONE_GETENV = (
    "import os\n\n"
    'TOKEN = os.getenv("API_KEY", "sk_live_" "0123456789abcdef0123456789ABCDEF")\n'
)

# The C-135 reviewer's second repro, same shape, a different crit-capable rule in the
# SAME first loop: OBFUSCATED_EXEC (a genuinely decoded/obfuscated exec() payload).
_BAD_OBFUSCATED_EXEC_BEHIND_FLOOD_SAME_LOOP = (
    "import os\nimport base64\n\n"
    + "\n".join(f'os.system("echo hi{i}")' for i in range(25))
    + "\n\n"
    'exec(base64.b64decode("cHJpbnQoMSk=").decode())\n'
)

_OBFUSCATED_EXEC_ALONE = (
    "import base64\n\n" 'exec(base64.b64decode("cHJpbnQoMSk=").decode())\n'
)

# A THIRD instance of the same intra-pass shape, in a DIFFERENT loop than the
# reviewer's two reports: the TT5/TT4/SSRF `ext_taint_map` pass itself mixes
# TT5_CMD_INJECTION (crit) with TT5_ARG_INJECTION/TT4_FILE_NET/TT_SSRF (info) in one
# walk. 25 list-argv (shell=False) calls -- each its own TT5_ARG_INJECTION, not
# TT5_CMD_INJECTION, per the B-132 fixed-argv carve-out -- ahead of a genuinely
# tainted os.system(cmd) call. Found independently while verifying this round's fix
# generalizes past the two loop-1 shapes the reviewer named.
_BAD_TT5_CMD_BEHIND_ARG_INJECTION_FLOOD = (
    "import subprocess, sys, os\n\n"
    + "\n\n".join(
        f"def handle{i}(phone):\n"
        f"    subprocess.run([sys.executable, '-m', 'scripts.query{i}', phone], shell=False)"
        for i in range(25)
    )
    + "\n\n"
    "def run_cmd(cmd):\n"
    "    os.system(cmd)\n\n"
    "def main(argv):\n"
    "    run_cmd(argv[1])\n"
)

_TT5_CMD_ALONE = (
    "import os\n\n"
    "def run_cmd(cmd):\n"
    "    os.system(cmd)\n\n"
    "def main(argv):\n"
    "    run_cmd(argv[1])\n"
)


def _rules(result):
    return [f.rule for f in result]


# ---------------------------------------------------------------------------
# 1. The defect, reproduced and fixed
# ---------------------------------------------------------------------------


def test_tt5_survives_dangerous_sink_flood():
    """The task's own repro: a real TT5_CMD_INJECTION crit must survive 30 padding
    DANGEROUS_SINK info findings that discovery-order alone would have filled the cap
    with first."""
    result = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    rules = _rules(result)
    assert "TT5_CMD_INJECTION" in rules
    hit = next(f for f in result if f.rule == "TT5_CMD_INJECTION")
    assert hit.severity == "crit"


def test_hardcoded_secret_survives_dangerous_sink_flood():
    """The bug generalizes past TT5 specifically: ANY later capped pass (here, the
    plain-assignment HARDCODED_PROVIDER_SECRET rule, the LAST capped loop in the
    function) must survive an earlier pass filling `out` first."""
    result = analyze_python(_BAD_SECRET_BEHIND_FLOOD, "flood2.py")
    rules = _rules(result)
    assert "HARDCODED_PROVIDER_SECRET" in rules
    hit = next(f for f in result if f.rule == "HARDCODED_PROVIDER_SECRET")
    assert hit.severity == "crit"


# ---------------------------------------------------------------------------
# 1b. Round 2: the INTRA-pass shape (C-135 review of round 1's own fix) — the
# crit-capable rule shares the SAME walk as the padding, not a later one.
# ---------------------------------------------------------------------------


def test_getenv_secret_survives_flood_in_the_SAME_loop():
    """The C-135 reviewer's exact repro: HARDCODED_PROVIDER_SECRET (via the
    os.getenv(...) default-arg variant) is emitted by analyze_python's FIRST main
    Call-walk loop -- the SAME pass as the DANGEROUS_SINK padding, not a later one.
    Round 1's per-pass budget (sized at _MAX_FINDINGS_PER_FILE=25) did not close this:
    25 padding os.system() calls earlier in that one loop already exhausted it."""
    result = analyze_python(_BAD_SECRET_BEHIND_FLOOD_SAME_LOOP, "argflood_secret.py")
    rules = _rules(result)
    assert "HARDCODED_PROVIDER_SECRET" in rules
    hit = next(f for f in result if f.rule == "HARDCODED_PROVIDER_SECRET")
    assert hit.severity == "crit"


def test_getenv_secret_alone_control():
    """Control: the detector itself fires correctly with no padding at all — isolates
    the defect to the padded/capped interaction, not the HARDCODED_PROVIDER_SECRET
    getenv-default-arg predicate."""
    result = analyze_python(_SECRET_ALONE_GETENV, "small_secret.py")
    rules = _rules(result)
    assert rules == ["HARDCODED_PROVIDER_SECRET"]
    assert result[0].severity == "crit"


def test_obfuscated_exec_survives_flood_in_the_SAME_loop():
    """The C-135 reviewer's second repro: OBFUSCATED_EXEC (a genuinely decoded/
    obfuscated exec() payload) is ALSO emitted by the first main Call-walk loop —
    confirms the intra-pass gap is structural (shared first-loop budget covering
    multiple crit-capable rules), not a one-rule fluke."""
    result = analyze_python(
        _BAD_OBFUSCATED_EXEC_BEHIND_FLOOD_SAME_LOOP, "argflood_obf.py"
    )
    rules = _rules(result)
    assert "OBFUSCATED_EXEC" in rules
    hit = next(f for f in result if f.rule == "OBFUSCATED_EXEC")
    assert hit.severity == "crit"


def test_obfuscated_exec_alone_control():
    result = analyze_python(_OBFUSCATED_EXEC_ALONE, "small_obf.py")
    rules = _rules(result)
    assert rules == ["OBFUSCATED_EXEC"]
    assert result[0].severity == "crit"


def test_tt5_cmd_injection_survives_arg_injection_flood_in_the_SAME_pass():
    """A THIRD instance of the same intra-pass shape, found independently while
    verifying round 2's fix generalizes: the TT5/TT4/SSRF `ext_taint_map` pass ALSO
    mixes a crit rule (TT5_CMD_INJECTION) with an info rule (TT5_ARG_INJECTION) in one
    walk. 25 list-argv (shell=False) calls -- each correctly TT5_ARG_INJECTION, not
    TT5_CMD_INJECTION, per the B-132 fixed-argv carve-out -- must not starve a later,
    genuinely tainted os.system(cmd) call in the SAME pass."""
    result = analyze_python(
        _BAD_TT5_CMD_BEHIND_ARG_INJECTION_FLOOD, "argflood_tt5.py"
    )
    rules = _rules(result)
    assert "TT5_CMD_INJECTION" in rules
    hit = next(f for f in result if f.rule == "TT5_CMD_INJECTION")
    assert hit.severity == "crit"


def test_tt5_cmd_injection_alone_control():
    result = analyze_python(_TT5_CMD_ALONE, "small_tt5.py")
    rules = _rules(result)
    assert "TT5_CMD_INJECTION" in rules
    assert next(f for f in result if f.rule == "TT5_CMD_INJECTION").severity == "crit"


# ---------------------------------------------------------------------------
# 1c. Round 3: no finite per-pass ceiling survives, at any padding size — a second
# C-135 review found round 2's own `_PASS_SAFETY_CEILING` (20x = 500) was still a
# finite early-break, reproducibly bypassed at n_pad=500 (round 2's own boundary,
# exactly at the `>=` comparison). These fixtures pad well past that boundary; a
# regression that reintroduces ANY finite per-pass ceiling sized below these counts
# would make the crit vanish again exactly as it did in rounds 1 and 2.
# ---------------------------------------------------------------------------


def _secret_behind_flood(n_pad):
    return (
        "import os\n\n"
        + "\n".join(f'os.system("echo hi{i}")' for i in range(n_pad))
        + "\n\n"
        'TOKEN = os.getenv("API_KEY", "sk_live_" "0123456789abcdef0123456789ABCDEF")\n'
    )


def _obfuscated_exec_behind_flood(n_pad):
    return (
        "import os\nimport base64\n\n"
        + "\n".join(f'os.system("echo hi{i}")' for i in range(n_pad))
        + "\n\n"
        'exec(base64.b64decode("cHJpbnQoMSk=").decode())\n'
    )


def _tt5_cmd_behind_arg_injection_flood(n_pad):
    return (
        "import subprocess, sys, os\n\n"
        + "\n\n".join(
            f"def handle{i}(phone):\n"
            f"    subprocess.run([sys.executable, '-m', 'scripts.query{i}', phone], shell=False)"
            for i in range(n_pad)
        )
        + "\n\n"
        "def run_cmd(cmd):\n"
        "    os.system(cmd)\n\n"
        "def main(argv):\n"
        "    run_cmd(argv[1])\n"
    )


@pytest.mark.parametrize("n_pad", [500, 501, 600, 5000])
def test_getenv_secret_survives_flood_past_round2_ceiling(n_pad):
    """Round 2's own C-135 reviewer repro: at n_pad=500 exactly, round 2's
    `_PASS_SAFETY_CEILING` (=25*20) was exhausted before this crit was reached. No
    finite ceiling should exist any more, so this must hold at 500 and well beyond."""
    result = analyze_python(_secret_behind_flood(n_pad), "argflood_secret_big.py")
    hit = next((f for f in result if f.rule == "HARDCODED_PROVIDER_SECRET"), None)
    assert hit is not None, f"HARDCODED_PROVIDER_SECRET dropped at n_pad={n_pad}"
    assert hit.severity == "crit"
    assert len(result) <= _MAX_FINDINGS_PER_FILE


@pytest.mark.parametrize("n_pad", [500, 501, 600])
def test_obfuscated_exec_survives_flood_past_round2_ceiling(n_pad):
    result = analyze_python(_obfuscated_exec_behind_flood(n_pad), "argflood_obf_big.py")
    hit = next((f for f in result if f.rule == "OBFUSCATED_EXEC"), None)
    assert hit is not None, f"OBFUSCATED_EXEC dropped at n_pad={n_pad}"
    assert hit.severity == "crit"
    assert len(result) <= _MAX_FINDINGS_PER_FILE


@pytest.mark.parametrize("n_pad", [500, 501, 600])
def test_tt5_cmd_injection_survives_arg_injection_flood_past_round2_ceiling(n_pad):
    result = analyze_python(
        _tt5_cmd_behind_arg_injection_flood(n_pad), "argflood_tt5_big.py"
    )
    hit = next((f for f in result if f.rule == "TT5_CMD_INJECTION"), None)
    assert hit is not None, f"TT5_CMD_INJECTION dropped at n_pad={n_pad}"
    assert hit.severity == "crit"
    assert len(result) <= _MAX_FINDINGS_PER_FILE


def test_getenv_secret_e2e_fails_b13_past_round2_ceiling():
    """End-to-end pin of round 2's exact live evasion (500-call pad): before this
    round's fix, `check_installed_skills` returned PASS, "no shell-exec /
    exfiltration / obfuscation patterns found", on the round-2 tree. Must FAIL B13 on
    the real secret now."""
    ctx = _ctx(
        {"evasive-skill-500": "---\nname: evasive-skill-500\ndescription: does things\n---\n# X\n"},
        py={"evasive-skill-500": [("scripts/run.py", _secret_behind_flood(500))]},
    )
    fx = check_installed_skills(ctx)
    assert fx.status == "FAIL"
    assert "hardcoded provider-shaped secret" in fx.detail
    assert "AST_FINDINGS_TRUNCATED" not in fx.detail
    assert "suppressed" not in fx.detail


def test_no_finite_pass_safety_ceiling_constant_remains():
    """Pins the round-3 removal itself: `_PASS_SAFETY_CEILING` (round 2's finite
    per-pass budget) must not exist any more. A future round that reintroduces ANY
    named finite per-pass ceiling should have to touch this test deliberately,
    not silently reintroduce the round-1/round-2 starvation shape."""
    import clawseccheck.skillast as skillast_mod

    assert not hasattr(skillast_mod, "_PASS_SAFETY_CEILING")


# ---------------------------------------------------------------------------
# 2. The cap invariant + disclosure
# ---------------------------------------------------------------------------


def test_cap_still_enforced():
    result = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    assert len(result) <= _MAX_FINDINGS_PER_FILE


def test_truncation_is_disclosed():
    result = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    disclosures = [f for f in result if f.rule == "AST_FINDINGS_TRUNCATED"]
    assert len(disclosures) == 1
    d = disclosures[0]
    assert d.severity == "info"
    assert d.lineno == 0
    assert "suppressed" in d.reason
    # the disclosure occupies the LAST of the _MAX_FINDINGS_PER_FILE slots
    assert result[-1] is d
    assert len(result) == _MAX_FINDINGS_PER_FILE


def test_crit_sorted_ahead_of_info_when_truncated():
    """A cap must never drop a higher-severity finding in favour of lower ones: among
    the kept (non-disclosure) findings, severity is non-increasing."""
    result = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    kept = [f for f in result if f.rule != "AST_FINDINGS_TRUNCATED"]
    severities = [f.severity for f in kept]
    assert severities == sorted(severities, key=lambda s: {"crit": 0}.get(s, 1))
    assert severities[0] == "crit"


def test_ordering_is_deterministic():
    r1 = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    r2 = analyze_python(_BAD_TT5_BEHIND_FLOOD, "flood.py")
    assert r1 == r2


# The three round-2 (intra-pass) bad fixtures each push their single pass to 26
# candidates (25 padding + 1 real crit), one over _MAX_FINDINGS_PER_FILE, so the
# SAME cap/disclosure/determinism invariants above must hold for each of them too —
# `_PASS_SAFETY_CEILING` must never itself become a second, looser cap that leaks
# through to callers.
_INTRA_PASS_BAD_FIXTURES = {
    "getenv_secret": (_BAD_SECRET_BEHIND_FLOOD_SAME_LOOP, "HARDCODED_PROVIDER_SECRET"),
    "obfuscated_exec": (
        _BAD_OBFUSCATED_EXEC_BEHIND_FLOOD_SAME_LOOP,
        "OBFUSCATED_EXEC",
    ),
    "tt5_cmd_injection": (
        _BAD_TT5_CMD_BEHIND_ARG_INJECTION_FLOOD,
        "TT5_CMD_INJECTION",
    ),
}


def test_intra_pass_fixtures_still_honor_the_per_file_cap():
    for src, _crit_rule in _INTRA_PASS_BAD_FIXTURES.values():
        result = analyze_python(src, "x.py")
        assert len(result) <= _MAX_FINDINGS_PER_FILE


def test_intra_pass_fixtures_disclose_truncation_and_keep_crit_first():
    for src, crit_rule in _INTRA_PASS_BAD_FIXTURES.values():
        result = analyze_python(src, "x.py")
        disclosures = [f for f in result if f.rule == "AST_FINDINGS_TRUNCATED"]
        assert len(disclosures) == 1
        assert result[-1] is disclosures[0]
        kept = [f for f in result if f.rule != "AST_FINDINGS_TRUNCATED"]
        assert kept[0].rule == crit_rule
        assert kept[0].severity == "crit"


def test_intra_pass_fixtures_are_deterministic():
    for src, _crit_rule in _INTRA_PASS_BAD_FIXTURES.values():
        r1 = analyze_python(src, "x.py")
        r2 = analyze_python(src, "x.py")
        assert r1 == r2


# ---------------------------------------------------------------------------
# 3. Controls
# ---------------------------------------------------------------------------


def test_file_under_cap_is_unchanged():
    """Control: a file whose total findings never reach the cap gets no truncation
    treatment at all — no disclosure finding, and findings stay in DISCOVERY order
    (not severity-resorted), exactly as analyze_python behaved before this fix."""
    result = analyze_python(_CLEAN_UNDER_CAP, "small.py")
    rules = _rules(result)
    assert "AST_FINDINGS_TRUNCATED" not in rules
    assert len(result) < _MAX_FINDINGS_PER_FILE
    # DANGEROUS_SINK (info, from the main Call-walk pass) is discovered before
    # HARDCODED_PROVIDER_SECRET (crit, from the last plain-assignment pass) in this
    # source — under the cap, that pre-existing discovery order must survive
    # untouched, i.e. NOT severity-sorted.
    assert rules.index("DANGEROUS_SINK") < rules.index("HARDCODED_PROVIDER_SECRET")


def test_unanalyzable_source_untouched_by_truncation_logic():
    """UNKNOWN path: a parse failure returns via the early `except` branch, well under
    the cap, and is completely unaffected by the truncation/disclosure logic."""
    result = analyze_python(_UNPARSEABLE, "broken.py")
    assert result == [
        ASTFinding(
            "AST_UNANALYZABLE",
            "unknown",
            0,
            result[0].reason,
        )
    ]
    assert "could not parse" in result[0].reason


# ---------------------------------------------------------------------------
# 4. checks/_vet.py routing safety — the disclosure must never become a verdict
# ---------------------------------------------------------------------------


def test_truncation_rule_registered_never_fail_capable():
    assert "AST_FINDINGS_TRUNCATED" in _AST_NEVER_FAIL_RULES
    af = ASTFinding("AST_FINDINGS_TRUNCATED", "info", 0, "1 additional finding(s) suppressed")
    assert not ast_finding_is_fail_capable(af)


def _ctx(skills, py=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills
    if py:
        c.installed_skill_py = py
    return c


def test_truncation_disclosure_does_not_bleed_into_b13_crit_bucket():
    """End-to-end: a skill whose Python file hits the cap must still FAIL B13 on its
    real crit (TT5_CMD_INJECTION), and the FAIL text must carry that real reason, not
    the unrelated scan-completeness disclosure."""
    ctx = _ctx(
        {"flood-skill": "---\nname: flood-skill\ndescription: does things\n---\n# X\n"},
        py={"flood-skill": [("scripts/run.py", _BAD_TT5_BEHIND_FLOOD)]},
    )
    fx = check_installed_skills(ctx)
    assert fx.status == "FAIL"
    assert "command/code injection" in fx.detail
    assert "AST_FINDINGS_TRUNCATED" not in fx.detail
    assert "suppressed" not in fx.detail


def test_intra_pass_secret_e2e_fails_b13():
    """Round 2, end-to-end: the C-135 reviewer's exact live evasion — before this
    round's fix, this exact skill scanned clean (`check_installed_skills` -> PASS,
    "no shell-exec / exfiltration / obfuscation patterns found") on both the round-1
    tree and the pre-B-907 base, because the secret shared analyze_python's first
    Call-walk pass with the 25-call padding. Must FAIL B13 on the real secret now."""
    ctx = _ctx(
        {"evasive-skill": "---\nname: evasive-skill\ndescription: does things\n---\n# X\n"},
        py={
            "evasive-skill": [
                ("scripts/run.py", _BAD_SECRET_BEHIND_FLOOD_SAME_LOOP)
            ]
        },
    )
    fx = check_installed_skills(ctx)
    assert fx.status == "FAIL"
    assert "hardcoded provider-shaped secret" in fx.detail
    assert "AST_FINDINGS_TRUNCATED" not in fx.detail
    assert "suppressed" not in fx.detail
