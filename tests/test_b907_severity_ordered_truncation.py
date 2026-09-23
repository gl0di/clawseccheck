"""CLAWSECCHECK-B-907: the 25-finding cap on `analyze_python` silently dropped a real
TT5_CMD_INJECTION crit behind enough DANGEROUS_SINK info findings.

Every finding-collection loop in `analyze_python` gated on the SAME shared, global
`if len(out) >= _MAX_FINDINGS_PER_FILE: break`. An earlier pass (e.g. the plain
DANGEROUS_SINK sweep) that happened to fill `out` to the cap made every LATER pass's
loop break on its very first iteration — not merely capped alongside the earlier
pass's findings, but skipped entirely, so a real crit that pass would have found
(TT5_CMD_INJECTION, HARDCODED_PROVIDER_SECRET, ...) never appeared in the output at
all. This is a trivially exploitable evasion: pad a skill with two dozen harmless
`os.system("<literal>")` calls ahead of the real attacker-controlled sink.

The fix (skillast.py):
  1. Each pass now tracks its OWN contribution via a `_pass_start = len(out)` snapshot
     and breaks only once IT has added `_MAX_FINDINGS_PER_FILE` findings of its own —
     an earlier pass filling `out` can no longer starve a later one.
  2. `analyze_python`'s final `return` truncates the (now possibly over-cap) combined
     list by SEVERITY, not by discovery order — crit sorts ahead of info — and appends
     one `AST_FINDINGS_TRUNCATED` disclosure finding when anything was actually cut,
     so `len(result) <= _MAX_FINDINGS_PER_FILE` still holds for every caller.

checks/_vet.py: `AST_FINDINGS_TRUNCATED` is routed through its own `continue` arm
(alongside CHUNKED_FILE_EXEC/TUNNEL_LAUNCH_ARGV) and added to `_AST_NEVER_FAIL_RULES`,
so a cap-disclosure note can never itself become a B13 FAIL or bleed into the `high`
(cred-exfil) bucket.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3 / the B-740 idiom) — Python folds them into one `ast.Constant` at parse
time, so the AST detector still sees one joined value, but no contiguous secret-shaped
substring exists in this file's own raw text.

Offline, deterministic. No network calls, no writes outside tmp_path.
"""

from __future__ import annotations

from pathlib import Path

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
